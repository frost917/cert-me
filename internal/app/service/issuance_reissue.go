package service

import (
	"context"
	"errors"
	"sort"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

const issuanceOperationReissue = "issuance.reissue"

type reissueHashInput struct {
	SourceCertificateID string                 `json:"source_certificate_id"`
	TargetAuthorityID   *string                `json:"target_authority_id,omitempty"`
	TransitionID        *string                `json:"transition_id,omitempty"`
	Reason              contract.ReissueReason `json:"reason"`
}

type reissueContext struct {
	snapshot        port.SeriesSnapshot
	source          domain.Certificate
	sourceRecord    port.LeafCertificateRecord
	sourceAuthority domain.Authority
	targetAuthority domain.Authority
	targetCert      domain.Certificate
	transition      *domain.Transition
	impact          *domain.TransitionImpact
}

type reissuePrepared struct {
	now                   domain.Instant
	snapshot              port.SeriesSnapshot
	source                domain.Certificate
	sourceRecord          port.LeafCertificateRecord
	sourceAuthority       domain.Authority
	targetAuthorityID     domain.AuthorityID
	targetIssuerKeyID     domain.CAKeyGenerationID
	targetCert            domain.Certificate
	transitionID          domain.TransitionID
	plan                  domain.IssuancePlan
	keyMaterialID         domain.KeyMaterialID
	publicKey             domain.PublicKey
	generatedSecret       *domain.EncryptedSecret
	certificate           domain.Certificate
	deliverySeconds       int
	settingsVersion       domain.Version
	crlDistributionPoints []string
	issuerSecret          domain.EncryptedSecret
}

// Reissue always generates a new leaf key and records a new immutable
// certificate in the existing series. Delivery cleanup, revocations, CRL
// demands, lineage, transition impact, request replay state, and audit are
// committed with the new certificate in one UnitOfWork.
func (s *IssuanceService) Reissue(ctx context.Context, meta contract.MutationMeta, cmd contract.IssuanceReissueCommand) (contract.IssuanceView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.IssuanceView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.IssuanceView{}, contract.NewAppError(contract.ErrorKindForbidden, "issuance_requires_admin",
			"reissuing a certificate requires an administrator session")
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.IssuanceView{}, err
	}
	hashInput := reissueHashInput{SourceCertificateID: NormalizeUUID(string(cmd.SourceCertificateID)), Reason: cmd.Reason}
	if cmd.TargetAuthorityID != "" {
		value := NormalizeUUID(string(cmd.TargetAuthorityID))
		hashInput.TargetAuthorityID = &value
	}
	if cmd.TransitionID != "" {
		value := NormalizeUUID(string(cmd.TransitionID))
		hashInput.TransitionID = &value
	}
	inputHash, err := InputHash(issuanceOperationReissue,
		map[string]string{"series_id": NormalizeUUID(string(cmd.SeriesID))}, hashInput)
	if err != nil {
		return contract.IssuanceView{}, err
	}
	reqKey, err := RequestKey(meta, issuanceOperationReissue)
	if err != nil {
		return contract.IssuanceView{}, err
	}
	if err := ctx.Err(); err != nil {
		return contract.IssuanceView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	var result contract.IssuanceView
	if found, err := s.replayReissueBeforePreparation(ctx, meta, cmd, reqKey, inputHash, &result); err != nil {
		return contract.IssuanceView{}, err
	} else if found {
		return result, nil
	}

	var reuse *reissuePrepared
	for attempt := 0; attempt < maxSerialAttempts; attempt++ {
		prep, err := s.prepareReissue(ctx, meta, cmd, expectedVersion, reuse)
		if err != nil {
			// A concurrent caller can commit after the initial replay probe but
			// before this preparation read. Re-check the same request identity
			// before returning a stale-source or version error.
			if found, replayErr := s.replayReissueBeforePreparation(ctx, meta, cmd, reqKey, inputHash, &result); replayErr != nil {
				return contract.IssuanceView{}, replayErr
			} else if found {
				return result, nil
			}
			return contract.IssuanceView{}, err
		}
		reuse = &prep
		err = RunWithRetry(ctx, func() error {
			return s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
				return s.commitReissue(ctx, tx, meta, cmd, reqKey, inputHash, expectedVersion, prep, &result)
			})
		})
		if errors.Is(err, errRePrepare) {
			continue
		}
		if err != nil {
			return contract.IssuanceView{}, err
		}
		return result, nil
	}
	return contract.IssuanceView{}, contract.NewAppError(contract.ErrorKindConflict, "issuance_serial_exhausted",
		"could not obtain a unique serial after repeated signing attempts")
}

func (s *IssuanceService) replayReissueBeforePreparation(
	ctx context.Context,
	meta contract.MutationMeta,
	cmd contract.IssuanceReissueCommand,
	key port.OperationRequestKey,
	inputHash string,
	result *contract.IssuanceView,
) (bool, error) {
	var found bool
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if _, err := s.loadReissueContext(ctx, tx, meta.Principal, cmd, false); err != nil {
			return err
		}
		stored, ok, err := ReplayStoredResult(ctx, tx, key, inputHash)
		if err != nil || !ok {
			return err
		}
		view, err := decodeStoredIssuanceResult(stored)
		if err != nil {
			return err
		}
		projected, err := view.toView(ctx, tx)
		if err != nil {
			return err
		}
		projected.Replayed = true
		*result = projected
		found = true
		return nil
	})
	return found, err
}

func (s *IssuanceService) prepareReissue(
	ctx context.Context,
	meta contract.MutationMeta,
	cmd contract.IssuanceReissueCommand,
	expectedVersion domain.Version,
	reuse *reissuePrepared,
) (reissuePrepared, error) {
	prep := reissuePrepared{now: s.deps.Clock.Now()}
	var loaded reissueContext
	var issuerSecret domain.EncryptedSecret
	var settings resolvedSeriesDefaults
	if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		value, err := s.loadReissueContext(ctx, tx, meta.Principal, cmd, true)
		if err != nil {
			return err
		}
		loaded = value
		if value.snapshot.Series.IsArchived() {
			return contract.NewAppError(contract.ErrorKindConflict, "series_archived", "series is archived")
		}
		if value.snapshot.Series.CurrentCertificateID() != cmd.SourceCertificateID {
			return contract.NewAppError(contract.ErrorKindConflict, "source_certificate_mismatch",
				"source_certificate_id does not match the series' current certificate")
		}
		if value.source.Kind() != domain.CertificateKindLeaf || value.snapshot.Series.Purpose() != domain.SeriesPurposeDistributed {
			return contract.NewAppError(contract.ErrorKindForbidden, "issuance_reissue_leaf_only",
				"only distributed leaf certificates can be reissued through this operation")
		}
		if err := validateReissueDeliveryEvidence(ctx, tx, value, cmd.Reason, prep.now); err != nil {
			return err
		}
		secret, _, err := caSigningSecret(ctx, tx, value.targetAuthority)
		if err != nil {
			return err
		}
		issuerSecret = secret
		settings, err = resolveSeriesDefaults(ctx, tx, nil, nil)
		return err
	}); err != nil {
		return reissuePrepared{}, err
	}

	if loaded.snapshot.Series.Version() != expectedVersion {
		return reissuePrepared{}, contract.NewAppError(contract.ErrorKindConflict, "version_mismatch",
			"series has moved on since expected_version was read")
	}
	window, err := loaded.snapshot.Series.Policy().PlanWindow(x509NotBefore(prep.now))
	if err != nil {
		return reissuePrepared{}, contract.FromDomainError(err)
	}
	if err := loaded.targetAuthority.CanIssue(domain.IssuerContext{RequestedWindow: window, Intent: domain.IssuanceIntentLeaf}, prep.now); err != nil {
		return reissuePrepared{}, contract.FromDomainError(err)
	}
	prep.snapshot = loaded.snapshot
	prep.source = loaded.source
	prep.sourceRecord = loaded.sourceRecord
	prep.sourceAuthority = loaded.sourceAuthority
	prep.targetAuthorityID = loaded.targetAuthority.ID()
	prep.targetIssuerKeyID = loaded.targetAuthority.KeyGenerationID()
	prep.targetCert = loaded.targetCert
	prep.issuerSecret = issuerSecret
	prep.transitionID = cmd.TransitionID
	prep.deliverySeconds = settings.PrivateDeliverySeconds
	prep.settingsVersion = settings.SettingsVersion
	points, err := leafCRLDistributionPoints(settings.ServiceURL, prep.targetCert.ID())
	if err != nil {
		return reissuePrepared{}, err
	}
	prep.crlDistributionPoints = points
	prep.plan = domain.IssuancePlan{
		Profile: prep.source.Profile(), Subject: prep.source.Subject(), SANs: prep.source.SANs(),
		KeyAlgorithm: prep.source.KeyAlgorithm(), Window: window, IssuerAuthorityID: prep.targetAuthorityID,
		IssuerKeyGenerationID: prep.targetIssuerKeyID,
	}

	certificateID, err := domain.ParseCertificateID(s.deps.IDs.NewUUID())
	if err != nil {
		return reissuePrepared{}, contract.FromDomainError(err)
	}
	if reuse != nil && reuse.source.ID() == prep.source.ID() && reuse.targetIssuerKeyID == prep.targetIssuerKeyID {
		prep.keyMaterialID = reuse.keyMaterialID
		prep.publicKey = reuse.publicKey
		prep.generatedSecret = reuse.generatedSecret
		cert, err := resignWithNewSerial(ctx, s.deps.CertificateSigner, s.deps.SerialGenerator, prep.plan, certificateID,
			prep.keyMaterialID, prep.publicKey, domain.CertificateKindLeaf, meta.Principal.AccountID(), prep.targetCert,
			issuerSecret, prep.crlDistributionPoints)
		if err != nil {
			return reissuePrepared{}, err
		}
		prep.certificate = cert
		return prep, nil
	}

	keyMaterialID, err := domain.ParseKeyMaterialID(s.deps.IDs.NewUUID())
	if err != nil {
		return reissuePrepared{}, contract.FromDomainError(err)
	}
	ref := signingKeyRef{Fresh: &port.KeySpec{KeyMaterialID: keyMaterialID, Algorithm: prep.source.KeyAlgorithm(), Purpose: domain.SecretPurposeLeafDelivery}}
	prepared, err := prepareCertificate(ctx, s.deps.KeyEngine, s.deps.CertificateSigner, s.deps.SerialGenerator,
		prep.plan, ref, domain.PublicKey{}, certificateID, prep.targetCert, issuerSecret, domain.CertificateKindLeaf,
		meta.Principal.AccountID(), prep.crlDistributionPoints)
	if err != nil {
		return reissuePrepared{}, err
	}
	prep.keyMaterialID = prepared.KeyMaterialID
	prep.publicKey = prepared.GeneratedPublic
	prep.generatedSecret = prepared.GeneratedSecret
	prep.certificate = prepared.Certificate
	return prep, nil
}

// loadReissueContext resolves all authorization and lineage scope from
// persisted rows. strict is false for replay so a completed operation may
// still be replayed after its source is no longer the series' current
// certificate or its transition impact has been resolved.
func (s *IssuanceService) loadReissueContext(
	ctx context.Context,
	tx port.TxStores,
	principal contract.Principal,
	cmd contract.IssuanceReissueCommand,
	strict bool,
) (reissueContext, error) {
	var out reissueContext
	snapshot, err := tx.PKI().GetSeriesForUpdate(ctx, cmd.SeriesID)
	if errors.Is(err, port.ErrNotFound) {
		return out, contract.NewAppError(contract.ErrorKindValidation, "series_not_found", "series does not exist").
			WithField("series_id", string(cmd.SeriesID))
	} else if err != nil {
		return out, storeError(err, "issuance_series_read_failed", "could not read the series")
	}
	source, err := tx.PKI().GetCertificate(ctx, cmd.SourceCertificateID)
	if errors.Is(err, port.ErrNotFound) {
		return out, contract.NewAppError(contract.ErrorKindValidation, "certificate_not_found", "source certificate does not exist")
	} else if err != nil {
		return out, storeError(err, "issuance_certificate_read_failed", "could not read the source certificate")
	}
	record, err := tx.PKI().GetLeafCertificateRecord(ctx, source.ID())
	if errors.Is(err, port.ErrNotFound) {
		return out, contract.NewAppError(contract.ErrorKindConflict, "reissue_source_not_leaf", "source certificate has no leaf issuance record")
	} else if err != nil {
		return out, storeError(err, "issuance_leaf_record_read_failed", "could not read the source leaf lineage")
	}
	if record.SeriesID != cmd.SeriesID {
		return out, contract.NewAppError(contract.ErrorKindConflict, "source_series_mismatch",
			"source_certificate_id does not belong to the requested series")
	}
	sourceGeneration, err := tx.PKI().GetCAKeyGeneration(ctx, source.IssuerCAKeyGenerationID())
	if errors.Is(err, port.ErrNotFound) {
		return out, contract.NewAppError(contract.ErrorKindUnavailable, "issuance_source_issuer_missing",
			"the source certificate's issuing key generation is missing")
	} else if err != nil {
		return out, storeError(err, "issuance_source_issuer_read_failed", "could not read the source certificate's issuing authority")
	}
	sourceAuthority, err := tx.PKI().GetIssuerForUpdate(ctx, sourceGeneration.AuthorityID)
	if errors.Is(err, port.ErrNotFound) {
		return out, contract.NewAppError(contract.ErrorKindUnavailable, "issuance_source_authority_missing",
			"the source certificate's issuing authority is missing")
	} else if err != nil {
		return out, storeError(err, "issuance_source_issuer_read_failed", "could not read the source certificate's issuing authority")
	}

	var transition *domain.Transition
	if cmd.TransitionID != "" {
		value, err := tx.Transitions().GetForUpdate(ctx, cmd.TransitionID)
		if errors.Is(err, port.ErrNotFound) {
			return out, contract.NewAppError(contract.ErrorKindValidation, "transition_not_found", "transition does not exist")
		} else if err != nil {
			return out, storeError(err, "issuance_transition_read_failed", "could not read the certificate transition")
		}
		transition = &value
	}
	targetID := cmd.TargetAuthorityID
	if targetID == "" && transition != nil && transition.TargetAuthorityID() != "" {
		targetID = transition.TargetAuthorityID()
	}
	if targetID == "" {
		targetID = snapshot.Series.ManagementAuthorityID()
	}
	if strict {
		if snapshot.Series.IsArchived() {
			return out, contract.NewAppError(contract.ErrorKindConflict, "series_archived", "series is archived")
		}
		if snapshot.Series.CurrentCertificateID() != cmd.SourceCertificateID {
			return out, contract.NewAppError(contract.ErrorKindConflict, "source_certificate_mismatch",
				"source_certificate_id does not match the series' current certificate")
		}
		if snapshot.CurrentKeyGeneration.ID() != record.LeafKeyGenerationID {
			return out, contract.NewAppError(contract.ErrorKindConflict, "source_key_generation_mismatch",
				"source certificate does not use the series' current key generation")
		}
		if cmd.Reason == contract.ReissueReasonEmergency && transition == nil {
			return out, contract.NewAppError(contract.ErrorKindValidation, "reissue_transition_required",
				"emergency reissue requires a matching emergency transition")
		}
		if transition != nil {
			if !transition.IsInProgress() {
				return out, contract.NewAppError(contract.ErrorKindConflict, "transition_not_in_progress",
					"the certificate transition is no longer open for reissue")
			}
			if transition.SourceAuthorityID() != sourceAuthority.ID() {
				return out, contract.NewAppError(contract.ErrorKindConflict, "transition_source_mismatch",
					"transition source does not match the certificate's issuing authority")
			}
			if transition.TargetAuthorityID() == "" || targetID != transition.TargetAuthorityID() {
				return out, contract.NewAppError(contract.ErrorKindConflict, "transition_target_mismatch",
					"reissue target must match the transition's successor authority")
			}
			if cmd.Reason == contract.ReissueReasonEmergency && transition.Mode() != domain.TransitionModeEmergency {
				return out, contract.NewAppError(contract.ErrorKindConflict, "emergency_transition_required",
					"emergency reissue requires an emergency CA transition")
			}
			if cmd.Reason != contract.ReissueReasonEmergency && transition.Mode() == domain.TransitionModeEmergency {
				return out, contract.NewAppError(contract.ErrorKindConflict, "emergency_reissue_reason_required",
					"an emergency CA transition requires the emergency reissue reason")
			}
			impacts, err := tx.Transitions().ListImpacts(ctx, transition.ID())
			if err != nil {
				return out, storeError(err, "issuance_transition_impacts_read_failed", "could not read transition impact")
			}
			var found bool
			for i := range impacts {
				if impacts[i].CertificateID() != source.ID() {
					continue
				}
				if impacts[i].IsResolved() {
					return out, contract.NewAppError(contract.ErrorKindConflict, "transition_impact_resolved",
						"the source certificate already has a replacement in this transition")
				}
				impact := impacts[i]
				out.impact = &impact
				found = true
				break
			}
			if !found {
				return out, contract.NewAppError(contract.ErrorKindConflict, "transition_impact_missing",
					"the source certificate is not an unresolved impact of this transition")
			}
		}
		if cmd.Reason == contract.ReissueReasonEmergency && targetID == sourceAuthority.ID() {
			return out, contract.NewAppError(contract.ErrorKindConflict, "emergency_target_must_change",
				"emergency reissue must use a different issuing authority")
		}
	}
	targetAuthority, err := tx.PKI().GetIssuerForUpdate(ctx, targetID)
	if errors.Is(err, port.ErrNotFound) {
		return out, contract.NewAppError(contract.ErrorKindValidation, "authority_not_found", "target authority does not exist").
			WithField("authority_id", string(targetID))
	} else if err != nil {
		return out, storeError(err, "issuance_authority_read_failed", "could not read the target authority")
	}
	scopes := []domain.AuthorityID{snapshot.Series.ManagementAuthorityID(), sourceAuthority.ID(), targetAuthority.ID()}
	if transition != nil {
		scopes = append(scopes, transition.SourceAuthorityID())
		if transition.TargetAuthorityID() != "" {
			scopes = append(scopes, transition.TargetAuthorityID())
		}
	}
	if err := s.deps.Authorizer.Authorize(ctx, principal, port.ActionIssuanceReissue, port.NewAuthorizationScope(scopes...)); err != nil {
		return out, err
	}
	if strict {
		keyMaterial, err := tx.PKI().GetKeyMaterial(ctx, source.KeyMaterialID())
		if err != nil {
			return out, storeError(err, "issuance_source_key_read_failed", "could not read the source leaf key status")
		}
		if !keyMaterial.CompromisedAt.IsZero() && cmd.Reason != contract.ReissueReasonKeyCompromise {
			return out, contract.NewAppError(contract.ErrorKindForbidden, "issuance_key_compromise_reason_required",
				"a compromised source key must be reissued through the key_compromise reason")
		}
	}
	var targetCert domain.Certificate
	if strict {
		targetCert, _, err = verifyCASigningKeyLive(ctx, tx, targetAuthority)
		if err != nil {
			return out, err
		}
	}
	out.snapshot = snapshot
	out.source = source
	out.sourceRecord = record
	out.sourceAuthority = sourceAuthority
	out.targetAuthority = targetAuthority
	out.targetCert = targetCert
	out.transition = transition
	return out, nil
}

func validateReissueDeliveryEvidence(ctx context.Context, tx port.TxStores, loaded reissueContext, reason contract.ReissueReason, now domain.Instant) error {
	delivery, err := tx.Delivery().GetDeliveryByLeafKeyGenerationForUpdate(ctx, loaded.snapshot.CurrentKeyGeneration.ID())
	if errors.Is(err, port.ErrNotFound) {
		if reason == contract.ReissueReasonDeliveryFailed || reason == contract.ReissueReasonDeliveryExpired {
			return contract.NewAppError(contract.ErrorKindConflict, "reissue_delivery_missing",
				"the source certificate has no delivery record matching the requested reason")
		}
		if loaded.snapshot.CurrentKeyGeneration.Custody() == domain.KeyCustodyPendingDelivery {
			return contract.NewAppError(contract.ErrorKindUnavailable, "reissue_pending_delivery_missing",
				"a pending source key generation has no delivery record")
		}
		return nil
	} else if err != nil {
		return storeError(err, "issuance_delivery_read_failed", "could not read the source key delivery")
	}
	if err := validateReissueDeliveryLineage(ctx, tx, loaded, delivery); err != nil {
		return err
	}
	if delivery.State() == domain.DeliveryStateTransferring {
		return contract.NewAppError(contract.ErrorKindConflict, "reissue_delivery_in_progress",
			"the source private key is currently being transferred")
	}
	switch reason {
	case contract.ReissueReasonDeliveryFailed:
		if delivery.State() != domain.DeliveryStateFailed {
			return contract.NewAppError(contract.ErrorKindConflict, "reissue_delivery_not_failed",
				"delivery must be marked failed before using the delivery_failed reason")
		}
	case contract.ReissueReasonDeliveryExpired:
		if delivery.State() != domain.DeliveryStateExpired &&
			!(delivery.State() == domain.DeliveryStatePending && delivery.ExpiresAt().IsExpiredAt(now)) {
			return contract.NewAppError(contract.ErrorKindConflict, "reissue_delivery_not_expired",
				"delivery must be expired before using the delivery_expired reason")
		}
	}
	return nil
}

func validateReissueDeliveryLineage(ctx context.Context, tx port.TxStores, loaded reissueContext, delivery domain.Delivery) error {
	if delivery.LeafKeyGenerationID() != loaded.snapshot.CurrentKeyGeneration.ID() {
		return contract.NewAppError(contract.ErrorKindUnavailable, "reissue_delivery_mismatch",
			"the source delivery points at a different leaf key generation")
	}
	record, err := tx.PKI().GetLeafCertificateRecord(ctx, delivery.CertificateID())
	if errors.Is(err, port.ErrNotFound) {
		return contract.NewAppError(contract.ErrorKindUnavailable, "reissue_delivery_lineage_missing",
			"the source delivery's certificate lineage is missing")
	} else if err != nil {
		return storeError(err, "issuance_delivery_lineage_read_failed", "could not validate the source delivery's lineage")
	}
	if record.SeriesID != loaded.snapshot.Series.ID() || record.LeafKeyGenerationID != loaded.snapshot.CurrentKeyGeneration.ID() {
		return contract.NewAppError(contract.ErrorKindUnavailable, "reissue_delivery_mismatch",
			"the source delivery does not belong to the current series and key generation")
	}
	return nil
}

func (s *IssuanceService) commitReissue(
	ctx context.Context,
	tx port.TxStores,
	meta contract.MutationMeta,
	cmd contract.IssuanceReissueCommand,
	key port.OperationRequestKey,
	inputHash string,
	expectedVersion domain.Version,
	prep reissuePrepared,
	result *contract.IssuanceView,
) error {
	if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
		return err
	}
	snapshot, err := tx.PKI().GetSeriesForUpdate(ctx, cmd.SeriesID)
	if errors.Is(err, port.ErrNotFound) {
		return contract.NewAppError(contract.ErrorKindValidation, "series_not_found", "series does not exist").
			WithField("series_id", string(cmd.SeriesID))
	} else if err != nil {
		return storeError(err, "issuance_series_read_failed", "could not read the series")
	}
	loaded, err := s.loadReissueContext(ctx, tx, meta.Principal, cmd, false)
	if err != nil {
		return err
	}
	if stored, found, err := ReplayStoredResult(ctx, tx, key, inputHash); err != nil {
		return err
	} else if found {
		view, err := decodeStoredIssuanceResult(stored)
		if err != nil {
			return err
		}
		projected, err := view.toView(ctx, tx)
		if err != nil {
			return err
		}
		projected.Replayed = true
		*result = projected
		return nil
	}
	if snapshot.Series.IsArchived() {
		return contract.NewAppError(contract.ErrorKindConflict, "series_archived", "series is archived")
	}
	if snapshot.Series.Version() != expectedVersion {
		return contract.NewAppError(contract.ErrorKindConflict, "version_mismatch", "series has moved on since expected_version was read")
	}
	if snapshot.Series.CurrentCertificateID() != cmd.SourceCertificateID {
		return contract.NewAppError(contract.ErrorKindConflict, "source_certificate_mismatch",
			"source_certificate_id does not match the series' current certificate")
	}
	if loaded.source.Kind() != domain.CertificateKindLeaf || snapshot.Series.Purpose() != domain.SeriesPurposeDistributed {
		return contract.NewAppError(contract.ErrorKindForbidden, "issuance_reissue_leaf_only",
			"only distributed leaf certificates can be reissued through this operation")
	}
	strict, err := s.loadReissueContext(ctx, tx, meta.Principal, cmd, true)
	if err != nil {
		return err
	}
	if strict.targetAuthority.ID() != prep.targetAuthorityID || strict.targetAuthority.KeyGenerationID() != prep.targetIssuerKeyID ||
		strict.targetCert.ID() != prep.targetCert.ID() {
		return errRePrepare
	}
	if strict.snapshot.CurrentKeyGeneration.ID() != prep.snapshot.CurrentKeyGeneration.ID() ||
		strict.snapshot.CurrentKeyGeneration.KeyMaterialID() != prep.snapshot.CurrentKeyGeneration.KeyMaterialID() {
		return errRePrepare
	}
	commitNow := s.deps.Clock.Now()
	if err := strict.targetAuthority.CanIssue(domain.IssuerContext{RequestedWindow: prep.plan.Window, Intent: domain.IssuanceIntentLeaf}, commitNow); err != nil {
		return contract.FromDomainError(err)
	}
	if _, _, err := verifyCASigningKeyLive(ctx, tx, strict.targetAuthority); err != nil {
		return err
	}
	if err := settingsUnchanged(ctx, tx, prep.settingsVersion); err != nil {
		return err
	}
	if err := ensureSerialUnused(ctx, tx, prep.plan.IssuerKeyGenerationID, prep.certificate.Serial()); err != nil {
		return err
	}

	terminalDelivery, needsDeliveryRevocation, err := closeOldReissueDelivery(ctx, tx, strict, cmd.Reason, commitNow)
	if err != nil {
		return err
	}
	if cmd.Reason == contract.ReissueReasonKeyCompromise {
		if err := tx.PKI().MarkCompromised(ctx, strict.snapshot.CurrentKeyGeneration.KeyMaterialID(), commitNow); err != nil {
			return storeError(err, "issuance_key_compromise_mark_failed", "could not record the source leaf key compromise")
		}
	}
	if prep.generatedSecret == nil || prep.generatedSecret.OwnerKeyID() != prep.keyMaterialID || prep.generatedSecret.Purpose() != domain.SecretPurposeLeafDelivery {
		return contract.NewAppError(contract.ErrorKindUnavailable, "issuance_missing_generated_secret",
			"the reissue did not produce a new private key for delivery")
	}
	if err := insertGeneratedKeyMaterial(ctx, tx, prep.keyMaterialID, prep.publicKey); err != nil {
		return err
	}
	if err := tx.PKI().InsertCertificate(ctx, prep.certificate); err != nil {
		return storeError(err, "issuance_certificate_store_failed", "could not store the reissued certificate")
	}

	newGenerationID, err := domain.ParseLeafKeyGenerationID(s.deps.IDs.NewUUID())
	if err != nil {
		return contract.FromDomainError(err)
	}
	newGeneration, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
		ID: newGenerationID, SeriesID: snapshot.Series.ID(), KeyMaterialID: prep.keyMaterialID,
		GenerationNo: snapshot.CurrentKeyGeneration.GenerationNo() + 1, RenewalCount: 0,
		Custody: domain.KeyCustodyPendingDelivery,
	})
	if err != nil {
		return contract.FromDomainError(err)
	}
	if err := tx.PKI().InsertLeafKeyGeneration(ctx, newGeneration); err != nil {
		return storeError(err, "issuance_leaf_key_generation_store_failed", "could not store the new leaf key generation")
	}
	operation := reissueCertificateOperation(cmd.Reason, strict.sourceAuthority.ID(), strict.targetAuthority.ID())
	policySnapshot, err := leafPolicySnapshotJSON(prep.certificate, snapshot.Series.Policy())
	if err != nil {
		return err
	}
	if err := tx.PKI().InsertLeafCertificateRecord(ctx, port.LeafCertificateRecord{
		CertificateID: prep.certificate.ID(), SeriesID: snapshot.Series.ID(), LeafKeyGenerationID: newGenerationID,
		IssuerCACertificateID: prep.targetCert.ID(), PreviousCertificateID: cmd.SourceCertificateID,
		Operation: operation, RenewalCountAtIssue: 0, PolicySnapshotJSON: policySnapshot,
	}); err != nil {
		return storeError(err, "issuance_leaf_certificate_record_store_failed", "could not store the leaf certificate lineage")
	}
	updatedSeries, err := domain.NewLeafSeries(domain.LeafSeriesFacts{
		ID: snapshot.Series.ID(), Name: snapshot.Series.Name(), Purpose: snapshot.Series.Purpose(),
		ManagementAuthorityID: snapshot.Series.ManagementAuthorityID(), CurrentCertificateID: prep.certificate.ID(),
		CurrentKeyGenerationID: newGenerationID, Policy: snapshot.Series.Policy(), Version: snapshot.Series.Version().Next(),
		ArchivedAt: snapshot.Series.ArchivedAt(),
	})
	if err != nil {
		return contract.FromDomainError(err)
	}
	if err := tx.PKI().SaveSeries(ctx, updatedSeries, expectedVersion); err != nil {
		return storeError(err, "issuance_series_save_failed", "could not update the series with its replacement certificate")
	}
	newDelivery, err := storeFreshKeyAndDelivery(ctx, tx, s.deps.IDs, commitNow, prep.keyMaterialID,
		*prep.generatedSecret, newGenerationID, prep.certificate.ID(), prep.deliverySeconds)
	if err != nil {
		return err
	}

	if cmd.Reason == contract.ReissueReasonKeyCompromise {
		changes, err := compromisedLeafRevocations(ctx, tx, prep.snapshot.CurrentKeyGeneration.KeyMaterialID(), commitNow)
		if err != nil {
			return err
		}
		if _, err := applyRevocations(ctx, tx, changes, RevocationMeta{
			Request: meta.RequestMeta, ActorKind: contract.AuditActorAccount, ActorID: string(meta.Principal.AccountID()),
			Action: "issuance.reissue.key_compromise", Now: commitNow, IDs: s.deps.IDs,
		}); err != nil {
			return err
		}
	} else if cmd.Reason == contract.ReissueReasonDeliveryFailed || cmd.Reason == contract.ReissueReasonDeliveryExpired || needsDeliveryRevocation {
		if terminalDelivery == nil {
			return contract.NewAppError(contract.ErrorKindUnavailable, "reissue_delivery_missing",
				"the source delivery needed for revocation is unavailable")
		}
		revokedAt := terminalDelivery.FinishedAt()
		if revokedAt.IsZero() {
			revokedAt = commitNow
		}
		changes, err := leafRevocationsUsingKey(ctx, tx, strict.snapshot.CurrentKeyGeneration.KeyMaterialID(), revokedAt,
			domain.RevocationReasonUnspecified)
		if err != nil {
			return err
		}
		if _, err := applyRevocations(ctx, tx, changes, RevocationMeta{
			Request: meta.RequestMeta, ActorKind: contract.AuditActorAccount, ActorID: string(meta.Principal.AccountID()),
			Action: "issuance.reissue.delivery_cleanup", Now: commitNow, IDs: s.deps.IDs,
		}); err != nil {
			return err
		}
	}

	if strict.impact != nil {
		resolvedImpact, err := strict.impact.RecordReplacement(prep.certificate.ID(), commitNow)
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.Transitions().LinkReplacement(ctx, resolvedImpact); err != nil {
			return storeError(err, "issuance_transition_impact_link_failed", "could not link the reissued certificate to its transition")
		}
	}

	view := storedIssuanceResult{
		SchemaVersion: issuanceStoredResultSchemaVersion, SeriesID: string(snapshot.Series.ID()),
		CertificateID: string(prep.certificate.ID()), KeyGenerationID: string(newGenerationID),
		RenewalCount: 0, KeyRotated: true, DeliveryID: string(newDelivery.ID()),
	}
	if err := StoreRequestResult(ctx, tx, key, inputHash, view); err != nil {
		return err
	}
	if err := appendReissueAudit(ctx, tx, s.deps.IDs, commitNow, meta, prep.certificate,
		strict.snapshot.Series.ManagementAuthorityID(), strict.sourceAuthority.ID(), strict.targetAuthority.ID(), cmd.Reason,
		transitionScopes(strict.transition)); err != nil {
		return err
	}
	projected, err := view.toView(ctx, tx)
	if err != nil {
		return err
	}
	*result = projected
	return nil
}

func closeOldReissueDelivery(
	ctx context.Context,
	tx port.TxStores,
	loaded reissueContext,
	reason contract.ReissueReason,
	now domain.Instant,
) (*domain.Delivery, bool, error) {
	delivery, err := tx.Delivery().GetDeliveryByLeafKeyGenerationForUpdate(ctx, loaded.snapshot.CurrentKeyGeneration.ID())
	if errors.Is(err, port.ErrNotFound) {
		if reason == contract.ReissueReasonDeliveryFailed || reason == contract.ReissueReasonDeliveryExpired {
			return nil, false, contract.NewAppError(contract.ErrorKindConflict, "reissue_delivery_missing",
				"the source certificate has no delivery record matching the requested reason")
		}
		if loaded.snapshot.CurrentKeyGeneration.Custody() == domain.KeyCustodyPendingDelivery {
			return nil, false, contract.NewAppError(contract.ErrorKindUnavailable, "reissue_pending_delivery_missing",
				"a pending source key generation has no delivery record")
		}
		return nil, false, nil
	} else if err != nil {
		return nil, false, storeError(err, "issuance_delivery_read_failed", "could not read the source key delivery")
	}
	if err := validateReissueDeliveryLineage(ctx, tx, loaded, delivery); err != nil {
		return nil, false, err
	}
	state := delivery.State()
	originalState := state
	var needsRevocation bool
	if state == domain.DeliveryStateTransferring {
		return nil, false, contract.NewAppError(contract.ErrorKindConflict, "reissue_delivery_in_progress",
			"the source private key is currently being transferred")
	}
	if state == domain.DeliveryStatePending {
		if delivery.ExpiresAt().IsExpiredAt(now) {
			expired, err := delivery.Expire(now)
			if err != nil {
				return nil, false, contract.FromDomainError(err)
			}
			if err := tx.Delivery().SaveDelivery(ctx, expired, delivery.Version()); err != nil {
				return nil, false, storeError(err, "issuance_delivery_save_failed", "could not record the expired source delivery")
			}
			delivery = expired
			needsRevocation = true
		} else if reason == contract.ReissueReasonDeliveryFailed {
			return nil, false, contract.NewAppError(contract.ErrorKindConflict, "reissue_delivery_not_failed",
				"delivery must be marked failed before using the delivery_failed reason")
		} else if reason == contract.ReissueReasonDeliveryExpired {
			return nil, false, contract.NewAppError(contract.ErrorKindConflict, "reissue_delivery_not_expired",
				"delivery must be expired before using the delivery_expired reason")
		} else {
			failed, err := delivery.Fail("reissued", now)
			if err != nil {
				return nil, false, contract.FromDomainError(err)
			}
			if err := tx.Delivery().SaveDelivery(ctx, failed, delivery.Version()); err != nil {
				return nil, false, storeError(err, "issuance_delivery_save_failed", "could not close the source private key delivery")
			}
			delivery = failed
			needsRevocation = true
		}
	}
	if reason == contract.ReissueReasonDeliveryFailed && delivery.State() != domain.DeliveryStateFailed {
		return nil, false, contract.NewAppError(contract.ErrorKindConflict, "reissue_delivery_not_failed",
			"delivery must be marked failed before using the delivery_failed reason")
	}
	if reason == contract.ReissueReasonDeliveryExpired && delivery.State() != domain.DeliveryStateExpired {
		return nil, false, contract.NewAppError(contract.ErrorKindConflict, "reissue_delivery_not_expired",
			"delivery must be expired before using the delivery_expired reason")
	}
	if reason == contract.ReissueReasonDeliveryFailed || reason == contract.ReissueReasonDeliveryExpired ||
		originalState == domain.DeliveryStateFailed || originalState == domain.DeliveryStateExpired || needsRevocation {
		needsRevocation = true
	}
	if err := tx.Delivery().InvalidatePrivateGrants(ctx, delivery.ID(), now); err != nil {
		return nil, false, storeError(err, "issuance_delivery_grants_invalidate_failed", "could not invalidate the old private download links")
	}
	if err := tx.Secrets().Delete(ctx, loaded.snapshot.CurrentKeyGeneration.KeyMaterialID(), domain.SecretPurposeLeafDelivery); err != nil {
		return nil, false, storeError(err, "issuance_delivery_secret_delete_failed", "could not delete the old private key ciphertext")
	}
	return &delivery, needsRevocation, nil
}

func compromisedLeafRevocations(ctx context.Context, tx port.TxStores, keyID domain.KeyMaterialID, now domain.Instant) ([]RevocationChange, error) {
	return leafRevocationsUsingKey(ctx, tx, keyID, now, domain.RevocationReasonKeyCompromise)
}

func leafRevocationsUsingKey(ctx context.Context, tx port.TxStores, keyID domain.KeyMaterialID, now domain.Instant, reason domain.RevocationReason) ([]RevocationChange, error) {
	certificates, err := tx.PKI().ListCertificatesUsingKey(ctx, keyID)
	if err != nil {
		return nil, storeError(err, "issuance_reissue_certificates_read_failed", "could not list certificates using the source leaf key")
	}
	if len(certificates) == 0 && reason == domain.RevocationReasonKeyCompromise {
		return nil, contract.NewAppError(contract.ErrorKindUnavailable, "issuance_compromised_source_missing",
			"the compromised leaf key has no certificate history")
	}
	sort.Slice(certificates, func(i, j int) bool { return certificates[i].ID() < certificates[j].ID() })
	changes := make([]RevocationChange, 0, len(certificates))
	for _, cert := range certificates {
		if cert.Kind() != domain.CertificateKindLeaf {
			return nil, contract.NewAppError(contract.ErrorKindForbidden, "issuance_leaf_compromise_ca_key",
				"a key shared with a CA certificate must use the CA compromise transition")
		}
		if cert.IsExpiredAt(now) {
			continue
		}
		record, err := tx.PKI().GetLeafCertificateRecord(ctx, cert.ID())
		if err != nil {
			return nil, storeError(err, "issuance_reissue_lineage_read_failed", "could not resolve a leaf certificate's management scope")
		}
		series, err := tx.PKI().GetSeriesForUpdate(ctx, record.SeriesID)
		if err != nil {
			return nil, storeError(err, "issuance_reissue_series_read_failed", "could not resolve a leaf certificate's management scope")
		}
		changes = append(changes, RevocationChange{
			IssuerID: cert.IssuerCAKeyGenerationID(), Serial: cert.Serial(), CertificateID: cert.ID(),
			RevokedAt: now, Reason: reason, Source: domain.RevocationSourceCascade,
			AuthorityID: series.Series.ManagementAuthorityID(),
		})
	}
	return changes, nil
}

func reissueCertificateOperation(reason contract.ReissueReason, sourceAuthority, targetAuthority domain.AuthorityID) string {
	if reason == contract.ReissueReasonEmergency {
		return port.CertificateOperationEmergency
	}
	if sourceAuthority != targetAuthority {
		return port.CertificateOperationMigrate
	}
	return port.CertificateOperationRekey
}

func transitionScopes(transition *domain.Transition) []domain.AuthorityID {
	if transition == nil {
		return nil
	}
	scopes := []domain.AuthorityID{transition.SourceAuthorityID()}
	if transition.TargetAuthorityID() != "" {
		scopes = append(scopes, transition.TargetAuthorityID())
	}
	return scopes
}

func appendReissueAudit(
	ctx context.Context,
	tx port.TxStores,
	ids port.IDGenerator,
	now domain.Instant,
	meta contract.MutationMeta,
	cert domain.Certificate,
	managementAuthorityID, sourceAuthorityID, targetAuthorityID domain.AuthorityID,
	reason contract.ReissueReason,
	extraScopes []domain.AuthorityID,
) error {
	event := port.AuditEvent{
		ID: ids.NewUUID(), OccurredAt: now, ActorKind: contract.AuditActorAccount,
		ActorID: string(meta.Principal.AccountID()), Action: "issuance.reissue",
		TargetType: "certificate", TargetID: string(cert.ID()), ClientIP: clientIP(meta.RequestMeta),
		Result: contract.AuditResultSuccess,
		Details: contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{
			"serial": cert.Serial().Hex(), "reason": string(reason),
		}},
	}
	scopes := []domain.AuthorityID{managementAuthorityID, sourceAuthorityID, targetAuthorityID}
	scopes = append(scopes, extraScopes...)
	if err := tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(scopes...)); err != nil {
		return storeError(err, "issuance_audit_failed", "could not record the reissue audit event")
	}
	return nil
}
