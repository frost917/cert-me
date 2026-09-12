// crl.go implements CRLService (docs/backend-implementation.md §3 CRLService
// row): RequestPublication (admin) and Publish (worker/maintenance only).
//
// §8's table splits the CRL work into two rows -- "CRL 생성" (no
// out-of-transaction prep; the single Write reserves the next number and
// captures the revocation snapshot/generation together) and "CRL 게시"
// (out-of-transaction prep is signing the reserved snapshot with the CA's
// ciphertext; the Write re-checks the signer is still usable, compares
// number/generation and stores the result) -- but §3's public method table
// exposes only ONE method, Publish(jobID, CAKeyGenerationID). This file reads
// that as two internal phases of one call: reserveSnapshot (an internal
// helper doing the "CRL 생성" Write), a signing step run outside any
// transaction, and finalizePublish (the "CRL 게시" Write). This mirrors how
// Authority/Issuance already split "prepare outside the transaction, commit
// inside it" across two helper functions under one public method -- the
// novelty here is only that the prep step (reserving the number/snapshot)
// itself needs its own short Write, since it changes CRLState under lock,
// which the existing single-prep/single-commit services never needed.
//
// U12's requirement -- CRL completion-order reversal and a new revocation
// arriving mid-generation must never make publication regress -- is carried
// entirely by domain.CRLState.CanPublish/MarkPublished (internal/domain/
// revocation.go), which already refuses a number or covered generation that
// is not strictly forward. This file's job is to never paper over that
// refusal: a losing (superseded) Publish attempt still stores its signed
// document (crl_documents.der_sha256 makes storing it idempotent, and §8
// "실패한 예약 번호는 되돌리지 않는다" already forbids reusing or discarding
// the number), but does not call MarkPublished and reports
// PublicationResult{Published: false, ...} without treating that as an
// error.
//
// RequestPublication's JobAcceptedView.JobID is filled from
// JobRepository.GetByDedupKey, read back right after UpsertDemand merges the
// demand in the same Write. This method was added to port/jobs.go (with a
// porttest implementation) once the lead confirmed an earlier round's
// report that UpsertDemand's error-only return gave no way to name the row
// it just touched. porttest's job ids are now minted as real, validly-
// shaped uuids (syntheticUUID), so a client-supplied JobID -- e.g. a later
// CRLPublishCommand.JobID -- round-trips through this response instead of
// only ever working for an id the test double invented for its own internal
// bookkeeping.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// CRLDeps is CRLService's dependency set: CommonDeps plus the one signing
// dependency §5 names ("CRL | CRLSigner").
type CRLDeps struct {
	CommonDeps
	CRLSigner port.CRLSigner
}

// Validate reports the first missing dependency, common or CRL-specific.
func (d CRLDeps) Validate() error {
	if err := d.CommonDeps.Validate(); err != nil {
		return err
	}
	return firstMissing(required{"CRLSigner", d.CRLSigner == nil})
}

// CRLService implements RequestPublication and Publish (docs/backend-
// implementation.md §3 CRLService row).
type CRLService struct {
	deps CRLDeps
}

// NewCRLService constructs the service, failing fast on a missing
// dependency rather than at the first request.
func NewCRLService(deps CRLDeps) (*CRLService, error) {
	if err := deps.Validate(); err != nil {
		return nil, err
	}
	return &CRLService{deps: deps}, nil
}

// ---- RequestPublication ----

// RequestPublication merges an administrator's manual "publish now" request
// into the CA key's single CRL job (docs/backend-implementation.md §3
// "RequestPublication(authorityID) → JobAccepted"; "Request는 관리자"). It
// reuses UpsertDemand/JobKindCRLPublish/CRLDedupKey/crlPublishPayload from
// revocations.go rather than defining a second job-demand shape.
func (s *CRLService) RequestPublication(ctx context.Context, meta contract.MutationMeta, cmd contract.CRLRequestPublicationCommand) (contract.JobAcceptedView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.JobAcceptedView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.JobAcceptedView{}, contract.NewAppError(contract.ErrorKindForbidden, "crl_requires_admin",
			"requesting CRL publication requires an administrator session")
	}

	var result contract.JobAcceptedView
	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		authority, err := tx.PKI().GetIssuerForUpdate(ctx, cmd.AuthorityID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "crl_authority_not_found", "authority does not exist").
				WithField("authority_id", string(cmd.AuthorityID))
		} else if err != nil {
			return storeError(err, "crl_authority_read_failed", "could not read the authority")
		}
		scope, err := authorityScopeFromRow(authority)
		if err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionCRLRequestPublication, port.NewAuthorizationScope(scope)); err != nil {
			return err
		}

		state, err := tx.CRLs().GetStateForUpdate(ctx, authority.KeyGenerationID())
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindUnavailable, "crl_state_missing",
				"this authority has no CRL state to publish").WithField("authority_id", string(cmd.AuthorityID))
		} else if err != nil {
			return storeError(err, "crl_state_read_failed", "could not read the authority's CRL state")
		}

		// §12 closing note: "CA 신규 발급 stopped 상태만으로 CRL 서명을
		// 금지하지 않는다" -- issuance_state is deliberately not checked here.
		// A closed publication state is still worth reporting as a demand
		// (Publish itself is what refuses to sign a closed CA key), so this
		// method does not pre-reject on PublicationStateClosed either.

		dedupKey := CRLDedupKey(authority.KeyGenerationID())
		payload, err := json.Marshal(crlPublishPayload{RequiredGeneration: state.RevocationGeneration()})
		if err != nil {
			return contract.WrapAppError(contract.ErrorKindValidation, "crl_demand_payload_failed",
				"could not encode the CRL job payload", err)
		}
		if err := tx.Jobs().UpsertDemand(ctx, dedupKey, JobKindCRLPublish, crlPublishPayloadVersion, payload); err != nil {
			return storeError(err, "crl_demand_failed", "could not record the CRL publication demand")
		}
		// Read the merged row back for its real id -- UpsertDemand itself
		// returns only error (§4's table row; every other caller wants
		// nothing back), so this is the one place that needs to NAME the
		// job it just touched.
		job, err := tx.Jobs().GetByDedupKey(ctx, dedupKey)
		if err != nil {
			return storeError(err, "crl_demand_read_failed", "could not read back the recorded CRL publication demand")
		}

		now := s.deps.Clock.Now()
		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorAccount,
			ActorID:    string(meta.Principal.AccountID()),
			Action:     "crl.request_publication",
			TargetType: "ca_key_generation",
			TargetID:   string(authority.KeyGenerationID()),
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details:    contract.AuditDetails{SchemaVersion: 1},
		}
		if err := tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(scope)); err != nil {
			return storeError(err, "crl_audit_failed", "could not record the CRL request audit event")
		}

		result = contract.JobAcceptedView{JobID: job.ID}
		return nil
	})
	if err != nil {
		return contract.JobAcceptedView{}, err
	}
	return result, nil
}

// ---- Publish ----

// crlReservation is reserveSnapshot's result: the captured signing input
// plus everything finalizePublish needs afterward that is a FACT fixed at
// reservation time rather than something to recompute with a later clock
// read (§14.2-style rule: "준비 시각은 저장되는 사실에만 쓴다"). nextPublishAt
// is derived from snapshot.ThisUpdate + the CA's configured interval, so it
// must travel with the snapshot rather than being rederived against a
// second, later "now".
type crlReservation struct {
	snapshot      port.CRLSnapshot
	caKey         domain.EncryptedSecret
	nextPublishAt domain.Instant
}

// Publish signs and, if still valid to do so, stores a CA key generation's
// next CRL (docs/backend-implementation.md §3 "Publish(jobID,
// CAKeyGenerationID) → PublicationResult"; "Publish는 worker/maintenance
// 전용"). Like IdentityService.BeginReset, this is checked directly against
// Principal.Can rather than through the generic Authorizer: there is no CA
// scope an AuthorizationScope would add here that CanSignCRL/CanPublish do
// not already enforce against stored state, and
// port.actionInternalOperations does not pair ActionCRLPublish to
// InternalOperationCRLPublish any more than it pairs
// ActionIdentityBeginReset -- outside this developer's assigned files
// (port/services.go); see the report.
func (s *CRLService) Publish(ctx context.Context, meta contract.MutationMeta, cmd contract.CRLPublishCommand) (contract.PublicationResult, error) {
	if err := cmd.Validate(); err != nil {
		return contract.PublicationResult{}, err
	}
	if !meta.Principal.IsInternal() || !meta.Principal.Can(contract.InternalOperationCRLPublish) {
		return contract.PublicationResult{}, contract.NewAppError(contract.ErrorKindForbidden, "crl_publish_requires_internal_operation",
			"publishing a CRL requires the internal crl_publish operation")
	}
	if err := ctx.Err(); err != nil {
		return contract.PublicationResult{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	reservation, err := s.reserveSnapshot(ctx, cmd.CAKeyGenerationID)
	if err != nil {
		return contract.PublicationResult{}, err
	}

	// Signing runs OUTSIDE the reservation transaction (§8 "CRL 게시" row's
	// out-of-transaction prep: "예약 snapshot과 CA 암호문으로 서명").
	signed, err := s.deps.CRLSigner.SignCRL(ctx, reservation.snapshot, reservation.caKey)
	if err != nil {
		return contract.PublicationResult{}, contract.WrapAppError(contract.ErrorKindUnavailable, "crl_sign_failed",
			"could not sign the CRL", err)
	}

	return s.finalizePublish(ctx, meta, cmd.JobID, reservation, signed)
}

// reserveSnapshot is the "CRL 생성" Write: it locks CRLState, reserves the
// next number, and captures the revocation ledger and revocation generation
// under that SAME lock so both reflect one instant (§8/data-model.md "CRL
// snapshot 예약은 번호와 목록을 같은 순간의 상태로 캡처한다"). It also
// resolves and returns the CA's signing ciphertext here (cheap key-liveness
// checks before the expensive signature, §6), so the caller need not open a
// second transaction just to fetch it.
func (s *CRLService) reserveSnapshot(ctx context.Context, caKeyGenerationID domain.CAKeyGenerationID) (crlReservation, error) {
	var reservation crlReservation
	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		state, err := tx.CRLs().GetStateForUpdate(ctx, caKeyGenerationID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "crl_state_missing",
				"no CRL state exists for this CA key generation").WithField("ca_key_generation_id", string(caKeyGenerationID))
		} else if err != nil {
			return storeError(err, "crl_state_read_failed", "could not read the CRL state")
		}
		stateVersion := state.Version()

		authority, generation, err := loadCRLSigningAuthority(ctx, tx, caKeyGenerationID)
		if err != nil {
			return err
		}

		now := s.deps.Clock.Now()
		if err := authority.CanSignCRL(now); err != nil {
			return contract.FromDomainError(err)
		}

		secret, err := readCRLSigningSecret(ctx, tx, authority, generation)
		if err != nil {
			return err
		}

		settings, err := tx.Installation().GetSettings(ctx)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindConflict, "crl_settings_not_configured",
				"installation settings have not been initialized; complete Setup before publishing a CRL")
		} else if err != nil {
			return storeError(err, "crl_settings_read_failed", "could not read installation settings")
		}
		settingsV1, err := DecodeSettingsV1(settings)
		if err != nil {
			return err
		}

		revoked, err := tx.Revocations().ListByIssuer(ctx, caKeyGenerationID)
		if err != nil {
			return storeError(err, "crl_revocation_list_failed", "could not read the revocation ledger")
		}

		number, reserved := state.ReserveNext()
		if err := tx.CRLs().SaveState(ctx, reserved, stateVersion); err != nil {
			return storeError(err, "crl_state_reserve_failed", "could not reserve the next CRL number")
		}

		thisUpdate := now
		nextUpdate := thisUpdate.Add(domain.NewDuration(time.Duration(settingsV1.CRLValiditySeconds) * time.Second))
		nextPublishAt := thisUpdate.Add(domain.NewDuration(time.Duration(settingsV1.CRLIntervalSeconds) * time.Second))

		reservation = crlReservation{
			snapshot: port.CRLSnapshot{
				CAKeyGenerationID: caKeyGenerationID,
				Number:            number,
				ThisUpdate:        thisUpdate,
				NextUpdate:        nextUpdate,
				CoveredGeneration: reserved.RevocationGeneration(),
				Revoked:           revoked,
			},
			caKey:         secret,
			nextPublishAt: nextPublishAt,
		}
		return nil
	})
	if err != nil {
		return crlReservation{}, err
	}
	return reservation, nil
}

// loadCRLSigningAuthority resolves caKeyGenerationID's owning authority and
// key generation, and refuses a destroyed signing key before any further
// work -- the cheap half of "signer 여전히 사용 가능 확인" (§8), shared
// between reserveSnapshot (before signing) and finalizePublish (the
// authoritative re-check after signing).
//
// This does not reuse verifyCASigningKeyLive/caSigningSecret from
// issuance.go: those tie the check to authority.KeyGenerationID() being the
// authority's CURRENT generation, which is exactly right for issuing a NEW
// certificate but wrong for CRL publication -- a CA whose issuance has
// stopped (a normal-transition retirement) keeps publishing CRLs for its
// remaining certificates under its OWN, unchanged generation
// (certificate-lifecycle.md "기존 CA는 남은 인증서의 폐기 처리와 CRL 발행을
// 유지한다"). In this codebase a CA key generation is in practice never
// replaced under the SAME authority id (a new generation always means a new
// Authority row, created through AuthorityService.Create), so the two checks
// happen to agree today, but this function does not encode that coincidence
// as a rule the way verifyCASigningKeyLive's consistency check would.
func loadCRLSigningAuthority(ctx context.Context, tx port.TxStores, caKeyGenerationID domain.CAKeyGenerationID) (domain.Authority, port.CAKeyGeneration, error) {
	generation, err := tx.PKI().GetCAKeyGeneration(ctx, caKeyGenerationID)
	if errors.Is(err, port.ErrNotFound) {
		return domain.Authority{}, port.CAKeyGeneration{}, contract.NewAppError(contract.ErrorKindUnavailable,
			"crl_ca_key_generation_missing", "the CA key generation could not be found").
			WithField("ca_key_generation_id", string(caKeyGenerationID))
	} else if err != nil {
		return domain.Authority{}, port.CAKeyGeneration{}, storeError(err, "crl_ca_key_generation_read_failed",
			"could not read the CA key generation")
	}
	if !generation.KeyDestroyedAt.IsZero() {
		return domain.Authority{}, port.CAKeyGeneration{}, contract.NewAppError(contract.ErrorKindForbidden,
			"crl_signing_key_destroyed", "this CA key has been destroyed and can no longer sign a CRL")
	}
	authority, err := tx.PKI().GetIssuerForUpdate(ctx, generation.AuthorityID)
	if errors.Is(err, port.ErrNotFound) {
		return domain.Authority{}, port.CAKeyGeneration{}, contract.NewAppError(contract.ErrorKindUnavailable,
			"crl_authority_missing", "the authority owning this CA key generation could not be found")
	} else if err != nil {
		return domain.Authority{}, port.CAKeyGeneration{}, storeError(err, "crl_authority_read_failed",
			"could not read the authority")
	}
	return authority, generation, nil
}

// readCRLSigningSecret fetches the CA/bootstrap signing ciphertext for
// generation, choosing the purpose the same way caSigningSecret
// (issuance.go) does (§14.9).
func readCRLSigningSecret(ctx context.Context, tx port.TxStores, authority domain.Authority, generation port.CAKeyGeneration) (domain.EncryptedSecret, error) {
	purpose := domain.SecretPurposeCASigning
	if authority.Kind() == domain.AuthorityKindBootstrap {
		purpose = domain.SecretPurposeBootstrapCA
	}
	secret, err := tx.Secrets().GetEncrypted(ctx, generation.KeyMaterialID, purpose)
	if err != nil {
		return domain.EncryptedSecret{}, storeError(err, "crl_signing_secret_read_failed", "could not read the CA signing key")
	}
	return secret, nil
}

// finalizePublish is the "CRL 게시" Write: re-check the signer is still
// usable, compare the reserved number/generation against current state
// (never regressing it -- U12), store the signed document, decide the CRL
// job's outcome, and audit.
func (s *CRLService) finalizePublish(ctx context.Context, meta contract.MutationMeta, jobID domain.JobID, reservation crlReservation, signed port.SignedCRL) (contract.PublicationResult, error) {
	snapshot := reservation.snapshot
	var result contract.PublicationResult
	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		state, err := tx.CRLs().GetStateForUpdate(ctx, snapshot.CAKeyGenerationID)
		if err != nil {
			return storeError(err, "crl_state_read_failed", "could not read the CRL state")
		}
		stateVersion := state.Version()

		authority, generation, err := loadCRLSigningAuthority(ctx, tx, snapshot.CAKeyGenerationID)
		if err != nil {
			return err
		}
		now := s.deps.Clock.Now()
		if err := authority.CanSignCRL(now); err != nil {
			return contract.FromDomainError(err)
		}

		job, err := tx.Jobs().GetForUpdate(ctx, jobID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "crl_job_not_found", "job does not exist").
				WithField("job_id", string(jobID))
		} else if err != nil {
			return storeError(err, "crl_job_read_failed", "could not read the CRL publication job")
		}
		if job.DedupKey != CRLDedupKey(snapshot.CAKeyGenerationID) {
			return contract.NewAppError(contract.ErrorKindValidation, "crl_job_mismatch",
				"job does not belong to this CA key generation")
		}

		documentID, err := domain.ParseCRLDocumentID(s.deps.IDs.NewUUID())
		if err != nil {
			return contract.FromDomainError(err)
		}
		document := port.CRLDocument{
			ID:                documentID,
			CAKeyGenerationID: snapshot.CAKeyGenerationID,
			NumberHex:         snapshot.Number,
			DERSHA256:         signed.DERSHA256,
			DER:               signed.DER,
			ThisUpdate:        snapshot.ThisUpdate,
			NextUpdate:        snapshot.NextUpdate,
			CoveredGeneration: snapshot.CoveredGeneration,
			Origin:            "generated",
		}
		// §8 "실패한 예약 번호는 되돌리지 않는다": the document for this
		// reserved number is stored regardless of whether it goes on to
		// become the published one below.
		if err := tx.CRLs().InsertDocument(ctx, document); err != nil {
			return storeError(err, "crl_document_store_failed", "could not store the signed CRL document")
		}

		published := false
		if canErr := state.CanPublish(snapshot.Number, snapshot.CoveredGeneration); canErr == nil {
			marked, markErr := state.MarkPublished(documentID, snapshot.Number, snapshot.CoveredGeneration, reservation.nextPublishAt)
			if markErr != nil {
				return contract.FromDomainError(markErr)
			}
			if err := tx.CRLs().SaveState(ctx, marked, stateVersion); err != nil {
				return storeError(err, "crl_state_publish_failed", "could not record the published CRL")
			}
			state = marked
			published = true
		} else if !errors.Is(canErr, domain.ErrConflict) {
			// CanPublish's only non-conflict failure is "publication closed"
			// (ErrNotPermitted) -- a hard refusal, not a supersession.
			return contract.FromDomainError(canErr)
		}
		// else: a number/generation regression -- another, later-numbered
		// CRL for this CA key already published (U12's completion-order
		// reversal). This attempt's document stays stored above, but does
		// not become the published one and nothing here is rolled back
		// (§8 "게시 이전에 새 폐기가 추가되면 새 작업 요구를 남기고 기존
		// 작업 완료로 지우지 않는다" -- the same "never regress, never
		// silently drop a still-needed demand" principle applied to THIS
		// attempt losing the race instead of a demand arriving mid-flight).

		followupRequired := state.RevocationGeneration() > state.PublishedGeneration()
		if job.State == contract.JobStateRunning {
			next := job
			if followupRequired {
				// A newer demand (revocation generation not yet covered by
				// what is published) survives this completion instead of
				// being marked done -- docs/data-model.md "완료 시 처리한
				// generation보다 새 요구가 있으면 pending으로 남긴다".
				next.State = contract.JobStatePending
				next.AvailableAt = now
			} else {
				next.State = contract.JobStateSucceeded
				next.LastErrorCode = ""
			}
			if err := tx.Jobs().Save(ctx, next, job.Version); err != nil {
				return storeError(err, "crl_job_save_failed", "could not record the CRL job outcome")
			}
		}
		// A job not in JobStateRunning here means a concurrent/earlier
		// finalizePublish already resolved it (or a test seeded it that
		// way); this attempt must not clobber that outcome with stale
		// information from a superseded run.

		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorSystem,
			Action:     "crl.publish",
			TargetType: "ca_key_generation",
			TargetID:   string(snapshot.CAKeyGenerationID),
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details: contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{
				"number":             snapshot.Number.Hex(),
				"covered_generation": fmt.Sprintf("%d", snapshot.CoveredGeneration),
				"published":          fmt.Sprintf("%t", published),
			}},
		}
		if err := tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(generation.AuthorityID)); err != nil {
			return storeError(err, "crl_audit_failed", "could not record the CRL publish audit event")
		}

		result = contract.PublicationResult{
			CAKeyGenerationID: snapshot.CAKeyGenerationID,
			DocumentID:        documentID,
			Number:            snapshot.Number,
			CoveredGeneration: snapshot.CoveredGeneration,
			Published:         published,
			FollowupRequired:  followupRequired,
		}
		return nil
	})
	if err != nil {
		return contract.PublicationResult{}, err
	}
	return result, nil
}
