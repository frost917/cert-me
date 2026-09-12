// maintenance.go implements MaintenanceService (docs/backend-
// implementation.md §3 table row "MaintenanceService"): Rotate,
// FinalizeRestore, RecoverTransfers, PruneAudit. It also carries
// ExpireDeliveries, the once-a-minute receipt-expiry sweep §14.1 names
// ("delivery_expired") but that no service in this codebase implemented yet
// -- placed here, not on DistributionService, because this developer's
// assignment is scoped to maintenance.go/maintenance_test.go only and
// DistributionService's files (distribution.go, recovery.go) are a
// different developer's committed work. This placement is also a
// substantive fit, not just a file-scope accident: contract.
// InternalOperationDeliveryExpiry already exists (internal/app/contract/
// meta.go) alongside SecretRotate/RestoreFinalize/AuditPrune/
// TransferRecovery -- the same family of background/maintenance operations
// this file's other four methods gate on -- and ExpireDeliveries needs
// nothing from DistributionDeps (TokenCodec, DeliveryEncoder,
// PublicCertificateEncoder, OperationalLogger) that MaintenanceDeps does not
// already have.
//
// Every method here is reached only through a verified internal/local
// Principal (§3: "runtime이 오프라인 허가 또는 제한된 복구 실행 경로로
// 호출"), never an admin session, so none call requireCurrentAuth (that
// helper only ever has work to do for an admin principal -- see its own doc
// comment) and none go through the generic port.Authorizer/
// AuthorizationScope path: see requireMaintenanceOperation's doc comment
// for why a direct Principal.Can check is used instead, mirroring crl.go's
// Publish and tls.go's requireInternalOperation.
package service

import (
	"context"
	"errors"
	"fmt"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// MaintenanceDeps is MaintenanceService's dependency set: CommonDeps plus
// the two additional dependencies §5 names for this row ("Maintenance |
// KeyEngine, RuntimeGate; CRL 후속 작업은 JobStore로 기록"). CRLSigner is
// deliberately absent: FinalizeRestore only records a CRL publication
// DEMAND (via recordCRLDemand, the same job-queue path every revocation
// writes through) for a CA that still has a usable key -- it never signs a
// CRL itself, which is why actually publishing one is JobStore/worker-driven
// (CRLService.Publish) rather than something this file calls synchronously.
type MaintenanceDeps struct {
	CommonDeps
	KeyEngine   port.KeyEngine
	RuntimeGate port.RuntimeGate
}

// Validate reports the first missing dependency, common or Maintenance-
// specific.
func (d MaintenanceDeps) Validate() error {
	if err := d.CommonDeps.Validate(); err != nil {
		return err
	}
	return firstMissing(
		required{"KeyEngine", d.KeyEngine == nil},
		required{"RuntimeGate", d.RuntimeGate == nil},
	)
}

// MaintenanceService implements Rotate, FinalizeRestore, RecoverTransfers,
// PruneAudit (docs/backend-implementation.md §3) plus ExpireDeliveries (see
// this file's package comment).
type MaintenanceService struct {
	deps MaintenanceDeps
}

// NewMaintenanceService constructs the service, failing fast on a missing
// dependency rather than at the first call (§5).
func NewMaintenanceService(deps MaintenanceDeps) (*MaintenanceService, error) {
	if err := deps.Validate(); err != nil {
		return nil, err
	}
	return &MaintenanceService{deps: deps}, nil
}

// deliveryExpiredFailureCode is the failure_code §14.1 fixes for the
// receipt-expiry sweep, distinct from transfer_failed (distribution.go) and
// interrupted_transfer (recovery.go, reused directly below as
// recoveryFailureCode): "감사 action/failure_code로 transfer_failed·
// delivery_expired·interrupted_transfer 원인을 구별한다."
const deliveryExpiredFailureCode = "delivery_expired"

// restoreDeliveryFailureCode distinguishes restore cleanup from the ordinary
// expiry and restart-transfer sweeps. A restore must not disguise an
// unexpired pending delivery as expired merely to reach a terminal state.
const restoreDeliveryFailureCode = "restore_pending"

// requireMaintenanceOperation gates a MaintenanceService entry point to the
// exact contract.InternalOperation it needs, checked directly against the
// principal rather than through the generic port.Authorizer/
// AuthorizationScope path.
//
// Reasoning, matching crl.go's Publish and tls.go's requireInternalOperation:
// every method in this file is process-internal (§3), never an admin
// session, and there is no AuthorityID scope an AuthorizationScope would add
// here -- Rotate re-encrypts every stored secret across every CA at once,
// PruneAudit touches the whole audit log, and RecoverTransfers/
// ExpireDeliveries sweep every delivery in the store; none of these name a
// single owning authority the way an Authority/Issuance method's scope does.
//
// This does NOT go through port.Action.RequiredInternalOperation() the way
// tls.go's requireInternalOperation does for ActionTLSBootstrap/
// ActionTLSReconcile: port/services.go's actionInternalOperations map (the
// only place that pairing is declared) pairs just those two actions, not
// any of ActionMaintenanceRotate/FinalizeRestore/RecoverTransfers/
// PruneAudit -- so calling RequiredInternalOperation for those would always
// report "not paired" and reject every legitimate caller. Adding that
// pairing is a port/services.go change, outside this developer's assigned
// files (maintenance.go/maintenance_test.go only); reported to the lead
// rather than done here. A direct Principal.Can(op) check, exactly like
// crl.go's Publish uses for ActionCRLPublish (also unpaired), is what this
// function does instead.
func requireMaintenanceOperation(principal contract.Principal, op contract.InternalOperation) error {
	if !principal.IsInternal() || !principal.Can(op) {
		return contract.NewAppError(contract.ErrorKindForbidden, "maintenance_internal_operation_required",
			"this maintenance operation requires the matching internal operation").WithField("operation", op.String())
	}
	return nil
}

// maintenanceScope is UNRESOLVED, not a considered answer -- matching
// tlsScope (tls.go) and settingsScope (settings_service.go)'s own,
// already-reported open question. §14.6 requires a non-empty stored audit
// scope ("현재 MVP도 scope를 비워 저장하지 않는다"), but Rotate's own
// summary event, FinalizeRestore's own summary event and PruneAudit's own
// event describe a store-wide action with no single authority relation to
// read: a key rotation touches every stored secret across every CA at once,
// an audit prune touches the whole log, and a restore run's own outcome
// covers however many CAs ended up in BlockingCAIDs, not one. (The
// PER-REVOCATION events RecoverTransfers/ExpireDeliveries/FinalizeRestore's
// pending-key sweep record are NOT this case -- those go through
// applyRevocations, which scopes each one to the certificate's own stored
// management authority via leafManagementAuthority, exactly like
// recovery.go.) See tlsScope's doc comment for the identical tension; this
// file does not resolve it any differently.
func maintenanceScope() []domain.AuthorityID { return nil }

// ---- Rotate ----

// Rotate re-encrypts every stored secret plus the store-wide decryption
// verifier under a new encryption generation, and only then advances the
// installation's active generation (docs/backend-implementation.md §3
// "Rotate(oldKey,newKey) → MaintenanceResult"; §9 "MaintenanceService.Rotate는
// RuntimeGate가 보장한 오프라인 상태에서만 실행한다").
//
// Transaction boundary: this is the ONE method in this file (and, so far,
// in this whole package) that does the real work inside a single
// UnitOfWork.Write rather than following the app-wide "prepare outside the
// transaction, Write only re-checks and saves" shape (docs/backend-
// implementation.md §5/§8 -- see CRLService.Publish's reserve/sign/finalize
// split, or DistributionService.Deliver's prepare/commitConsumption/
// sendAndRecord split, for the normal shape). docs/architecture.md's key-
// rotation section requires exactly this: "모든 재암호화와 키 세대 갱신을
// 단일 DB 트랜잭션으로 처리한다. 커밋 전 실패는 롤백한다... 검증 레코드
// 역시 같은 트랜잭션에서 재암호화한다." That requirement is not a stylistic
// choice this file could route around by pulling KeyEngine.Reencrypt calls
// "outside" the transaction the way CRLSigner.SignCRL runs outside CRL
// publication's reservation transaction: unlike a CRL signature (which is
// re-validated against fresh state after signing, in finalizePublish),
// there is no safe way to re-encrypt a secret outside a transaction and
// then "re-check" that re-encryption is still valid before committing --
// the re-encrypted ciphertext either becomes the new stored ciphertext atomically
// with every other secret and the verifier and the generation bump, or the
// old ciphertext stays exactly as it was. Putting the whole batch inside
// one UnitOfWork.Write is what makes "실패하면 기존 저장 상태를 유지한다"
// hold for free, using nothing more than this package's own UnitOfWork
// contract (unitofwork.go: "A non-nil callback error rolls back every
// change"): a KeyEngine.Reencrypt failure on the Nth secret rolls back the
// N-1 secrets this same loop already successfully re-encrypted and saved
// moments earlier, because none of those writes are visible outside the
// callback until it returns nil.
func (s *MaintenanceService) Rotate(ctx context.Context, meta contract.MutationMeta, cmd contract.MaintenanceRotateCommand) (contract.MaintenanceResult, error) {
	if err := cmd.Validate(); err != nil {
		return contract.MaintenanceResult{}, err
	}
	if err := requireMaintenanceOperation(meta.Principal, contract.InternalOperationSecretRotate); err != nil {
		return contract.MaintenanceResult{}, err
	}

	var result contract.MaintenanceResult
	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		installation, err := tx.Installation().GetForUpdate(ctx)
		if err != nil {
			return storeError(err, "maintenance_rotate_installation_read_failed", "could not read installation state")
		}
		installationVersion := installation.Version

		switch installation.ActiveEncryptionGenerationID {
		case cmd.NewEncryptionGenerationID:
			// docs/architecture.md: "성공한 회전을 무조건 다시 적용하지
			// 않는다." This exact rotation already committed -- the caller
			// may be retrying after never learning the outcome (a
			// commit_unknown, a crash between commit and response). Every
			// secret is already on the new generation, so replaying the
			// re-encryption loop below would be wrong (KeyEngine.Reencrypt
			// would be asked to decrypt already-new-generation ciphertext
			// under the OLD generation's key). Report the same completed
			// result without touching anything.
			result = contract.MaintenanceResult{
				Kind: contract.MaintenanceKindKeyRotation, Phase: contract.MaintenancePhaseFinished, Completed: true,
			}
			return nil
		case cmd.OldEncryptionGenerationID:
			// Expected precondition -- fall through and perform the rotation.
		default:
			return contract.NewAppError(contract.ErrorKindConflict, "maintenance_rotate_generation_mismatch",
				"the installation's active encryption generation does not match this rotation's expected old generation").
				WithField("active_generation", installation.ActiveEncryptionGenerationID)
		}

		keys := port.RotationKeys{SourceGenerationID: cmd.OldEncryptionGenerationID, TargetGenerationID: cmd.NewEncryptionGenerationID}

		secrets, err := tx.Secrets().ListEncrypted(ctx)
		if err != nil {
			return storeError(err, "maintenance_rotate_secrets_list_failed", "could not list stored secrets")
		}
		for _, encrypted := range secrets {
			reencrypted, err := s.deps.KeyEngine.Reencrypt(ctx, encrypted, keys)
			if err != nil {
				// KeyEngine.Reencrypt (port/crypto.go) returns only
				// domain.EncryptedSecret/error, never plaintext -- there is
				// no key material to redact here, only the identifying
				// (public) owner/purpose fields.
				return contract.WrapAppError(contract.ErrorKindUnavailable, "maintenance_rotate_reencrypt_failed",
					"could not re-encrypt a stored secret under the new key", err).
					WithField("owner_key_id", string(encrypted.OwnerKeyID())).
					WithField("purpose", string(encrypted.Purpose()))
			}
			if err := tx.Secrets().ReplaceEncrypted(ctx, reencrypted); err != nil {
				return storeError(err, "maintenance_rotate_secret_save_failed", "could not store a re-encrypted secret")
			}
		}

		// The store-wide decryption verifier travels through the SAME
		// transaction and the SAME Reencrypt call as every ordinary secret
		// above (docs/architecture.md "검증 레코드 역시 같은 트랜잭션에서
		// 재암호화한다"): a verifier-only failure here rolls back every
		// secret this loop already re-encrypted, exactly like any other
		// mid-batch failure.
		verifier, err := tx.Secrets().GetVerifier(ctx)
		if err != nil {
			return storeError(err, "maintenance_rotate_verifier_read_failed",
				"could not read the encryption verifier; rotate requires one to already exist")
		}
		reencryptedVerifier, err := s.deps.KeyEngine.Reencrypt(ctx, verifier, keys)
		if err != nil {
			return contract.WrapAppError(contract.ErrorKindUnavailable, "maintenance_rotate_verifier_reencrypt_failed",
				"could not re-encrypt the encryption verifier under the new key", err)
		}
		if err := tx.Secrets().SaveVerifier(ctx, reencryptedVerifier); err != nil {
			return storeError(err, "maintenance_rotate_verifier_save_failed", "could not store the re-encrypted verifier")
		}

		installation.ActiveEncryptionGenerationID = cmd.NewEncryptionGenerationID
		if err := tx.Installation().Save(ctx, installation, installationVersion); err != nil {
			return storeError(err, "maintenance_rotate_installation_save_failed", "could not record the new active encryption generation")
		}

		now := s.deps.Clock.Now()
		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorSystem,
			Action:     "maintenance.rotate",
			TargetType: "installation",
			TargetID:   cmd.NewEncryptionGenerationID,
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details: contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{
				// Never the key material itself (docs/architecture.md "키
				// 원문은 로그에 남기지 않고 교체 결과만 감사 기록에
				// 남긴다") -- only the generation ids and a count.
				"old_generation": cmd.OldEncryptionGenerationID,
				"new_generation": cmd.NewEncryptionGenerationID,
				"secret_count":   fmt.Sprintf("%d", len(secrets)),
			}},
		}
		if err := tx.Audit().Append(ctx, event, maintenanceScope()); err != nil {
			return storeError(err, "maintenance_rotate_audit_failed", "could not record the rotate audit event")
		}

		result = contract.MaintenanceResult{Kind: contract.MaintenanceKindKeyRotation, Phase: contract.MaintenancePhaseFinished, Completed: true}
		return nil
	})
	if err != nil {
		if errors.Is(err, port.ErrCommitUnknown) {
			// §12's FailClosed rule is written for "private 소비", but the
			// same undetermined-state concern applies here: after an
			// unresolved commit following a batch of Reencrypt/Replace
			// calls, it is unknown whether some secrets now sit on the new
			// generation while others (or the verifier, or the installation
			// row itself) are still on the old one. docs/architecture.md is
			// explicit that ordinary requests stay stopped from before this
			// call until a verified restart on ONE consistent active
			// generation -- an unresolved commit cannot establish that, so
			// this actively shuts the running process rather than merely
			// reporting an error and letting live traffic continue.
			s.deps.RuntimeGate.FailClosed("maintenance_rotate_commit_unknown")
		}
		return contract.MaintenanceResult{}, err
	}
	return result, nil
}

// ---- ExpireDeliveries (B03 homework: §14.1's delivery_expired scan) ----

// ExpireDeliveries fails every pending delivery whose receipt deadline has
// passed and revokes its certificate, the once-a-minute sweep §14.1 names
// but that this codebase had not implemented before this change ("전송
// 실패·수령 만료·잔류 transferring 복구의 기본 reason은 unspecified, source는
// cascade로 확정한다... 감사 action/failure_code로 transfer_failed·
// delivery_expired·interrupted_transfer 원인을 구별한다"); §4's closing
// note that a request's own discovered delivery-expiry key
// deletion/revocation/CRL work "is an ordinary business change" applies
// here just as much as it does inline in a request handler.
//
// Structure mirrors recovery.go's RecoverInterruptedTransfers exactly, per
// the lead's brief: a preparation Read lists candidates in
// recoveryBatchSize batches, each row is resolved in its OWN
// UnitOfWork.Write (so one unresolvable row does not strand the rest), the
// failure/revocation/CRL-demand/audit trail share one commit through the
// same applyRevocations every other caller uses, and an all-skipped batch
// terminates the loop instead of re-reading the same rows forever. The one
// deliberate difference from recovery.go's failInterruptedTransfer: THIS
// row's own precondition is time-based (a pending delivery is only
// resolved once its own deadline has actually passed), so the per-row
// helper below takes no `now` parameter at all and reads the clock itself
// AFTER locking the row -- the batch listing's own `now` is a preparation
// read and must not be trusted as the instant that decides the transition
// (project rule: expiry is always decided from the clock read immediately
// after the row is locked, never from an earlier listing read).
func (s *MaintenanceService) ExpireDeliveries(ctx context.Context, meta contract.MutationMeta) (RecoveryOutcome, error) {
	if err := requireMaintenanceOperation(meta.Principal, contract.InternalOperationDeliveryExpiry); err != nil {
		return RecoveryOutcome{}, err
	}

	var outcome RecoveryOutcome
	for {
		var batch []domain.Delivery
		if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
			var readErr error
			batch, readErr = tx.Delivery().ListExpired(ctx, s.deps.Clock.Now(), recoveryBatchSize)
			return readErr
		}); err != nil {
			return outcome, storeError(err, "maintenance_expire_deliveries_list_failed", "could not list expired deliveries")
		}
		if len(batch) == 0 {
			return outcome, nil
		}

		progressed := false
		for _, delivery := range batch {
			changed, err := s.expireOneDelivery(ctx, delivery.ID())
			if err != nil {
				return outcome, err
			}
			if changed {
				outcome.Failed++
				progressed = true
				continue
			}
			outcome.Skipped++
		}
		if !progressed {
			return outcome, nil
		}
	}
}

// expireOneDelivery resolves one delivery in its own transaction. It
// reports false when the row was not (or no longer) an expired pending row
// under lock, which is not an error.
func (s *MaintenanceService) expireOneDelivery(ctx context.Context, deliveryID domain.DeliveryID) (bool, error) {
	changed := false
	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		changed = false
		delivery, err := tx.Delivery().GetDeliveryForUpdate(ctx, deliveryID)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return nil
			}
			return storeError(err, "maintenance_expire_delivery_read_failed", "could not read the expiring delivery")
		}
		if delivery.State() != domain.DeliveryStatePending {
			// Stored non-pending state (consumed, already failed/expired by
			// something else) is kept as-is.
			return nil
		}

		// Read the clock only now, with the row already locked: the batch
		// listing's `now` is a preparation read and may be stale by the
		// time this row's own commit happens.
		now := s.deps.Clock.Now()
		if !delivery.ExpiresAt().IsExpiredAt(now) {
			// The listing read is stale by construction; re-check rather
			// than trust it (no concurrent deadline-extension exists in
			// this codebase today, but the discipline is the same one
			// requireCurrentAuth documents for auth: never act on a
			// preparation-time fact once the lock is held).
			return nil
		}

		certificate, err := tx.PKI().GetCertificate(ctx, delivery.CertificateID())
		if err != nil {
			return storeError(err, "maintenance_expire_delivery_certificate_read_failed", "could not read the expiring delivery's certificate")
		}
		scope, err := leafManagementAuthority(ctx, tx, certificate.ID())
		if err != nil {
			return err
		}

		failedDelivery, err := delivery.Fail(deliveryExpiredFailureCode, now)
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.Delivery().SaveDelivery(ctx, failedDelivery, delivery.Version()); err != nil {
			return storeError(err, "maintenance_expire_delivery_save_failed", "could not record the expired delivery's failure")
		}
		if err := tx.Delivery().InvalidatePrivateGrants(ctx, delivery.ID(), now); err != nil {
			return storeError(err, "maintenance_expire_delivery_grant_invalidate_failed", "could not invalidate the expired delivery's links")
		}

		// Same reason/source every §14.1 cascade revocation uses: "기본
		// reason은 unspecified, source는 cascade로 확정한다."
		change := RevocationChange{
			IssuerID:      certificate.IssuerCAKeyGenerationID(),
			Serial:        certificate.Serial(),
			CertificateID: certificate.ID(),
			RevokedAt:     now,
			Reason:        domain.RevocationReasonUnspecified,
			Source:        domain.RevocationSourceCascade,
			AuthorityID:   scope,
		}
		revMeta := RevocationMeta{
			ActorKind: contract.AuditActorSystem,
			Action:    "maintenance.expire_deliveries.delivery_expired",
			Now:       now,
			IDs:       s.deps.IDs,
		}
		if _, err := applyRevocations(ctx, tx, []RevocationChange{change}, revMeta); err != nil {
			return err
		}
		changed = true
		return nil
	})
	if err != nil {
		if errors.Is(err, port.ErrCommitUnknown) {
			s.deps.RuntimeGate.FailClosed("maintenance_expire_delivery_commit_unknown")
		}
		return false, err
	}
	return changed, nil
}

// ---- RecoverTransfers ----

// RecoverTransfers is MaintenanceService's own transferring-delivery sweep
// (docs/backend-implementation.md §3 "RecoverTransfers() → RecoverySummary"),
// reachable through the "제한된 복구 실행 경로" §3 names -- an
// operator-triggered recovery pass, distinct from
// DistributionService.RecoverInterruptedTransfers (recovery.go), which runs
// automatically, once, before the runtime opens admission at startup.
//
// The two intentionally do the SAME underlying domain operation (fail a
// transferring delivery, revoke its certificate, record the CRL demand and
// audit trail -- all in one commit per row) but cannot share an
// implementation: they are methods on different service types with
// different dependency sets (DistributionDeps carries TokenCodec/
// DeliveryEncoder/PublicCertificateEncoder/OperationalLogger that
// MaintenanceDeps has no use for), this codebase has no precedent anywhere
// for one service holding another service as a dependency, and recovery.go
// is a different developer's committed file this developer's brief
// explicitly must not modify. The per-row helper below (recoverOneTransfer)
// is therefore this file's own copy of failInterruptedTransfer's logic, but
// it reuses -- rather than redefines -- every shared building block that
// already exists at package scope: recoveryBatchSize, recoveryFailureCode,
// leafManagementAuthority and applyRevocations.
//
// Error handling deliberately differs from recovery.go's abort-on-first-
// failure gate: recovery.go's caller must not open admission after a
// partial recovery, so ANY row failure aborts the whole run. RecoverySummary
// (Checked/Changed/Failed counters plus FailedIDs) is shaped for a
// different contract -- an operator-triggered pass that tolerates
// individual unresolvable rows and reports exactly which ones need manual
// attention, rather than an all-or-nothing gate. This is an interpretation
// of a result shape the docs state tersely ("RecoverySummary는
// Checked/Changed/Failed 카운터와 비밀 없는 FailedIDs다") without spelling
// out the per-row failure policy; flagged for the lead in the PR report.
func (s *MaintenanceService) RecoverTransfers(ctx context.Context, meta contract.MutationMeta, cmd contract.MaintenanceRecoverTransfersCommand) (contract.RecoverySummary, error) {
	if err := cmd.Validate(); err != nil {
		return contract.RecoverySummary{}, err
	}
	if err := requireMaintenanceOperation(meta.Principal, contract.InternalOperationTransferRecovery); err != nil {
		return contract.RecoverySummary{}, err
	}

	var summary contract.RecoverySummary
	for {
		var batch []domain.Delivery
		if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
			var readErr error
			batch, readErr = tx.Delivery().ListTransferring(ctx, recoveryBatchSize)
			return readErr
		}); err != nil {
			return summary, storeError(err, "maintenance_recover_transfers_list_failed", "could not list interrupted transfers")
		}
		if len(batch) == 0 {
			return summary, nil
		}

		progressed := false
		for _, delivery := range batch {
			summary.Checked++
			changed, err := s.recoverOneTransfer(ctx, delivery.ID())
			if err != nil {
				summary.Failed++
				summary.FailedIDs = append(summary.FailedIDs, delivery.ID())
				continue
			}
			if changed {
				summary.Changed++
				progressed = true
			}
		}
		if !progressed {
			return summary, nil
		}
	}
}

// recoverOneTransfer resolves one delivery in its own transaction, exactly
// like recovery.go's failInterruptedTransfer (see this file's RecoverTransfers
// doc comment for why this is a separate copy rather than a shared call).
func (s *MaintenanceService) recoverOneTransfer(ctx context.Context, deliveryID domain.DeliveryID) (bool, error) {
	changed := false
	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		changed = false
		delivery, err := tx.Delivery().GetDeliveryForUpdate(ctx, deliveryID)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return nil
			}
			return storeError(err, "maintenance_recover_transfer_read_failed", "could not read the interrupted delivery")
		}
		if delivery.State() != domain.DeliveryStateTransferring {
			return nil
		}

		now := s.deps.Clock.Now()
		certificate, err := tx.PKI().GetCertificate(ctx, delivery.CertificateID())
		if err != nil {
			return storeError(err, "maintenance_recover_transfer_certificate_read_failed", "could not read the interrupted delivery's certificate")
		}
		scope, err := leafManagementAuthority(ctx, tx, certificate.ID())
		if err != nil {
			return err
		}

		failedDelivery, err := delivery.Fail(recoveryFailureCode, now)
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.Delivery().SaveDelivery(ctx, failedDelivery, delivery.Version()); err != nil {
			return storeError(err, "maintenance_recover_transfer_save_failed", "could not record the interrupted delivery's failure")
		}
		if err := tx.Delivery().InvalidatePrivateGrants(ctx, delivery.ID(), now); err != nil {
			return storeError(err, "maintenance_recover_transfer_grant_invalidate_failed", "could not invalidate the interrupted delivery's links")
		}

		change := RevocationChange{
			IssuerID:      certificate.IssuerCAKeyGenerationID(),
			Serial:        certificate.Serial(),
			CertificateID: certificate.ID(),
			RevokedAt:     now,
			Reason:        domain.RevocationReasonUnspecified,
			Source:        domain.RevocationSourceCascade,
			AuthorityID:   scope,
		}
		revMeta := RevocationMeta{
			ActorKind: contract.AuditActorSystem,
			Action:    "maintenance.recover_transfers.interrupted_transfer",
			Now:       now,
			IDs:       s.deps.IDs,
		}
		if _, err := applyRevocations(ctx, tx, []RevocationChange{change}, revMeta); err != nil {
			return err
		}
		changed = true
		return nil
	})
	if err != nil {
		if errors.Is(err, port.ErrCommitUnknown) {
			s.deps.RuntimeGate.FailClosed("maintenance_recover_transfer_commit_unknown")
		}
		return false, err
	}
	return changed, nil
}

// ---- PruneAudit ----

// PruneAudit deletes audit events older than cutoff, the once-a-day
// retention sweep §9 fixes ("감사 정리는 하루 한 번, 처리 batch는 100개").
// It loops calling AuditRepository.DeleteBefore in its own
// UnitOfWork.Write per batch (rather than one giant transaction) until a
// batch comes back smaller than the batch size, so an installation with a
// large backlog does not hold one long-running transaction open across
// however many rows are due. PKI history survives by construction, not by
// anything this method checks itself: docs/data-model.md "감사 행은 업무
// 데이터의 FK 부모로 사용하지 않는다" -- pruning audit rows can never cascade
// into certificates, revocations or transitions (U15's "감사 정리 후 PKI
// 이력 보존" requirement).
func (s *MaintenanceService) PruneAudit(ctx context.Context, meta contract.MutationMeta, cmd contract.MaintenancePruneAuditCommand) (contract.MaintenancePruneAuditResult, error) {
	if err := cmd.Validate(); err != nil {
		return contract.MaintenancePruneAuditResult{}, err
	}
	if err := requireMaintenanceOperation(meta.Principal, contract.InternalOperationAuditPrune); err != nil {
		return contract.MaintenancePruneAuditResult{}, err
	}

	var total int64
	for {
		var deleted int
		err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
			var derr error
			deleted, derr = tx.Audit().DeleteBefore(ctx, cmd.Cutoff, recoveryBatchSize)
			if derr != nil {
				return storeError(derr, "maintenance_prune_audit_failed", "could not delete old audit events")
			}
			return nil
		})
		if err != nil {
			// No FailClosed here, unlike Rotate/ExpireDeliveries/
			// RecoverTransfers above: this write never touches a private
			// secret, a delivery or a certificate's revocation state --
			// only audit rows, which are never a FK parent for business
			// data (docs/data-model.md). A commit_unknown here means "it is
			// unclear whether this batch of already-old audit rows was
			// deleted", which is not a private-key-custody ambiguity §12's
			// rule is written for.
			return contract.MaintenancePruneAuditResult{Deleted: total}, err
		}
		total += int64(deleted)
		if deleted < recoveryBatchSize {
			return contract.MaintenancePruneAuditResult{Deleted: total}, nil
		}
	}
}

// ---- FinalizeRestore ----

// FinalizeRestore is the post-DB-restore recovery step docs/architecture.md
// describes: invalidate what a restored snapshot can no longer guarantee
// (administrator sessions, one-shot leaf key deliveries) and determine
// which CAs block reopening ordinary service.
//
// Transaction boundary: UNLIKE Rotate, this is deliberately NOT one single
// transaction. §9's own wording is "세션/토큰 무효화·대기 키 삭제/폐기와
// 필요한 CRL 작업을 먼저 커밋하고 영속 복구 단계로 추적한다" -- "commit...
// FIRST, then track [an ongoing] recovery phase" -- which already reads as
// multiple commits over time, not one. Concretely this method is: a
// preparation existence check for the run (no lock needed -- nothing else
// ever deletes a job row), one small Write for session invalidation, a
// batched per-row sweep of independent Writes for pending-key deletion
// (mirroring ExpireDeliveries/RecoverTransfers above -- and reusing their
// exact per-row helpers -- for the same §9 "각 수령 실패 변경은 독립
// 트랜잭션으로 처리한다" reason: one unresolvable delivery must not strand
// the rest), a read-only pass to determine BlockingCAIDs, and a final Write
// that records the run's outcome on its job row. Every step here is safe to
// repeat: DeliveryRepository.Delete/Fail/Invalidate are idempotent or
// state-checked, DeleteAllSessions on an already-empty session set is a
// no-op, and BlockingCAIDs is recomputed fresh from current state every
// call rather than cached -- so calling this twice with the same RunID
// (a lease retry, an operator re-running the CLI after fixing a missing CA
// key) is safe and converges rather than double-applying anything (U15).
func (s *MaintenanceService) FinalizeRestore(ctx context.Context, meta contract.MutationMeta, cmd contract.MaintenanceFinalizeRestoreCommand) (contract.MaintenanceResult, error) {
	if err := cmd.Validate(); err != nil {
		return contract.MaintenanceResult{}, err
	}
	if err := requireMaintenanceOperation(meta.Principal, contract.InternalOperationRestoreFinalize); err != nil {
		return contract.MaintenanceResult{}, err
	}
	runID := cmd.Options.RunID

	// The run must already be tracked as a job row. JobRepository's only
	// row-creating method is UpsertDemand (internal/app/port/jobs.go),
	// which mints its OWN id from a dedup key and cannot be handed a
	// caller-chosen RunID -- so FinalizeRestore cannot be the thing that
	// first creates this row. Whatever starts restore mode (outside the
	// app layer entirely, per §3 "runtime이 오프라인 허가 또는 제한된 복구
	// 실행 경로로 호출") must have already recorded RunID before calling
	// this. No lock is taken for this existence check: nothing in this
	// package ever deletes a job row, so there is nothing a concurrent
	// writer could remove between this check and the writes below.
	if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		_, err := tx.Jobs().GetForUpdate(ctx, runID)
		return err
	}); err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return contract.MaintenanceResult{}, contract.NewAppError(contract.ErrorKindValidation, "maintenance_restore_run_not_found",
				"no restore run is tracked under this run id").WithField("run_id", string(runID))
		}
		return contract.MaintenanceResult{}, storeError(err, "maintenance_restore_run_read_failed", "could not read the restore run")
	}

	if cmd.Options.InvalidateAllSessions {
		if err := s.invalidateAllAdminSessions(ctx); err != nil {
			return contract.MaintenanceResult{}, err
		}
	}

	if cmd.Options.DeletePendingKeys {
		if err := s.deleteRestorePendingKeys(ctx); err != nil {
			return contract.MaintenanceResult{}, err
		}
	}

	blocking, err := s.blockingCAsNeedingCRLResumption(ctx)
	if err != nil {
		return contract.MaintenanceResult{}, err
	}
	completed := len(blocking) == 0
	phase := contract.MaintenancePhaseFinished
	if !completed {
		phase = contract.MaintenancePhaseBlocked
	}

	if err := s.finalizeRestoreRun(ctx, meta, runID, completed, blocking); err != nil {
		return contract.MaintenanceResult{}, err
	}

	return contract.MaintenanceResult{
		RunID:         runID,
		Kind:          contract.MaintenanceKindRestoreFinalize,
		Phase:         phase,
		Completed:     completed,
		BlockingCAIDs: blocking,
	}, nil
}

// invalidateAllAdminSessions deletes every administrator session row and
// invalidates every outstanding password-reset link (docs/architecture.md
// "복구 시 기존 다운로드 토큰과 관리자 세션을 모두 무효화한다" and its
// reset-link requirement).
//
// It calls AccountRepository.DeleteAllSessions directly rather than routing
// through Account.BeginReset's AccountResetOutcome: BeginReset also moves
// the account to reset_pending and bumps auth_epoch, which blocks ordinary
// login until a password reset completes (internal/domain/identity.go) --
// architecture.md's restore text asks for invalidation, never that the
// administrator be forced through a password reset, and there is no lighter
// domain transition that deletes sessions without also forcing that state
// change. Not bumping auth_epoch is not a gap here: the session ROWS
// themselves are gone, so any principal derived from one of them fails
// GetSessionForUpdate (requireCurrentAuth, auth.go) on its very next
// re-check regardless of epoch. Reset links are invalidated through the
// repository's bulk operation in this same transaction.
//
// This reaches every administrator because MVP has exactly one:
// Installation.FirstAdminID (docs/backend-implementation.md §2 "MVP
// Authorization은 전체 관리자만 허용한다"; settingsScope's own comment,
// settings_service.go, "현재 MVP 역할 모델에 CA 범위 관리자가 없다"). If a
// later role model adds more admin accounts, this call stops being
// "invalidate ALL administrator sessions" -- flagged here rather than
// silently assumed to still hold.
func (s *MaintenanceService) invalidateAllAdminSessions(ctx context.Context) error {
	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		installation, err := tx.Installation().GetForUpdate(ctx)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				// Nothing has ever been set up; nothing to invalidate.
				return nil
			}
			return storeError(err, "maintenance_restore_installation_read_failed", "could not read installation state")
		}
		if installation.FirstAdminID == "" {
			return nil
		}
		if err := tx.Accounts().DeleteAllSessions(ctx, installation.FirstAdminID); err != nil {
			return storeError(err, "maintenance_restore_session_invalidate_failed", "could not invalidate administrator sessions")
		}
		if err := tx.Accounts().InvalidateResetTokens(ctx, installation.FirstAdminID, s.deps.Clock.Now()); err != nil {
			return storeError(err, "maintenance_restore_reset_tokens_invalidate_failed", "could not invalidate administrator reset links")
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, port.ErrCommitUnknown) {
			s.deps.RuntimeGate.FailClosed("maintenance_restore_session_commit_unknown")
		}
		return err
	}
	return nil
}

// deleteRestorePendingKeys deletes and revokes every one-shot leaf key
// delivery a restored snapshot can no longer guarantee the one-shot
// property for (docs/architecture.md "복원된 수령 대기 Leaf 개인키를
// 삭제하며 해당 인증서를 폐기한다"; CA and internal_tls keys are never
// key_deliveries rows at all, so they are excluded by construction, not by
// an extra check here).
//
// Restore uses ListPending rather than ListExpired: the deadline is not the
// deciding fact here. Both pending and transferring rows are re-locked and
// handled by restoreOneDelivery, which deletes the leaf secret, invalidates
// private grants, marks the delivery failed with a restore-specific reason,
// revokes the certificate, records the CRL demand and appends the audit event
// in one row transaction. The global public-grant invalidation is committed
// after the row sweep and is safe to repeat.
func (s *MaintenanceService) deleteRestorePendingKeys(ctx context.Context) error {
	for {
		var batch []domain.Delivery
		if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
			var readErr error
			batch, readErr = tx.Delivery().ListPending(ctx, recoveryBatchSize)
			return readErr
		}); err != nil {
			return storeError(err, "maintenance_restore_pending_list_failed", "could not list pending deliveries")
		}
		if len(batch) == 0 {
			break
		}
		progressed := false
		for _, delivery := range batch {
			changed, err := s.restoreOneDelivery(ctx, delivery.ID())
			if err != nil {
				return err
			}
			if changed {
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}

	for {
		var batch []domain.Delivery
		if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
			var readErr error
			batch, readErr = tx.Delivery().ListTransferring(ctx, recoveryBatchSize)
			return readErr
		}); err != nil {
			return storeError(err, "maintenance_restore_transferring_list_failed", "could not list mid-transfer deliveries")
		}
		if len(batch) == 0 {
			break
		}
		progressed := false
		for _, delivery := range batch {
			changed, err := s.restoreOneDelivery(ctx, delivery.ID())
			if err != nil {
				return err
			}
			if changed {
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}

	if err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := tx.Delivery().InvalidateAllPublicGrants(ctx, s.deps.Clock.Now()); err != nil {
			return storeError(err, "maintenance_restore_public_grants_invalidate_failed", "could not invalidate restored public download links")
		}
		return nil
	}); err != nil {
		if errors.Is(err, port.ErrCommitUnknown) {
			s.deps.RuntimeGate.FailClosed("maintenance_restore_public_grants_commit_unknown")
		}
		return err
	}
	return nil
}

// restoreOneDelivery resolves one pending or transferring delivery under its
// row lock. It is deliberately separate from the ordinary expiry and restart
// recovery helpers: restore cleanup has stronger semantics and must delete the
// leaf secret even when the receipt deadline has not passed.
func (s *MaintenanceService) restoreOneDelivery(ctx context.Context, deliveryID domain.DeliveryID) (bool, error) {
	changed := false
	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		changed = false
		delivery, err := tx.Delivery().GetDeliveryForUpdate(ctx, deliveryID)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return nil
			}
			return storeError(err, "maintenance_restore_delivery_read_failed", "could not read the restored delivery")
		}
		if delivery.State() != domain.DeliveryStatePending && delivery.State() != domain.DeliveryStateTransferring {
			return nil
		}

		certificate, err := tx.PKI().GetCertificate(ctx, delivery.CertificateID())
		if err != nil {
			return storeError(err, "maintenance_restore_delivery_certificate_read_failed", "could not read the restored delivery's certificate")
		}
		scope, err := leafManagementAuthority(ctx, tx, certificate.ID())
		if err != nil {
			return err
		}
		now := s.deps.Clock.Now()
		failedDelivery, err := delivery.Fail(restoreDeliveryFailureCode, now)
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.Delivery().SaveDelivery(ctx, failedDelivery, delivery.Version()); err != nil {
			return storeError(err, "maintenance_restore_delivery_save_failed", "could not record the restored delivery failure")
		}
		if err := tx.Secrets().Delete(ctx, certificate.KeyMaterialID(), domain.SecretPurposeLeafDelivery); err != nil {
			return storeError(err, "maintenance_restore_leaf_secret_delete_failed", "could not delete the restored leaf delivery secret")
		}
		if err := tx.Delivery().InvalidatePrivateGrants(ctx, delivery.ID(), now); err != nil {
			return storeError(err, "maintenance_restore_private_grants_invalidate_failed", "could not invalidate the restored private download links")
		}

		change := RevocationChange{
			IssuerID:      certificate.IssuerCAKeyGenerationID(),
			Serial:        certificate.Serial(),
			CertificateID: certificate.ID(),
			RevokedAt:     now,
			Reason:        domain.RevocationReasonUnspecified,
			Source:        domain.RevocationSourceCascade,
			AuthorityID:   scope,
		}
		if _, err := applyRevocations(ctx, tx, []RevocationChange{change}, RevocationMeta{
			ActorKind: contract.AuditActorSystem,
			Action:    "maintenance.finalize_restore.restore_pending",
			Now:       now,
			IDs:       s.deps.IDs,
		}); err != nil {
			return err
		}
		changed = true
		return nil
	})
	if err != nil {
		if errors.Is(err, port.ErrCommitUnknown) {
			s.deps.RuntimeGate.FailClosed("maintenance_restore_delivery_commit_unknown")
		}
		return false, err
	}
	return changed, nil
}

// blockingCAsNeedingCRLResumption enumerates every stored authority and
// reports which ones block completing this restore run
// (docs/architecture.md "필요한 CA 키가 없거나 CRL 게시에 실패하면 복구
// 미완료로 남기고 일반 서비스를 열지 않는다... 단순 이력 보관용으로 가져온
// 서명 키 없는 CA 때문에 전체 복구를 차단하지 않는다").
//
// It reads through tx.Queries().ListAuthorities/GetCRLStatus (the
// non-locking QueryRepository side) rather than CRLRepository.
// GetStateForUpdate: this is a determination pass over potentially every
// CA in the installation, not a write, and nothing here needs the
// publication-serialization lock GetStateForUpdate exists for.
func (s *MaintenanceService) blockingCAsNeedingCRLResumption(ctx context.Context) ([]domain.AuthorityID, error) {
	var blocking []domain.AuthorityID
	query := contract.AuthorityListQuery{Page: contract.PageRequest{Limit: 200}}
	if err := query.Validate(); err != nil {
		return nil, err
	}
	for {
		var page contract.Page[domain.Authority]
		if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
			var readErr error
			page, readErr = tx.Queries().ListAuthorities(ctx, query, port.QueryScope{All: true})
			return readErr
		}); err != nil {
			return nil, storeError(err, "maintenance_restore_authority_list_failed", "could not list authorities")
		}
		for _, authority := range page.Items {
			blocks, err := s.authorityBlocksRestore(ctx, authority)
			if err != nil {
				return nil, err
			}
			if blocks {
				blocking = append(blocking, authority.ID())
			}
		}
		if page.NextCursor == nil {
			return blocking, nil
		}
		query.Page.Cursor = *page.NextCursor
	}
}

// authorityBlocksRestore reports whether one authority blocks this restore.
// An archived authority, one with no CRL activity at all, or one whose
// published generation already covers its revocation ledger is never
// blocking. A CA with unpublished revocations AND a usable signing key is
// not blocking either -- its CRL demand is (re-)recorded so the worker
// resumes publishing, exactly the "게시 재개가 필요한 운영 CA" case.
// Blocking is reserved for the one case architecture.md names: unpublished
// revocations with NO usable key to sign them.
func (s *MaintenanceService) authorityBlocksRestore(ctx context.Context, authority domain.Authority) (bool, error) {
	if authority.IsArchived() {
		return false, nil
	}

	var state domain.CRLState
	found := false
	if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		s2, err := tx.Queries().GetCRLStatus(ctx, authority.KeyGenerationID(), port.QueryScope{All: true})
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return nil
			}
			return err
		}
		state, found = s2, true
		return nil
	}); err != nil {
		return false, storeError(err, "maintenance_restore_crl_status_read_failed", "could not read the authority's CRL state")
	}
	if !found {
		// No CRL activity ever recorded for this CA -- a plain historical
		// import with nothing to publish, never blocking.
		return false, nil
	}

	backlog := state.RevocationGeneration() > state.PublishedGeneration()
	if !backlog {
		return false, nil
	}
	if authority.KeyAvailable() {
		if err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
			return recordCRLDemand(ctx, tx, authority.KeyGenerationID(), state.RevocationGeneration())
		}); err != nil {
			return false, storeError(err, "maintenance_restore_crl_demand_failed", "could not record the CRL resumption demand")
		}
		return false, nil
	}
	// Unpublished revocations with no usable key to sign them for --
	// architecture.md's blocking case.
	return true, nil
}

// finalizeRestoreRun records this run's outcome on its job row and appends
// the run's own summary audit event. A blocked outcome is stored as
// JobStateFailed, a terminal state, rather than JobStatePending:
// JobRepository.ClaimDue (internal/app/port/jobs.go) has no per-kind filter,
// so a Pending row here would be eligible for whatever generic worker loop
// claims due jobs, which has no handler for a restore run. Architecture.md's
// own retry story is an OPERATOR action ("유지보수 CLI에서 키·자료 보완 후
// 재시도한다"), not an automatic background retry -- the operator reissues
// FinalizeRestore with the SAME RunID once the missing CA key/material is
// restored, which re-enters this method and recomputes fresh state (see
// this method's caller's own transaction-boundary doc comment on why that
// re-run is safe).
func (s *MaintenanceService) finalizeRestoreRun(ctx context.Context, meta contract.MutationMeta, runID domain.JobID, completed bool, blocking []domain.AuthorityID) error {
	return s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		job, err := tx.Jobs().GetForUpdate(ctx, runID)
		if err != nil {
			return storeError(err, "maintenance_restore_run_read_failed", "could not re-read the restore run")
		}
		jobVersion := job.Version
		if completed {
			job.State = contract.JobStateSucceeded
			job.LastErrorCode = ""
		} else {
			job.State = contract.JobStateFailed
			job.LastErrorCode = "maintenance_restore_blocked_ca_key_missing"
		}
		if err := tx.Jobs().Save(ctx, job, jobVersion); err != nil {
			return storeError(err, "maintenance_restore_run_save_failed", "could not record the restore run outcome")
		}

		now := s.deps.Clock.Now()
		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorSystem,
			Action:     "maintenance.finalize_restore",
			TargetType: "job",
			TargetID:   string(runID),
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details: contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{
				"completed":      fmt.Sprintf("%t", completed),
				"blocking_count": fmt.Sprintf("%d", len(blocking)),
			}},
		}
		if err := tx.Audit().Append(ctx, event, maintenanceScope()); err != nil {
			return storeError(err, "maintenance_restore_audit_failed", "could not record the restore audit event")
		}
		return nil
	})
}
