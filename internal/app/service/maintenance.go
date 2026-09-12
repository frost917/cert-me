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
	"encoding/json"
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

// Maintenance summaries describe installation-wide operations: rotation,
// restore and audit pruning span the store rather than one authority. Use a
// typed installation scope so that this is distinct from a missing scope.
func maintenanceScope() port.AuditScope { return port.NewInstallationAuditScope() }

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
// 필요한 CRL 작업을 먼저 커밋하고 영속 복구 단계로 추적한다" -- the
// cleanup commits first and the durable maintenance run is updated after each
// resumable stage. The run itself is stored in maintenance_runs, never jobs:
// jobs remain the worker queue, while this row preserves the restore phase and
// its per-CA CRL evidence. Every cleanup step is safe to repeat: delivery
// transitions are state-checked, secret/grant deletion is idempotent, session
// invalidation on an empty set is a no-op, and the CRL plan is recomputed from
// current state before its final locked write (U15).
func (s *MaintenanceService) FinalizeRestore(ctx context.Context, meta contract.MutationMeta, cmd contract.MaintenanceFinalizeRestoreCommand) (contract.MaintenanceResult, error) {
	if err := cmd.Validate(); err != nil {
		return contract.MaintenanceResult{}, err
	}
	if err := requireMaintenanceOperation(meta.Principal, contract.InternalOperationRestoreFinalize); err != nil {
		return contract.MaintenanceResult{}, err
	}
	if !cmd.Options.InvalidateAllSessions || !cmd.Options.DeletePendingKeys {
		return contract.MaintenanceResult{}, contract.NewAppError(contract.ErrorKindValidation,
			"maintenance_restore_cleanup_confirmation_required",
			"restore finalization requires administrator-session/reset-token and pending-delivery cleanup")
	}
	runID := cmd.Options.RunID

	if err := s.startRestoreRun(ctx, runID); err != nil {
		return contract.MaintenanceResult{}, err
	}

	if err := s.invalidateAllAdminSessions(ctx); err != nil {
		return contract.MaintenanceResult{}, err
	}

	if err := s.deleteRestorePendingKeys(ctx); err != nil {
		return contract.MaintenanceResult{}, err
	}

	plan, err := s.restoreCRLPlan(ctx, runID)
	if err != nil {
		return contract.MaintenanceResult{}, err
	}
	blocking, err := s.finalizeRestoreRun(ctx, meta, runID, plan)
	if err != nil {
		return contract.MaintenanceResult{}, err
	}
	completed := len(blocking) == 0
	phase := contract.MaintenancePhaseFinished
	if !completed {
		phase = contract.MaintenancePhaseBlocked
	}

	return contract.MaintenanceResult{
		RunID:         runID,
		Kind:          contract.MaintenanceKindRestoreFinalize,
		Phase:         phase,
		Completed:     completed,
		BlockingCAIDs: blocking,
	}, nil
}

// startRestoreRun creates or reopens the dedicated maintenance run. A
// caller-chosen RunID is still accepted for idempotent retries, but the row is
// maintained by MaintenanceRepository rather than being faked with a Job.
func (s *MaintenanceService) startRestoreRun(ctx context.Context, runID domain.JobID) error {
	now := s.deps.Clock.Now()
	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		run, err := tx.Maintenance().GetRunForUpdate(ctx, runID)
		if errors.Is(err, port.ErrNotFound) {
			run = port.MaintenanceRun{
				ID:        runID,
				CreatedAt: now,
				UpdatedAt: now,
				Kind:      contract.MaintenanceKindRestoreFinalize,
				Phase:     contract.MaintenancePhaseStarted,
				StartedAt: now,
			}
			if err := tx.Maintenance().InsertRun(ctx, run); err != nil {
				return storeError(err, "maintenance_restore_run_insert_failed", "could not create the restore maintenance run")
			}
			return nil
		}
		if err != nil {
			return storeError(err, "maintenance_restore_run_read_failed", "could not read the restore maintenance run")
		}
		if run.Kind != contract.MaintenanceKindRestoreFinalize {
			return contract.NewAppError(contract.ErrorKindConflict, "maintenance_run_kind_conflict",
				"the run id belongs to a different maintenance operation").WithField("run_id", string(runID))
		}
		run.Phase = contract.MaintenancePhaseStarted
		run.CompletedAt = domain.Instant{}
		run.ErrorCode = ""
		run.UpdatedAt = now
		if err := tx.Maintenance().SaveRun(ctx, run, run.Version); err != nil {
			return storeError(err, "maintenance_restore_run_reopen_failed", "could not reopen the restore maintenance run")
		}
		return nil
	})
	if errors.Is(err, port.ErrCommitUnknown) {
		s.deps.RuntimeGate.FailClosed("maintenance_restore_run_commit_unknown")
	}
	return err
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

type restoreCRLPlan struct {
	BlockingCAIDs []domain.AuthorityID
	Requirements  []port.MaintenanceCRLRequirement
}

// restoreRunDetails is deliberately public-fact-only JSON. It is persisted in
// maintenance_runs.details_json so a restart can explain why admission stayed
// closed without consulting a jobs payload or retaining any secret input.
type restoreRunDetails struct {
	SchemaVersion        int                  `json:"schema_version"`
	BlockingAuthorityIDs []domain.AuthorityID `json:"blocking_authority_ids"`
	CRLRequirementCount  int                  `json:"crl_requirement_count"`
}

// restoreCRLPlan enumerates every operational CA and carries the durable
// minimum generation/number forward across retries. A requirement already
// stored for this run is never replaced with a newly computed "next number"
// after a worker has published it; this is what makes SatisfiedCRLID an
// observable completion proof rather than a moving target.
func (s *MaintenanceService) restoreCRLPlan(ctx context.Context, runID domain.JobID) (restoreCRLPlan, error) {
	var plan restoreCRLPlan
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		existing, err := tx.Maintenance().ListCRLRequirements(ctx, runID)
		if err != nil && !errors.Is(err, port.ErrNotFound) {
			return storeError(err, "maintenance_restore_requirements_read_failed", "could not read restore CRL requirements")
		}
		existingByIssuer := make(map[domain.CAKeyGenerationID]port.MaintenanceCRLRequirement, len(existing))
		for _, requirement := range existing {
			existingByIssuer[requirement.CAKeyGenerationID] = requirement
		}

		query := contract.AuthorityListQuery{Page: contract.PageRequest{Limit: 200}}
		if err := query.Validate(); err != nil {
			return err
		}
		for {
			page, err := tx.Queries().ListAuthorities(ctx, query, port.QueryScope{All: true})
			if err != nil {
				return storeError(err, "maintenance_restore_authority_list_failed", "could not list authorities")
			}
			for _, authority := range page.Items {
				if authority.IsArchived() || authority.KeyGenerationID() == "" {
					continue
				}
				historyOnly, err := isHistoryOnlyCA(ctx, tx, authority)
				if err != nil {
					return storeError(err, "maintenance_restore_key_material_read_failed", "could not determine the authority's key custody")
				}
				if historyOnly {
					// Certificate-only imported CAs retain public history but
					// were never operational CRL signers. They are not a
					// reason to block restore or create a fictitious demand.
					continue
				}
				state, err := tx.Queries().GetCRLStatus(ctx, authority.KeyGenerationID(), port.QueryScope{All: true})
				if errors.Is(err, port.ErrNotFound) {
					// A keyless inventory CA with no CRL state has no
					// operational publication obligation and must not block restore.
					continue
				}
				if err != nil {
					return storeError(err, "maintenance_restore_crl_status_read_failed", "could not read the authority's CRL state")
				}

				requirement, hadRequirement := existingByIssuer[authority.KeyGenerationID()]
				if !hadRequirement {
					if state.RevocationGeneration() <= state.PublishedGeneration() {
						continue
					}
					requirement = port.MaintenanceCRLRequirement{
						MaintenanceRunID:  runID,
						CAKeyGenerationID: authority.KeyGenerationID(),
						MinimumGeneration: state.RevocationGeneration(),
						MinimumNumber:     state.MaxReservedNumber().Increment(),
					}
				} else if state.RevocationGeneration() > requirement.MinimumGeneration {
					requirement.MinimumGeneration = state.RevocationGeneration()
					nextNumber := state.MaxReservedNumber().Increment()
					if nextNumber.Compare(requirement.MinimumNumber) > 0 {
						requirement.MinimumNumber = nextNumber
					}
				}

				requirement.SatisfiedCRLID = ""
				if crlRequirementSatisfied(state, requirement) {
					requirement.SatisfiedCRLID = state.PublishedDocumentID()
				}
				plan.Requirements = append(plan.Requirements, requirement)
				if requirement.SatisfiedCRLID == "" && !authority.KeyAvailable() {
					plan.BlockingCAIDs = append(plan.BlockingCAIDs, authority.ID())
				}
			}
			if page.NextCursor == nil {
				break
			}
			query.Page.Cursor = *page.NextCursor
		}
		return nil
	})
	if err != nil {
		return restoreCRLPlan{}, err
	}
	return plan, nil
}

func crlRequirementSatisfied(state domain.CRLState, requirement port.MaintenanceCRLRequirement) bool {
	return requirement.MinimumGeneration >= 0 &&
		!requirement.MinimumNumber.IsZero() &&
		state.PublishedGeneration() >= requirement.MinimumGeneration &&
		state.PublishedNumber().Compare(requirement.MinimumNumber) >= 0 &&
		state.PublishedDocumentID() != ""
}

// finalizeRestoreRun re-reads each CRL state under its publication lock,
// records the requirement and satisfaction evidence, requeues an ordinary
// CRL worker demand when a usable key exists, and updates the dedicated run in
// one transaction. Jobs are used only for the publication work; they never
// carry the restore execution state.
func (s *MaintenanceService) finalizeRestoreRun(ctx context.Context, meta contract.MutationMeta, runID domain.JobID, plan restoreCRLPlan) ([]domain.AuthorityID, error) {
	var blocking []domain.AuthorityID
	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		run, err := tx.Maintenance().GetRunForUpdate(ctx, runID)
		if err != nil {
			return storeError(err, "maintenance_restore_run_read_failed", "could not re-read the restore maintenance run")
		}
		if run.Kind != contract.MaintenanceKindRestoreFinalize {
			return contract.NewAppError(contract.ErrorKindConflict, "maintenance_run_kind_conflict",
				"the run id belongs to a different maintenance operation")
		}

		for _, prepared := range plan.Requirements {
			requirement := prepared
			state, err := tx.CRLs().GetStateForUpdate(ctx, requirement.CAKeyGenerationID)
			if err != nil {
				if errors.Is(err, port.ErrNotFound) {
					continue
				}
				return storeError(err, "maintenance_restore_crl_state_lock_failed", "could not lock the restore CRL state")
			}
			if state.RevocationGeneration() > requirement.MinimumGeneration {
				requirement.MinimumGeneration = state.RevocationGeneration()
				nextNumber := state.MaxReservedNumber().Increment()
				if nextNumber.Compare(requirement.MinimumNumber) > 0 {
					requirement.MinimumNumber = nextNumber
				}
			}
			requirement.SatisfiedCRLID = ""
			if crlRequirementSatisfied(state, requirement) {
				requirement.SatisfiedCRLID = state.PublishedDocumentID()
			}
			if err := tx.Maintenance().UpsertCRLRequirement(ctx, requirement); err != nil {
				return storeError(err, "maintenance_restore_requirement_save_failed", "could not record the restore CRL requirement")
			}

			generation, err := tx.PKI().GetCAKeyGeneration(ctx, requirement.CAKeyGenerationID)
			if err != nil {
				return storeError(err, "maintenance_restore_ca_generation_read_failed", "could not read the restore CA key generation")
			}
			authority, err := tx.PKI().GetIssuerForUpdate(ctx, generation.AuthorityID)
			if err != nil {
				return storeError(err, "maintenance_restore_authority_lock_failed", "could not read the restore authority")
			}
			if requirement.SatisfiedCRLID == "" {
				if authority.KeyAvailable() {
					if err := recordCRLDemand(ctx, tx, requirement.CAKeyGenerationID, requirement.MinimumGeneration); err != nil {
						return storeError(err, "maintenance_restore_crl_demand_failed", "could not record the CRL resumption demand")
					}
				} else if !authority.IsArchived() {
					blocking = append(blocking, authority.ID())
				}
			}
		}

		completed := len(blocking) == 0
		now := s.deps.Clock.Now()
		run.UpdatedAt = now
		run.Phase = contract.MaintenancePhaseFinished
		run.CompletedAt = now
		run.ErrorCode = ""
		if !completed {
			run.Phase = contract.MaintenancePhaseBlocked
			run.CompletedAt = domain.Instant{}
			run.ErrorCode = "maintenance_restore_blocked_ca_key_missing"
		}
		runDetails, err := json.Marshal(restoreRunDetails{
			SchemaVersion:        1,
			BlockingAuthorityIDs: append([]domain.AuthorityID(nil), blocking...),
			CRLRequirementCount:  len(plan.Requirements),
		})
		if err != nil {
			return contract.WrapAppError(contract.ErrorKindValidation, "maintenance_restore_details_encode_failed",
				"could not encode the restore run details", err)
		}
		run.DetailsJSON = runDetails
		if err := tx.Maintenance().SaveRun(ctx, run, run.Version); err != nil {
			return storeError(err, "maintenance_restore_run_save_failed", "could not record the restore run outcome")
		}

		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorSystem,
			Action:     "maintenance.finalize_restore",
			TargetType: "maintenance_run",
			TargetID:   string(runID),
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details: contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{
				"completed":         fmt.Sprintf("%t", completed),
				"blocking_count":    fmt.Sprintf("%d", len(blocking)),
				"requirement_count": fmt.Sprintf("%d", len(plan.Requirements)),
			}},
		}
		if err := tx.Audit().Append(ctx, event, maintenanceScope()); err != nil {
			return storeError(err, "maintenance_restore_audit_failed", "could not record the restore audit event")
		}
		return nil
	})
	if errors.Is(err, port.ErrCommitUnknown) {
		s.deps.RuntimeGate.FailClosed("maintenance_restore_run_commit_unknown")
	}
	if err != nil {
		return nil, err
	}
	return blocking, nil
}
