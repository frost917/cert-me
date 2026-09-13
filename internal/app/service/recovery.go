// recovery.go is the restart path docs/backend-implementation.md §9 and §12
// require before a process opens admission again: every delivery the
// previous process left mid-transfer is resolved conservatively, and a
// failure here means download and issuance requests are never opened
// ("재시작 복구 commit이 실패하면 다운로드/발급 요청을 열지 않는다").
package service

import (
	"context"
	"errors"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// recoveryBatchSize matches the 100-row processing batch §9 fixes for the
// sweeps ("처리 batch는 100개이며").
const recoveryBatchSize = 100

// recoveryFailureCode is the failure_code a transfer interrupted by a
// process exit is recorded under. §14.1 fixes this exact name (distinct from
// a live send failure's transfer_failed) so the audit/failure_code alone
// tells apart a request that failed mid-transfer from one that was simply
// still open when the previous process exited.
const recoveryFailureCode = "interrupted_transfer"

// RecoveryOutcome reports what a restart resolved, for the operator log the
// runtime writes before opening admission.
type RecoveryOutcome struct {
	// Failed counts deliveries moved from transferring to failed.
	Failed int
	// Skipped counts rows that had already left transferring by the time
	// their own transaction locked them.
	Skipped int
}

// RecoverInterruptedTransfers resolves every delivery left in transferring
// by a previous process (docs/certificate-lifecycle.md "재시작 후 남은 전송
// 중 상태는 보수적으로 수령 실패 처리해 인증서를 폐기한다").
//
// The rules it encodes:
//   - Only transferring rows are touched. A delivery that reached completed
//     before the process died is stored state, and stored state is kept --
//     a restart never re-opens or re-fails it. ListTransferring is the only
//     source of work, so a completed row is never even read for update.
//   - Each delivery is its own transaction (§9 "각 수령 실패 변경은 독립
//     트랜잭션으로 처리한다"), so one unresolvable row does not strand the
//     rest; the first failure is still returned, because the caller must
//     not open admission after a partial recovery.
//   - The failure, the revocation, its CRL demand and the audit trail share
//     one commit, through the same applyRevocations every other caller uses.
//
// The caller (the runtime, at startup) must not open download or issuance
// admission until this returns nil (§9, §12).
func (s *DistributionService) RecoverInterruptedTransfers(ctx context.Context) (RecoveryOutcome, error) {
	var outcome RecoveryOutcome
	now := s.deps.Clock.Now()

	for {
		var batch []domain.Delivery
		if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
			var readErr error
			batch, readErr = tx.Delivery().ListTransferring(ctx, recoveryBatchSize)
			return readErr
		}); err != nil {
			return outcome, storeError(err, "recovery_list_failed", "could not list interrupted transfers")
		}
		if len(batch) == 0 {
			return outcome, nil
		}

		progressed := false
		for _, delivery := range batch {
			failed, err := s.failInterruptedTransfer(ctx, delivery.ID(), now)
			if err != nil {
				return outcome, err
			}
			if failed {
				outcome.Failed++
				progressed = true
				continue
			}
			outcome.Skipped++
		}
		if !progressed {
			// Every row in this batch had already left transferring, so
			// another pass would return the same rows forever.
			return outcome, nil
		}
	}
}

// failInterruptedTransfer resolves one delivery in its own transaction. It
// reports false when the row was no longer transferring under lock, which is
// not an error: a concurrent finish is exactly the state recovery wants.
func (s *DistributionService) failInterruptedTransfer(ctx context.Context, deliveryID domain.DeliveryID, now domain.Instant) (bool, error) {
	changed := false
	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		changed = false
		delivery, err := tx.Delivery().GetDeliveryForUpdate(ctx, deliveryID)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return nil
			}
			return storeError(err, "recovery_delivery_read_failed", "could not read the interrupted delivery")
		}
		if delivery.State() != domain.DeliveryStateTransferring {
			// Stored completed (or already failed) state is kept as-is.
			return nil
		}

		if err := failInterruptedDelivery(ctx, tx, delivery, RevocationMeta{
			ActorKind: contract.AuditActorSystem,
			Action:    "distribution.recovery.transfer_failed",
			Now:       now,
			IDs:       s.deps.IDs,
		}, transferRecoveryErrors{
			certificateRead: "recovery_certificate_read_failed",
			deliverySave:    "recovery_delivery_save_failed",
			grantInvalidate: "recovery_grant_invalidate_failed",
		}); err != nil {
			return err
		}
		changed = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return changed, nil
}

// transferRecoveryErrors preserves each recovery entry point's error codes.
type transferRecoveryErrors struct {
	certificateRead string
	deliverySave    string
	grantInvalidate string
}

// failInterruptedDelivery applies the shared recovery mutation to a locked,
// transferring delivery. The caller owns the transaction, the observation time,
// and the policy for reporting a failed or uncertain commit.
func failInterruptedDelivery(ctx context.Context, tx port.TxStores, delivery domain.Delivery, meta RevocationMeta, codes transferRecoveryErrors) error {
	certificate, err := tx.PKI().GetCertificate(ctx, delivery.CertificateID())
	if err != nil {
		return storeError(err, codes.certificateRead, "could not read the interrupted delivery's certificate")
	}
	scope, err := leafManagementAuthority(ctx, tx, certificate.ID())
	if err != nil {
		return err
	}

	failedDelivery, err := delivery.Fail(recoveryFailureCode, meta.Now)
	if err != nil {
		return contract.FromDomainError(err)
	}
	if err := tx.Delivery().SaveDelivery(ctx, failedDelivery, delivery.Version()); err != nil {
		return storeError(err, codes.deliverySave, "could not record the interrupted delivery's failure")
	}
	if err := tx.Delivery().InvalidatePrivateGrants(ctx, delivery.ID(), meta.Now); err != nil {
		return storeError(err, codes.grantInvalidate, "could not invalidate the interrupted delivery's links")
	}

	// The same reason/source DistributionService uses for a live
	// transfer failure -- §14.1 confirms both for "잔류 transferring
	// 복구" too: "기본 reason은 unspecified, source는 cascade로 확정한다."
	change := RevocationChange{
		IssuerID:      certificate.IssuerCAKeyGenerationID(),
		Serial:        certificate.Serial(),
		CertificateID: certificate.ID(),
		RevokedAt:     meta.Now,
		Reason:        domain.RevocationReasonUnspecified,
		Source:        domain.RevocationSourceCascade,
		AuthorityID:   scope,
	}
	_, err = applyRevocations(ctx, tx, []RevocationChange{change}, meta)
	return err
}
