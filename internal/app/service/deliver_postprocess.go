// deliver_postprocess.go holds Deliver's §7 steps 4-6: the only-after-commit
// sink.Send call and the bounded-time recording of what actually happened.
// It is a separate file from distribution.go purely for size; nothing here
// is reachable except through DistributionService.Deliver.
package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// boundReader is the only io.Reader a DownloadSink ever sees. It wraps the
// plaintext bundle bytes for exactly the lifetime of one Send call: disable
// is called the instant Send returns (success, error or recovered panic),
// so a sink that ignores port.DownloadSink's "Send 반환 전에 사용을 종료한다"
// rule and keeps reading afterward gets errPayloadReaderClosed instead of
// silently reading memory this package no longer owns.
type boundReader struct {
	r        *bytes.Reader
	disabled bool
}

func (b *boundReader) Read(p []byte) (int, error) {
	if b.disabled {
		return 0, errPayloadReaderClosed
	}
	return b.r.Read(p)
}

func (b *boundReader) disable() { b.disabled = true }

// sendResult is invokeSink's observation of one Send call, panic included.
type sendResult struct {
	outcome  port.TransferOutcome
	sendErr  error
	panicked bool
	panicVal any
}

// failed reports whether, from Deliver's point of view, the transfer did not
// go well enough to call a private delivery complete or a public delivery
// clean: a panic, a returned error, or Send itself reporting !Completed all
// count (docs/backend-implementation.md §7: "Complete ... 응답 본문이 완료
// 쓰기만 뜻한다", i.e. anything short of an observed-complete write is not a
// success).
func (r sendResult) failed() bool {
	return r.panicked || r.sendErr != nil || !r.outcome.Completed
}

// invokeSink calls sink.Send with a reader bound to bundle's plaintext,
// recovering a panic instead of letting it unwind past this frame -- §7 step
// 5's "Send가 반환하거나 panic하면 payload를 정리한다" requires the payload
// to be cleaned up on the panic path too, which only a recovered panic makes
// possible from here. The plaintext is only ever reachable inside bundle's
// own Use callback (never copied out to a longer-lived variable), so the
// non-retention discipline secret.Input.Use documents applies transitively
// to this reader as well.
func invokeSink(ctx context.Context, sink port.DownloadSink, descriptor port.FileDescriptor, bundle port.EncodedBundle) sendResult {
	var result sendResult
	_ = bundle.Use(func(data []byte) error {
		br := &boundReader{r: bytes.NewReader(data)}
		func() {
			defer func() {
				if p := recover(); p != nil {
					result.panicked = true
					result.panicVal = p
				}
			}()
			result.outcome, result.sendErr = sink.Send(ctx, descriptor, br)
		}()
		br.disable()
		return nil
	})
	return result
}

// sendAndRecord is §7 steps 4-6, run only once commitConsumption has
// produced a consumedTransfer -- i.e. only for the one request that actually
// won the consuming commit (§7 step 4: "commit 패자에게는 sink 호출이
// 없다").
func (s *DistributionService) sendAndRecord(ctx context.Context, meta contract.RequestMeta, sink port.DownloadSink, prep preparedDelivery, consumed consumedTransfer, now domain.Instant) (contract.TransferSummary, error) {
	descriptor := port.FileDescriptor{
		ContentType: prep.contentType,
		Filename:    prep.filename,
		Size:        int64(prep.bundle.Len()),
	}

	sendCtx, cancel := context.WithTimeout(ctx, deliverSendTimeout)
	defer cancel()

	result := invokeSink(sendCtx, sink, descriptor, prep.bundle)
	// Step 5: "Send가 반환하거나 panic하면 payload를 정리한다" -- before
	// anything else, regardless of outcome.
	prep.bundle.Close()

	// The recording context is deliberately independent of ctx (the
	// caller's request context) and of sendCtx: §7 step 5 requires it
	// detached from server runtime lifetime, with its own bounded budget.
	postCtx, postCancel := context.WithTimeout(context.Background(), deliverPostProcessTimeout)
	defer postCancel()

	if prep.purpose == domain.GrantPurposeLeafPrivate {
		if postErr := s.recordPrivateOutcome(postCtx, meta, prep, consumed, result, now); postErr != nil {
			code := "distribution_private_postprocess_failed"
			if errors.Is(postErr, port.ErrCommitUnknown) {
				code = "distribution_private_postprocess_commit_unknown"
			}
			// §12: private post-processing failure or an undetermined
			// outcome both go to FailClosed -- there is no safe way to leave
			// the process serving other private transfers once this
			// delivery's true state (consumed? completed? failed and
			// revoked?) cannot be recorded.
			s.deps.RuntimeGate.FailClosed(code)
			return contract.TransferSummary{}, contract.WrapAppError(contract.ErrorKindCommitUnknown,
				code, "the private transfer outcome could not be safely recorded", postErr)
		}
	} else if result.failed() {
		// §7 step 5/§12: "public 후처리 실패는 키 폐기를 만들지 않고 정제된
		// 오류를 운영 로그에 남긴다." Distribution has no Logger dependency
		// (§5 lists none for it), so there is nothing further to route this
		// to; the error is deliberately swallowed here rather than
		// escalated to FailClosed or turned into the method's returned
		// error, matching "키 폐기를 만들지 않는다" -- a public failure to
		// audit must not become a private-grade incident. Flagged for the
		// lead: this is a gap (no logging sink), not a decision that the
		// error should vanish silently forever.
		_ = s.recordPublicFailureAudit(postCtx, meta, consumed, now)
	}

	if result.panicked {
		return contract.TransferSummary{}, contract.WrapAppError(contract.ErrorKindUnavailable,
			"distribution_send_panicked", "the download transfer failed unexpectedly", fmt.Errorf("panic: %v", result.panicVal))
	}
	if result.sendErr != nil {
		return contract.TransferSummary{}, contract.WrapAppError(contract.ErrorKindUnavailable,
			"distribution_send_failed", "the download transfer failed", result.sendErr)
	}

	summary := contract.TransferSummary{
		TokenID:      consumed.grant.ID(),
		Completed:    result.outcome.Completed,
		BytesWritten: result.outcome.BytesWritten,
		FinishedAt:   result.outcome.FinishedAt,
	}
	if prep.purpose == domain.GrantPurposeLeafPrivate {
		summary.DeliveryID = consumed.delivery.ID()
	}
	return summary, nil
}

// recordPrivateOutcome is the private half of §7 step 5/6: a single Write
// that either completes the delivery (transfer succeeded) or fails it and
// revokes the now-untrusted key in the same commit (transfer failed),
// through the shared applyRevocations path -- never a hand-rolled
// revocation (docs/backend-implementation.md §5: "Distribution의 실패/만료
// ... 이 함수를 사용한다").
func (s *DistributionService) recordPrivateOutcome(ctx context.Context, meta contract.RequestMeta, prep preparedDelivery, consumed consumedTransfer, result sendResult, now domain.Instant) error {
	return s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		delivery, err := tx.Delivery().GetDeliveryForUpdate(ctx, consumed.delivery.ID())
		if err != nil {
			return storeError(err, "delivery_read_failed", "could not read the delivery record")
		}

		if !result.failed() {
			completed, err := delivery.Complete(now)
			if err != nil {
				return contract.FromDomainError(err)
			}
			if err := tx.Delivery().SaveDelivery(ctx, completed, delivery.Version()); err != nil {
				return storeError(err, "delivery_save_failed", "could not record the delivery completion")
			}
			return appendDistributionAudit(ctx, tx, s.deps.IDs, now, meta, "distribution.deliver.private.completed", consumed.grant.ID(), contract.AuditResultSuccess)
		}

		code := "transfer_failed"
		if result.panicked {
			code = "transfer_panic"
		}
		failedDelivery, err := delivery.Fail(code, now)
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.Delivery().SaveDelivery(ctx, failedDelivery, delivery.Version()); err != nil {
			return storeError(err, "delivery_save_failed", "could not record the delivery failure")
		}

		// ASSUMPTION (flagged for the lead): no RevocationReason value maps
		// cleanly onto "we failed to hand the key over" -- the fixed set
		// (key_compromise, ca_compromise, affiliation_changed, superseded,
		// cessation_of_operation, privilege_withdrawn, aa_compromise, or
		// unspecified) has no "delivery failed" member, and no document
		// states which of these a delivery-failure revocation should carry.
		// unspecified is used as the conservative default. Likewise no
		// RevocationSource value (manual/import/cascade) is defined for "the
		// system revoked this on its own because the transfer failed";
		// cascade is used as the closest existing meaning (a system-derived
		// consequence of another event, not a direct admin action or an
		// imported CRL entry). Both picks need the lead's confirmation.
		change := RevocationChange{
			IssuerID:      prep.certificate.IssuerCAKeyGenerationID(),
			Serial:        prep.certificate.Serial(),
			CertificateID: prep.certificate.ID(),
			RevokedAt:     now,
			Reason:        domain.RevocationReasonUnspecified,
			Source:        domain.RevocationSourceCascade,
		}
		revMeta := RevocationMeta{
			Request:   meta,
			ActorKind: contract.AuditActorDownloadToken,
			ActorID:   string(consumed.grant.ID()),
			TokenID:   string(consumed.grant.ID()),
			Action:    "distribution.deliver.private.failed",
			Now:       now,
			IDs:       s.deps.IDs,
		}
		// applyRevocations owns the revocation merge, the issuer's CRL
		// job/generation bump and the revocation's own audit row together
		// (docs/backend-implementation.md §5); a failure anywhere inside it
		// rolls back this whole Write, which is exactly what keeps "폐기·
		// CRL job·감사가 같은 커밋(하나라도 실패하면 전부 없어야 한다)" true
		// without this function doing anything special itself.
		if _, err := applyRevocations(ctx, tx, []RevocationChange{change}, revMeta); err != nil {
			return err
		}
		return appendDistributionAudit(ctx, tx, s.deps.IDs, now, meta, "distribution.deliver.private.failed", consumed.grant.ID(), contract.AuditResultFailure)
	})
}

// recordPublicFailureAudit is the public half of §7 step 5: a public
// transfer failure gets an audit row and nothing else (no revocation, no CRL
// job). Its own failure is swallowed by the caller -- see sendAndRecord's
// comment on why.
func (s *DistributionService) recordPublicFailureAudit(ctx context.Context, meta contract.RequestMeta, consumed consumedTransfer, now domain.Instant) error {
	return s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		return appendDistributionAudit(ctx, tx, s.deps.IDs, now, meta, "distribution.deliver.public.failed", consumed.grant.ID(), contract.AuditResultFailure)
	})
}
