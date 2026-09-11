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
		// 오류를 운영 로그에 남긴다." §14.5 gives this a home:
		// OperationalLogger.Record, with only the fixed code/request id/
		// stage/ids -- never the raw sendErr, a URL, a token or key material.
		// A public failure must never become a private-grade incident (no
		// FailClosed, no key revocation), and the operational log is not a
		// substitute for the audit DB ("운영 로그는 감사 DB의 대체 성공
		// 기록이 아니다"), so recordPublicFailureAudit below still runs
		// regardless of what Record does. Record itself is best-effort/
		// non-blocking/non-panicking by its own contract and returns
		// nothing, so there is no error path to fold in here.
		code := "distribution_public_send_failed"
		if result.panicked {
			code = "distribution_public_send_panicked"
		}
		if auditErr := s.recordPublicFailureAudit(postCtx, meta, prep, consumed, now); auditErr != nil {
			// The business audit row itself could not be written. This is
			// exactly the "public 후처리 오류" §14.5 requires a home for --
			// recorded here rather than silently dropped as the old `_ =`
			// discard did, but still never escalated to FailClosed or
			// folded into Deliver's own returned error (a public transfer's
			// audit failure is not a private-grade incident).
			code = "distribution_public_postprocess_audit_failed"
		}
		s.deps.OperationalLogger.Record(port.OperationalEvent{
			Code:          code,
			RequestID:     meta.RequestID,
			Stage:         port.OperationalStagePublicPostProcess,
			GrantID:       consumed.grant.ID(),
			CertificateID: prep.certificate.ID(),
		})
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
		scope, err := distributionManagementAuthority(ctx, tx, prep.certificate.ID())
		if err != nil {
			return err
		}

		if !result.failed() {
			completed, err := delivery.Complete(now)
			if err != nil {
				return contract.FromDomainError(err)
			}
			if err := tx.Delivery().SaveDelivery(ctx, completed, delivery.Version()); err != nil {
				return storeError(err, "delivery_save_failed", "could not record the delivery completion")
			}
			return appendDistributionAudit(ctx, tx, s.deps.IDs, now, meta, "distribution.deliver.private.completed", consumed.grant.ID(), contract.AuditResultSuccess, scope)
		}

		// §14.1 settled failure_code naming: a live send failure is recorded
		// as transfer_failed (transfer_panic distinguishes the panic case,
		// which is not one of the three §14.1 names but is not a new CRL
		// reason or DB enum either -- delivery.failure_code is a free-form
		// operator-facing string).
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

		// §14.1 settles reason=unspecified/source=cascade for a delivery
		// failure's derived revocation: "전송 실패·수령 만료·잔류
		// transferring 복구의 기본 reason은 unspecified, source는 cascade로
		// 확정한다." Merge (internal/domain/revocation.go) never lets an
		// incoming assertion downgrade a stronger existing reason -- a
		// conflicting reason/time leaves the existing record untouched and
		// only flags NeedsReview -- so an unspecified/cascade assertion here
		// can never weaken an earlier key_compromise revocation on the same
		// (issuer, serial).
		change := RevocationChange{
			IssuerID:      prep.certificate.IssuerCAKeyGenerationID(),
			Serial:        prep.certificate.Serial(),
			CertificateID: prep.certificate.ID(),
			RevokedAt:     now,
			Reason:        domain.RevocationReasonUnspecified,
			Source:        domain.RevocationSourceCascade,
			AuthorityID:   scope,
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
		return appendDistributionAudit(ctx, tx, s.deps.IDs, now, meta, "distribution.deliver.private.failed", consumed.grant.ID(), contract.AuditResultFailure, scope)
	})
}

// recordPublicFailureAudit is the public half of §7 step 5: a public
// transfer failure gets an audit row and nothing else (no revocation, no CRL
// job). Its own failure is now surfaced to the caller (sendAndRecord routes
// it into the §14.5 OperationalLogger call) instead of being swallowed.
func (s *DistributionService) recordPublicFailureAudit(ctx context.Context, meta contract.RequestMeta, prep preparedDelivery, consumed consumedTransfer, now domain.Instant) error {
	return s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		scope, err := distributionManagementAuthority(ctx, tx, prep.certificate.ID())
		if err != nil {
			return err
		}
		return appendDistributionAudit(ctx, tx, s.deps.IDs, now, meta, "distribution.deliver.public.failed", consumed.grant.ID(), contract.AuditResultFailure, scope)
	})
}
