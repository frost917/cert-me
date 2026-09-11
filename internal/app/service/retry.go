package service

import (
	"context"
	"errors"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
)

// maxPreparationAttempts is the ceiling §4 sets on redoing a whole
// preparation: "서비스가 외부 효과 전의 명확한 rollback·DB 경합일 때만 최대
// 3회 전체 준비를 재시도한다."
const maxPreparationAttempts = 3

// RunWithRetry redoes attempt in full -- preparation and the single Write --
// for a definite rollback caused by store contention, at most
// maxPreparationAttempts times.
//
// The rules this encodes, all from §4 and §10:
//   - Only port.ErrVersionConflict is retried. A duplicate-key conflict
//     means the row already exists, so repeating the same write cannot
//     help; commit_unknown means the commit may have happened, so retrying
//     could double-apply it; every other error is the caller's answer.
//   - The retry redoes the caller's whole closure, because the preparation
//     that produced the stale version has to be redone too, not just the
//     commit.
//   - The request id is NOT changed between attempts ("새 요청 ID로 바꾸지
//     않는다"), which falls out of attempt taking no arguments: the caller's
//     closure keeps the same meta.
//   - This must never wrap an attempt that already produced an external
//     effect (a DownloadSink write, an installed TLS config). Deliver does
//     its own single Write for exactly that reason.
func RunWithRetry(ctx context.Context, attempt func() error) error {
	var lastErr error
	for i := 0; i < maxPreparationAttempts; i++ {
		if err := ctx.Err(); err != nil {
			return contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
				"the request was canceled before it completed", err)
		}
		lastErr = attempt()
		if lastErr == nil {
			return nil
		}
		if !retryablePreparation(lastErr) {
			return lastErr
		}
	}
	return contract.WrapAppError(contract.ErrorKindConflict, "store_contention",
		"the request lost a version race repeatedly", lastErr)
}

// retryablePreparation reports whether err is the one situation a full
// re-preparation can resolve: a definite rollback from a version race.
func retryablePreparation(err error) bool {
	if errors.Is(err, port.ErrCommitUnknown) || errors.Is(err, port.ErrDuplicate) {
		return false
	}
	return errors.Is(err, port.ErrVersionConflict)
}
