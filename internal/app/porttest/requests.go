package porttest

import (
	"context"

	"cert-me/internal/app/port"
)

type requestRepo struct{ s *state }

var _ port.RequestRepository = requestRepo{}

func (r requestRepo) Find(_ context.Context, key port.OperationRequestKey) (port.OperationRequestResult, error) {
	result, ok := r.s.requestResults[key]
	if !ok {
		return port.OperationRequestResult{}, port.ErrNotFound
	}
	return cloneRequestResult(result), nil
}

// InsertResult stores a successful result exactly once. The losing side of
// two concurrent requests under the same key must not overwrite the winner's
// stored result (docs/backend-implementation.md §4: "commit 안에서 먼저
// 결과를 확인하고 한 쪽만 반영한다. 패자는 새 키/서명 결과를 버리고 기존
// 공개 결과를 반환한다"), so a second insert is a duplicate, not an update.
func (r requestRepo) InsertResult(_ context.Context, key port.OperationRequestKey, inputHash string, publicResult []byte) error {
	if _, ok := r.s.requestResults[key]; ok {
		return ErrDuplicate
	}
	r.s.requestResults[key] = port.OperationRequestResult{
		InputHash:  inputHash,
		ResultJSON: cloneBytes(publicResult),
	}
	return nil
}
