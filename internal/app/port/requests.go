package port

import (
	"context"

	"cert-me/internal/domain"
)

// OperationRequestKey identifies one operation_requests row by its unique
// key (actor_key, operation, request_id)
// (docs/data-model.md "operation_requests" row). Find and InsertResult share
// this shape rather than repeating the three fields separately, since a
// service always looks a key up and later inserts its result under the
// exact same identity.
type OperationRequestKey struct {
	ActorKey  string
	Operation string
	RequestID string
}

// OperationRequestResult is the port-level projection of a completed
// operation_requests row: enough to replay a prior success without
// re-running the operation (docs/backend-implementation.md §8 "기대 version
// 검사보다 기존 성공 요청 결과 재생이 먼저다"). There is no domain object for
// it -- result_json is an opaque, already-public result the service
// produced and stored, not something with its own transitions.
type OperationRequestResult struct {
	InputHash           string
	ResultCertificateID domain.CertificateID // empty when the operation did not produce a certificate
	ResultJSON          []byte
}

// RequestRepository is the storage boundary for idempotent operation replay
// (docs/backend-implementation.md §4 table row "RequestRepository";
// docs/data-model.md "operation_requests"). MVP only stores successful
// results (docs/backend-implementation.md §4 "MVP 서비스는 성공 결과를 업무
// 커밋에 함께 InsertResult한다. 사전 준비 중에는 영속 processing 행을 만들지
// 않는다"): a plain failure leaves no row, so the same key can simply be
// retried.
type RequestRepository interface {
	// Find looks up a previously stored result for key. It returns
	// ErrNotFound when no result has been stored yet for this key, which a
	// caller treats as "proceed with the operation," not as an error to
	// surface.
	Find(ctx context.Context, key OperationRequestKey) (OperationRequestResult, error)

	// InsertResult stores the successful, public result for key in the same
	// commit that produced it. inputHash is the normalized-input hash used
	// to detect an idempotency key reused with different input; publicResult
	// is result_json's exact bytes and must never include a token, private
	// key or other secret (docs/data-model.md "결과에 토큰 원문·개인키 포함
	// 금지").
	InsertResult(ctx context.Context, key OperationRequestKey, inputHash string, publicResult []byte) error
}
