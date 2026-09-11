package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// inputHashSchemaVersion is the "v1" of docs/backend-implementation.md §11.6
// ("idempotency input hash v1"). It is part of the hashed envelope itself,
// so a future normalization change produces a different hash rather than
// silently colliding with a v1 request.
const inputHashSchemaVersion = 1

// requestEnvelope is what actually gets hashed. Nothing beyond these four
// members is included: §11.6 requires the operation, the path target ids and
// every validated business input, and forbids blanket-serializing the whole
// command ("command 전체를 무차별 직렬화하지 않는다"). Trace RequestID, client
// IP, session token and If-Match are deliberately absent, as is the
// idempotency key itself (it is a lookup key, not hashed input).
type requestEnvelope struct {
	SchemaVersion int               `json:"schema_version"`
	Operation     string            `json:"operation"`
	Target        map[string]string `json:"target"`
	Input         any               `json:"input"`
}

// InputHash computes the v1 idempotency input hash for one operation.
//
// input must be a dedicated, per-operation typed DTO whose JSON shape is
// stable and whose values the caller has already normalized (see
// NormalizeUUID/NormalizeFingerprint/NormalizeInstant). Optional fields are
// represented as pointers or omitted keys so that "absent" stays
// distinguishable from an explicit value -- §11.6 "선택값 생략은 명시값과
// 구별해 보존한다" -- which is why this function never applies omitempty of
// its own or rewrites the caller's DTO.
//
// encoding/json writes struct fields in declaration order and map keys in
// sorted order, so the byte sequence is deterministic for a given DTO.
func InputHash(operation string, target map[string]string, input any) (string, error) {
	if operation == "" {
		return "", contract.NewAppError(contract.ErrorKindValidation, "request_operation_missing",
			"an idempotent operation must name itself in its input hash")
	}
	if target == nil {
		target = map[string]string{}
	}
	encoded, err := json.Marshal(requestEnvelope{
		SchemaVersion: inputHashSchemaVersion,
		Operation:     operation,
		Target:        target,
		Input:         input,
	})
	if err != nil {
		return "", contract.WrapAppError(contract.ErrorKindValidation, "request_input_hash_failed",
			"could not normalize the request input", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// NormalizeUUID lowercases an id for hashing (§11.6 "UUID/지문은 소문자").
func NormalizeUUID(raw string) string { return strings.ToLower(raw) }

// NormalizeFingerprint lowercases a fingerprint for hashing, same rule.
func NormalizeFingerprint(raw string) string { return strings.ToLower(raw) }

// NormalizeInstant renders a time as UTC with microsecond precision
// (§11.6 "시간은 UTC 마이크로초로 정규화한다"). A zero instant renders as the
// empty string so "no time given" never collides with an epoch timestamp.
func NormalizeInstant(at domain.Instant) string {
	if at.IsZero() {
		return ""
	}
	return at.Time().UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z")
}

// ActorKey is the operation_requests.actor_key for a principal. It is a
// lookup key, never hashed input: §11.6 "actor와 idempotency key는 조회
// 키이며 ... 해시에서 제외한다". Scoping replay per actor is what stops one
// administrator's idempotency key from replaying another's stored result.
func ActorKey(principal contract.Principal) string {
	switch {
	case principal.IsAdmin():
		return "account:" + NormalizeUUID(string(principal.AccountID()))
	case principal.IsInternal():
		return "internal"
	default:
		return "anonymous"
	}
}

// RequestKey builds the operation_requests identity for a mutation.
func RequestKey(meta contract.MutationMeta, operation string) (port.OperationRequestKey, error) {
	key, err := meta.RequireIdempotencyKey()
	if err != nil {
		return port.OperationRequestKey{}, err
	}
	return port.OperationRequestKey{
		ActorKey:  ActorKey(meta.Principal),
		Operation: operation,
		RequestID: key,
	}, nil
}

// ReplayStoredResult looks for a previously committed result for key.
//
// Call order matters and is fixed by §8: this runs BEFORE the expected
// version check ("기대 version 검사보다 기존 성공 요청 결과 재생이 먼저다")
// but AFTER the caller has authenticated and authorized the request, because
// a principal who no longer has permission must not receive the stored
// result either ("현재 인증/권한이 없는 요청은 기존 결과도 받지 못한다").
//
// It returns:
//   - (result, true, nil) when a stored result exists for the same input
//     hash: the caller replays it verbatim, including for a request whose
//     settings snapshot has since changed ("이미 성공한 요청의 재생은 당시
//     결과를 유지한다").
//   - (_, false, nil) when nothing is stored yet.
//   - a conflict AppError when the same key was used with different input.
func ReplayStoredResult(ctx context.Context, tx port.TxStores, key port.OperationRequestKey, inputHash string) (port.OperationRequestResult, bool, error) {
	if inputHash == "" {
		return port.OperationRequestResult{}, false, contract.NewAppError(contract.ErrorKindValidation,
			"request_input_hash_missing", "an idempotent operation requires an input hash")
	}
	stored, err := tx.Requests().Find(ctx, key)
	switch {
	case errors.Is(err, port.ErrNotFound):
		return port.OperationRequestResult{}, false, nil
	case err != nil:
		return port.OperationRequestResult{}, false, storeError(err, "request_lookup_failed",
			"could not check for an existing request result")
	}
	if stored.InputHash != inputHash {
		return port.OperationRequestResult{}, false, contract.NewAppError(contract.ErrorKindConflict,
			"idempotency_key_reused", "this idempotency key was already used with different input")
	}
	return stored, true, nil
}

// StoreRequestResult records the public result in the same commit that
// produced it (§4 "MVP 서비스는 성공 결과를 업무 커밋에 함께
// InsertResult한다"). publicResult must already be free of tokens and
// private keys; a rejection is never stored as a success result.
func StoreRequestResult(ctx context.Context, tx port.TxStores, key port.OperationRequestKey, inputHash string, publicResult any) error {
	encoded, err := json.Marshal(publicResult)
	if err != nil {
		return contract.WrapAppError(contract.ErrorKindValidation, "request_result_encode_failed",
			"could not encode the request result", err)
	}
	if err := tx.Requests().InsertResult(ctx, key, inputHash, encoded); err != nil {
		return storeError(err, "request_result_store_failed", "could not record the request result")
	}
	return nil
}

// DecodeStoredResult unmarshals a replayed result into the caller's view
// type. A stored row that no longer decodes is a server fault, not a client
// error, so it surfaces as unavailable rather than validation.
func DecodeStoredResult(stored port.OperationRequestResult, into any) error {
	if err := json.Unmarshal(stored.ResultJSON, into); err != nil {
		return contract.WrapAppError(contract.ErrorKindUnavailable, "request_result_decode_failed",
			"a stored result could not be replayed", err)
	}
	return nil
}
