package port

import (
	"errors"

	"cert-me/internal/app/contract"
)

// ErrNotFound is returned by a repository lookup that found no row. It is a
// plain storage-layer signal, not a policy decision: services translate a
// missing row into whatever contract.AppError kind the calling method
// requires (usually validation or conflict), the same way every other
// repository error is mapped. Declaring one shared sentinel here keeps every
// implementation (SQL dialect, in-memory test double) reporting "no such
// row" the same way instead of each inventing its own not-found value.
var ErrNotFound = errors.New("port: not found")

// S3 fix: these three sentinels used to be declared only in porttest
// (porttest.ErrVersionConflict / porttest.ErrDuplicate), which meant a real
// service implementing B03's retry/409 mapping could only recognize them by
// importing a test-only package or by comparing error strings. Neither is
// acceptable: a service must never import a test double, and
// docs/backend-implementation.md §10 requires the mapping onto
// contract.ErrorKind to be a real classification, not string matching.
// Declaring them here means the SQL adapter (B05) and the in-memory double
// (porttest) return the exact same values, and any service can recognize
// them with errors.Is against port alone.

// ErrVersionConflict is returned by a Save/SaveXxx method when the caller's
// expectedVersion does not match the row currently stored -- the
// optimistic-lock rejection docs/backend-implementation.md §4 requires
// ("WHERE version=expectedVersion으로 검사"). It is distinct from
// ErrNotFound: a version mismatch means the row exists but has moved on, not
// that it is missing. It is also distinct from ErrDuplicate: §10 says
// "conflict는 자동 재시도 허가를 뜻하지 않으며 버전 불일치와 저장소 경합을
// 구분한다" -- a version race and a unique-key collision are both
// conflicts, but a caller may still want to tell them apart (e.g. only a
// version race is a candidate for the "redo whole preparation, at most
// three times" retry §4 describes for a clean rollback; a duplicate key
// means the row already exists and retrying the same write cannot help).
var ErrVersionConflict = errors.New("port: version conflict")

// ErrDuplicate is returned by an Insert-style method when a unique key it
// owns (e.g. certificates.der_sha256, key_deliveries.leaf_key_generation_id)
// already has a row, mirroring the DB unique-constraint violation the real
// adapter would report as a conflict error (docs/backend-implementation.md
// §8 "최초 관리자" race relies on exactly this signal).
var ErrDuplicate = errors.New("port: duplicate")

// ErrCommitUnknown is returned by UnitOfWork.Write (see unitofwork.go) when
// the commit outcome cannot be determined -- the caller must not release a
// result. It must classify to contract.ErrorKindCommitUnknown, never to
// ErrorKindConflict: §10 "commit_unknown means the commit outcome is
// undetermined; no result may be returned on this kind" is a strictly
// different situation from either sentinel above (the write may or may not
// have happened at all, as opposed to definitely having been rejected), so
// collapsing it into "conflict" would tell a caller it is safe to treat the
// prior state as authoritative when it is not.
var ErrCommitUnknown = errors.New("port: commit unknown")

// ClassifyStoreError maps a port-level store sentinel onto the
// contract.ErrorKind a service must return, without any string comparison
// (docs/backend-implementation.md §10). ok is false for an error this
// function does not recognize, so a caller falls back to its own
// domain-error mapping (e.g. contract.FromDomainError) instead of silently
// defaulting to one kind. errors.Is is used, so a wrapped sentinel (e.g.
// fmt.Errorf("save: %w", ErrVersionConflict)) still classifies correctly.
func ClassifyStoreError(err error) (contract.ErrorKind, bool) {
	switch {
	case errors.Is(err, ErrVersionConflict), errors.Is(err, ErrDuplicate):
		return contract.ErrorKindConflict, true
	case errors.Is(err, ErrCommitUnknown):
		return contract.ErrorKindCommitUnknown, true
	default:
		return "", false
	}
}
