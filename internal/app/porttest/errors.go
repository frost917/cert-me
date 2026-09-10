package porttest

import "errors"

// ErrVersionConflict is returned by every Save/SaveXxx method when the
// caller's expectedVersion does not match the row currently stored --
// the optimistic-lock rejection docs/backend-implementation.md §4 requires
// ("WHERE version=expectedVersion으로 검사"). It is distinct from
// port.ErrNotFound: a version mismatch means the row exists but has moved
// on, not that it is missing.
var ErrVersionConflict = errors.New("porttest: version conflict")

// ErrDuplicate is returned by an Insert-style method when a unique key it
// owns (e.g. certificates.der_sha256, key_deliveries.leaf_key_generation_id)
// already has a row, mirroring the DB unique-constraint violation the real
// adapter would report as a conflict error (docs/backend-implementation.md
// §8 "최초 관리자" race relies on exactly this signal).
var ErrDuplicate = errors.New("porttest: duplicate")
