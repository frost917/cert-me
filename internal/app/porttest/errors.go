package porttest

import "cert-me/internal/app/port"

// ErrVersionConflict and ErrDuplicate used to be independent sentinels
// declared only in this test-only package, so a real service could not
// recognize a store's conflict/duplicate outcome (for retry logic or 409
// mapping, per docs/backend-implementation.md §10) without importing
// porttest or comparing error strings -- and a service must never import a
// test double. They are now the exact same values port.ErrVersionConflict
// and port.ErrDuplicate declare (see internal/app/port/errors.go), kept
// here as aliases only so every existing call site in this package
// (state.go, pki.go, jobs.go, tls.go, ...) that already names
// porttest.ErrVersionConflict/porttest.ErrDuplicate keeps compiling
// unchanged. Because these are the literal same error values, not wrapped
// copies, errors.Is(err, port.ErrVersionConflict) succeeds against a value
// returned as porttest.ErrVersionConflict with no extra unwrapping.
var (
	ErrVersionConflict = port.ErrVersionConflict
	ErrDuplicate       = port.ErrDuplicate
)
