package port

import (
	"errors"
	"fmt"
	"testing"

	"cert-me/internal/app/contract"
)

// S3 (docs/backend-implementation.md §10: "AppError는 ... Kind(validation/
// auth/forbidden/conflict/unavailable/commit_unknown) ... conflict는 자동
// 재시도 허가를 뜻하지 않으며 버전 불일치와 저장소 경합을 구분한다"):
// version-conflict and duplicate-key contention must be expressible from
// port alone, without a service importing the porttest double, and
// commit_unknown must classify to a different contract.ErrorKind than
// either of them.

func TestStoreErrors_ClassifyWithoutImportingPortTest(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantKind contract.ErrorKind
	}{
		{"version conflict", ErrVersionConflict, contract.ErrorKindConflict},
		{"duplicate", ErrDuplicate, contract.ErrorKindConflict},
		{"commit unknown", ErrCommitUnknown, contract.ErrorKindCommitUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, ok := ClassifyStoreError(tt.err)
			if !ok {
				t.Fatalf("ClassifyStoreError(%v): want ok=true", tt.err)
			}
			if kind != tt.wantKind {
				t.Fatalf("ClassifyStoreError(%v): got kind %q, want %q", tt.err, kind, tt.wantKind)
			}
		})
	}

	// The three sentinels must remain individually distinguishable via
	// errors.Is even though two of them share a Kind -- a service that
	// needs to tell a version race apart from a unique-key collision (e.g.
	// to decide whether a retry of its own preparation is sensible) must
	// not be forced into string comparison to do so.
	if errors.Is(ErrVersionConflict, ErrDuplicate) {
		t.Fatalf("ErrVersionConflict and ErrDuplicate must not be the same sentinel")
	}
	if errors.Is(ErrVersionConflict, ErrCommitUnknown) || errors.Is(ErrDuplicate, ErrCommitUnknown) {
		t.Fatalf("ErrCommitUnknown must not collapse into the conflict sentinels")
	}

	if _, ok := ClassifyStoreError(errors.New("some unrelated error")); ok {
		t.Fatalf("ClassifyStoreError must return ok=false for an error it does not recognize")
	}
}

func TestStoreErrors_WrappedSentinelsStillClassify(t *testing.T) {
	wrapped := fmt.Errorf("save: %w", ErrVersionConflict)
	kind, ok := ClassifyStoreError(wrapped)
	if !ok || kind != contract.ErrorKindConflict {
		t.Fatalf("a wrapped ErrVersionConflict must still classify as conflict, got kind=%q ok=%v", kind, ok)
	}
}
