package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

type hashInput struct {
	Name     string  `json:"name"`
	Optional *string `json:"optional,omitempty"`
}

func mustHash(t *testing.T, operation string, target map[string]string, input any) string {
	t.Helper()
	hash, err := InputHash(operation, target, input)
	if err != nil {
		t.Fatalf("input hash: %v", err)
	}
	return hash
}

func TestInputHashIsStableAcrossEqualInputs(t *testing.T) {
	first := mustHash(t, "issuance.issue", map[string]string{"authority_id": "a", "series_id": "b"}, hashInput{Name: "x"})
	second := mustHash(t, "issuance.issue", map[string]string{"series_id": "b", "authority_id": "a"}, hashInput{Name: "x"})
	if first != second {
		t.Fatal("hash depends on the order target keys were written in")
	}
}

func TestInputHashSeparatesOmittedFromExplicitOptional(t *testing.T) {
	empty := ""
	omitted := mustHash(t, "issuance.issue", nil, hashInput{Name: "x"})
	explicit := mustHash(t, "issuance.issue", nil, hashInput{Name: "x", Optional: &empty})
	if omitted == explicit {
		t.Fatal("an omitted optional hashed the same as an explicit empty value")
	}
}

func TestInputHashSeparatesOperationsAndTargets(t *testing.T) {
	base := mustHash(t, "issuance.issue", map[string]string{"id": "a"}, hashInput{Name: "x"})
	otherOp := mustHash(t, "issuance.renew", map[string]string{"id": "a"}, hashInput{Name: "x"})
	otherTarget := mustHash(t, "issuance.issue", map[string]string{"id": "b"}, hashInput{Name: "x"})
	otherInput := mustHash(t, "issuance.issue", map[string]string{"id": "a"}, hashInput{Name: "y"})
	for _, other := range []string{otherOp, otherTarget, otherInput} {
		if base == other {
			t.Fatal("two materially different requests share one hash")
		}
	}
}

func TestNormalizeInstantIsUTCMicroseconds(t *testing.T) {
	zone := time.FixedZone("KST", 9*60*60)
	at := domain.NewInstant(time.Date(2026, 9, 11, 21, 0, 0, 123456789, zone))
	if got, want := NormalizeInstant(at), "2026-09-11T12:00:00.123456Z"; got != want {
		t.Fatalf("normalized = %q, want %q", got, want)
	}
	if got := NormalizeInstant(domain.Instant{}); got != "" {
		t.Fatalf("zero instant normalized to %q, want empty", got)
	}
}

func testKey(actor string) port.OperationRequestKey {
	return port.OperationRequestKey{ActorKey: actor, Operation: "issuance.issue", RequestID: "44444444-4444-4444-8444-444444444444"}
}

type storedView struct {
	CertificateID string `json:"certificate_id"`
}

func TestReplayStoredResultReturnsTheStoredResultForTheSameInput(t *testing.T) {
	store := porttest.NewStore()
	key := testKey("account:a")
	hash := mustHash(t, "issuance.issue", nil, hashInput{Name: "x"})
	ctx := context.Background()

	if err := store.Write(ctx, func(tx port.TxStores) error {
		return StoreRequestResult(ctx, tx, key, hash, storedView{CertificateID: "cert-1"})
	}); err != nil {
		t.Fatalf("store result: %v", err)
	}

	var replayed storedView
	err := store.Read(ctx, func(tx port.TxStores) error {
		stored, found, err := ReplayStoredResult(ctx, tx, key, hash)
		if err != nil {
			return err
		}
		if !found {
			return errors.New("stored result was not found")
		}
		return DecodeStoredResult(stored, &replayed)
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replayed.CertificateID != "cert-1" {
		t.Fatalf("replayed = %+v", replayed)
	}
}

func TestReplayStoredResultRejectsTheSameKeyWithDifferentInput(t *testing.T) {
	store := porttest.NewStore()
	key := testKey("account:a")
	ctx := context.Background()
	if err := store.Write(ctx, func(tx port.TxStores) error {
		return StoreRequestResult(ctx, tx, key, mustHash(t, "issuance.issue", nil, hashInput{Name: "x"}), storedView{})
	}); err != nil {
		t.Fatalf("store result: %v", err)
	}

	err := store.Read(ctx, func(tx port.TxStores) error {
		_, _, replayErr := ReplayStoredResult(ctx, tx, key, mustHash(t, "issuance.issue", nil, hashInput{Name: "y"}))
		return replayErr
	})

	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindConflict {
		t.Fatalf("err = %v, want a conflict AppError", err)
	}
	if appErr.Code() != "idempotency_key_reused" {
		t.Fatalf("code = %q", appErr.Code())
	}
}

// A different actor reusing the same idempotency key must not see the first
// actor's result: actor_key is part of the lookup identity.
func TestReplayStoredResultIsScopedToTheActor(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()
	hash := mustHash(t, "issuance.issue", nil, hashInput{Name: "x"})
	if err := store.Write(ctx, func(tx port.TxStores) error {
		return StoreRequestResult(ctx, tx, testKey("account:a"), hash, storedView{CertificateID: "cert-1"})
	}); err != nil {
		t.Fatalf("store result: %v", err)
	}

	var found bool
	if err := store.Read(ctx, func(tx port.TxStores) error {
		_, ok, err := ReplayStoredResult(ctx, tx, testKey("account:b"), hash)
		found = ok
		return err
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if found {
		t.Fatal("one actor replayed another actor's stored result")
	}
}

func TestReplayStoredResultReportsNotFoundForAFreshKey(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()
	var found bool
	if err := store.Read(ctx, func(tx port.TxStores) error {
		_, ok, err := ReplayStoredResult(ctx, tx, testKey("account:a"), "abc")
		found = ok
		return err
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if found {
		t.Fatal("an empty store reported a stored result")
	}
}

func TestRunWithRetryRedoesAVersionRaceAtMostThreeTimes(t *testing.T) {
	attempts := 0
	err := RunWithRetry(context.Background(), func() error {
		attempts++
		return fmt.Errorf("save: %w", port.ErrVersionConflict)
	})
	if attempts != maxPreparationAttempts {
		t.Fatalf("attempts = %d, want %d", attempts, maxPreparationAttempts)
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindConflict {
		t.Fatalf("err = %v, want a conflict AppError", err)
	}
}

func TestRunWithRetryStopsAtTheFirstSuccess(t *testing.T) {
	attempts := 0
	err := RunWithRetry(context.Background(), func() error {
		attempts++
		if attempts == 1 {
			return fmt.Errorf("save: %w", port.ErrVersionConflict)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

// commit_unknown may already have applied the change, and a duplicate key
// cannot be resolved by repeating the write: neither is retried.
func TestRunWithRetryDoesNotRetryCommitUnknownOrDuplicate(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"commit unknown", port.ErrCommitUnknown},
		{"duplicate", port.ErrDuplicate},
		{"plain failure", errors.New("boom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempts := 0
			err := RunWithRetry(context.Background(), func() error {
				attempts++
				return tc.err
			})
			if attempts != 1 {
				t.Fatalf("attempts = %d, want 1", attempts)
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want the original error", err)
			}
		})
	}
}

func TestRunWithRetryStopsOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	attempts := 0
	err := RunWithRetry(ctx, func() error {
		attempts++
		return nil
	})
	if attempts != 0 {
		t.Fatalf("attempts = %d, want 0", attempts)
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindUnavailable {
		t.Fatalf("err = %v, want an unavailable AppError", err)
	}
}

func TestCommonDepsValidateNamesTheMissingDependency(t *testing.T) {
	deps := CommonDeps{UnitOfWork: porttest.NewStore(), ReadStore: porttest.NewStore()}
	err := deps.Validate()
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if got := appErr.PublicFields()["dependency"]; got != "Authorizer" {
		t.Fatalf("dependency = %q, want Authorizer", got)
	}
}

func TestActorKeySeparatesPrincipalKinds(t *testing.T) {
	anonymous := ActorKey(contract.Principal{})
	if anonymous != "anonymous" {
		t.Fatalf("anonymous actor key = %q", anonymous)
	}
}
