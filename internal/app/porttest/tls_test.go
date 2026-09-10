package porttest

import (
	"context"
	"testing"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

const tlsVersionID = "77777777-7777-4777-8777-777777777777"

func baseTLSVersion(t *testing.T) domain.TLSVersion {
	t.Helper()
	v, err := domain.NewTLSVersion(domain.TLSVersionFacts{
		ID:                  domain.TLSVersionID(tlsVersionID),
		Source:              domain.TLSSourceBootstrap,
		KeyMaterialID:       domain.KeyMaterialID(authID),
		LeafDER:             []byte("leaf"),
		ValidatedServiceURL: "",
		NotAfter:            instant(100000),
	})
	if err != nil {
		t.Fatalf("NewTLSVersion: %v", err)
	}
	return v
}

func baseTLSChange(t *testing.T, version domain.Version) domain.TLSChange {
	t.Helper()
	c, err := domain.NewTLSChange(domain.TLSChangeFacts{
		CandidateVersionID: domain.TLSVersionID(tlsVersionID),
		Phase:              domain.TLSChangePhaseCommitted,
		Validated:          true,
		Version:            version,
	})
	if err != nil {
		t.Fatalf("NewTLSChange: %v", err)
	}
	return c
}

// TestSetActive_GuardsInstallationVersionNotCandidateVersion is T1's
// reproduction. port.TLSRepository.SetActive's doc comment says plainly
// that expectedVersion "guards the installation row's own version, not the
// TLSChange's". Here the installation row sits at version 7 while the
// candidate TLSChange sits at version 1; calling SetActive with the
// installation's real version (7) must succeed, even though it does not
// match the candidate's version (1).
func TestSetActive_GuardsInstallationVersionNotCandidateVersion(t *testing.T) {
	repo := tlsRepo{s: newState()}
	instRepo := installationRepo{s: repo.s}
	ctx := context.Background()

	if err := repo.InsertVersion(ctx, baseTLSVersion(t)); err != nil {
		t.Fatalf("InsertVersion: %v", err)
	}
	if err := repo.SaveChange(ctx, baseTLSChange(t, 0), 0); err != nil {
		t.Fatalf("SaveChange: %v", err)
	}

	// Seed the installation row far ahead of the candidate's own version,
	// to prove SetActive must check the installation's version (7), not
	// the candidate's (1).
	installation := port.Installation{Version: 0}
	if err := instRepo.Save(ctx, installation, 0); err != nil {
		t.Fatalf("seed installation Save: %v", err)
	}
	for v := domain.Version(0); v < 7; v++ {
		cur, err := instRepo.GetForUpdate(ctx)
		if err != nil {
			t.Fatalf("GetForUpdate: %v", err)
		}
		expected := cur.Version
		cur.Version = cur.Version.Next()
		if err := instRepo.Save(ctx, cur, expected); err != nil {
			t.Fatalf("advance installation version: %v", err)
		}
	}
	cur, err := instRepo.GetForUpdate(ctx)
	if err != nil {
		t.Fatalf("GetForUpdate: %v", err)
	}
	if cur.Version != 7 {
		t.Fatalf("expected installation seeded at version 7, got %v", cur.Version)
	}

	// The candidate TLSChange is still at version 0 (never re-saved), so
	// passing the installation's real version (7) must NOT be rejected by
	// comparing against the candidate's version.
	if err := repo.SetActive(ctx, 7, domain.TLSVersionID(tlsVersionID)); err != nil {
		t.Fatalf("SetActive with correct installation version must succeed, got: %v", err)
	}

	after, err := instRepo.GetForUpdate(ctx)
	if err != nil {
		t.Fatalf("GetForUpdate after SetActive: %v", err)
	}
	if after.ActiveTLSVersionID != domain.TLSVersionID(tlsVersionID) {
		t.Fatalf("SetActive must move Installation.ActiveTLSVersionID, got %q", after.ActiveTLSVersionID)
	}
	if after.Version != 8 {
		t.Fatalf("SetActive must advance the installation's own version, got %v", after.Version)
	}
}

// TestSetActive_RejectsStaleInstallationVersion checks the other half of
// the same contract: a caller holding a stale installation version must be
// refused, even if it happens to match the candidate's version -- SetActive
// must not silently activate against an installation row that has moved on
// under it (this is the conflict case Activate's re-check exists to catch,
// docs/backend-implementation.md §9).
func TestSetActive_RejectsStaleInstallationVersion(t *testing.T) {
	repo := tlsRepo{s: newState()}
	instRepo := installationRepo{s: repo.s}
	ctx := context.Background()

	if err := repo.InsertVersion(ctx, baseTLSVersion(t)); err != nil {
		t.Fatalf("InsertVersion: %v", err)
	}
	if err := repo.SaveChange(ctx, baseTLSChange(t, 0), 0); err != nil {
		t.Fatalf("SaveChange: %v", err)
	}
	if err := instRepo.Save(ctx, port.Installation{Version: 0}, 0); err != nil {
		t.Fatalf("seed installation Save: %v", err)
	}
	// Someone else advances the installation row after the caller read it.
	seeded, err := instRepo.GetForUpdate(ctx)
	if err != nil {
		t.Fatalf("GetForUpdate: %v", err)
	}
	advanced := seeded
	advanced.Version = seeded.Version.Next()
	if err := instRepo.Save(ctx, advanced, seeded.Version); err != nil {
		t.Fatalf("advance installation: %v", err)
	}

	// Caller still holds the stale version (0); the candidate's own
	// version also happens to be 0, so a buggy candidate-version check
	// would wrongly let this through.
	err = repo.SetActive(ctx, 0, domain.TLSVersionID(tlsVersionID))
	if err != ErrVersionConflict {
		t.Fatalf("expected ErrVersionConflict for stale installation version, got %v", err)
	}

	unchanged, err := instRepo.GetForUpdate(ctx)
	if err != nil {
		t.Fatalf("GetForUpdate: %v", err)
	}
	if unchanged.ActiveTLSVersionID != "" {
		t.Fatalf("rejected SetActive must not move the active pointer, got %q", unchanged.ActiveTLSVersionID)
	}
}

// TestSetActive_RollbackOnFailingCallback exercises SetActive through the
// Store's Write/rollback path: Activate's sequence commits the pointer move
// and only then calls Installer.Apply (docs/backend-implementation.md §9),
// so a failing callback after SetActive must leave the installation's
// active pointer exactly where it was -- the copy-on-write rollback this
// package's Write implements (see state.go).
func TestSetActive_RollbackOnFailingCallback(t *testing.T) {
	store := NewStore()
	ctx := context.Background()

	if err := store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.TLS().InsertVersion(ctx, baseTLSVersion(t)); err != nil {
			return err
		}
		if err := tx.TLS().SaveChange(ctx, baseTLSChange(t, 0), 0); err != nil {
			return err
		}
		return tx.Installation().Save(ctx, port.Installation{Version: 0}, 0)
	}); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	sentinel := context.Canceled
	err := store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.TLS().SetActive(ctx, 0, domain.TLSVersionID(tlsVersionID)); err != nil {
			return err
		}
		return sentinel
	})
	if err != sentinel {
		t.Fatalf("expected the sentinel error to propagate, got %v", err)
	}

	var installation port.Installation
	if err := store.Read(ctx, func(tx port.TxStores) error {
		var readErr error
		installation, readErr = tx.Installation().GetForUpdate(ctx)
		return readErr
	}); err != nil {
		t.Fatalf("read after rollback: %v", err)
	}
	if installation.ActiveTLSVersionID != "" {
		t.Fatalf("a failing callback must roll back SetActive's pointer move, got %q", installation.ActiveTLSVersionID)
	}
	if installation.Version != 0 {
		t.Fatalf("a failing callback must roll back the installation's version bump, got %v", installation.Version)
	}
}
