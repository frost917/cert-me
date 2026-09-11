package porttest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

const (
	revID     = "11111111-1111-4111-8111-111111111111"
	certID    = "22222222-2222-4222-8222-222222222222"
	issuerID  = "33333333-3333-4333-8333-333333333333"
	authID    = "44444444-4444-4444-8444-444444444444"
	docID     = "55555555-5555-4555-8555-555555555555"
	altCertID = "66666666-6666-4666-8666-666666666666"
)

func instant(sec int64) domain.Instant { return domain.InstantFromUnixMicro(sec * 1_000_000) }

func serial(t *testing.T, hex string) domain.SerialNumber {
	t.Helper()
	s, err := domain.ParseSerialNumber(hex)
	if err != nil {
		t.Fatalf("ParseSerialNumber(%q): %v", hex, err)
	}
	return s
}

// baseRevocation is a stored revocation at version 1 with no certificate id,
// so a later Merge can fill one in and bump the version.
func baseRevocation(t *testing.T) domain.Revocation {
	t.Helper()
	rev, err := domain.NewRevocation(domain.RevocationFacts{
		ID:               domain.RevocationID(revID),
		IssuerID:         domain.CAKeyGenerationID(issuerID),
		Serial:           serial(t, "a1"),
		RevokedAt:        instant(1000),
		Reason:           domain.RevocationReasonSuperseded,
		Source:           domain.RevocationSourceManual,
		ChangeGeneration: 1,
		Version:          1,
	})
	if err != nil {
		t.Fatalf("NewRevocation: %v", err)
	}
	return rev
}

func seedRevocation(t *testing.T, store *Store) domain.Revocation {
	t.Helper()
	rev := baseRevocation(t)
	err := store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Revocations().Insert(context.Background(), rev)
	})
	if err != nil {
		t.Fatalf("seed insert: %v", err)
	}
	return rev
}

// A committed callback publishes its writes.
func TestWrite_CommitPublishes(t *testing.T) {
	store := NewStore()
	rev := seedRevocation(t, store)

	var got domain.Revocation
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		var readErr error
		got, readErr = tx.Revocations().FindForUpdate(context.Background(), rev.IssuerID(), rev.Serial())
		return readErr
	})
	if err != nil {
		t.Fatalf("read after commit: %v", err)
	}
	if got.ID() != rev.ID() {
		t.Fatalf("committed revocation not visible: got %q", got.ID())
	}
}

// A callback error must roll back EVERY repository it touched, including the
// writes that succeeded before the failing one. This is the B02 acceptance
// criterion, and it is the test a naive map mock that applies each method
// immediately cannot pass.
func TestWrite_CallbackErrorRollsBackEveryRepository(t *testing.T) {
	store := NewStore()
	sentinel := errors.New("callback failed")

	err := store.Write(context.Background(), func(tx port.TxStores) error {
		ctx := context.Background()
		if err := tx.Revocations().Insert(ctx, baseRevocation(t)); err != nil {
			return err
		}
		if err := tx.CRLs().InsertDocument(ctx, port.CRLDocument{
			ID:                domain.CRLDocumentID(docID),
			CAKeyGenerationID: domain.CAKeyGenerationID(issuerID),
			DER:               []byte("der"),
		}); err != nil {
			return err
		}
		if err := tx.Audit().Append(ctx, port.AuditEvent{Action: "revoke"}, nil); err != nil {
			return err
		}
		if err := tx.Jobs().UpsertDemand(ctx, "crl:"+issuerID, "crl_publish", 1, []byte("{}")); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write returned %v, want the callback's error", err)
	}

	readErr := store.Read(context.Background(), func(tx port.TxStores) error {
		ctx := context.Background()
		if _, err := tx.Revocations().FindForUpdate(ctx, domain.CAKeyGenerationID(issuerID), serial(t, "a1")); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("revocation survived rollback (err=%v)", err)
		}
		if _, err := tx.CRLs().GetDocument(ctx, domain.CRLDocumentID(docID)); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("crl document survived rollback (err=%v)", err)
		}
		jobs, err := tx.Jobs().ClaimDue(ctx, instant(2000), instant(2300), 10)
		if err != nil {
			return err
		}
		if len(jobs) != 0 {
			t.Errorf("job demand survived rollback: %d jobs", len(jobs))
		}
		return nil
	})
	if readErr != nil {
		t.Fatalf("read after rollback: %v", readErr)
	}
	if events := store.AuditEvents(); len(events) != 0 {
		t.Fatalf("audit events survived rollback: %d", len(events))
	}
}

// A panic must roll back and still reach the caller: the runtime error
// handler is what turns it into a failed request, so swallowing it here
// would hide a bug and leave the store half-written.
func TestWrite_PanicRollsBackAndRepanics(t *testing.T) {
	store := NewStore()

	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("the panic did not reach the caller")
			}
			if msg, ok := r.(string); !ok || msg != "boom" {
				t.Fatalf("recovered %v, want the original panic value", r)
			}
		}()
		_ = store.Write(context.Background(), func(tx port.TxStores) error {
			if err := tx.Revocations().Insert(context.Background(), baseRevocation(t)); err != nil {
				return err
			}
			panic("boom")
		})
	}()

	err := store.Read(context.Background(), func(tx port.TxStores) error {
		_, err := tx.Revocations().FindForUpdate(context.Background(), domain.CAKeyGenerationID(issuerID), serial(t, "a1"))
		if !errors.Is(err, port.ErrNotFound) {
			t.Errorf("the panicking transaction's write survived (err=%v)", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read after panic: %v", err)
	}

	// The store must still be usable: a panic must not leave the write mutex
	// held, which would deadlock the next transaction.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = store.Write(context.Background(), func(port.TxStores) error { return nil })
	}()
	<-done
}

// A stale expectedVersion must be rejected rather than silently overwriting
// a row that has moved on.
func TestSave_RejectsStaleExpectedVersion(t *testing.T) {
	store := NewStore()
	rev := seedRevocation(t, store)

	corrected, err := rev.Correct(domain.RevocationReasonKeyCompromise, instant(1500), "corrected", instant(2000))
	if err != nil {
		t.Fatalf("Correct: %v", err)
	}
	err = store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Revocations().Save(context.Background(), corrected, rev.Version())
	})
	if err != nil {
		t.Fatalf("first save: %v", err)
	}

	// A second writer that read the row before that commit still holds the
	// old version and must lose.
	err = store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Revocations().Save(context.Background(), corrected, rev.Version())
	})
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale save returned %v, want ErrVersionConflict", err)
	}
}

// A single request may bump a version more than once: applyRevocations
// merges and then stamps a generation. The store must check the FIRST read
// version and then persist the object's own final version -- a store that
// forced expectedVersion+1 would corrupt exactly this path
// (docs/backend-implementation.md §5).
func TestSave_StoresTheObjectsOwnFinalVersionAfterTwoBumps(t *testing.T) {
	store := NewStore()
	rev := seedRevocation(t, store)
	firstRead := rev.Version()

	merged, changed, err := rev.Merge(domain.RevocationFacts{
		IssuerID:      rev.IssuerID(),
		Serial:        rev.Serial(),
		CertificateID: domain.CertificateID(certID),
		RevokedAt:     rev.RevokedAt(),
		Reason:        domain.RevocationReasonSuperseded,
		Source:        domain.RevocationSourceCascade,
	})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if !changed {
		t.Fatal("Merge reported no change; the fixture no longer exercises a version bump")
	}
	stamped, err := merged.StampChangeGeneration(rev.ChangeGeneration() + 1)
	if err != nil {
		t.Fatalf("StampChangeGeneration: %v", err)
	}

	if stamped.Version() != firstRead+2 {
		t.Fatalf("fixture bumped the version %d times, want 2", stamped.Version()-firstRead)
	}

	err = store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Revocations().Save(context.Background(), stamped, firstRead)
	})
	if err != nil {
		t.Fatalf("save after two bumps: %v", err)
	}

	var stored domain.Revocation
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		var readErr error
		stored, readErr = tx.Revocations().FindForUpdate(context.Background(), rev.IssuerID(), rev.Serial())
		return readErr
	}); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.Version() != stamped.Version() {
		t.Fatalf("stored version %d, want the object's own final version %d (the store must not recompute it)",
			stored.Version(), stamped.Version())
	}
}

// A read is preparation input only: writes made through a Read callback must
// never be published, so a read can never smuggle a commit through.
func TestRead_NeverPublishes(t *testing.T) {
	store := NewStore()

	err := store.Read(context.Background(), func(tx port.TxStores) error {
		return tx.Revocations().Insert(context.Background(), baseRevocation(t))
	})
	if err != nil {
		t.Fatalf("read callback: %v", err)
	}

	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		_, err := tx.Revocations().FindForUpdate(context.Background(), domain.CAKeyGenerationID(issuerID), serial(t, "a1"))
		if !errors.Is(err, port.ErrNotFound) {
			t.Errorf("a write made inside Read was published (err=%v)", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("verification read: %v", err)
	}
}

// Concurrent transactions must not corrupt state, and a loser on the same
// row must fail rather than silently overwrite. Run under -race.
func TestWrite_ConcurrentTransactions(t *testing.T) {
	store := NewStore()
	rev := seedRevocation(t, store)
	firstRead := rev.Version()

	corrected, err := rev.Correct(domain.RevocationReasonKeyCompromise, instant(1500), "corrected", instant(2000))
	if err != nil {
		t.Fatalf("Correct: %v", err)
	}

	const writers = 8
	var wg sync.WaitGroup
	results := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- store.Write(context.Background(), func(tx port.TxStores) error {
				return tx.Revocations().Save(context.Background(), corrected, firstRead)
			})
		}()
	}
	wg.Wait()
	close(results)

	won, lost := 0, 0
	for err := range results {
		switch {
		case err == nil:
			won++
		case errors.Is(err, ErrVersionConflict):
			lost++
		default:
			t.Fatalf("unexpected error from a concurrent writer: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d writers committed the same expectedVersion, want exactly 1", won)
	}
	if lost != writers-1 {
		t.Fatalf("%d writers lost, want %d", lost, writers-1)
	}
}

// A caller holding a slice it passed in, or one it read back, must not be
// able to reach into stored state through it.
func TestStore_CopiesMutableValuesInAndOut(t *testing.T) {
	store := NewStore()
	payload := []byte("original")

	err := store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.CRLs().InsertDocument(context.Background(), port.CRLDocument{
			ID:                domain.CRLDocumentID(docID),
			CAKeyGenerationID: domain.CAKeyGenerationID(issuerID),
			DER:               payload,
		})
	})
	if err != nil {
		t.Fatalf("insert document: %v", err)
	}

	// Mutating the caller's slice after the write must not change the store.
	copy(payload, "tampered")

	var got port.CRLDocument
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		var readErr error
		got, readErr = tx.CRLs().GetDocument(context.Background(), domain.CRLDocumentID(docID))
		return readErr
	}); err != nil {
		t.Fatalf("get document: %v", err)
	}
	if string(got.DER) != "original" {
		t.Fatalf("stored DER changed with the caller's slice: %q", string(got.DER))
	}

	// Mutating the returned slice must not change the store either.
	copy(got.DER, "mutated!")
	var again port.CRLDocument
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		var readErr error
		again, readErr = tx.CRLs().GetDocument(context.Background(), domain.CRLDocumentID(docID))
		return readErr
	}); err != nil {
		t.Fatalf("second get: %v", err)
	}
	if string(again.DER) != "original" {
		t.Fatalf("stored DER changed through a returned slice: %q", string(again.DER))
	}
}

// An audit event's mutable detail map must be copied on the way in, so a
// caller that reuses its map for the next event cannot rewrite history.
func TestAudit_CopiesDetailFields(t *testing.T) {
	store := NewStore()
	fields := map[string]string{"target": "first"}

	err := store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Audit().Append(context.Background(), port.AuditEvent{
			Action:  "revoke",
			Details: contract.AuditDetails{SchemaVersion: 1, Fields: fields},
		}, []domain.AuthorityID{domain.AuthorityID(authID)})
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	fields["target"] = "second"

	events := store.AuditEvents()
	if len(events) != 1 {
		t.Fatalf("got %d audit events, want 1", len(events))
	}
	if events[0].Details.Fields["target"] != "first" {
		t.Fatalf("stored audit details changed with the caller's map: %q", events[0].Details.Fields["target"])
	}
}

// Sanity check that the double really is wired to every repository the
// TxStores contract names, so a service test cannot reach a nil accessor.
func TestTxStores_ExposesEveryRepository(t *testing.T) {
	store := NewStore()
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		checks := map[string]any{
			"Accounts": tx.Accounts(), "Installation": tx.Installation(), "PKI": tx.PKI(),
			"Delivery": tx.Delivery(), "Revocations": tx.Revocations(), "CRLs": tx.CRLs(),
			"Transitions": tx.Transitions(), "TLS": tx.TLS(), "Requests": tx.Requests(),
			"Secrets": tx.Secrets(), "Jobs": tx.Jobs(), "Audit": tx.Audit(),
		}
		var missing []string
		for name, repo := range checks {
			if repo == nil {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			t.Errorf("TxStores returned nil for: %s", strings.Join(missing, ", "))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
}
