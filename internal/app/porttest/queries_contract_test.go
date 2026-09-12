package porttest

import (
	"context"
	"errors"
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// These tests pin the two properties port.QueryRepository's contract rests
// on and that a wrong implementation would still "pass" a naive test:
// the scope filter runs BEFORE paging, and the cursor is exclusive on a
// total order. A double that filtered a fetched page instead would return
// short pages and skip rows, and a service test built on it would then
// assert the wrong behaviour everywhere.

const (
	authAID = "a0000000-0000-4000-8000-000000000001"
	authBID = "a0000000-0000-4000-8000-000000000002"
	authCID = "a0000000-0000-4000-8000-000000000003"
)

func queryAuthority(t *testing.T, id domain.AuthorityID, name string) domain.Authority {
	t.Helper()
	a, err := domain.NewAuthority(domain.AuthorityFacts{
		ID:              id,
		Kind:            domain.AuthorityKindRoot,
		Name:            name,
		IssuanceState:   domain.IssuanceStateEnabled,
		KeyGenerationID: domain.CAKeyGenerationID(issuerID),
		KeyAvailable:    true,
		Version:         1,
	})
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	return a
}

// seedAuthorities stores three authorities, A < B < C by id.
func seedAuthorities(t *testing.T, store *Store) {
	t.Helper()
	ctx := context.Background()
	err := store.Write(ctx, func(tx port.TxStores) error {
		for _, a := range []domain.Authority{
			queryAuthority(t, domain.AuthorityID(authAID), "alpha"),
			queryAuthority(t, domain.AuthorityID(authBID), "bravo"),
			queryAuthority(t, domain.AuthorityID(authCID), "charlie"),
		} {
			if err := tx.PKI().InsertAuthority(ctx, a); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// TestQueryScopeAppliedBeforePaging is the regression this file exists for.
// With a limit of 2 and a scope that admits only A and C, a correct
// implementation returns both of them in ONE page. An implementation that
// paged first and filtered after would fetch {A,B}, drop B, and return a
// single-item page -- losing C entirely behind a cursor pointing past it.
func TestQueryScopeAppliedBeforePaging(t *testing.T) {
	store := NewStore()
	seedAuthorities(t, store)

	var page contract.Page[domain.Authority]
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		page, err = tx.Queries().ListAuthorities(context.Background(),
			contract.AuthorityListQuery{Page: contract.PageRequest{Limit: 2}},
			port.QueryScope{AuthorityIDs: []domain.AuthorityID{
				domain.AuthorityID(authAID), domain.AuthorityID(authCID),
			}})
		return err
	})
	if err != nil {
		t.Fatalf("ListAuthorities: %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("want 2 in-scope authorities in one page, got %d", len(page.Items))
	}
	if page.Items[0].ID() != domain.AuthorityID(authAID) || page.Items[1].ID() != domain.AuthorityID(authCID) {
		t.Fatalf("want A and C, got %q and %q", page.Items[0].ID(), page.Items[1].ID())
	}
	if page.NextCursor != nil {
		t.Fatalf("want an exhausted page, got cursor %q", *page.NextCursor)
	}
}

// TestQueryCursorIsExclusive walks every row one page at a time and checks
// that no row is repeated and none is skipped.
func TestQueryCursorIsExclusive(t *testing.T) {
	store := NewStore()
	seedAuthorities(t, store)
	ctx := context.Background()

	var seen []domain.AuthorityID
	cursor := ""
	for step := 0; step < 5; step++ {
		var page contract.Page[domain.Authority]
		err := store.Read(ctx, func(tx port.TxStores) error {
			var err error
			page, err = tx.Queries().ListAuthorities(ctx,
				contract.AuthorityListQuery{Page: contract.PageRequest{Limit: 1, Cursor: cursor}},
				port.QueryScope{All: true})
			return err
		})
		if err != nil {
			t.Fatalf("ListAuthorities: %v", err)
		}
		for _, a := range page.Items {
			seen = append(seen, a.ID())
		}
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}

	want := []domain.AuthorityID{
		domain.AuthorityID(authAID), domain.AuthorityID(authBID), domain.AuthorityID(authCID),
	}
	if len(seen) != len(want) {
		t.Fatalf("want %d rows across pages, got %d (%v)", len(want), len(seen), seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("row %d: want %q, got %q", i, want[i], seen[i])
		}
	}
}

// TestQueryGetOutOfScopeIsNotFound checks that an out-of-scope row is
// indistinguishable from a missing one, so a reader cannot probe for the
// existence of a range it may not see.
func TestQueryGetOutOfScopeIsNotFound(t *testing.T) {
	store := NewStore()
	seedAuthorities(t, store)
	ctx := context.Background()

	err := store.Read(ctx, func(tx port.TxStores) error {
		_, err := tx.Queries().GetAuthority(ctx, domain.AuthorityID(authBID),
			port.QueryScope{AuthorityIDs: []domain.AuthorityID{domain.AuthorityID(authAID)}})
		return err
	})
	if !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("want ErrNotFound for an out-of-scope authority, got %v", err)
	}
}

// TestQueryAuditRequiresEveryScope pins §14.6's rule that a multi-scope
// audit event requires permission on ALL of its scopes, and that an event
// stored with no scopes at all is not a wildcard.
func TestQueryAuditRequiresEveryScope(t *testing.T) {
	store := NewStore()
	ctx := context.Background()

	event := func(id string) port.AuditEvent {
		return port.AuditEvent{
			ID:         id,
			OccurredAt: instant(1000),
			ActorKind:  contract.AuditActorAccount,
			Action:     "Test.Action",
			Result:     contract.AuditResultSuccess,
			Details:    contract.AuditDetails{SchemaVersion: 1},
		}
	}
	err := store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.Audit().Append(ctx, event("evt-1"), port.NewAuthoritiesAuditScope(domain.AuthorityID(authAID))); err != nil {
			return err
		}
		if err := tx.Audit().Append(ctx, event("evt-2"), port.NewAuthoritiesAuditScope(
			domain.AuthorityID(authAID), domain.AuthorityID(authBID),
		)); err != nil {
			return err
		}
		return tx.Audit().Append(ctx, event("evt-3"), port.NewInstallationAuditScope())
	})
	if err != nil {
		t.Fatalf("seed audit: %v", err)
	}

	var page contract.Page[contract.AuditEventView]
	err = store.Read(ctx, func(tx port.TxStores) error {
		var err error
		page, err = tx.Queries().ListAudit(ctx, contract.AuditListQuery{Page: contract.PageRequest{Limit: 50}},
			port.QueryScope{AuthorityIDs: []domain.AuthorityID{domain.AuthorityID(authAID)}})
		return err
	})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	// evt-2 needs B as well, evt-3 carries no scope at all: only evt-1 is
	// visible to a reader holding A.
	if len(page.Items) != 1 || page.Items[0].ID != "evt-1" {
		ids := make([]string, 0, len(page.Items))
		for _, e := range page.Items {
			ids = append(ids, e.ID)
		}
		t.Fatalf("want only evt-1 visible to a reader holding A, got %v", ids)
	}
}
