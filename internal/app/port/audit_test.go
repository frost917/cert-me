package port

import (
	"context"
	"reflect"
	"testing"

	"cert-me/internal/domain"
)

// TestAuditEvent_HasNoAuthorityIDsField pins the core fix for P1: the
// write-side AuditEvent type must not carry its own scope field, so scopes
// is the single source of truth Append's second argument decides.
func TestAuditEvent_HasNoAuthorityIDsField(t *testing.T) {
	typ := reflect.TypeOf(AuditEvent{})
	if _, ok := typ.FieldByName("AuthorityIDs"); ok {
		t.Fatalf("AuditEvent must not declare AuthorityIDs -- scopes is the only source of scope rows")
	}
}

// fakeAuditRepository is a minimal compile-time check that AuditRepository
// is satisfiable with the new Append(AuditEvent, []domain.AuthorityID)
// signature.
type fakeAuditRepository struct {
	gotEvent  AuditEvent
	gotScopes []domain.AuthorityID
}

func (f *fakeAuditRepository) Append(_ context.Context, event AuditEvent, scopes []domain.AuthorityID) error {
	f.gotEvent = event
	f.gotScopes = scopes
	return nil
}

func (f *fakeAuditRepository) DeleteBefore(_ context.Context, _ domain.Instant, _ int) (int, error) {
	return 0, nil
}

var _ AuditRepository = (*fakeAuditRepository)(nil)

func TestAuditRepository_AppendUsesScopesArgumentOnly(t *testing.T) {
	repo := &fakeAuditRepository{}
	scopes := []domain.AuthorityID{domain.AuthorityID("11111111-1111-1111-1111-111111111111")}

	if err := repo.Append(context.Background(), AuditEvent{ID: "evt-1"}, scopes); err != nil {
		t.Fatalf("Append returned error: %v", err)
	}
	if !reflect.DeepEqual(repo.gotScopes, scopes) {
		t.Fatalf("scopes not passed through: got %v, want %v", repo.gotScopes, scopes)
	}
	if repo.gotEvent.ID != "evt-1" {
		t.Fatalf("event not passed through: got %v", repo.gotEvent)
	}
}
