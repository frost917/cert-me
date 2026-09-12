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
// is satisfiable with the typed AuditScope signature.
type fakeAuditRepository struct {
	gotEvent AuditEvent
	gotScope AuditScope
}

func (f *fakeAuditRepository) Append(_ context.Context, event AuditEvent, scope AuditScope) error {
	f.gotEvent = event
	f.gotScope = scope
	return nil
}

func (f *fakeAuditRepository) DeleteBefore(_ context.Context, _ domain.Instant, _ int) (int, error) {
	return 0, nil
}

var _ AuditRepository = (*fakeAuditRepository)(nil)

func TestAuditRepository_AppendUsesScopesArgumentOnly(t *testing.T) {
	repo := &fakeAuditRepository{}
	scope := NewAuthoritiesAuditScope(domain.AuthorityID("11111111-1111-1111-1111-111111111111"))

	if err := repo.Append(context.Background(), AuditEvent{ID: "evt-1"}, scope); err != nil {
		t.Fatalf("Append returned error: %v", err)
	}
	if !reflect.DeepEqual(repo.gotScope.AuthorityIDs(), scope.AuthorityIDs()) {
		t.Fatalf("scope authorities not passed through: got %v, want %v", repo.gotScope.AuthorityIDs(), scope.AuthorityIDs())
	}
	if repo.gotScope.Kind() != AuditScopeAuthorities {
		t.Fatalf("scope kind = %q, want authorities", repo.gotScope.Kind())
	}
	if repo.gotEvent.ID != "evt-1" {
		t.Fatalf("event not passed through: got %v", repo.gotEvent)
	}
}

func TestAuditScope_InstallationIsExplicitAndAuthorityScopeIsNonEmpty(t *testing.T) {
	installation := NewInstallationAuditScope()
	if err := installation.Validate(); err != nil {
		t.Fatalf("installation scope invalid: %v", err)
	}
	if installation.Kind() != AuditScopeInstallation || len(installation.AuthorityIDs()) != 0 {
		t.Fatalf("unexpected installation scope: kind=%q ids=%v", installation.Kind(), installation.AuthorityIDs())
	}
	if err := NewAuthoritiesAuditScope().Validate(); err == nil {
		t.Fatal("empty authority scope accepted")
	}
	if err := (AuditScope{}).Validate(); err == nil {
		t.Fatal("zero audit scope accepted")
	}
}
