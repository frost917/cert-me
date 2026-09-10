package port

import (
	"testing"

	"cert-me/internal/domain"
)

func TestAuthorizationScope_AuthorityIDsIsACopy(t *testing.T) {
	id := domain.AuthorityID("11111111-1111-1111-1111-111111111111")
	scope := NewAuthorizationScope(id)

	ids := scope.AuthorityIDs()
	ids[0] = domain.AuthorityID("22222222-2222-2222-2222-222222222222")

	again := scope.AuthorityIDs()
	if again[0] != id {
		t.Fatalf("mutating a returned slice must not affect the scope: got %s, want %s", again[0], id)
	}
}

func TestAuthorizationScope_EmptyIsNil(t *testing.T) {
	scope := NewAuthorizationScope()
	if got := scope.AuthorityIDs(); got != nil {
		t.Fatalf("an empty scope must report a nil id list, got %v", got)
	}
}
