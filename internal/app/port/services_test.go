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

// These four tests previously constructed EncodedBundle with a public Data
// []byte field directly. S1 replaced that field with a private secret.Input
// (see NewEncodedBundle/Use/Close in services.go); the tests below check the
// exact same behaviors -- Close zeroes and drops the plaintext, Close is
// idempotent, Close is safe on a zero value/nil receiver, and the original
// backing array is actually overwritten -- through the new API instead of a
// now-removed field. See secret_serialization_test.go for the additional
// no-plaintext-leak coverage S1 requires.

func TestEncodedBundle_CloseClosesThePayload(t *testing.T) {
	bundle := NewEncodedBundle([]byte{1, 2, 3, 4}, "application/x-pem-file")
	bundle.Close()

	if err := bundle.Use(func([]byte) error { return nil }); err == nil {
		t.Fatalf("Use after Close must fail")
	}
}

func TestEncodedBundle_CloseIsIdempotent(t *testing.T) {
	bundle := NewEncodedBundle([]byte{1, 2, 3, 4}, "")
	bundle.Close()
	bundle.Close() // must not panic on an already-closed bundle

	if err := bundle.Use(func([]byte) error { return nil }); err == nil {
		t.Fatalf("Use after a double Close must still fail")
	}
}

func TestEncodedBundle_CloseOnZeroValue(t *testing.T) {
	var bundle EncodedBundle
	bundle.Close() // must not panic on a zero value

	var nilBundle *EncodedBundle
	nilBundle.Close() // must not panic on a nil receiver

	if err := bundle.Use(func([]byte) error { return nil }); err == nil {
		t.Fatalf("Use on a zero-value bundle must fail, not run the callback")
	}
}

func TestEncodedBundle_CloseActuallyOverwritesBytes(t *testing.T) {
	data := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	bundle := NewEncodedBundle(data, "")
	bundle.Close()

	// The original backing array (still reachable via the pre-Close local
	// variable) must have been overwritten with zeros, not merely detached.
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: got %#x", i, b)
		}
	}
}

func TestAction_Validate(t *testing.T) {
	tests := []struct {
		name    string
		action  Action
		wantErr bool
	}{
		{"known action", ActionIssuanceIssue, false},
		{"another known action", ActionAuthorityDestroyKey, false},
		{"empty action", Action(""), true},
		{"typo of a known action", Action("Issuance.Issu"), true},
		{"invented action", Action("Issuance.SuperAdminOverride"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.action.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("Validate(%q): want error, got nil", tt.action)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate(%q): want nil, got %v", tt.action, err)
			}
		})
	}
}
