package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"cert-me/internal/domain"
)

const (
	testAccountID = "11111111-1111-4111-8111-111111111111"
	testSessionID = "22222222-2222-4222-8222-222222222222"
)

func mustAdminPrincipal(t *testing.T) Principal {
	t.Helper()
	p, err := NewAdminPrincipal(AdminPrincipalFacts{
		AccountID: domain.AccountID(testAccountID),
		SessionID: domain.SessionID(testSessionID),
		AuthEpoch: 7,
	})
	if err != nil {
		t.Fatalf("NewAdminPrincipal: %v", err)
	}
	return p
}

// The zero Principal must be anonymous. A struct that was never populated --
// because a handler forgot to set it, or a test built a RequestMeta by hand --
// must not read as an authenticated caller.
func TestPrincipal_ZeroValueIsAnonymous(t *testing.T) {
	var p Principal
	if !p.IsAnonymous() {
		t.Fatalf("zero principal is not anonymous: kind=%q", p.Kind())
	}
	if p.IsAdmin() || p.IsInternal() {
		t.Fatal("zero principal reports a privileged kind")
	}
	if p.AccountID() != "" || p.SessionID() != "" || p.AuthEpoch() != 0 {
		t.Fatal("zero principal exposes identity fields")
	}
	if p.Can(InternalOperationCRLPublish) {
		t.Fatal("zero principal satisfies an internal operation check")
	}
}

// A request body must never be able to assert who it is. This is the whole
// reason Principal's fields are unexported and it declares UnmarshalJSON.
func TestPrincipal_CannotBeDeserialized(t *testing.T) {
	var p Principal
	err := json.Unmarshal([]byte(`{"kind":"admin"}`), &p)
	if err == nil {
		t.Fatal("unmarshalling a principal succeeded")
	}
	if !errors.Is(err, domain.ErrNotPermitted) {
		t.Fatalf("want ErrNotPermitted, got %v", err)
	}
	if !p.IsAnonymous() {
		t.Fatal("a refused unmarshal still changed the principal")
	}
}

// Decoding a whole struct that embeds a Principal must fail too, so a
// command type can never smuggle one in through a nested field.
func TestPrincipal_NestedDecodeIsRefused(t *testing.T) {
	var meta struct {
		Principal Principal `json:"principal"`
	}
	if err := json.Unmarshal([]byte(`{"principal":{}}`), &meta); err == nil {
		t.Fatal("decoding a nested principal succeeded")
	}
}

func TestPrincipal_CannotBeSerialized(t *testing.T) {
	p := mustAdminPrincipal(t)
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("marshalling a principal succeeded")
	}
}

// An admin principal only exists after a session has been validated, so the
// constructor re-parses every identifier rather than trusting its caller.
func TestNewAdminPrincipal_RejectsUnvalidatedIdentifiers(t *testing.T) {
	tests := map[string]AdminPrincipalFacts{
		"bad account id": {AccountID: "not-a-uuid", SessionID: domain.SessionID(testSessionID)},
		"bad session id": {AccountID: domain.AccountID(testAccountID), SessionID: "not-a-uuid"},
		"empty":          {},
		"negative epoch": {
			AccountID: domain.AccountID(testAccountID),
			SessionID: domain.SessionID(testSessionID),
			AuthEpoch: -1,
		},
	}
	for name, facts := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := NewAdminPrincipal(facts)
			if err == nil {
				t.Fatal("constructed an admin principal from invalid facts")
			}
			if !p.IsAnonymous() {
				t.Fatal("a failed construction returned a privileged principal")
			}
		})
	}
}

// "system" is not blanket permission: a factory only mints principals for the
// operations it was assembled with.
func TestInternalPrincipalFactory_RefusesUnallowedOperation(t *testing.T) {
	factory, err := NewInternalPrincipalFactory(InternalOperationCRLPublish)
	if err != nil {
		t.Fatalf("NewInternalPrincipalFactory: %v", err)
	}
	p, err := factory.Principal(InternalOperationCRLPublish)
	if err != nil {
		t.Fatalf("allowed operation refused: %v", err)
	}
	if !p.Can(InternalOperationCRLPublish) {
		t.Fatal("minted principal cannot perform the operation it was minted for")
	}
	if p.Can(InternalOperationSecretRotate) {
		t.Fatal("principal can perform an operation it was never granted")
	}

	denied, err := factory.Principal(InternalOperationSecretRotate)
	if err == nil {
		t.Fatal("factory minted a principal for an operation it was not given")
	}
	if !errors.Is(err, domain.ErrNotPermitted) {
		t.Fatalf("want ErrNotPermitted, got %v", err)
	}
	if !denied.IsAnonymous() {
		t.Fatal("a refused mint returned a privileged principal")
	}
}

// An empty factory must not act as a wildcard, and a nil one must not mint.
func TestInternalPrincipalFactory_RejectsEmptyAndNil(t *testing.T) {
	if _, err := NewInternalPrincipalFactory(); err == nil {
		t.Fatal("built a factory with no operations")
	}
	if _, err := NewInternalPrincipalFactory("not-an-operation"); err == nil {
		t.Fatal("built a factory with an unknown operation")
	}
	var nilFactory *InternalPrincipalFactory
	if _, err := nilFactory.Principal(InternalOperationCRLPublish); err == nil {
		t.Fatal("a nil factory minted a principal")
	}
}

// Operations must be returned as a copy: a caller must not be able to widen a
// principal it already holds.
func TestPrincipal_OperationsCannotBeWidenedInPlace(t *testing.T) {
	factory, err := NewInternalPrincipalFactory(InternalOperationCRLPublish)
	if err != nil {
		t.Fatalf("NewInternalPrincipalFactory: %v", err)
	}
	p, err := factory.Principal(InternalOperationCRLPublish)
	if err != nil {
		t.Fatalf("Principal: %v", err)
	}
	ops := p.Operations()
	ops[0] = InternalOperationSecretRotate
	if p.Can(InternalOperationSecretRotate) {
		t.Fatal("mutating the returned slice widened the principal")
	}
	if !p.Can(InternalOperationCRLPublish) {
		t.Fatal("mutating the returned slice narrowed the principal")
	}
}

// An admin principal is not an internal one: Can must never be satisfied by
// an operator session, only by a purpose-built internal principal.
func TestPrincipal_AdminCannotPerformInternalOperations(t *testing.T) {
	p := mustAdminPrincipal(t)
	for _, op := range []InternalOperation{
		InternalOperationCRLPublish, InternalOperationSecretRotate, InternalOperationAuditPrune,
	} {
		if p.Can(op) {
			t.Fatalf("admin principal satisfies internal operation %q", op)
		}
	}
}

// Rendering a principal must not be a way to smuggle it into a log as data a
// later decoder could trust, and must stay stable between String and slog.
func TestPrincipal_RenderingIsStable(t *testing.T) {
	p := mustAdminPrincipal(t)
	got := fmt.Sprintf("%v", p)
	if !strings.Contains(got, "admin") {
		t.Fatalf("rendered principal does not name its kind: %q", got)
	}
	if p.LogValue().String() != p.String() {
		t.Fatalf("slog rendering %q differs from String %q", p.LogValue().String(), p.String())
	}
	_ = slog.StringValue(got)
}

// A method whose table entry requires If-Match must refuse to run without it,
// rather than defaulting to "whatever is stored now".
func TestMutationMeta_RequireExpectedVersion(t *testing.T) {
	var meta MutationMeta
	if _, err := meta.RequireExpectedVersion(); err == nil {
		t.Fatal("a missing expected version was accepted")
	} else if appErr, ok := AsAppError(err); !ok || appErr.Kind() != ErrorKindConflict {
		t.Fatalf("want a conflict AppError, got %v", err)
	}

	meta.ExpectedVersion = WithExpectedVersion(domain.Version(4))
	got, err := meta.RequireExpectedVersion()
	if err != nil {
		t.Fatalf("RequireExpectedVersion: %v", err)
	}
	if got != 4 {
		t.Fatalf("got version %d, want 4", got)
	}
}

// The idempotency key is a UUID so two clients cannot collide on a short
// string and replay each other's stored result.
func TestMutationMeta_RequireIdempotencyKey(t *testing.T) {
	tests := map[string]struct {
		key  string
		want bool
	}{
		"valid uuid":       {"33333333-3333-4333-8333-333333333333", true},
		"empty":            {"", false},
		"short string":     {"retry-1", false},
		"uppercase hex":    {"33333333-3333-4333-8333-33333333333A", false},
		"missing hyphens":  {"3333333333334333833333333333333f", false},
		"trailing garbage": {"33333333-3333-4333-8333-333333333333x", false},
		"non hex":          {"3333333g-3333-4333-8333-333333333333", false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			meta := MutationMeta{IdempotencyKey: tc.key}
			got, err := meta.RequireIdempotencyKey()
			if tc.want {
				if err != nil {
					t.Fatalf("valid key rejected: %v", err)
				}
				if got != tc.key {
					t.Fatalf("got %q, want %q", got, tc.key)
				}
				return
			}
			if err == nil {
				t.Fatalf("invalid key %q accepted", tc.key)
			}
			if appErr, ok := AsAppError(err); !ok || appErr.Kind() != ErrorKindValidation {
				t.Fatalf("want a validation AppError, got %v", err)
			}
		})
	}
}
