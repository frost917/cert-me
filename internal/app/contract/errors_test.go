package contract

import (
	"errors"
	"strings"
	"testing"

	"cert-me/internal/domain"
)

// The internal cause must never reach a rendered error string. A handler that
// logs err.Error(), or an adapter that puts it in a response body, must not be
// able to leak it, which is why AppError.Error deliberately omits it.
func TestAppError_ErrorNeverRendersCause(t *testing.T) {
	const sensitive = "connection to postgres://admin:hunter2@db:5432 failed"
	err := WrapAppError(ErrorKindConflict, "version_mismatch", "the record changed", errors.New(sensitive))

	rendered := err.Error()
	if strings.Contains(rendered, sensitive) {
		t.Fatalf("Error() leaked the cause: %q", rendered)
	}
	for _, want := range []string{"conflict", "version_mismatch", "the record changed"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("Error() %q is missing %q", rendered, want)
		}
	}
	// The cause is still reachable for server-side handling.
	if !errors.Is(err, err.Unwrap()) {
		t.Fatal("the cause is not reachable through errors.Is")
	}
}

// WithField must not mutate a shared error value in place: two requests that
// decorate the same base error must not see each other's fields.
func TestAppError_WithFieldDoesNotMutateTheReceiver(t *testing.T) {
	base := NewAppError(ErrorKindValidation, "invalid_request", "bad input")
	a := base.WithField("field", "name")
	b := base.WithField("field", "authority_id")

	if len(base.PublicFields()) != 0 {
		t.Fatalf("WithField mutated the base error: %v", base.PublicFields())
	}
	if a.PublicFields()["field"] != "name" {
		t.Fatalf("first copy lost its field: %v", a.PublicFields())
	}
	if b.PublicFields()["field"] != "authority_id" {
		t.Fatalf("second copy lost its field: %v", b.PublicFields())
	}
}

// PublicFields must hand back a copy so a caller cannot inject a field into an
// error that is on its way to a response.
func TestAppError_PublicFieldsIsACopy(t *testing.T) {
	err := NewAppError(ErrorKindValidation, "invalid_request", "bad input").WithField("field", "name")
	fields := err.PublicFields()
	fields["field"] = "tampered"
	fields["injected"] = "yes"

	if got := err.PublicFields(); got["field"] != "name" || len(got) != 1 {
		t.Fatalf("mutating the returned map changed the error: %v", got)
	}
}

// commit_unknown must never be presented as safely retryable: the work may
// already have happened, so a caller repeating it could duplicate it.
func TestAppError_OnlyUnavailableIsRetryable(t *testing.T) {
	tests := map[ErrorKind]bool{
		ErrorKindValidation:    false,
		ErrorKindAuth:          false,
		ErrorKindForbidden:     false,
		ErrorKindConflict:      false,
		ErrorKindUnavailable:   true,
		ErrorKindCommitUnknown: false,
	}
	for kind, want := range tests {
		t.Run(string(kind), func(t *testing.T) {
			if got := NewAppError(kind, "code", "detail").IsRetryable(); got != want {
				t.Fatalf("kind %q retryable=%v, want %v", kind, got, want)
			}
			if err := kind.Validate(); err != nil {
				t.Fatalf("declared kind %q failed Validate: %v", kind, err)
			}
		})
	}
	if err := ErrorKind("teapot").Validate(); err == nil {
		t.Fatal("an unknown error kind passed Validate")
	}
}

// A domain policy error must arrive at the adapter already classified, with
// its code, public fields and sentinel intact.
func TestFromDomainError_CarriesCodeFieldsAndSentinel(t *testing.T) {
	policyErr := domain.NewPolicyError(domain.ErrConflict, "version_mismatch", "the record changed").
		WithField("field", "version")

	appErr, ok := AsAppError(FromDomainError(policyErr))
	if !ok {
		t.Fatal("FromDomainError did not produce an AppError")
	}
	if appErr.Kind() != ErrorKindConflict {
		t.Fatalf("kind %q, want conflict", appErr.Kind())
	}
	if appErr.Code() != "version_mismatch" {
		t.Fatalf("code %q, want version_mismatch", appErr.Code())
	}
	if appErr.PublicFields()["field"] != "version" {
		t.Fatalf("fields %v lost the policy error's field", appErr.PublicFields())
	}
	if !errors.Is(appErr, domain.ErrConflict) {
		t.Fatal("the domain sentinel is not reachable through errors.Is")
	}
}

func TestFromDomainError_MapsNotPermittedToForbidden(t *testing.T) {
	appErr, ok := AsAppError(FromDomainError(domain.ErrNotPermitted))
	if !ok {
		t.Fatal("FromDomainError did not produce an AppError")
	}
	if appErr.Kind() != ErrorKindForbidden {
		t.Fatalf("kind %q, want forbidden", appErr.Kind())
	}
	if !errors.Is(appErr, domain.ErrNotPermitted) {
		t.Fatal("the sentinel is not reachable through errors.Is")
	}
}

// An error that is already an AppError must pass through unchanged rather than
// being re-wrapped as a generic validation failure.
func TestFromDomainError_PassesThroughAnExistingAppError(t *testing.T) {
	original := NewAppError(ErrorKindUnavailable, "busy", "try again")
	if got := FromDomainError(original); got != original {
		t.Fatalf("an existing AppError was re-wrapped: %v", got)
	}
}

// FromDomainError must return a genuinely nil error for a nil input. It
// returns the error interface rather than *AppError precisely so that
// `return FromDomainError(err)` from an error-returning Validate cannot box a
// nil pointer into a non-nil interface -- a trap that reports every valid
// command as invalid, and one a developer hit during B02.
func TestFromDomainError_NilIsATrulyNilError(t *testing.T) {
	if got := FromDomainError(nil); got != nil {
		t.Fatalf("FromDomainError(nil) returned a non-nil error: %#v", got)
	}

	boxed := func() error { return FromDomainError(nil) }()
	if boxed != nil {
		t.Fatalf("returning FromDomainError(nil) through an error boundary produced %#v", boxed)
	}
}
