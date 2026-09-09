package domain

import (
	"errors"
	"fmt"
)

// Policy errors returned by domain constructors and transitions. Services map
// these to application error kinds; the domain does not know HTTP or SQL.
var (
	// ErrInvalidValue marks a malformed or out-of-range input value.
	ErrInvalidValue = errors.New("invalid value")
	// ErrPolicyViolation marks an input that is well formed but not allowed
	// by product policy.
	ErrPolicyViolation = errors.New("policy violation")
	// ErrInvalidTransition marks a state change the current state forbids.
	ErrInvalidTransition = errors.New("invalid transition")
	// ErrExpired marks an object whose deadline has passed.
	ErrExpired = errors.New("expired")
	// ErrAlreadyConsumed marks a one-shot object that was already used.
	ErrAlreadyConsumed = errors.New("already consumed")
	// ErrConflict marks a value that contradicts an existing record and needs
	// an operator decision rather than an automatic overwrite.
	ErrConflict = errors.New("conflict")
	// ErrNotPermitted marks an operation the object's own state forbids, such
	// as issuing from a stopped authority.
	ErrNotPermitted = errors.New("not permitted")
)

// PolicyError carries a stable code and public detail fields alongside one of
// the sentinel errors above so adapters can render a response without
// exposing internal causes.
type PolicyError struct {
	Code   string
	Detail string
	base   error
	fields map[string]string
}

// NewPolicyError wraps base with a code and human readable detail.
func NewPolicyError(base error, code, detail string) *PolicyError {
	return &PolicyError{Code: code, Detail: detail, base: base}
}

// WithField attaches a public, non-secret detail field.
func (e *PolicyError) WithField(name, value string) *PolicyError {
	if e.fields == nil {
		e.fields = make(map[string]string)
	}
	e.fields[name] = value
	return e
}

// Fields returns a copy of the public detail fields.
func (e *PolicyError) Fields() map[string]string {
	if len(e.fields) == 0 {
		return nil
	}
	out := make(map[string]string, len(e.fields))
	for k, v := range e.fields {
		out[k] = v
	}
	return out
}

func (e *PolicyError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("%s: %v", e.Code, e.base)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Detail)
}

// Unwrap exposes the sentinel so errors.Is keeps working.
func (e *PolicyError) Unwrap() error { return e.base }
