package contract

import (
	"errors"
	"fmt"
	"strings"

	"cert-me/internal/domain"
)

// ErrorKind is the fixed classification an adapter maps to a status code or an
// exit code. The mapping itself lives in adapter/http and cmd, not here.
type ErrorKind string

const (
	// ErrorKindValidation is malformed or out-of-policy input.
	ErrorKindValidation ErrorKind = "validation"
	// ErrorKindAuth is a missing or rejected credential.
	ErrorKindAuth ErrorKind = "auth"
	// ErrorKindForbidden is an authenticated principal without permission.
	ErrorKindForbidden ErrorKind = "forbidden"
	// ErrorKindConflict covers version mismatch and store contention. It does
	// not by itself authorize an automatic retry.
	ErrorKindConflict ErrorKind = "conflict"
	// ErrorKindUnavailable is a temporary refusal, such as an admission
	// semaphore that did not free up within its wait budget.
	ErrorKindUnavailable ErrorKind = "unavailable"
	// ErrorKindCommitUnknown means the commit outcome is undetermined. No
	// result may be returned to the caller on this kind.
	ErrorKindCommitUnknown ErrorKind = "commit_unknown"
)

// Validate rejects a kind outside the fixed set.
func (k ErrorKind) Validate() error {
	switch k {
	case ErrorKindValidation, ErrorKindAuth, ErrorKindForbidden,
		ErrorKindConflict, ErrorKindUnavailable, ErrorKindCommitUnknown:
		return nil
	default:
		return fmt.Errorf("%w: unsupported error kind %q", domain.ErrInvalidValue, string(k))
	}
}

func (k ErrorKind) String() string { return string(k) }

// AppError is the error contract every service method returns. Code and
// PublicFields are safe to render to a client; cause is internal detail that
// is never included in a response body or a log line rendered from this value.
type AppError struct {
	kind   ErrorKind
	code   string
	detail string
	fields map[string]string
	cause  error
}

// NewAppError builds an error with no internal cause. detail is client-safe
// text; anything sensitive belongs in the cause instead.
func NewAppError(kind ErrorKind, code, detail string) *AppError {
	return &AppError{kind: kind, code: code, detail: detail}
}

// WrapAppError attaches an internal cause. The cause is reachable through
// errors.Is/As for server-side handling but never rendered by Error or Public.
func WrapAppError(kind ErrorKind, code, detail string, cause error) *AppError {
	return &AppError{kind: kind, code: code, detail: detail, cause: cause}
}

// WithField returns a copy carrying one more public field, so an existing
// error value is never mutated by a caller that shares it.
func (e *AppError) WithField(key, value string) *AppError {
	if e == nil {
		return nil
	}
	next := *e
	next.fields = make(map[string]string, len(e.fields)+1)
	for k, v := range e.fields {
		next.fields[k] = v
	}
	next.fields[key] = value
	return &next
}

func (e *AppError) Kind() ErrorKind { return e.kind }

func (e *AppError) Code() string { return e.code }

// Detail is the client-safe explanation.
func (e *AppError) Detail() string { return e.detail }

// PublicFields returns a copy of the client-safe fields.
func (e *AppError) PublicFields() map[string]string {
	if len(e.fields) == 0 {
		return nil
	}
	out := make(map[string]string, len(e.fields))
	for k, v := range e.fields {
		out[k] = v
	}
	return out
}

// Error renders kind, code and detail only. The internal cause is deliberately
// omitted so that a handler which logs err.Error() cannot leak it.
func (e *AppError) Error() string {
	var b strings.Builder
	b.WriteString(string(e.kind))
	b.WriteString(": ")
	b.WriteString(e.code)
	if e.detail != "" {
		b.WriteString(": ")
		b.WriteString(e.detail)
	}
	return b.String()
}

// Unwrap exposes the cause to errors.Is/As without rendering it.
func (e *AppError) Unwrap() error { return e.cause }

// IsRetryable reports whether the caller may safely repeat the request as-is.
// commit_unknown is not retryable: the work may already have happened.
func (e *AppError) IsRetryable() bool {
	return e != nil && e.kind == ErrorKindUnavailable
}

// AsAppError extracts an AppError from a chain.
func AsAppError(err error) (*AppError, bool) {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}

// FromDomainError maps a domain policy error onto the app error contract so a
// service does not have to classify each sentinel by hand. The domain error is
// kept as the cause and its code and fields are carried through when present.
//
// It returns error rather than *AppError on purpose. A helper returning a
// concrete pointer type turns `return FromDomainError(err)` in an
// error-returning Validate into a non-nil interface holding a nil pointer
// whenever err is nil, so every valid input would be reported as a failure.
// Returning the interface makes the nil case a genuine nil. Use AsAppError
// when you need the concrete value back, and NewAppError/WrapAppError when
// you want to keep decorating with WithField.
func FromDomainError(err error) error {
	if err == nil {
		return nil
	}
	if appErr, ok := AsAppError(err); ok {
		return appErr
	}
	kind := ErrorKindValidation
	switch {
	case errors.Is(err, domain.ErrConflict):
		kind = ErrorKindConflict
	case errors.Is(err, domain.ErrNotPermitted):
		kind = ErrorKindForbidden
	}
	code := "invalid_request"
	detail := ""
	var policyErr *domain.PolicyError
	if errors.As(err, &policyErr) {
		if policyErr.Code != "" {
			code = policyErr.Code
		}
		detail = policyErr.Detail
	}
	out := WrapAppError(kind, code, detail, err)
	if policyErr != nil {
		for k, v := range policyErr.Fields() {
			out = out.WithField(k, v)
		}
	}
	return out
}
