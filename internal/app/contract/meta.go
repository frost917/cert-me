// Package contract holds the command, result and query DTOs that cross the
// boundary into internal/app. Types here carry only external input fields plus
// the server-derived request metadata; they never embed storage rows and never
// let a client assert who it is.
package contract

import (
	"fmt"
	"log/slog"
	"net/netip"

	"cert-me/internal/domain"
)

// PrincipalKind separates the trust paths a request can arrive on. The zero
// value is anonymous, so a Principal that was never populated has no authority.
type PrincipalKind string

const (
	// PrincipalKindAnonymous is the pre-auth and token-only path. Download and
	// login requests use it; the real check is the grant hash or the credential.
	PrincipalKindAnonymous PrincipalKind = "anonymous"
	// PrincipalKindAdmin is a verified admin session. Only IdentityService
	// produces one, after it has validated the session inside a transaction.
	PrincipalKindAdmin PrincipalKind = "admin"
	// PrincipalKindInternal is runtime, worker or local-socket work. It is not
	// an all-powerful principal: it carries the operations it may perform.
	PrincipalKindInternal PrincipalKind = "internal"
)

// InternalOperation names a job an internal principal is allowed to run. The
// doc rule is that "system" is not blanket permission, so every internal
// principal is minted with an explicit allow list.
type InternalOperation string

const (
	InternalOperationCRLPublish       InternalOperation = "crl_publish"
	InternalOperationDeliveryExpiry   InternalOperation = "delivery_expiry"
	InternalOperationAuditPrune       InternalOperation = "audit_prune"
	InternalOperationTLSReconcile     InternalOperation = "tls_reconcile"
	InternalOperationTLSBootstrap     InternalOperation = "tls_bootstrap"
	InternalOperationSecretRotate     InternalOperation = "secret_rotate"
	InternalOperationRestoreFinalize  InternalOperation = "restore_finalize"
	InternalOperationTransferRecovery InternalOperation = "transfer_recovery"
	InternalOperationResetBegin       InternalOperation = "reset_begin"
)

// Validate rejects an operation outside the fixed set.
func (o InternalOperation) Validate() error {
	switch o {
	case InternalOperationCRLPublish, InternalOperationDeliveryExpiry,
		InternalOperationAuditPrune, InternalOperationTLSReconcile,
		InternalOperationTLSBootstrap, InternalOperationSecretRotate,
		InternalOperationRestoreFinalize, InternalOperationTransferRecovery,
		InternalOperationResetBegin:
		return nil
	default:
		return fmt.Errorf("%w: unsupported internal operation %q", domain.ErrInvalidValue, string(o))
	}
}

func (o InternalOperation) String() string { return string(o) }

// Principal is who the request acts as. Every field is unexported: the only
// ways to obtain a non-anonymous Principal are NewAdminPrincipal, which
// IdentityService calls after validating a session, and an
// InternalPrincipalFactory injected during assembly. It deliberately has no
// JSON decoding, so a request body can never claim admin.
type Principal struct {
	kind       PrincipalKind
	accountID  domain.AccountID
	sessionID  domain.SessionID
	authEpoch  domain.AuthEpoch
	operations []InternalOperation
}

// AdminPrincipalFacts is the validated session state a principal is minted
// from. IdentityService fills it from the account and session it just read.
type AdminPrincipalFacts struct {
	AccountID domain.AccountID
	SessionID domain.SessionID
	AuthEpoch domain.AuthEpoch
}

// NewAdminPrincipal mints an admin principal. It re-parses the identifiers so
// an unvalidated string cannot become an authenticated principal.
func NewAdminPrincipal(facts AdminPrincipalFacts) (Principal, error) {
	if _, err := domain.ParseAccountID(string(facts.AccountID)); err != nil {
		return Principal{}, err
	}
	if _, err := domain.ParseSessionID(string(facts.SessionID)); err != nil {
		return Principal{}, err
	}
	if _, err := domain.ParseAuthEpoch(facts.AuthEpoch.Int64()); err != nil {
		return Principal{}, err
	}
	return Principal{
		kind:      PrincipalKindAdmin,
		accountID: facts.AccountID,
		sessionID: facts.SessionID,
		authEpoch: facts.AuthEpoch,
	}, nil
}

// AnonymousPrincipal is the pre-auth and token-only principal.
func AnonymousPrincipal() Principal { return Principal{kind: PrincipalKindAnonymous} }

// InternalPrincipalFactory is the only source of internal principals. Assembly
// constructs one per internal caller with the operations that caller may run,
// so a worker cannot mint itself a principal for an operation it was not given.
type InternalPrincipalFactory struct {
	allowed []InternalOperation
}

// NewInternalPrincipalFactory requires at least one operation and rejects
// unknown ones, so an empty factory cannot act as a wildcard.
func NewInternalPrincipalFactory(allowed ...InternalOperation) (*InternalPrincipalFactory, error) {
	if len(allowed) == 0 {
		return nil, fmt.Errorf("%w: internal principal factory needs at least one operation", domain.ErrInvalidValue)
	}
	seen := make(map[InternalOperation]struct{}, len(allowed))
	list := make([]InternalOperation, 0, len(allowed))
	for _, op := range allowed {
		if err := op.Validate(); err != nil {
			return nil, err
		}
		if _, dup := seen[op]; dup {
			continue
		}
		seen[op] = struct{}{}
		list = append(list, op)
	}
	return &InternalPrincipalFactory{allowed: list}, nil
}

// Principal mints an internal principal for one of the factory's operations.
// Asking for an operation the factory was not given is an error, not a
// silently weaker principal.
func (f *InternalPrincipalFactory) Principal(op InternalOperation) (Principal, error) {
	if f == nil {
		return Principal{}, fmt.Errorf("%w: internal principal factory is not configured", domain.ErrInvalidValue)
	}
	for _, allowed := range f.allowed {
		if allowed == op {
			return Principal{kind: PrincipalKindInternal, operations: []InternalOperation{op}}, nil
		}
	}
	return Principal{}, fmt.Errorf("%w: internal principal may not perform %q", domain.ErrNotPermitted, string(op))
}

// Kind reports the trust path. A zero Principal reports anonymous.
func (p Principal) Kind() PrincipalKind {
	if p.kind == "" {
		return PrincipalKindAnonymous
	}
	return p.kind
}

func (p Principal) IsAdmin() bool { return p.Kind() == PrincipalKindAdmin }

func (p Principal) IsInternal() bool { return p.Kind() == PrincipalKindInternal }

func (p Principal) IsAnonymous() bool { return p.Kind() == PrincipalKindAnonymous }

// AccountID is empty unless the principal is an admin session.
func (p Principal) AccountID() domain.AccountID {
	if !p.IsAdmin() {
		return ""
	}
	return p.accountID
}

// SessionID is empty unless the principal is an admin session.
func (p Principal) SessionID() domain.SessionID {
	if !p.IsAdmin() {
		return ""
	}
	return p.sessionID
}

// AuthEpoch is the epoch the session was minted at. Services re-check it
// against the account inside the transaction.
func (p Principal) AuthEpoch() domain.AuthEpoch {
	if !p.IsAdmin() {
		return 0
	}
	return p.authEpoch
}

// Can reports whether an internal principal may run an operation. Admin and
// anonymous principals never satisfy an internal-operation check.
func (p Principal) Can(op InternalOperation) bool {
	if !p.IsInternal() {
		return false
	}
	for _, allowed := range p.operations {
		if allowed == op {
			return true
		}
	}
	return false
}

// Operations returns a copy so a caller cannot widen a principal in place.
func (p Principal) Operations() []InternalOperation {
	if len(p.operations) == 0 {
		return nil
	}
	out := make([]InternalOperation, len(p.operations))
	copy(out, p.operations)
	return out
}

// String renders the kind and identifiers only. There is no secret in a
// Principal, but audit and debug output stays uniform with the rest of the app.
func (p Principal) String() string {
	switch p.Kind() {
	case PrincipalKindAdmin:
		return fmt.Sprintf("Principal{admin account:%s session:%s}", string(p.accountID), string(p.sessionID))
	case PrincipalKindInternal:
		return fmt.Sprintf("Principal{internal ops:%v}", p.operations)
	default:
		return "Principal{anonymous}"
	}
}

// LogValue keeps structured logs to the same shape as String.
func (p Principal) LogValue() slog.Value {
	return slog.StringValue(p.String())
}

// MarshalJSON refuses: a principal is derived server-side and must never be
// round-tripped through a payload.
func (p Principal) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("%w: principal is not serializable", domain.ErrNotPermitted)
}

// UnmarshalJSON refuses so a request body cannot assert a principal.
func (p *Principal) UnmarshalJSON([]byte) error {
	return fmt.Errorf("%w: principal is not deserializable", domain.ErrNotPermitted)
}

// RequestMeta is the server-derived context of a read request.
type RequestMeta struct {
	Principal Principal
	RequestID string
	ClientIP  netip.Addr
}

// MutationMeta adds the optimistic-lock token and the idempotency key. Which
// methods require which field is fixed by the service method tables.
type MutationMeta struct {
	RequestMeta
	ExpectedVersion *domain.Version
	IdempotencyKey  string
}

// RequireExpectedVersion returns the caller's version or a conflict error when
// a method that needs If-Match did not get one.
func (m MutationMeta) RequireExpectedVersion() (domain.Version, error) {
	if m.ExpectedVersion == nil {
		return 0, NewAppError(ErrorKindConflict, "version_required", "this request requires the current version")
	}
	return *m.ExpectedVersion, nil
}

// RequireIdempotencyKey validates the key for a retryable method. The key is a
// UUID so two different clients cannot collide on a short string.
func (m MutationMeta) RequireIdempotencyKey() (string, error) {
	key, err := parseIdempotencyKey(m.IdempotencyKey)
	if err != nil {
		return "", NewAppError(ErrorKindValidation, "idempotency_key_invalid", "this request requires a UUID idempotency key")
	}
	return key, nil
}

// WithExpectedVersion is a helper for callers and tests that need to attach a
// version without taking the address of a loop variable by hand.
func WithExpectedVersion(v domain.Version) *domain.Version { return &v }
