package domain

import "fmt"

// AuthorityKind names the management role of an authority. bootstrap is the
// internal cert-me HTTPS CA, which follows a different key-custody path than
// root/intermediate but shares the same management shape.
// [data-model.md §CA·인증서·갱신 계보: "kind=root/intermediate/bootstrap"]
type AuthorityKind string

const (
	AuthorityKindRoot         AuthorityKind = "root"
	AuthorityKindIntermediate AuthorityKind = "intermediate"
	AuthorityKindBootstrap    AuthorityKind = "bootstrap"
)

func (k AuthorityKind) Validate() error {
	switch k {
	case AuthorityKindRoot, AuthorityKindIntermediate, AuthorityKindBootstrap:
		return nil
	default:
		return fmt.Errorf("%w: unsupported authority kind %q", ErrInvalidValue, string(k))
	}
}

// IssuanceState controls whether an authority accepts new issuance/renewal
// requests. It is independent of the authority's own certificate validity
// and independent of CRL signing, which continues while stopped.
// [data-model.md: "issuance_state=inventory/enabled/stopped";
//
//	certificate-lifecycle.md §정상 CA 교체: "신규 발급 중지를 CA 폐기나 개인키
//	삭제로 처리하지 않는다"]
type IssuanceState string

const (
	// IssuanceStateInventory is a created-but-not-yet-activated authority
	// (e.g. a successor CA prepared ahead of a planned transition).
	IssuanceStateInventory IssuanceState = "inventory"
	IssuanceStateEnabled   IssuanceState = "enabled"
	IssuanceStateStopped   IssuanceState = "stopped"
)

func (s IssuanceState) Validate() error {
	switch s {
	case IssuanceStateInventory, IssuanceStateEnabled, IssuanceStateStopped:
		return nil
	default:
		return fmt.Errorf("%w: unsupported issuance state %q", ErrInvalidValue, string(s))
	}
}

// Authority is the management boundary for a CA key (a "management unit"),
// distinct from the cryptographic issuer chain. [data-model.md §핵심 관계:
// "authorities는 관리 권한의 경계이며 인증서의 암호학적 발급자와 다르다"]
type Authority struct {
	id                    AuthorityID
	kind                  AuthorityKind
	name                  string
	managementParentID    AuthorityID // empty for a root management unit
	issuanceState         IssuanceState
	issuanceCertificateID CertificateID // empty until the authority's own certificate is issued/attached
	keyGenerationID       CAKeyGenerationID
	keyAvailable          bool // false once the ca_key_generations key has been destroyed
	affected              bool // true when this authority carries an unresolved compromise/parent-impact flag
	pendingTakeover       bool // true for an imported CA awaiting explicit takeover confirmation
	certificateWindow     ValidityWindow
	archivedAt            Instant // zero if not archived
	version               Version
}

// AuthorityFacts is the constructor input for Authority.
type AuthorityFacts struct {
	ID                    AuthorityID
	Kind                  AuthorityKind
	Name                  string
	ManagementParentID    AuthorityID
	IssuanceState         IssuanceState
	IssuanceCertificateID CertificateID
	KeyGenerationID       CAKeyGenerationID
	KeyAvailable          bool
	Affected              bool
	PendingTakeover       bool
	CertificateWindow     ValidityWindow
	ArchivedAt            Instant
	Version               Version
}

const maxAuthorityNameLength = 255

// NewAuthority validates facts loaded from storage or produced by a prior
// command. It does not itself decide whether the authority may issue --
// that is CanIssue's job, evaluated against current facts at call time.
func NewAuthority(facts AuthorityFacts) (Authority, error) {
	if _, err := ParseAuthorityID(string(facts.ID)); err != nil {
		return Authority{}, err
	}
	if err := facts.Kind.Validate(); err != nil {
		return Authority{}, err
	}
	if facts.Name == "" || len(facts.Name) > maxAuthorityNameLength {
		return Authority{}, fmt.Errorf("%w: authority name must be 1..%d characters", ErrInvalidValue, maxAuthorityNameLength)
	}
	if facts.Kind == AuthorityKindIntermediate && facts.ManagementParentID == "" {
		return Authority{}, fmt.Errorf("%w: intermediate authority requires a management parent", ErrInvalidValue)
	}
	if facts.Kind == AuthorityKindRoot && facts.ManagementParentID != "" {
		return Authority{}, fmt.Errorf("%w: root authority must not have a management parent", ErrInvalidValue)
	}
	if err := facts.IssuanceState.Validate(); err != nil {
		return Authority{}, err
	}
	if _, err := ParseCAKeyGenerationID(string(facts.KeyGenerationID)); err != nil {
		return Authority{}, err
	}
	return Authority{
		id:                    facts.ID,
		kind:                  facts.Kind,
		name:                  facts.Name,
		managementParentID:    facts.ManagementParentID,
		issuanceState:         facts.IssuanceState,
		issuanceCertificateID: facts.IssuanceCertificateID,
		keyGenerationID:       facts.KeyGenerationID,
		keyAvailable:          facts.KeyAvailable,
		affected:              facts.Affected,
		pendingTakeover:       facts.PendingTakeover,
		certificateWindow:     facts.CertificateWindow,
		archivedAt:            facts.ArchivedAt,
		version:               facts.Version,
	}, nil
}

func (a Authority) ID() AuthorityID                      { return a.id }
func (a Authority) Kind() AuthorityKind                  { return a.kind }
func (a Authority) Name() string                         { return a.name }
func (a Authority) ManagementParentID() AuthorityID      { return a.managementParentID }
func (a Authority) IssuanceState() IssuanceState         { return a.issuanceState }
func (a Authority) IssuanceCertificateID() CertificateID { return a.issuanceCertificateID }
func (a Authority) KeyGenerationID() CAKeyGenerationID   { return a.keyGenerationID }
func (a Authority) KeyAvailable() bool                   { return a.keyAvailable }
func (a Authority) Affected() bool                       { return a.affected }
func (a Authority) PendingTakeover() bool                { return a.pendingTakeover }
func (a Authority) CertificateWindow() ValidityWindow    { return a.certificateWindow }
func (a Authority) Version() Version                     { return a.version }

func (a Authority) IsArchived() bool { return !a.archivedAt.IsZero() }

// IsExpired reports whether the authority's own signing certificate has
// passed its not_after under the project-wide now >= expires_at rule.
func (a Authority) IsExpired(now Instant) bool {
	if a.certificateWindow.IsZero() {
		return false
	}
	return a.certificateWindow.NotAfter().IsExpiredAt(now)
}

// IssuerContext carries the facts about the requested issuance that an
// Authority cannot know about itself: the exact period being requested (so
// CanIssue can enforce that the issuer's own window covers it) and whether a
// pending import takeover has been explicitly confirmed by an operator.
// [backend-implementation.md §2: "인증서·키·인수(takeover)·상위 영향 검사"]
type IssuerContext struct {
	RequestedWindow   ValidityWindow // zero value skips the period-covers check
	TakeoverConfirmed bool
}

// CanIssue reports whether the authority may sign a new certificate (initial
// issuance, renewal, or reissue) right now. It checks, in order: archival,
// issuance_state, key availability, compromise/parent-impact ("affected"),
// pending takeover confirmation, the authority's own certificate not being
// expired, and -- when a period is supplied -- that the authority's
// certificate window fully covers the requested one.
// [backend-implementation.md §2 Authority row; certificate-lifecycle.md
//
//	§유효기간과 계보: "하위 인증서 만료일은 발급 CA 만료일을 넘지 않는다";
//	§CA 키 유출 시 긴급 처리: affected blocks issuance;
//	planning.md: "신규 발급 중지 CA는 갱신을 포함한 발급을 거부"]
func (a Authority) CanIssue(ctx IssuerContext, now Instant) error {
	if a.IsArchived() {
		return fmt.Errorf("%w: authority is archived", ErrNotPermitted)
	}
	if a.issuanceState != IssuanceStateEnabled {
		return fmt.Errorf("%w: authority issuance state is %s", ErrNotPermitted, string(a.issuanceState))
	}
	if !a.keyAvailable {
		return fmt.Errorf("%w: authority signing key is not available", ErrNotPermitted)
	}
	if a.affected {
		return fmt.Errorf("%w: authority carries an unresolved compromise impact", ErrNotPermitted)
	}
	if a.pendingTakeover && !ctx.TakeoverConfirmed {
		return fmt.Errorf("%w: imported authority takeover is not confirmed", ErrNotPermitted)
	}
	if a.IsExpired(now) {
		return fmt.Errorf("%w: authority certificate has expired", ErrNotPermitted)
	}
	if !ctx.RequestedWindow.IsZero() && !a.certificateWindow.IsZero() && !a.certificateWindow.Covers(ctx.RequestedWindow) {
		return fmt.Errorf("%w: requested validity exceeds issuer certificate period", ErrPolicyViolation)
	}
	return nil
}

// CanSignCRL reports whether the authority may still sign/publish a CRL. CRL
// signing is deliberately independent of issuance_state: a stopped authority
// (mid normal CA transition) keeps publishing CRLs for its remaining
// certificates. [certificate-lifecycle.md §정상 CA 교체: "기존 CA는 남은
// 인증서의 폐기 처리와 CRL 발행을 유지한다"; §CA 종료와 보관]
func (a Authority) CanSignCRL(now Instant) error {
	if a.IsArchived() {
		return fmt.Errorf("%w: authority is archived", ErrNotPermitted)
	}
	if !a.keyAvailable {
		return fmt.Errorf("%w: authority signing key has been destroyed", ErrNotPermitted)
	}
	return nil
}

// StopIssuance returns a copy of the authority with issuance_state set to
// stopped, used for both a planned CA transition and the first step of an
// emergency compromise response. Stopping an authority that is not currently
// enabled is a no-op error: callers should not re-stop, and inventory
// authorities (never enabled) have nothing to stop.
func (a Authority) StopIssuance() (Authority, error) {
	if a.IsArchived() {
		return Authority{}, fmt.Errorf("%w: authority is archived", ErrInvalidTransition)
	}
	if a.issuanceState != IssuanceStateEnabled {
		return Authority{}, fmt.Errorf("%w: authority issuance state is already %s", ErrInvalidTransition, string(a.issuanceState))
	}
	next := a
	next.issuanceState = IssuanceStateStopped
	next.version = a.version.Next()
	return next, nil
}

// Enable returns a copy of the authority with issuance_state set to enabled,
// used to activate an inventory authority or resume a stopped one once its
// compromise/takeover conditions are cleared by the caller's own checks.
func (a Authority) Enable() (Authority, error) {
	if a.IsArchived() {
		return Authority{}, fmt.Errorf("%w: authority is archived", ErrInvalidTransition)
	}
	if a.issuanceState == IssuanceStateEnabled {
		return Authority{}, fmt.Errorf("%w: authority issuance state is already enabled", ErrInvalidTransition)
	}
	next := a
	next.issuanceState = IssuanceStateEnabled
	next.version = a.version.Next()
	return next, nil
}

// ClosureFacts are the externally verified conditions required before a CA
// signing key may be destroyed. cert-me never infers these from the
// Authority's own fields: they depend on every dependent certificate and CRL
// document, which the app layer gathers in one transaction.
// [certificate-lifecycle.md §CA 종료와 보관: "하위 인증서 만료·필요한 CRL 발행
//
//	완료·발급 중지 조건을 만족하면 전체 관리자가 명시적으로 파기할 수 있다"]
type ClosureFacts struct {
	AllDependentCertificatesExpired bool
	RequiredCRLsPublished           bool
}

// CanDestroyKey reports whether the authority's signing key may be
// permanently destroyed: issuance must already be stopped, every dependent
// certificate must have expired, the required CRLs (through the last
// dependent expiry) must be published, and the key must not already be
// destroyed.
func (a Authority) CanDestroyKey(facts ClosureFacts, now Instant) error {
	if a.IsArchived() {
		return fmt.Errorf("%w: authority is archived", ErrInvalidTransition)
	}
	if !a.keyAvailable {
		return fmt.Errorf("%w: authority signing key is already destroyed", ErrAlreadyConsumed)
	}
	if a.issuanceState == IssuanceStateEnabled {
		return fmt.Errorf("%w: authority must stop issuance before key destruction", ErrNotPermitted)
	}
	if !facts.AllDependentCertificatesExpired {
		return fmt.Errorf("%w: dependent certificates have not all expired", ErrNotPermitted)
	}
	if !facts.RequiredCRLsPublished {
		return fmt.Errorf("%w: required crl publications are not complete", ErrNotPermitted)
	}
	_ = now // reserved: a future grace-period check may compare against now
	return nil
}

// AuthorityPolicy is the subset of authority configuration an operator can
// change directly (currently just its display name; issuance state and key
// custody go through their own dedicated transitions).
type AuthorityPolicy struct {
	Name string
}

// Rename returns a copy of the authority with an updated name.
func (a Authority) Rename(policy AuthorityPolicy) (Authority, error) {
	if a.IsArchived() {
		return Authority{}, fmt.Errorf("%w: authority is archived", ErrInvalidTransition)
	}
	if policy.Name == "" || len(policy.Name) > maxAuthorityNameLength {
		return Authority{}, fmt.Errorf("%w: authority name must be 1..%d characters", ErrInvalidValue, maxAuthorityNameLength)
	}
	next := a
	next.name = policy.Name
	next.version = a.version.Next()
	return next, nil
}
