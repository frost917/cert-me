// This file implements the identity slice of B01: administrator accounts,
// server-side sessions, and the CLI-driven password reset policy. See
// docs/architecture.md ("관리자 비밀번호 복구") and docs/planning.md for the
// product rules and docs/data-model.md for the accounts/sessions/
// password_reset_tokens columns these objects mirror.
package domain

import (
	"strings"
	"time"
)

// AuthEpoch is a per-account counter. Every session and reset token carries
// the epoch that was current when it was issued; a mismatch against the
// account's current epoch means the credential predates a reset and is no
// longer honored, without having to enumerate and delete it individually.
type AuthEpoch int64

// ParseAuthEpoch rejects negative values.
func ParseAuthEpoch(raw int64) (AuthEpoch, error) {
	if raw < 0 {
		return 0, NewPolicyError(ErrInvalidValue, "invalid_auth_epoch", "auth epoch must not be negative")
	}
	return AuthEpoch(raw), nil
}

// Next returns the epoch a reset (begin or complete) must advance to.
func (e AuthEpoch) Next() AuthEpoch { return e + 1 }

func (e AuthEpoch) Int64() int64 { return int64(e) }

// AccountState mirrors the accounts.state column.
type AccountState string

const (
	// AccountStateActive can log in normally.
	AccountStateActive AccountState = "active"
	// AccountStateResetPending was put into a CLI-driven reset: general
	// login and all prior sessions are blocked until the reset completes.
	AccountStateResetPending AccountState = "reset_pending"
	// AccountStateDisabled cannot log in and is not eligible for the
	// self-service CLI reset flow (an operator must re-enable it first;
	// that transition is out of this file's scope).
	AccountStateDisabled AccountState = "disabled"
)

func (s AccountState) Validate() error {
	switch s {
	case AccountStateActive, AccountStateResetPending, AccountStateDisabled:
		return nil
	default:
		return NewPolicyError(ErrInvalidValue, "invalid_account_state", "unsupported account state").
			WithField("state", string(s))
	}
}

func (s AccountState) String() string { return string(s) }

// PasswordHash is an opaque Argon2id encoded hash (parameters embedded in the
// encoded string, per docs/data-model.md). The domain never sees or handles
// plaintext passwords; adapters hash/verify and hand the domain only this
// value.
type PasswordHash struct {
	encoded string
}

// NewPasswordHash wraps an already-encoded hash. It does not verify the
// encoding is a valid Argon2id string; that belongs to the hashing adapter.
func NewPasswordHash(encoded string) (PasswordHash, error) {
	if strings.TrimSpace(encoded) == "" {
		return PasswordHash{}, NewPolicyError(ErrInvalidValue, "invalid_password_hash", "password hash must not be empty")
	}
	return PasswordHash{encoded: encoded}, nil
}

// Encoded returns the storable hash string. Callers must not log it; use
// String() for anything that might reach a log or error message.
func (h PasswordHash) Encoded() string { return h.encoded }

func (h PasswordHash) IsZero() bool { return h.encoded == "" }

func (h PasswordHash) Equal(other PasswordHash) bool { return h.encoded == other.encoded }

// String is redacted: a password hash is a credential, not a diagnostic value.
func (h PasswordHash) String() string { return "<password hash>" }

// Account is the domain projection of one accounts row. All fields are
// immutable; state/epoch transitions return a new Account rather than
// mutating the receiver, per docs/backend-implementation.md §2.
type Account struct {
	id                  AccountID
	normalizedLoginName string
	passwordHash        PasswordHash
	state               AccountState
	authEpoch           AuthEpoch
	isGlobalAdmin       bool
	version             Version
}

// NormalizeLoginName is the single canonical transform from a login name as
// typed to the value stored in accounts.normalized_login_name (data-model.md).
// Both the uniqueness check on account creation and the lookup on login must
// go through it: if the two paths normalized differently, a case variant would
// either create a duplicate account or fail to log in, silently.
//
// The transform is ASCII lowercasing after trimming surrounding whitespace.
// That is sufficient and total here because the login-name charset is
// restricted to [A-Za-z0-9._-] by the OpenAPI Credentials schema, so there is
// no Unicode case-folding or normalization form to consider. data-model.md
// also requires identifier comparison to carry plain byte-comparison meaning
// rather than relying on a database collation, which is what a Go-side
// deterministic transform gives.
func NormalizeLoginName(raw string) string {
	trimmed := strings.TrimSpace(raw)
	out := []byte(trimmed)
	for i := 0; i < len(out); i++ {
		if out[i] >= 'A' && out[i] <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}

// AccountFacts is the constructor input for rehydrating an Account from
// storage. It carries every field the row-level invariants below need.
type AccountFacts struct {
	ID                  AccountID
	NormalizedLoginName string
	PasswordHash        PasswordHash
	State               AccountState
	AuthEpoch           AuthEpoch
	IsGlobalAdmin       bool
	Version             Version
}

// NewAccount validates and constructs an Account. It does not enforce
// cross-row uniqueness (normalized_login_name UQ); storage owns that.
func NewAccount(facts AccountFacts) (Account, error) {
	if _, err := ParseAccountID(string(facts.ID)); err != nil {
		return Account{}, err
	}
	if strings.TrimSpace(facts.NormalizedLoginName) == "" {
		return Account{}, NewPolicyError(ErrInvalidValue, "invalid_login_name", "normalized login name must not be empty")
	}
	// Reject a value that is not already canonical. Storing a non-normalized
	// name would defeat the normalized_login_name uniqueness constraint and
	// make a later lookup by the same name miss.
	if facts.NormalizedLoginName != NormalizeLoginName(facts.NormalizedLoginName) {
		return Account{}, NewPolicyError(ErrInvalidValue, "login_name_not_normalized",
			"normalized login name must already be normalized with NormalizeLoginName")
	}
	if facts.PasswordHash.IsZero() {
		return Account{}, NewPolicyError(ErrInvalidValue, "invalid_password_hash", "account must have a password hash")
	}
	if err := facts.State.Validate(); err != nil {
		return Account{}, err
	}
	return Account{
		id:                  facts.ID,
		normalizedLoginName: facts.NormalizedLoginName,
		passwordHash:        facts.PasswordHash,
		state:               facts.State,
		authEpoch:           facts.AuthEpoch,
		isGlobalAdmin:       facts.IsGlobalAdmin,
		version:             facts.Version,
	}, nil
}

func (a Account) ID() AccountID { return a.id }

func (a Account) NormalizedLoginName() string { return a.normalizedLoginName }

func (a Account) PasswordHash() PasswordHash { return a.passwordHash }

func (a Account) State() AccountState { return a.state }

func (a Account) AuthEpoch() AuthEpoch { return a.authEpoch }

func (a Account) IsGlobalAdmin() bool { return a.isGlobalAdmin }

func (a Account) Version() Version { return a.version }

// CanLogin reports whether a login attempt (correct password already
// verified by the caller) may proceed. reset_pending blocks login for as
// long as the account remains pending, independent of whether any reset
// link has since expired (docs/architecture.md: "링크 만료만으로 로그인
// 차단을 해제하지 않는다").
func (a Account) CanLogin() error {
	switch a.state {
	case AccountStateActive:
		return nil
	case AccountStateResetPending:
		return NewPolicyError(ErrNotPermitted, "account_reset_pending", "account is pending a password reset").
			WithField("account_id", string(a.id))
	case AccountStateDisabled:
		return NewPolicyError(ErrNotPermitted, "account_disabled", "account is disabled").
			WithField("account_id", string(a.id))
	default:
		return NewPolicyError(ErrInvalidValue, "invalid_account_state", "unsupported account state")
	}
}

// AccountResetOutcome is the result of a state/epoch transition on an
// Account. SessionsInvalidated signals that the caller's transaction must
// also delete every session row for this account; the domain does not
// reach into storage to do that itself (docs/backend-implementation.md §2:
// "세션 전체 삭제는 같은 트랜잭션의 서비스 책임").
type AccountResetOutcome struct {
	Account             Account
	SessionsInvalidated bool
}

// BeginReset moves the account into reset_pending and advances auth_epoch,
// which is what blocks general login and invalidates every existing
// session and credential issued under the old epoch (docs/architecture.md,
// docs/data-model.md "비밀번호 재설정 시작" row). It is called once per CLI
// reset invocation; calling it again while already reset_pending is the
// reissue path and is allowed, advancing the epoch again so any
// outstanding, unconsumed reset token is likewise orphaned by epoch
// mismatch (the caller separately invalidates it via
// AdminResetToken.Invalidate, per docs/architecture.md "재발급 시... 기존
// 미사용 재설정 링크를 모두 무효화").
func (a Account) BeginReset() (AccountResetOutcome, error) {
	if a.state == AccountStateDisabled {
		return AccountResetOutcome{}, NewPolicyError(ErrInvalidTransition, "account_disabled", "cannot begin a reset for a disabled account").
			WithField("account_id", string(a.id))
	}
	next := a
	next.state = AccountStateResetPending
	next.authEpoch = a.authEpoch.Next()
	// The account row changes, so the optimistic lock must move with it.
	// auth_epoch invalidating credentials and version detecting a concurrent
	// write are separate concerns, and SaveAccount(account, expectedVersion)
	// needs the latter to reject a stale writer.
	next.version = a.version.Next()
	return AccountResetOutcome{Account: next, SessionsInvalidated: true}, nil
}

// CompleteReset applies a new password hash, returns the account to active,
// and advances auth_epoch again so the reset token and every session
// (including any created between BeginReset and now, which is why the
// token/epoch check in AdminResetToken.CanConsume matters) are invalidated.
// The account must currently be reset_pending; this mirrors
// docs/data-model.md's "비밀번호 변경 완료" row, which only fires from that
// state.
func (a Account) CompleteReset(hash PasswordHash) (AccountResetOutcome, error) {
	if a.state != AccountStateResetPending {
		return AccountResetOutcome{}, NewPolicyError(ErrInvalidTransition, "account_not_reset_pending", "account is not pending a password reset").
			WithField("account_id", string(a.id))
	}
	if hash.IsZero() {
		return AccountResetOutcome{}, NewPolicyError(ErrInvalidValue, "invalid_password_hash", "completed reset requires a new password hash")
	}
	next := a
	next.state = AccountStateActive
	next.passwordHash = hash
	next.authEpoch = a.authEpoch.Next()
	next.version = a.version.Next()
	return AccountResetOutcome{Account: next, SessionsInvalidated: true}, nil
}

// SessionState is the domain projection of one sessions row. The cookie's
// plaintext token never reaches the domain; only its TokenHash does.
type SessionState struct {
	id                SessionID
	accountID         AccountID
	tokenHash         TokenHash
	authEpoch         AuthEpoch
	lastSeenAt        Instant
	absoluteExpiresAt Instant
}

// SessionStateFacts is the constructor input for rehydrating a SessionState.
type SessionStateFacts struct {
	ID                SessionID
	AccountID         AccountID
	TokenHash         TokenHash
	AuthEpoch         AuthEpoch
	LastSeenAt        Instant
	AbsoluteExpiresAt Instant
}

// NewSessionState validates and constructs a SessionState.
func NewSessionState(facts SessionStateFacts) (SessionState, error) {
	if _, err := ParseSessionID(string(facts.ID)); err != nil {
		return SessionState{}, err
	}
	if _, err := ParseAccountID(string(facts.AccountID)); err != nil {
		return SessionState{}, err
	}
	if facts.TokenHash.IsZero() {
		return SessionState{}, NewPolicyError(ErrInvalidValue, "invalid_session_token_hash", "session must have a token hash")
	}
	if facts.LastSeenAt.IsZero() {
		return SessionState{}, NewPolicyError(ErrInvalidValue, "invalid_session_last_seen", "session must have a last seen time")
	}
	if facts.AbsoluteExpiresAt.IsZero() {
		return SessionState{}, NewPolicyError(ErrInvalidValue, "invalid_session_absolute_expiry", "session must have an absolute expiry")
	}
	if facts.AbsoluteExpiresAt.Before(facts.LastSeenAt) {
		// absolute_expires_at is set once at login and never moves; it must
		// not precede the session's own last-seen watermark.
		return SessionState{}, NewPolicyError(ErrInvalidValue, "invalid_session_absolute_expiry", "absolute expiry must not be before last seen")
	}
	return SessionState{
		id:                facts.ID,
		accountID:         facts.AccountID,
		tokenHash:         facts.TokenHash,
		authEpoch:         facts.AuthEpoch,
		lastSeenAt:        facts.LastSeenAt,
		absoluteExpiresAt: facts.AbsoluteExpiresAt,
	}, nil
}

func (s SessionState) ID() SessionID { return s.id }

func (s SessionState) AccountID() AccountID { return s.accountID }

func (s SessionState) TokenHash() TokenHash { return s.tokenHash }

func (s SessionState) AuthEpoch() AuthEpoch { return s.authEpoch }

func (s SessionState) LastSeenAt() Instant { return s.lastSeenAt }

func (s SessionState) AbsoluteExpiresAt() Instant { return s.absoluteExpiresAt }

// SessionAccountFacts is the fresh, same-transaction account state a
// SessionState is checked against. The session cannot know these facts
// from its own fields, per docs/backend-implementation.md §2 ("객체는
// 자기 필드만으로 알 수 없는 사실을 DB에서 직접 찾지 않는다").
type SessionAccountFacts struct {
	AccountID AccountID
	State     AccountState
	AuthEpoch AuthEpoch
}

// ValidateAt checks the session against both of its expiry rules (idle and
// absolute, per docs/data-model.md's sessions row) and the account's
// current state/epoch (docs/backend-implementation.md §2: "관리 서비스의
// 모든 변경은 현재 계정 상태·epoch... 트랜잭션 안에서 다시 확인한다").
// Expiry uses the project-wide now >= expires_at rule via Instant.IsExpiredAt.
func (s SessionState) ValidateAt(now Instant, idleTimeout Duration, account SessionAccountFacts) error {
	if account.AccountID != s.accountID {
		return NewPolicyError(ErrConflict, "session_account_mismatch", "session does not belong to the given account").
			WithField("session_id", string(s.id))
	}
	if account.State != AccountStateActive {
		return NewPolicyError(ErrNotPermitted, "account_not_active", "account is not active").
			WithField("account_id", string(s.accountID))
	}
	if account.AuthEpoch != s.authEpoch {
		return NewPolicyError(ErrConflict, "session_epoch_mismatch", "session was issued under a superseded auth epoch").
			WithField("session_id", string(s.id))
	}
	idleDeadline := s.lastSeenAt.Add(idleTimeout)
	if idleDeadline.IsExpiredAt(now) {
		return NewPolicyError(ErrExpired, "session_idle_expired", "session idle timeout has elapsed").
			WithField("session_id", string(s.id))
	}
	if s.absoluteExpiresAt.IsExpiredAt(now) {
		return NewPolicyError(ErrExpired, "session_absolute_expired", "session absolute lifetime has elapsed").
			WithField("session_id", string(s.id))
	}
	return nil
}

// Touch returns a copy of the session with last_seen_at advanced to now.
// Callers must call ValidateAt first; Touch does not re-check expiry so
// that a single validated request can extend idle life exactly once.
func (s SessionState) Touch(now Instant) SessionState {
	next := s
	next.lastSeenAt = now
	return next
}

// SessionPolicy bundles the two session lifetime rules from
// docs/planning.md ("세션은 유휴 1시간 또는 로그인 후 24시간 중 먼저 도달한
// 때 만료된다"). It is not a stored row; the service reads it from
// configuration and passes the resulting values into SessionState.
type SessionPolicy struct {
	idleTimeout      Duration
	absoluteLifetime Duration
}

// NewSessionPolicy validates both spans are positive.
func NewSessionPolicy(idleTimeout, absoluteLifetime Duration) (SessionPolicy, error) {
	if !idleTimeout.IsPositive() {
		return SessionPolicy{}, NewPolicyError(ErrInvalidValue, "invalid_session_idle_timeout", "session idle timeout must be positive")
	}
	if !absoluteLifetime.IsPositive() {
		return SessionPolicy{}, NewPolicyError(ErrInvalidValue, "invalid_session_absolute_lifetime", "session absolute lifetime must be positive")
	}
	return SessionPolicy{idleTimeout: idleTimeout, absoluteLifetime: absoluteLifetime}, nil
}

// DefaultSessionPolicy returns the product default: 1 hour idle, 24 hours
// absolute, per docs/planning.md.
func DefaultSessionPolicy() SessionPolicy {
	p, err := NewSessionPolicy(NewDuration(time.Hour), NewDuration(24*time.Hour))
	if err != nil {
		// Unreachable: the literals above are always positive.
		panic(err)
	}
	return p
}

func (p SessionPolicy) IdleTimeout() Duration { return p.idleTimeout }

func (p SessionPolicy) AbsoluteLifetime() Duration { return p.absoluteLifetime }

// AbsoluteExpiresAt computes the fixed absolute deadline for a session
// created at loginAt. It is called once at login; the stored value never
// moves afterward.
func (p SessionPolicy) AbsoluteExpiresAt(loginAt Instant) Instant {
	return loginAt.Add(p.absoluteLifetime)
}

// ResetPolicy carries the CLI password reset link's validity window
// (docs/architecture.md/docs/planning.md: "재설정 링크의 유효기간은 발급 후
// 3시간이다").
type ResetPolicy struct {
	linkValidity Duration
}

// NewResetPolicy validates the link validity is positive.
func NewResetPolicy(linkValidity Duration) (ResetPolicy, error) {
	if !linkValidity.IsPositive() {
		return ResetPolicy{}, NewPolicyError(ErrInvalidValue, "invalid_reset_link_validity", "reset link validity must be positive")
	}
	return ResetPolicy{linkValidity: linkValidity}, nil
}

// DefaultResetPolicy returns the product default: 3 hours.
func DefaultResetPolicy() ResetPolicy {
	p, err := NewResetPolicy(NewDuration(3 * time.Hour))
	if err != nil {
		// Unreachable: the literal above is always positive.
		panic(err)
	}
	return p
}

func (p ResetPolicy) LinkValidity() Duration { return p.linkValidity }

// ExpiresAt computes the fixed deadline for a link issued at issuedAt. Like
// SessionPolicy.AbsoluteExpiresAt, this is only ever computed once, at
// issuance; the stored expires_at never moves, and expiring does not by
// itself lift the account's login block.
func (p ResetPolicy) ExpiresAt(issuedAt Instant) Instant {
	return issuedAt.Add(p.linkValidity)
}

// AdminResetToken is the domain projection of one password_reset_tokens
// row: the CLI-issued, one-time link an operator hands to an administrator
// to complete a password reset (docs/architecture.md "관리자 비밀번호
// 복구").
type AdminResetToken struct {
	id            ResetTokenID
	accountID     AccountID
	tokenHash     TokenHash
	authEpoch     AuthEpoch
	issuedAt      Instant
	expiresAt     Instant
	consumedAt    Instant
	invalidatedAt Instant
}

// AdminResetTokenFacts is the constructor input for rehydrating an
// AdminResetToken from storage. ConsumedAt/InvalidatedAt are zero Instants
// when not yet set, matching the nullable storage columns.
type AdminResetTokenFacts struct {
	ID            ResetTokenID
	AccountID     AccountID
	TokenHash     TokenHash
	AuthEpoch     AuthEpoch
	IssuedAt      Instant
	ExpiresAt     Instant
	ConsumedAt    Instant
	InvalidatedAt Instant
}

// NewAdminResetToken validates and constructs an AdminResetToken.
func NewAdminResetToken(facts AdminResetTokenFacts) (AdminResetToken, error) {
	if _, err := ParseResetTokenID(string(facts.ID)); err != nil {
		return AdminResetToken{}, err
	}
	if _, err := ParseAccountID(string(facts.AccountID)); err != nil {
		return AdminResetToken{}, err
	}
	if facts.TokenHash.IsZero() {
		return AdminResetToken{}, NewPolicyError(ErrInvalidValue, "invalid_reset_token_hash", "reset token must have a token hash")
	}
	if facts.IssuedAt.IsZero() {
		return AdminResetToken{}, NewPolicyError(ErrInvalidValue, "invalid_reset_token_issued_at", "reset token must have an issued time")
	}
	if facts.ExpiresAt.IsZero() || !facts.ExpiresAt.After(facts.IssuedAt) {
		return AdminResetToken{}, NewPolicyError(ErrInvalidValue, "invalid_reset_token_expiry", "reset token expiry must be after it was issued")
	}
	return AdminResetToken{
		id:            facts.ID,
		accountID:     facts.AccountID,
		tokenHash:     facts.TokenHash,
		authEpoch:     facts.AuthEpoch,
		issuedAt:      facts.IssuedAt,
		expiresAt:     facts.ExpiresAt,
		consumedAt:    facts.ConsumedAt,
		invalidatedAt: facts.InvalidatedAt,
	}, nil
}

// IssueAdminResetToken builds a freshly issued token (consumed_at and
// invalidated_at unset) using policy to compute the expiry from now. id and
// tokenHash are generated/hashed by the caller; the domain never sees the
// plaintext link.
func IssueAdminResetToken(id ResetTokenID, accountID AccountID, tokenHash TokenHash, authEpoch AuthEpoch, now Instant, policy ResetPolicy) (AdminResetToken, error) {
	return NewAdminResetToken(AdminResetTokenFacts{
		ID:        id,
		AccountID: accountID,
		TokenHash: tokenHash,
		AuthEpoch: authEpoch,
		IssuedAt:  now,
		ExpiresAt: policy.ExpiresAt(now),
	})
}

func (t AdminResetToken) ID() ResetTokenID { return t.id }

func (t AdminResetToken) AccountID() AccountID { return t.accountID }

func (t AdminResetToken) TokenHash() TokenHash { return t.tokenHash }

func (t AdminResetToken) AuthEpoch() AuthEpoch { return t.authEpoch }

func (t AdminResetToken) IssuedAt() Instant { return t.issuedAt }

func (t AdminResetToken) ExpiresAt() Instant { return t.expiresAt }

func (t AdminResetToken) ConsumedAt() Instant { return t.consumedAt }

func (t AdminResetToken) InvalidatedAt() Instant { return t.invalidatedAt }

func (t AdminResetToken) IsConsumed() bool { return !t.consumedAt.IsZero() }

func (t AdminResetToken) IsInvalidated() bool { return !t.invalidatedAt.IsZero() }

// IsExpiredAt is a pure inspection: looking a link up (e.g. to render a
// "this link has expired" page) never consumes it, per
// docs/architecture.md ("단순 링크 조회로... 토큰을 소비하지 않으며").
func (t AdminResetToken) IsExpiredAt(now Instant) bool { return t.expiresAt.IsExpiredAt(now) }

// ResetTokenAccountFacts is the fresh, same-transaction account state a
// token consumption is checked against.
type ResetTokenAccountFacts struct {
	AccountID AccountID
	State     AccountState
	AuthEpoch AuthEpoch
}

// CanConsume reports whether the token may be spent right now: it must be
// unconsumed, not invalidated (e.g. by a reissue), not expired, still
// pointed at the account it was issued for, issued under the account's
// current auth epoch (a stale epoch means a later BeginReset/CompleteReset
// has already superseded it), and the account must still be reset_pending.
func (t AdminResetToken) CanConsume(now Instant, account ResetTokenAccountFacts) error {
	if t.IsConsumed() {
		return NewPolicyError(ErrAlreadyConsumed, "reset_token_consumed", "reset token has already been used").
			WithField("reset_token_id", string(t.id))
	}
	if t.IsInvalidated() {
		return NewPolicyError(ErrNotPermitted, "reset_token_invalidated", "reset token has been superseded").
			WithField("reset_token_id", string(t.id))
	}
	if t.IsExpiredAt(now) {
		return NewPolicyError(ErrExpired, "reset_token_expired", "reset token has expired").
			WithField("reset_token_id", string(t.id))
	}
	if account.AccountID != t.accountID {
		return NewPolicyError(ErrConflict, "reset_token_account_mismatch", "reset token does not belong to the given account").
			WithField("reset_token_id", string(t.id))
	}
	if account.AuthEpoch != t.authEpoch {
		return NewPolicyError(ErrConflict, "reset_token_epoch_mismatch", "reset token was issued under a superseded auth epoch").
			WithField("reset_token_id", string(t.id))
	}
	if account.State != AccountStateResetPending {
		return NewPolicyError(ErrNotPermitted, "account_not_reset_pending", "account is not pending a password reset").
			WithField("account_id", string(account.AccountID))
	}
	return nil
}

// Consume marks the token spent. It re-checks CanConsume so a caller that
// forgets the separate check still cannot double-spend or use a stale
// token. It is the only method that sets consumed_at; a plain lookup never
// calls it.
func (t AdminResetToken) Consume(now Instant, account ResetTokenAccountFacts) (AdminResetToken, error) {
	if err := t.CanConsume(now, account); err != nil {
		return AdminResetToken{}, err
	}
	next := t
	next.consumedAt = now
	return next, nil
}

// Invalidate marks the token unusable without consuming it, used when a
// reissue supersedes an existing unused link (docs/architecture.md:
// "재발급 시 해당 계정의 기존 미사용 재설정 링크를 모두 무효화").
func (t AdminResetToken) Invalidate(now Instant) (AdminResetToken, error) {
	if t.IsConsumed() {
		return AdminResetToken{}, NewPolicyError(ErrInvalidTransition, "reset_token_consumed", "cannot invalidate an already consumed reset token").
			WithField("reset_token_id", string(t.id))
	}
	if t.IsInvalidated() {
		// Idempotent: invalidating an already-invalidated token is a no-op.
		return t, nil
	}
	next := t
	next.invalidatedAt = now
	return next, nil
}
