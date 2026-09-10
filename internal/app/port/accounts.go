package port

import (
	"context"

	"cert-me/internal/domain"
)

// RateLimitRecord is the port-level projection of one auth_rate_limits row
// (docs/data-model.md "설치·관리자·인증"). There is no domain object for it
// because a rate-limit window is pure bookkeeping with no product policy of
// its own; the service decides thresholds and this is just where the
// resulting counters live.
type RateLimitRecord struct {
	Kind         string
	SubjectHash  domain.Fingerprint
	WindowStart  domain.Instant
	FailureCount int
	BlockedUntil domain.Instant
}

// AccountRepository is the storage boundary for administrator accounts,
// their sessions and password-reset tokens
// (docs/backend-implementation.md §4 table row "AccountRepository";
// docs/data-model.md "설치·관리자·인증").
//
// Every method here reads or writes a single row (or a small, explicitly
// keyed set of rows) through an already-validated domain.Account,
// domain.SessionState or domain.AdminResetToken. There is no method that
// patches an individual column: IdentityService/SetupService build the next
// object with Account.BeginReset/CompleteReset/etc. and hand the whole
// object to Save, so the store never has to guess which fields a caller
// meant to change (backend-implementation.md §4 "저장소는 정책 객체 대신
// row를 검증 없이 덮어쓰는 우회 메서드를 제공하지 않는다").
type AccountRepository interface {
	// GetAccountForUpdate locks and returns the account row. It returns
	// ErrNotFound if no such account exists. Callers needing to enforce
	// uniqueness of the normalized login name do so through InsertAccount's
	// own conflict error, not by pre-checking with this method.
	GetAccountForUpdate(ctx context.Context, id domain.AccountID) (domain.Account, error)

	// FindSessionByHash looks up a session by its token hash without
	// locking, for the fast "is this cookie even known" path before the
	// transaction that actually authenticates the request. It returns
	// ErrNotFound when the hash is unknown, expired sessions included: a
	// caller re-checks absolute_expires_at itself against the fresh row it
	// then reads under GetSessionForUpdate.
	FindSessionByHash(ctx context.Context, hash domain.TokenHash) (domain.SessionState, error)

	// GetSessionForUpdate locks and returns the session row so the caller
	// can re-validate auth_epoch and expiry inside the write transaction
	// before trusting the principal it derives from it.
	GetSessionForUpdate(ctx context.Context, sessionID domain.SessionID) (domain.SessionState, error)

	// InsertAccount creates the first row for a brand-new account. It
	// returns a conflict error if normalized_login_name is already taken;
	// SetupService.CreateAdmin relies on that to resolve the "two requests
	// both preparing the first admin" race (docs/backend-implementation.md
	// §8 "최초 관리자").
	InsertAccount(ctx context.Context, account domain.Account) error

	// SaveAccount persists account, checking WHERE version = expectedVersion
	// and writing account's own final Version() -- which may already be more
	// than expectedVersion+1 when a single request chained more than one
	// domain transition (docs/backend-implementation.md §5's "한 요청에서 두
	// 번 증가할 수 있다" rule, stated there for Revocation but the same
	// expectedVersion/finalVersion contract applies to every Save method in
	// this package). The store must never force finalVersion =
	// expectedVersion+1 itself.
	SaveAccount(ctx context.Context, account domain.Account, expectedVersion domain.Version) error

	// InsertSession creates a new session row at login.
	InsertSession(ctx context.Context, session domain.SessionState) error

	// DeleteSession removes one session row (logout). It is idempotent:
	// deleting an already-gone session is not an error, since a concurrent
	// logout/epoch-bump may have already removed it.
	DeleteSession(ctx context.Context, sessionID domain.SessionID) error

	// DeleteAllSessions removes every session for accountID. BeginReset and
	// CompleteReset both require this in the same commit as the account
	// state/epoch change (docs/data-model.md "비밀번호 재설정 시작"/"비밀번호
	// 변경 완료" rows); the domain object itself only signals
	// SessionsInvalidated=true and leaves the deletion to this method.
	DeleteAllSessions(ctx context.Context, accountID domain.AccountID) error

	// GetResetToken looks up a reset token by its hash. The caller is
	// expected to call this inside the same write transaction that will
	// consume the token (AdminResetToken.Consume re-checks state itself, but
	// the row must be read under the transaction's isolation to avoid a
	// double-spend race), even though the method name does not repeat
	// "ForUpdate" the way the row-lock methods above do.
	GetResetToken(ctx context.Context, tokenHash domain.TokenHash) (domain.AdminResetToken, error)

	// InsertResetToken stores a freshly issued reset token.
	InsertResetToken(ctx context.Context, token domain.AdminResetToken) error

	// InvalidateResetTokens invalidates every outstanding (unconsumed,
	// not-yet-invalidated) reset token for accountID as of now, used both by
	// a reissued reset link and by CompleteReset
	// (docs/architecture.md "재발급 시... 기존 미사용 재설정 링크를 모두
	// 무효화"). It is expressed as one bulk call because the caller does not
	// enumerate token IDs up front, but the implementation applies the same
	// AdminResetToken.Invalidate transition (idempotent, never touches a
	// consumed token) row by row rather than issuing a raw column overwrite.
	InvalidateResetTokens(ctx context.Context, accountID domain.AccountID, now domain.Instant) error

	// SaveRateLimit upserts one rate-limit window keyed by
	// (Kind, SubjectHash, WindowStart), matching the auth_rate_limits UQ.
	SaveRateLimit(ctx context.Context, record RateLimitRecord) error
}
