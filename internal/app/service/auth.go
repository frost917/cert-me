package service

import (
	"context"
	"errors"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// SessionIdleTimeout is the project-wide idle window a session may sit
// unused before it expires (docs/architecture.md "세션은 유휴 1시간 또는
// 로그인 후 24시간 중 먼저 도달한 때 만료된다"). The absolute lifetime is
// carried on the session row itself; only the idle half needs a policy
// constant here.
var SessionIdleTimeout = domain.NewDuration(time.Hour)

// requireCurrentAuth re-checks, against stored rows, that the principal's
// authentication is still valid right now.
//
// docs/backend-implementation.md §2 requires this of every administrative
// change: "관리 서비스의 모든 변경은 현재 계정 상태·epoch ... 트랜잭션 안에서
// 다시 확인한다." An Authorizer call alone cannot do it -- port.Authorizer
// takes no TxStores, so it can only answer "may this kind of principal do
// this action", never "is this session still live". A request authenticated
// before a password reset, a deactivation or a logout was committed must not
// go through afterwards.
//
// It runs BEFORE the stored-result replay, in both the read-only probe and
// the Write, because §8's rule that a principal without current permission
// must not receive a stored result either ("현재 인증/권한이 없는 요청은
// 기존 결과도 받지 못한다") applies to authentication just as much as to
// authorization. An early replay that skipped this would be a way around it.
//
// The validation time is read from clock HERE, after the account and session
// rows are locked -- never carried in from the caller. A preparation
// timestamp is minutes old by the time a signature is produced and a lock is
// acquired, and validating against it lets a session that expired in that
// window through. The expiry boundary has to be the commit's own moment.
//
// Non-admin principals carry no session to check: an internal or anonymous
// principal is authenticated by the caller's own mechanism (an internal
// operation grant, a download token), not by an account row.
func requireCurrentAuth(ctx context.Context, tx port.TxStores, principal contract.Principal, clock port.Clock) error {
	if !principal.IsAdmin() {
		return nil
	}

	account, err := tx.Accounts().GetAccountForUpdate(ctx, principal.AccountID())
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindAuth, "account_not_found",
				"the account this session belongs to no longer exists")
		}
		return storeError(err, "account_read_failed", "could not read the account")
	}
	// The epoch the principal was minted under must still be current: a
	// reset or a forced logout advances it, which invalidates every session
	// issued before (docs/data-model.md accounts.auth_epoch).
	if account.AuthEpoch() != principal.AuthEpoch() {
		return contract.NewAppError(contract.ErrorKindAuth, "auth_epoch_superseded",
			"this session was issued under a superseded auth epoch")
	}

	session, err := tx.Accounts().GetSessionForUpdate(ctx, principal.SessionID())
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindAuth, "session_not_found",
				"this session no longer exists")
		}
		return storeError(err, "session_read_failed", "could not read the session")
	}
	// Read the clock only now, with both rows already locked: this is the
	// instant the commit is actually happening at.
	now := clock.Now()
	// ValidateAt owns the rest: session/account ownership, the account's
	// current state, the epoch again, and both expiry rules.
	if err := session.ValidateAt(now, SessionIdleTimeout, domain.SessionAccountFacts{
		AccountID: account.ID(),
		State:     account.State(),
		AuthEpoch: account.AuthEpoch(),
	}); err != nil {
		return authError(err)
	}
	return nil
}

// authError maps a session/account policy rejection onto an auth-kind
// AppError. contract.FromDomainError would classify these as forbidden or
// conflict; every one of them means "this credential is no longer good",
// which is auth, and an adapter maps that to 401 rather than 403.
func authError(err error) error {
	var policy *domain.PolicyError
	if errors.As(err, &policy) {
		return contract.WrapAppError(contract.ErrorKindAuth, policy.Code, policy.Detail, err)
	}
	return contract.WrapAppError(contract.ErrorKindAuth, "session_invalid", "this session is no longer valid", err)
}
