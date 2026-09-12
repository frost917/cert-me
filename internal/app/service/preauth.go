// preauth.go is the shared credential-checking path for the operations that
// run BEFORE a session exists: SetupService.CreateAdmin, IdentityService.Login
// and IdentityService.CompleteReset (docs/backend-implementation.md §3
// "Login/CompleteReset은 세션 인증 대신 pre-auth 검증 경로").
//
// requireCurrentAuth in auth.go is the post-authentication counterpart: it
// answers "is this session still live", and a pre-auth request has no session
// to ask that of. What a pre-auth request needs instead is the throttle
// (docs/architecture.md "로그인·재설정 시도에는 계정 및 IP별 속도 제한을
// 적용한다. 기본 15분 내 실패 10회 이후 재시도를 제한하며 영구 계정 잠금은
// 하지 않는다") and a locked account row to judge against.
//
// The same clock rule as auth.go applies and is enforced the same way: no
// function here takes a time argument. Each one reads port.Clock itself,
// after it has taken its locks, so a caller physically cannot hand in a
// preparation timestamp that a password hash spent hundreds of milliseconds
// aging (§14.8's "준비 시각은 저장되는 사실에만 쓴다"; the same defect was
// found three times in B03).
package service

import (
	"context"
	"errors"
	"strconv"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// The throttle policy docs/architecture.md fixes: "기본 15분 내 실패 10회
// 이후 재시도를 제한하며 영구 계정 잠금은 하지 않는다". A window that has
// elapsed starts over from zero; nothing here ever writes a lockout that
// outlives the window, which is what "영구 계정 잠금은 하지 않는다" forbids.
var (
	// PreAuthFailureWindow is the sliding window failures are counted in.
	PreAuthFailureWindow = domain.NewDuration(15 * time.Minute)
	// PreAuthFailureThreshold is the failure count within one window after
	// which further attempts are refused until the window rolls over.
	PreAuthFailureThreshold = 10
)

// Rate-limit kinds. Both an account-scoped and a client-IP-scoped counter is
// kept for each pre-auth operation ("계정 및 IP별 속도 제한"), so neither one
// account under attack nor one hostile client can exhaust the other's budget.
const (
	rateLimitKindLoginAccount = "login_account"
	rateLimitKindLoginIP      = "login_ip"
	rateLimitKindResetAccount = "reset_account"
	rateLimitKindResetIP      = "reset_ip"
)

// preAuthSubject identifies one throttled subject: a kind plus the hash of
// the identifying string. The raw login name and client IP are hashed rather
// than stored, so the rate-limit table never becomes a second, unaudited
// directory of who has accounts here.
type preAuthSubject struct {
	Kind string
	Hash domain.Fingerprint
}

// loginSubjects returns the two subjects a login attempt is counted against.
// normalizedLoginName must already be domain.NormalizeLoginName output, so a
// caller cannot dodge the account counter by varying case.
func loginSubjects(normalizedLoginName string, meta contract.RequestMeta) []preAuthSubject {
	return []preAuthSubject{
		{Kind: rateLimitKindLoginAccount, Hash: domain.NewFingerprint([]byte(normalizedLoginName))},
		{Kind: rateLimitKindLoginIP, Hash: domain.NewFingerprint([]byte(clientIP(meta)))},
	}
}

// resetSubjects returns the two subjects a reset-completion attempt is
// counted against. The account half is keyed by the account id rather than a
// login name because CompleteReset presents a token, not a name.
func resetSubjects(accountID domain.AccountID, meta contract.RequestMeta) []preAuthSubject {
	return []preAuthSubject{
		{Kind: rateLimitKindResetAccount, Hash: domain.NewFingerprint([]byte(accountID))},
		{Kind: rateLimitKindResetIP, Hash: domain.NewFingerprint([]byte(clientIP(meta)))},
	}
}

// requirePreAuthAdmission refuses an attempt whose subjects have already
// exhausted the current window.
//
// It is called BEFORE the password hash or decryption work
// (docs/architecture.md §"관리자 비밀번호 해시": "기존 계정/IP 시도 제한을
// 해시 전에 검사하고 admission 거부를 비밀번호 실패로 세지 않는다"), which
// is also §6's general rule that an expensive computation never runs before
// the cheap authorization checks. A rejection here is NOT recorded as a
// password failure -- that would let a blocked client extend its own block
// forever by continuing to knock.
//
// now is read from clock here, after the caller has its transaction, rather
// than taken as an argument: a window boundary judged against a preparation
// timestamp is the stale-clock defect this package keeps out by construction.
func requirePreAuthAdmission(ctx context.Context, tx port.TxStores, subjects []preAuthSubject, clock port.Clock) error {
	now := clock.Now()
	windowStart := currentWindowStart(now)
	for _, subject := range subjects {
		record, err := tx.Accounts().GetRateLimit(ctx, subject.Kind, subject.Hash, windowStart)
		switch {
		case errors.Is(err, port.ErrNotFound):
			continue // no attempts in this window yet
		case err != nil:
			return storeError(err, "rate_limit_read_failed", "could not read the attempt counter")
		}
		// BlockedUntil is honoured while it is still in the future; a
		// counter whose window has rolled over is simply not returned for
		// the new windowStart, so no explicit expiry sweep is needed.
		if !record.BlockedUntil.IsZero() && now.Before(record.BlockedUntil) {
			return rateLimitedError(record.BlockedUntil)
		}
		if record.FailureCount >= PreAuthFailureThreshold {
			return rateLimitedError(windowStart.Add(PreAuthFailureWindow))
		}
	}
	return nil
}

// recordPreAuthFailure increments each subject's counter for the current
// window and, at the threshold, stamps the block through the end of that
// window.
//
// §4 is explicit that this write survives the rejection it accompanies:
// "잘못된 비밀번호의 실패 카운터 ... 는 정상적인 업무 변경이다. 서비스가
// callback 밖 로컬 변수에 거부 결과를 담고 callback은 nil로 끝내 해당 변경을
// 커밋한 뒤 거부 오류를 반환한다." So callers hold their rejection in a local
// variable, let the Write commit, and return the rejection afterwards -- they
// must not return an error from the callback, which would roll the counter
// back and make the throttle unenforceable.
func recordPreAuthFailure(ctx context.Context, tx port.TxStores, subjects []preAuthSubject, clock port.Clock) error {
	now := clock.Now()
	windowStart := currentWindowStart(now)
	for _, subject := range subjects {
		record, err := tx.Accounts().GetRateLimit(ctx, subject.Kind, subject.Hash, windowStart)
		switch {
		case errors.Is(err, port.ErrNotFound):
			record = port.RateLimitRecord{Kind: subject.Kind, SubjectHash: subject.Hash, WindowStart: windowStart}
		case err != nil:
			return storeError(err, "rate_limit_read_failed", "could not read the attempt counter")
		}
		record.Kind = subject.Kind
		record.SubjectHash = subject.Hash
		record.WindowStart = windowStart
		record.FailureCount++
		if record.FailureCount >= PreAuthFailureThreshold {
			// The block ends with the window; it is never extended past it,
			// because "영구 계정 잠금은 하지 않는다".
			record.BlockedUntil = windowStart.Add(PreAuthFailureWindow)
		}
		if err := tx.Accounts().SaveRateLimit(ctx, record); err != nil {
			return storeError(err, "rate_limit_write_failed", "could not record the failed attempt")
		}
	}
	return nil
}

// currentWindowStart truncates now down to the start of its fixed window, so
// concurrent attempts agree on which row they are incrementing without having
// to lock a moving range.
func currentWindowStart(now domain.Instant) domain.Instant {
	width := PreAuthFailureWindow.Microseconds()
	if width <= 0 {
		return now
	}
	micros := now.UnixMicro()
	// Floor division, so a clock before the epoch still truncates downward
	// rather than toward zero and cannot produce a window in the future.
	start := micros - ((micros%width)+width)%width
	return domain.NewInstant(time.UnixMicro(start).UTC())
}

// rateLimitedError is the single spelling of the throttle rejection, so the
// HTTP adapter's 429 mapping (docs/api-contract.md "429 | rate_limited |
// Retry-After 포함") has one code to key on and one field to build
// Retry-After from.
func rateLimitedError(until domain.Instant) error {
	return contract.NewAppError(contract.ErrorKindAuth, "rate_limited",
		"too many attempts; try again later").
		WithField("retry_after_unix_micro", strconv.FormatInt(until.UnixMicro(), 10))
}

// lockAccountByLoginName resolves a normalized login name to a LOCKED account
// row, and reports the time observed after that lock was taken.
//
// The lookup is two steps on purpose: FindAccountByLoginName resolves the
// name, and GetAccountForUpdate then takes the row lock the commit's
// decisions are made under. A caller must never judge state from the
// unlocked lookup result -- between the two reads a reset can land, which is
// exactly U02's scenario ("로그인 준비 중 reset 시 세션 생성 거부").
//
// It deliberately does NOT report "no such account" differently from the
// caller's own wrong-password path; the caller is responsible for spending
// the same dummy-hash budget on an unknown name (docs/architecture.md "없는
// 계정은 같은 프로필의 dummy hash 비교를 사용하되 같은 실행 예산을
// 적용한다"), and it signals that case with ok=false rather than an error.
func lockAccountByLoginName(ctx context.Context, tx port.TxStores, normalizedLoginName string, clock port.Clock) (account domain.Account, now domain.Instant, ok bool, err error) {
	found, err := tx.Accounts().FindAccountByLoginName(ctx, normalizedLoginName)
	switch {
	case errors.Is(err, port.ErrNotFound):
		return domain.Account{}, clock.Now(), false, nil
	case err != nil:
		return domain.Account{}, domain.Instant{}, false, storeError(err, "account_lookup_failed", "could not look up the account")
	}
	locked, err := tx.Accounts().GetAccountForUpdate(ctx, found.ID())
	switch {
	case errors.Is(err, port.ErrNotFound):
		// Deleted between the two reads. Same answer as never having existed.
		return domain.Account{}, clock.Now(), false, nil
	case err != nil:
		return domain.Account{}, domain.Instant{}, false, storeError(err, "account_read_failed", "could not read the account")
	}
	// Only now, with the row locked, is the clock read: this is the instant
	// the commit's eligibility decisions belong to.
	return locked, clock.Now(), true, nil
}
