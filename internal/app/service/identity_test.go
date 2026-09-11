package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

// ---- fixtures --------------------------------------------------------

type identityFixture struct {
	store  *porttest.Store
	ids    *seqIDs
	hasher *fakePasswordHasher
	tokens *stubTokenCodec
	clock  fixedClock
	svc    *IdentityService
}

func newIdentityFixture(t *testing.T) *identityFixture {
	t.Helper()
	store := porttest.NewStore()
	hasher := &fakePasswordHasher{}
	tokens := &stubTokenCodec{}
	ids := &seqIDs{}
	clock := fixedClock{now: testNow()}
	svc, err := NewIdentityService(IdentityDeps{
		CommonDeps: CommonDeps{
			UnitOfWork: store,
			ReadStore:  store,
			Authorizer: &toggleAuthorizer{allow: true},
			Clock:      clock,
			IDs:        ids,
		},
		PasswordHasher: hasher,
		TokenCodec:     tokens,
	})
	if err != nil {
		t.Fatalf("new identity service: %v", err)
	}
	return &identityFixture{store: store, ids: ids, hasher: hasher, tokens: tokens, clock: clock, svc: svc}
}

// seedActiveAccount stores an active account whose password is
// "correct-password" under fakePasswordHasher's scheme, and returns its id.
func seedActiveAccount(t *testing.T, store *porttest.Store, loginName string) domain.AccountID {
	t.Helper()
	accountID, err := domain.ParseAccountID(fmt36(loginName, 1))
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	hash, err := domain.NewPasswordHash("fakehash:correct-password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	account, err := domain.NewAccount(domain.AccountFacts{
		ID: accountID, NormalizedLoginName: domain.NormalizeLoginName(loginName), PasswordHash: hash,
		State: domain.AccountStateActive, AuthEpoch: 0, IsGlobalAdmin: true,
	})
	if err != nil {
		t.Fatalf("account: %v", err)
	}
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Accounts().InsertAccount(context.Background(), account)
	}); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	return accountID
}

// fmt36 builds a deterministic, valid 36-char UUID (lowercase hex only,
// version/variant nibbles fixed) from a seed string and a tag, so different
// fixtures never collide on the same id.
func fmt36(seed string, tag byte) string {
	sum := 0
	for i := 0; i < len(seed); i++ {
		sum = sum*131 + int(seed[i])
	}
	if sum < 0 {
		sum = -sum
	}
	hexTag := fmt.Sprintf("%x", tag%16)
	block := ""
	for i := 0; i < 8; i++ {
		block += hexTag
	}
	return fmt.Sprintf("%s-%s%s%s%s-4%s%s%s-8%s%s%s-%012x",
		block, hexTag, hexTag, hexTag, hexTag, hexTag, hexTag, hexTag, hexTag, hexTag, hexTag, sum%0x1000000000000)
}

func loginCommand(loginName, password string) contract.IdentityLoginCommand {
	return contract.IdentityLoginCommand{LoginName: loginName, Password: secret.FromString(password)}
}

// ---- Login: happy path ----------------------------------------------

func TestLogin_Success_CreatesSessionAndReturnsCSRF(t *testing.T) {
	f := newIdentityFixture(t)
	seedActiveAccount(t, f.store, "operator")

	view, err := f.svc.Login(context.Background(), contract.MutationMeta{}, loginCommand("operator", "correct-password"))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if view.Account.LoginName != "operator" {
		t.Fatalf("login_name = %q, want operator", view.Account.LoginName)
	}
	if view.CSRFToken == nil {
		t.Fatal("no csrf token returned")
	}
	if view.CSRFToken.IsEmpty() {
		t.Fatal("csrf token is empty")
	}

	// A real session row exists, keyed by the hash of the session token
	// Login minted first (before the CSRF token minted last inside the
	// commit).
	rawSession := f.tokens.mintedAt(0)
	hash, err := domain.NewTokenHash(domain.NewFingerprint([]byte(rawSession)))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		session, err := tx.Accounts().FindSessionByHash(context.Background(), hash)
		if err != nil {
			return err
		}
		if session.AccountID() != view.Account.ID {
			t.Fatalf("session account = %q, want %q", session.AccountID(), view.Account.ID)
		}
		return nil
	}); err != nil {
		t.Fatalf("read back session: %v", err)
	}
}

func TestLogin_WrongPassword_RecordsFailureAndRejects(t *testing.T) {
	f := newIdentityFixture(t)
	seedActiveAccount(t, f.store, "operator")

	_, err := f.svc.Login(context.Background(), contract.MutationMeta{}, loginCommand("operator", "totally-wrong-password"))
	if err == nil {
		t.Fatal("login succeeded with the wrong password")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindAuth || appErr.Code() != "invalid_credentials" {
		t.Fatalf("err = %v, want auth/invalid_credentials", err)
	}
	assertRateLimitCount(t, f.store, rateLimitKindLoginAccount, "operator", 1)
}

func TestLogin_UnknownAccount_SameVerifyBudgetAsWrongPassword(t *testing.T) {
	fKnown := newIdentityFixture(t)
	seedActiveAccount(t, fKnown.store, "operator")
	if _, err := fKnown.svc.Login(context.Background(), contract.MutationMeta{}, loginCommand("operator", "definitely-wrong-password")); err == nil {
		t.Fatal("expected rejection for wrong password")
	}
	knownCalls := fKnown.hasher.verifyCalls()

	fUnknown := newIdentityFixture(t)
	// No account seeded at all.
	if _, err := fUnknown.svc.Login(context.Background(), contract.MutationMeta{}, loginCommand("nobody-here", "definitely-wrong-password")); err == nil {
		t.Fatal("expected rejection for an unknown account")
	}
	unknownCalls := fUnknown.hasher.verifyCalls()

	if knownCalls != unknownCalls {
		t.Fatalf("verify calls: known-account path = %d, unknown-account path = %d, want equal", knownCalls, unknownCalls)
	}
	if unknownCalls == 0 {
		t.Fatal("PasswordHasher.Verify was never called for an unknown login name -- dummy-hash budget parity is not being spent")
	}
}

// ---- Login: rate limiting -------------------------------------------

func assertRateLimitCount(t *testing.T, store *porttest.Store, kind, loginName string, want int) {
	t.Helper()
	normalized := domain.NormalizeLoginName(loginName)
	windowStart := currentWindowStart(testNow())
	var rec port.RateLimitRecord
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		rec, err = tx.Accounts().GetRateLimit(context.Background(), kind, domain.NewFingerprint([]byte(normalized)), windowStart)
		return err
	})
	if err != nil {
		t.Fatalf("read rate limit: %v", err)
	}
	if rec.FailureCount != want {
		t.Fatalf("failure_count = %d, want %d", rec.FailureCount, want)
	}
}

func seedLoginRateLimitBlocked(t *testing.T, store *porttest.Store, loginName string, now domain.Instant) {
	t.Helper()
	normalized := domain.NormalizeLoginName(loginName)
	windowStart := currentWindowStart(now)
	rec := port.RateLimitRecord{
		Kind:         rateLimitKindLoginAccount,
		SubjectHash:  domain.NewFingerprint([]byte(normalized)),
		WindowStart:  windowStart,
		FailureCount: PreAuthFailureThreshold,
		BlockedUntil: windowStart.Add(PreAuthFailureWindow),
	}
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Accounts().SaveRateLimit(context.Background(), rec)
	}); err != nil {
		t.Fatalf("seed rate limit: %v", err)
	}
}

// TestLogin_RateLimitBlocked_NeverCallsVerify proves admission is checked
// BEFORE the KDF: with the account already blocked, PasswordHasher.Verify
// must never run at all.
func TestLogin_RateLimitBlocked_NeverCallsVerify(t *testing.T) {
	f := newIdentityFixture(t)
	seedActiveAccount(t, f.store, "operator")
	seedLoginRateLimitBlocked(t, f.store, "operator", testNow())

	_, err := f.svc.Login(context.Background(), contract.MutationMeta{}, loginCommand("operator", "correct-password"))
	if err == nil {
		t.Fatal("login succeeded despite the account being rate-limited")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Code() != "rate_limited" {
		t.Fatalf("err = %v, want rate_limited", err)
	}
	if calls := f.hasher.verifyCalls(); calls != 0 {
		t.Fatalf("PasswordHasher.Verify was called %d times despite admission being blocked; rate limiting is not gating the KDF", calls)
	}
}

// TestLogin_RateLimitBlocked_DoesNotIncrementFailureCounter proves an
// admission rejection is not itself counted as a failed attempt --
// otherwise a blocked client could extend its own block forever.
func TestLogin_RateLimitBlocked_DoesNotIncrementFailureCounter(t *testing.T) {
	f := newIdentityFixture(t)
	seedActiveAccount(t, f.store, "operator")
	seedLoginRateLimitBlocked(t, f.store, "operator", testNow())

	if _, err := f.svc.Login(context.Background(), contract.MutationMeta{}, loginCommand("operator", "correct-password")); err == nil {
		t.Fatal("login succeeded despite the account being rate-limited")
	}
	assertRateLimitCount(t, f.store, rateLimitKindLoginAccount, "operator", PreAuthFailureThreshold)
}

// ---- Login: U02 ---------------------------------------------------------

// TestLogin_ConcurrentReset_SessionCreationRejected is U02: a Login attempt
// whose outside-the-transaction password verification already succeeded is
// rejected once a concurrent BeginReset commits before Login's own Write
// runs -- the account's version moved, so the pre-computed verify result is
// discarded rather than trusted.
//
// The race is real, not asserted by comment: raceBeforeFirstWrite
// (distribution_test.go, same package) fires its hook exactly once,
// immediately before Login's own Write is delegated to the store, and the
// hook commits the reset directly against the same underlying store.
func TestLogin_ConcurrentReset_SessionCreationRejected(t *testing.T) {
	f := newIdentityFixture(t)
	accountID := seedActiveAccount(t, f.store, "operator")

	racingUoW := &raceBeforeFirstWrite{inner: f.store, race: func() {
		if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
			account, err := tx.Accounts().GetAccountForUpdate(context.Background(), accountID)
			if err != nil {
				return err
			}
			originalVersion := account.Version()
			outcome, err := account.BeginReset()
			if err != nil {
				return err
			}
			if err := tx.Accounts().SaveAccount(context.Background(), outcome.Account, originalVersion); err != nil {
				return err
			}
			return tx.Accounts().DeleteAllSessions(context.Background(), accountID)
		}); err != nil {
			t.Fatalf("concurrent reset: %v", err)
		}
	}}
	f.svc.deps.UnitOfWork = racingUoW

	_, err := f.svc.Login(context.Background(), contract.MutationMeta{}, loginCommand("operator", "correct-password"))
	if err == nil {
		t.Fatal("login succeeded despite a reset committing between preparation and commit")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Kind() != contract.ErrorKindAuth {
		t.Fatalf("kind = %s (code %q), want auth", appErr.Kind(), appErr.Code())
	}

	// No session was created for the account despite the correct password.
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		account, err := tx.Accounts().GetAccountForUpdate(context.Background(), accountID)
		if err != nil {
			return err
		}
		if account.State() != domain.AccountStateResetPending {
			t.Fatalf("account state = %q, want reset_pending", account.State())
		}
		return nil
	}); err != nil {
		t.Fatalf("read back account: %v", err)
	}
}

// ---- Logout / Authenticate ------------------------------------------

func seedSessionFor(t *testing.T, f *identityFixture, accountID domain.AccountID, rawToken string) (domain.SessionID, contract.MutationMeta) {
	t.Helper()
	sessionID, err := domain.ParseSessionID(fmt36(rawToken, 5))
	if err != nil {
		t.Fatalf("session id: %v", err)
	}
	hash, err := domain.NewTokenHash(domain.NewFingerprint([]byte(rawToken)))
	if err != nil {
		t.Fatalf("token hash: %v", err)
	}
	session, err := domain.NewSessionState(domain.SessionStateFacts{
		ID: sessionID, AccountID: accountID, TokenHash: hash, AuthEpoch: 0,
		LastSeenAt: testNow(), AbsoluteExpiresAt: testNow().Add(domain.NewDuration(24 * time.Hour)),
	})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Accounts().InsertSession(context.Background(), session)
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	principal, err := contract.NewAdminPrincipal(contract.AdminPrincipalFacts{AccountID: accountID, SessionID: sessionID, AuthEpoch: 0})
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	return sessionID, contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: principal}}
}

func TestLogout_DeletesSession(t *testing.T) {
	f := newIdentityFixture(t)
	accountID := seedActiveAccount(t, f.store, "operator")
	sessionID, meta := seedSessionFor(t, f, accountID, "raw-session-token-0123456789")

	if _, err := f.svc.Logout(context.Background(), meta, contract.IdentityLogoutCommand{}); err != nil {
		t.Fatalf("logout: %v", err)
	}

	err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		_, err := tx.Accounts().GetSessionForUpdate(context.Background(), sessionID)
		return err
	})
	if !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("session still exists after logout: err = %v", err)
	}
}

func TestLogout_RequiresAdmin(t *testing.T) {
	f := newIdentityFixture(t)
	_, err := f.svc.Logout(context.Background(), contract.MutationMeta{}, contract.IdentityLogoutCommand{})
	if err == nil {
		t.Fatal("logout succeeded without an admin principal")
	}
}

// TestLogout_RejectsExpiredAdminSession is the "관리 서비스의 모든 변경은
// 현재 계정 상태·epoch·세션 존재·만료를 트랜잭션 안에서 다시 확인한다" check
// applied to Logout: presenting a Principal that was valid when minted is
// not enough once the session it names has since gone idle-expired.
// Logout's own DeleteSession is itself an administrative change (and its
// audit event records who performed it), so it must not act on a stale
// Principal any more than Complete or IssueCSRF may.
func TestLogout_RejectsExpiredAdminSession(t *testing.T) {
	f := newIdentityFixture(t)
	accountID := seedActiveAccount(t, f.store, "operator")
	sessionID, meta := seedSessionFor(t, f, accountID, "raw-session-token-for-logout-expiry")

	movable := &movableClock{now: testNow().Add(domain.NewDuration(2 * time.Hour))}
	f.svc.deps.Clock = movable

	_, err := f.svc.Logout(context.Background(), meta, contract.IdentityLogoutCommand{})
	if err == nil {
		t.Fatal("logout succeeded for an idle-expired session")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindAuth {
		t.Fatalf("err = %v, want auth", err)
	}

	// The session row must still exist: Logout must not have deleted it
	// while rejecting the request as unauthenticated.
	err = f.store.Read(context.Background(), func(tx port.TxStores) error {
		_, err := tx.Accounts().GetSessionForUpdate(context.Background(), sessionID)
		return err
	})
	if err != nil {
		t.Fatalf("session no longer exists after a rejected logout: %v", err)
	}
}

func TestAuthenticate_ValidatesAndTouchesSession(t *testing.T) {
	f := newIdentityFixture(t)
	accountID := seedActiveAccount(t, f.store, "operator")
	rawToken := "raw-session-token-abcdef0123456789"
	_, _ = seedSessionFor(t, f, accountID, rawToken)

	result, err := f.svc.Authenticate(context.Background(), contract.RequestMeta{},
		contract.IdentityAuthenticateCommand{SessionToken: secret.FromString(rawToken)})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !result.Principal.IsAdmin() {
		t.Fatal("authenticate did not mint an admin principal")
	}
	if result.Principal.AccountID() != accountID {
		t.Fatalf("principal account = %q, want %q", result.Principal.AccountID(), accountID)
	}
}

func TestAuthenticate_UnknownTokenRejected(t *testing.T) {
	f := newIdentityFixture(t)
	_, err := f.svc.Authenticate(context.Background(), contract.RequestMeta{},
		contract.IdentityAuthenticateCommand{SessionToken: secret.FromString("00000000000000000000000000000000")})
	if err == nil {
		t.Fatal("authenticate succeeded for an unknown session token")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindAuth {
		t.Fatalf("err = %v, want auth", err)
	}
}

// ---- BeginReset -------------------------------------------------------

func internalResetPrincipal(t *testing.T) contract.Principal {
	t.Helper()
	factory, err := contract.NewInternalPrincipalFactory(contract.InternalOperationResetBegin)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	p, err := factory.Principal(contract.InternalOperationResetBegin)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	return p
}

func TestBeginReset_IssuesLinkAndInvalidatesSessions(t *testing.T) {
	f := newIdentityFixture(t)
	accountID := seedActiveAccount(t, f.store, "operator")
	_, sessionMeta := seedSessionFor(t, f, accountID, "raw-session-token-preexisting")
	seedDefaultSettings(t, f.store)

	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: internalResetPrincipal(t)}}
	view, err := f.svc.BeginReset(context.Background(), meta, contract.IdentityBeginResetCommand{AccountID: accountID})
	if err != nil {
		t.Fatalf("begin reset: %v", err)
	}
	if view.URL == nil || view.URL.IsEmpty() {
		t.Fatal("no reset link url returned")
	}
	err = view.URL.Use(func(b []byte) error {
		got := string(b)
		want := "https://cert.example.test/reset-password/"
		if len(got) <= len(want) || got[:len(want)] != want {
			t.Fatalf("url = %q, want prefix %q", got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read url: %v", err)
	}

	// The existing session was invalidated.
	if !sessionWasDeleted(t, f, sessionMeta) {
		t.Fatal("pre-existing session survived BeginReset")
	}

	// Account moved to reset_pending.
	err = f.store.Read(context.Background(), func(tx port.TxStores) error {
		account, err := tx.Accounts().GetAccountForUpdate(context.Background(), accountID)
		if err != nil {
			return err
		}
		if account.State() != domain.AccountStateResetPending {
			t.Fatalf("state = %q, want reset_pending", account.State())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read back account: %v", err)
	}
}

func sessionWasDeleted(t *testing.T, f *identityFixture, meta contract.MutationMeta) bool {
	t.Helper()
	sessionID := meta.Principal.SessionID()
	var deleted bool
	err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		_, err := tx.Accounts().GetSessionForUpdate(context.Background(), sessionID)
		deleted = errors.Is(err, port.ErrNotFound)
		return nil
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return deleted
}

func TestBeginReset_RequiresInternalOperation(t *testing.T) {
	f := newIdentityFixture(t)
	accountID := seedActiveAccount(t, f.store, "operator")
	seedDefaultSettings(t, f.store)

	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: contract.AnonymousPrincipal()}}
	_, err := f.svc.BeginReset(context.Background(), meta, contract.IdentityBeginResetCommand{AccountID: accountID})
	if err == nil {
		t.Fatal("begin reset succeeded for an anonymous principal")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("err = %v, want forbidden", err)
	}
}

func TestBeginReset_RequiresServiceURLConfigured(t *testing.T) {
	f := newIdentityFixture(t)
	accountID := seedActiveAccount(t, f.store, "operator")
	// No seedDefaultSettings call.

	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: internalResetPrincipal(t)}}
	_, err := f.svc.BeginReset(context.Background(), meta, contract.IdentityBeginResetCommand{AccountID: accountID})
	if err == nil {
		t.Fatal("begin reset succeeded without configured settings")
	}

	// The account must not have been touched: a failed reset must not
	// silently leave the account reset_pending with no usable link.
	err2 := f.store.Read(context.Background(), func(tx port.TxStores) error {
		account, err := tx.Accounts().GetAccountForUpdate(context.Background(), accountID)
		if err != nil {
			return err
		}
		if account.State() != domain.AccountStateActive {
			t.Fatalf("state = %q, want unchanged active", account.State())
		}
		return nil
	})
	if err2 != nil {
		t.Fatalf("read back: %v", err2)
	}
}

// ---- CompleteReset: U03 -----------------------------------------------

// beginResetAndCapture drives the real BeginReset flow and hands back the
// raw token string the stub TokenCodec minted (recovered by asking the
// stub for the last raw token it generated, since ResetLinkView only
// exposes it wrapped in the full URL).
func beginResetAndCapture(t *testing.T, f *identityFixture, accountID domain.AccountID) string {
	t.Helper()
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: internalResetPrincipal(t)}}
	view, err := f.svc.BeginReset(context.Background(), meta, contract.IdentityBeginResetCommand{AccountID: accountID})
	if err != nil {
		t.Fatalf("begin reset: %v", err)
	}
	var raw string
	if err := view.URL.Use(func(b []byte) error {
		s := string(b)
		prefix := "https://cert.example.test/reset-password/"
		raw = s[len(prefix):]
		return nil
	}); err != nil {
		t.Fatalf("read url: %v", err)
	}
	return raw
}

func completeResetCommand(rawToken, newPassword string) contract.IdentityCompleteResetCommand {
	return contract.IdentityCompleteResetCommand{ResetToken: secret.FromString(rawToken), NewPassword: secret.FromString(newPassword)}
}

func TestCompleteReset_Success(t *testing.T) {
	f := newIdentityFixture(t)
	accountID := seedActiveAccount(t, f.store, "operator")
	seedDefaultSettings(t, f.store)
	raw := beginResetAndCapture(t, f, accountID)

	if _, err := f.svc.CompleteReset(context.Background(), contract.MutationMeta{}, completeResetCommand(raw, "brand-new-password")); err != nil {
		t.Fatalf("complete reset: %v", err)
	}

	err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		account, err := tx.Accounts().GetAccountForUpdate(context.Background(), accountID)
		if err != nil {
			return err
		}
		if account.State() != domain.AccountStateActive {
			t.Fatalf("state = %q, want active", account.State())
		}
		if account.PasswordHash().Encoded() != "fakehash:brand-new-password" {
			t.Fatalf("password hash not updated: %q", account.PasswordHash().Encoded())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
}

func TestCompleteReset_UnknownTokenRejected(t *testing.T) {
	f := newIdentityFixture(t)
	_, err := f.svc.CompleteReset(context.Background(), contract.MutationMeta{}, completeResetCommand("does-not-exist-0123456789abcdef01234567", "brand-new-password"))
	if err == nil {
		t.Fatal("complete reset succeeded for an unknown token")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindAuth {
		t.Fatalf("err = %v, want auth", err)
	}
}

// TestCompleteReset_ConcurrentSameToken_ConsumedExactlyOnce is U03: two
// concurrent CompleteReset calls presenting the SAME valid token. Exactly
// one must succeed; the other must be rejected with reset_token_consumed
// (or an equivalent one-shot rejection), and the account's password must
// reflect only ONE of the two attempts.
func TestCompleteReset_ConcurrentSameToken_ConsumedExactlyOnce(t *testing.T) {
	f := newIdentityFixture(t)
	accountID := seedActiveAccount(t, f.store, "operator")
	seedDefaultSettings(t, f.store)
	raw := beginResetAndCapture(t, f, accountID)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	passwords := []string{"new-password-one", "new-password-two"}
	wg.Add(2)
	for i := 0; i < 2; i++ {
		i := i
		go func() {
			defer wg.Done()
			_, errs[i] = f.svc.CompleteReset(context.Background(), contract.MutationMeta{}, completeResetCommand(raw, passwords[i]))
		}()
	}
	wg.Wait()

	successes := 0
	var winnerPassword string
	for i, err := range errs {
		if err == nil {
			successes++
			winnerPassword = passwords[i]
			continue
		}
		var appErr *contract.AppError
		if !errors.As(err, &appErr) {
			t.Fatalf("attempt %d: err = %v, want an AppError", i, err)
		}
		if appErr.Kind() != contract.ErrorKindAuth {
			t.Fatalf("attempt %d: kind = %s (code %q), want auth", i, appErr.Kind(), appErr.Code())
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1 (errors: %v)", successes, errs)
	}

	err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		account, err := tx.Accounts().GetAccountForUpdate(context.Background(), accountID)
		if err != nil {
			return err
		}
		want := "fakehash:" + winnerPassword
		if account.PasswordHash().Encoded() != want {
			t.Fatalf("stored hash = %q, want %q (the single winner's password)", account.PasswordHash().Encoded(), want)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
}

// TestCompleteReset_OldConsumedTokenRejectedDuringALaterResetWindow isolates
// the token's own one-shot consumption check from Account.CompleteReset's
// separate reset_pending state guard. Those two checks are usually
// redundant (a completed reset always leaves the account active, so a
// second attempt with the same token also fails the state guard on its
// own) -- but this scenario defeats that redundancy on purpose: a SECOND,
// later BeginReset legitimately returns the account to reset_pending under
// a fresh token, and the OLD, already-consumed token from the FIRST cycle
// is replayed against it. The account genuinely IS reset_pending at that
// point, so only the token's own CanConsume/consumed_at check can still
// reject the replay -- proving AdminResetToken.Consume's re-check, not
// just the account state, is what U03 depends on.
func TestCompleteReset_OldConsumedTokenRejectedDuringALaterResetWindow(t *testing.T) {
	f := newIdentityFixture(t)
	accountID := seedActiveAccount(t, f.store, "operator")
	seedDefaultSettings(t, f.store)

	firstToken := beginResetAndCapture(t, f, accountID)
	if _, err := f.svc.CompleteReset(context.Background(), contract.MutationMeta{}, completeResetCommand(firstToken, "first-new-password")); err != nil {
		t.Fatalf("first complete reset: %v", err)
	}
	// A second, independent reset cycle -- the account is legitimately
	// reset_pending again, under a brand new token and a bumped epoch.
	_ = beginResetAndCapture(t, f, accountID)

	// Replaying the FIRST cycle's already-consumed token now.
	_, err := f.svc.CompleteReset(context.Background(), contract.MutationMeta{}, completeResetCommand(firstToken, "replayed-password"))
	if err == nil {
		t.Fatal("complete reset succeeded with an already-consumed token from an earlier reset cycle")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindAuth {
		t.Fatalf("err = %v, want auth", err)
	}

	// The replay must not have touched the password.
	err = f.store.Read(context.Background(), func(tx port.TxStores) error {
		account, err := tx.Accounts().GetAccountForUpdate(context.Background(), accountID)
		if err != nil {
			return err
		}
		if account.PasswordHash().Encoded() != "fakehash:first-new-password" {
			t.Fatalf("password hash = %q, want it unchanged by the replayed token", account.PasswordHash().Encoded())
		}
		if account.State() != domain.AccountStateResetPending {
			t.Fatalf("state = %q, want reset_pending (the second cycle is still open)", account.State())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
}

// ---- IssueCSRF ----------------------------------------------------------

func TestIssueCSRF_AnonymousMintsToken(t *testing.T) {
	f := newIdentityFixture(t)
	view, err := f.svc.IssueCSRF(context.Background(), contract.RequestMeta{}, contract.IdentityIssueCSRFCommand{})
	if err != nil {
		t.Fatalf("issue csrf: %v", err)
	}
	if view.CSRFToken == nil || view.CSRFToken.IsEmpty() {
		t.Fatal("no csrf token returned")
	}
}

func TestIssueCSRF_AdminRequiresLiveSession(t *testing.T) {
	f := newIdentityFixture(t)
	accountID := seedActiveAccount(t, f.store, "operator")
	_, meta := seedSessionFor(t, f, accountID, "raw-session-token-for-csrf")

	view, err := f.svc.IssueCSRF(context.Background(), meta.RequestMeta, contract.IdentityIssueCSRFCommand{})
	if err != nil {
		t.Fatalf("issue csrf: %v", err)
	}
	if view.CSRFToken == nil {
		t.Fatal("no csrf token returned")
	}
}

func TestIssueCSRF_ExpiredAdminSessionRejected(t *testing.T) {
	f := newIdentityFixture(t)
	accountID := seedActiveAccount(t, f.store, "operator")
	_, meta := seedSessionFor(t, f, accountID, "raw-session-token-for-csrf-2")

	movable := &movableClock{now: testNow().Add(domain.NewDuration(2 * time.Hour))}
	f.svc.deps.Clock = movable

	_, err := f.svc.IssueCSRF(context.Background(), meta.RequestMeta, contract.IdentityIssueCSRFCommand{})
	if err == nil {
		t.Fatal("issue csrf succeeded for an idle-expired session")
	}
}
