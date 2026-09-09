package domain

import (
	"errors"
	"testing"
	"time"
)

func mustAccountID(t *testing.T, raw string) AccountID {
	t.Helper()
	id, err := ParseAccountID(raw)
	if err != nil {
		t.Fatalf("ParseAccountID(%q): %v", raw, err)
	}
	return id
}

func mustSessionID(t *testing.T, raw string) SessionID {
	t.Helper()
	id, err := ParseSessionID(raw)
	if err != nil {
		t.Fatalf("ParseSessionID(%q): %v", raw, err)
	}
	return id
}

func mustResetTokenID(t *testing.T, raw string) ResetTokenID {
	t.Helper()
	id, err := ParseResetTokenID(raw)
	if err != nil {
		t.Fatalf("ParseResetTokenID(%q): %v", raw, err)
	}
	return id
}

func mustPasswordHash(t *testing.T, s string) PasswordHash {
	t.Helper()
	h, err := NewPasswordHash(s)
	if err != nil {
		t.Fatalf("NewPasswordHash(%q): %v", s, err)
	}
	return h
}

func mustTokenHash(t *testing.T, seed string) TokenHash {
	t.Helper()
	h, err := NewTokenHash(NewFingerprint([]byte(seed)))
	if err != nil {
		t.Fatalf("NewTokenHash: %v", err)
	}
	return h
}

func instantAt(t *testing.T, rfc3339 string) Instant {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		t.Fatalf("time.Parse(%q): %v", rfc3339, err)
	}
	return NewInstant(parsed)
}

const (
	testAccountA = "11111111-1111-1111-1111-111111111111"
	testAccountB = "22222222-2222-2222-2222-222222222222"
	testSessionA = "33333333-3333-3333-3333-333333333333"
	testTokenA   = "44444444-4444-4444-4444-444444444444"
)

func newTestAccount(t *testing.T, state AccountState, epoch AuthEpoch) Account {
	t.Helper()
	a, err := NewAccount(AccountFacts{
		ID:                  mustAccountID(t, testAccountA),
		NormalizedLoginName: "admin",
		PasswordHash:        mustPasswordHash(t, "argon2id$old"),
		State:               state,
		AuthEpoch:           epoch,
		IsGlobalAdmin:       true,
		Version:             Version(1),
	})
	if err != nil {
		t.Fatalf("NewAccount: %v", err)
	}
	return a
}

// --- Account.CanLogin ---

func TestIdentityAccountCanLogin(t *testing.T) {
	cases := []struct {
		name    string
		state   AccountState
		wantErr bool
		code    string
	}{
		{name: "active can login", state: AccountStateActive, wantErr: false},
		{name: "reset_pending blocks login even long after any link would have expired", state: AccountStateResetPending, wantErr: true, code: "account_reset_pending"},
		{name: "disabled blocks login", state: AccountStateDisabled, wantErr: true, code: "account_disabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			acc := newTestAccount(t, tc.state, AuthEpoch(1))
			err := acc.CanLogin()
			if tc.wantErr {
				requirePolicyError(t, err, ErrNotPermitted, tc.code)
				return
			}
			if err != nil {
				t.Fatalf("CanLogin() = %v, want nil", err)
			}
		})
	}
}

// --- Account.BeginReset ---

func TestIdentityAccountBeginReset(t *testing.T) {
	cases := []struct {
		name      string
		state     AccountState
		wantErr   bool
		wantState AccountState
		wantEpoch AuthEpoch
		errBase   error
		errCode   string
	}{
		{name: "active starts a reset", state: AccountStateActive, wantState: AccountStateResetPending, wantEpoch: 2},
		{name: "reset_pending reissue advances epoch again", state: AccountStateResetPending, wantState: AccountStateResetPending, wantEpoch: 2},
		{name: "disabled cannot begin a reset", state: AccountStateDisabled, wantErr: true, errBase: ErrInvalidTransition, errCode: "account_disabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			acc := newTestAccount(t, tc.state, AuthEpoch(1))
			out, err := acc.BeginReset()
			if tc.wantErr {
				requirePolicyError(t, err, tc.errBase, tc.errCode)
				return
			}
			if err != nil {
				t.Fatalf("BeginReset() error = %v", err)
			}
			if out.Account.State() != tc.wantState {
				t.Errorf("state = %v, want %v", out.Account.State(), tc.wantState)
			}
			if out.Account.AuthEpoch() != tc.wantEpoch {
				t.Errorf("epoch = %v, want %v", out.Account.AuthEpoch(), tc.wantEpoch)
			}
			if !out.SessionsInvalidated {
				t.Errorf("SessionsInvalidated = false, want true")
			}
			// The input account must not have been mutated in place.
			if acc.State() != tc.state {
				t.Errorf("receiver mutated: state = %v, want unchanged %v", acc.State(), tc.state)
			}
		})
	}
}

// --- Account.CompleteReset ---

func TestIdentityAccountCompleteReset(t *testing.T) {
	newHash := mustPasswordHash(t, "argon2id$new")

	cases := []struct {
		name    string
		state   AccountState
		hash    PasswordHash
		wantErr bool
		errBase error
		errCode string
	}{
		{name: "reset_pending completes to active with new hash", state: AccountStateResetPending, hash: newHash},
		{name: "active cannot complete a reset that was not begun", state: AccountStateActive, hash: newHash, wantErr: true, errBase: ErrInvalidTransition, errCode: "account_not_reset_pending"},
		{name: "disabled cannot complete a reset", state: AccountStateDisabled, hash: newHash, wantErr: true, errBase: ErrInvalidTransition, errCode: "account_not_reset_pending"},
		{name: "empty hash is rejected", state: AccountStateResetPending, hash: PasswordHash{}, wantErr: true, errBase: ErrInvalidValue, errCode: "invalid_password_hash"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			acc := newTestAccount(t, tc.state, AuthEpoch(2))
			out, err := acc.CompleteReset(tc.hash)
			if tc.wantErr {
				requirePolicyError(t, err, tc.errBase, tc.errCode)
				return
			}
			if err != nil {
				t.Fatalf("CompleteReset() error = %v", err)
			}
			if out.Account.State() != AccountStateActive {
				t.Errorf("state = %v, want active", out.Account.State())
			}
			if out.Account.AuthEpoch() != AuthEpoch(3) {
				t.Errorf("epoch = %v, want 3", out.Account.AuthEpoch())
			}
			if !out.Account.PasswordHash().Equal(newHash) {
				t.Errorf("password hash not updated")
			}
			if !out.SessionsInvalidated {
				t.Errorf("SessionsInvalidated = false, want true")
			}
		})
	}
}

// --- SessionState.ValidateAt ---

func newTestSession(t *testing.T, lastSeen, absoluteExpires Instant, epoch AuthEpoch) SessionState {
	t.Helper()
	s, err := NewSessionState(SessionStateFacts{
		ID:                mustSessionID(t, testSessionA),
		AccountID:         mustAccountID(t, testAccountA),
		TokenHash:         mustTokenHash(t, "session-token"),
		AuthEpoch:         epoch,
		LastSeenAt:        lastSeen,
		AbsoluteExpiresAt: absoluteExpires,
	})
	if err != nil {
		t.Fatalf("NewSessionState: %v", err)
	}
	return s
}

func TestIdentitySessionStateValidateAt(t *testing.T) {
	login := instantAt(t, "2026-01-01T00:00:00Z")
	absoluteExpiry := instantAt(t, "2026-01-02T00:00:00Z") // 24h absolute lifetime
	idleTimeout := NewDuration(time.Hour)

	baseAccount := func() SessionAccountFacts {
		return SessionAccountFacts{
			AccountID: mustAccountID(t, testAccountA),
			State:     AccountStateActive,
			AuthEpoch: AuthEpoch(1),
		}
	}

	cases := []struct {
		name      string
		now       Instant
		lastSeen  Instant
		sessEpoch AuthEpoch
		account   func() SessionAccountFacts
		wantErr   bool
		errBase   error
		errCode   string
	}{
		{
			name:      "fresh session within idle and absolute windows is valid",
			now:       login.Add(NewDuration(10 * time.Minute)),
			lastSeen:  login,
			sessEpoch: 1,
			account:   baseAccount,
		},
		{
			name:      "idle timeout exactly at boundary is expired (now >= expires_at)",
			now:       login.Add(NewDuration(time.Hour)),
			lastSeen:  login,
			sessEpoch: 1,
			account:   baseAccount,
			wantErr:   true, errBase: ErrExpired, errCode: "session_idle_expired",
		},
		{
			name:      "idle timeout one microsecond before boundary is still valid",
			now:       login.Add(NewDuration(time.Hour - time.Microsecond)),
			lastSeen:  login,
			sessEpoch: 1,
			account:   baseAccount,
		},
		{
			name:      "absolute expiry reached even though idle window alone would still be fine",
			now:       absoluteExpiry,
			lastSeen:  absoluteExpiry.Add(NewDuration(-10 * time.Minute)),
			sessEpoch: 1,
			account:   baseAccount,
			wantErr:   true, errBase: ErrExpired, errCode: "session_absolute_expired",
		},
		{
			name:      "auth epoch mismatch invalidates the session",
			now:       login.Add(NewDuration(time.Minute)),
			lastSeen:  login,
			sessEpoch: 1,
			account: func() SessionAccountFacts {
				f := baseAccount()
				f.AuthEpoch = 2
				return f
			},
			wantErr: true, errBase: ErrConflict, errCode: "session_epoch_mismatch",
		},
		{
			name:      "disabled account blocks an otherwise valid session",
			now:       login.Add(NewDuration(time.Minute)),
			lastSeen:  login,
			sessEpoch: 1,
			account: func() SessionAccountFacts {
				f := baseAccount()
				f.State = AccountStateDisabled
				return f
			},
			wantErr: true, errBase: ErrNotPermitted, errCode: "account_not_active",
		},
		{
			name:      "reset_pending account blocks an otherwise valid session",
			now:       login.Add(NewDuration(time.Minute)),
			lastSeen:  login,
			sessEpoch: 1,
			account: func() SessionAccountFacts {
				f := baseAccount()
				f.State = AccountStateResetPending
				return f
			},
			wantErr: true, errBase: ErrNotPermitted, errCode: "account_not_active",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := newTestSession(t, tc.lastSeen, absoluteExpiry, tc.sessEpoch)
			err := sess.ValidateAt(tc.now, idleTimeout, tc.account())
			if tc.wantErr {
				requirePolicyError(t, err, tc.errBase, tc.errCode)
				return
			}
			if err != nil {
				t.Fatalf("ValidateAt() = %v, want nil", err)
			}
		})
	}
}

// --- AdminResetToken issuance, consumption, invalidation ---

func newTestToken(t *testing.T, issuedAt, expiresAt Instant, epoch AuthEpoch) AdminResetToken {
	t.Helper()
	tok, err := NewAdminResetToken(AdminResetTokenFacts{
		ID:        mustResetTokenID(t, testTokenA),
		AccountID: mustAccountID(t, testAccountA),
		TokenHash: mustTokenHash(t, "reset-token"),
		AuthEpoch: epoch,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatalf("NewAdminResetToken: %v", err)
	}
	return tok
}

func TestIdentityResetPolicyDefaultIsThreeHours(t *testing.T) {
	issuedAt := instantAt(t, "2026-01-01T00:00:00Z")
	policy := DefaultResetPolicy()
	got := policy.ExpiresAt(issuedAt)
	want := issuedAt.Add(NewDuration(3 * time.Hour))
	if !got.Equal(want) {
		t.Errorf("DefaultResetPolicy expiry = %v, want %v", got, want)
	}
}

func TestIdentityAdminResetTokenCanConsume(t *testing.T) {
	issuedAt := instantAt(t, "2026-01-01T00:00:00Z")
	policy := DefaultResetPolicy()
	expiresAt := policy.ExpiresAt(issuedAt) // issuedAt + 3h

	pendingAccount := func() ResetTokenAccountFacts {
		return ResetTokenAccountFacts{
			AccountID: mustAccountID(t, testAccountA),
			State:     AccountStateResetPending,
			AuthEpoch: AuthEpoch(2),
		}
	}

	cases := []struct {
		name    string
		now     Instant
		mutate  func(AdminResetToken) AdminResetToken
		account func() ResetTokenAccountFacts
		wantErr bool
		errBase error
		errCode string
	}{
		{
			name: "unused, unexpired, matching epoch link can be consumed",
			now:  issuedAt.Add(NewDuration(time.Minute)),
		},
		{
			name:    "link at exactly the 3h boundary is expired (now >= expires_at)",
			now:     expiresAt,
			wantErr: true, errBase: ErrExpired, errCode: "reset_token_expired",
		},
		{
			name:    "link one microsecond before the boundary is still usable",
			now:     expiresAt.Add(NewDuration(-time.Microsecond)),
			wantErr: false,
		},
		{
			name: "already consumed link cannot be consumed again",
			now:  issuedAt.Add(NewDuration(time.Minute)),
			mutate: func(tok AdminResetToken) AdminResetToken {
				consumed, err := tok.Consume(issuedAt.Add(NewDuration(time.Second)), pendingAccount())
				if err != nil {
					t.Fatalf("setup Consume: %v", err)
				}
				return consumed
			},
			wantErr: true, errBase: ErrAlreadyConsumed, errCode: "reset_token_consumed",
		},
		{
			name: "invalidated link (superseded by reissue) cannot be consumed",
			now:  issuedAt.Add(NewDuration(time.Minute)),
			mutate: func(tok AdminResetToken) AdminResetToken {
				invalidated, err := tok.Invalidate(issuedAt.Add(NewDuration(time.Second)))
				if err != nil {
					t.Fatalf("setup Invalidate: %v", err)
				}
				return invalidated
			},
			wantErr: true, errBase: ErrNotPermitted, errCode: "reset_token_invalidated",
		},
		{
			name: "epoch mismatch (account moved on) cannot be consumed",
			now:  issuedAt.Add(NewDuration(time.Minute)),
			account: func() ResetTokenAccountFacts {
				f := pendingAccount()
				f.AuthEpoch = 3
				return f
			},
			wantErr: true, errBase: ErrConflict, errCode: "reset_token_epoch_mismatch",
		},
		{
			name: "account no longer reset_pending cannot be consumed",
			now:  issuedAt.Add(NewDuration(time.Minute)),
			account: func() ResetTokenAccountFacts {
				f := pendingAccount()
				f.State = AccountStateActive
				return f
			},
			wantErr: true, errBase: ErrNotPermitted, errCode: "account_not_reset_pending",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := newTestToken(t, issuedAt, expiresAt, AuthEpoch(2))
			if tc.mutate != nil {
				tok = tc.mutate(tok)
			}
			account := pendingAccount
			if tc.account != nil {
				account = tc.account
			}
			err := tok.CanConsume(tc.now, account())
			if tc.wantErr {
				requirePolicyError(t, err, tc.errBase, tc.errCode)
				return
			}
			if err != nil {
				t.Fatalf("CanConsume() = %v, want nil", err)
			}
		})
	}
}

// TestIdentityAdminResetTokenConsumeIsOneShot proves the token can only be
// spent once, and that inspecting it (IsExpiredAt/CanConsume) never mutates
// consumed_at on its own.
func TestIdentityAdminResetTokenConsumeIsOneShot(t *testing.T) {
	issuedAt := instantAt(t, "2026-01-01T00:00:00Z")
	policy := DefaultResetPolicy()
	expiresAt := policy.ExpiresAt(issuedAt)
	account := ResetTokenAccountFacts{
		AccountID: mustAccountID(t, testAccountA),
		State:     AccountStateResetPending,
		AuthEpoch: AuthEpoch(2),
	}
	tok := newTestToken(t, issuedAt, expiresAt, AuthEpoch(2))
	consumeAt := issuedAt.Add(NewDuration(time.Minute))

	// A plain lookup does not consume the link.
	if tok.IsConsumed() {
		t.Fatalf("freshly issued token reports consumed")
	}
	if err := tok.CanConsume(consumeAt, account); err != nil {
		t.Fatalf("CanConsume() before spending = %v, want nil", err)
	}
	if tok.IsConsumed() {
		t.Fatalf("CanConsume (a read-only check) must not mutate consumed_at")
	}

	spent, err := tok.Consume(consumeAt, account)
	if err != nil {
		t.Fatalf("first Consume() = %v, want nil", err)
	}
	if !spent.IsConsumed() {
		t.Fatalf("spent token does not report consumed")
	}
	// The original value is untouched (immutability).
	if tok.IsConsumed() {
		t.Fatalf("Consume() mutated the receiver in place")
	}

	if _, err := spent.Consume(consumeAt.Add(NewDuration(time.Second)), account); err == nil {
		t.Fatalf("second Consume() succeeded, want ErrAlreadyConsumed")
	} else {
		requirePolicyError(t, err, ErrAlreadyConsumed, "reset_token_consumed")
	}
}

// TestIdentityResetExpiryDoesNotLiftLoginBlock covers the B01 requirement
// that an expired reset link does not, by itself, restore login: the
// account only leaves reset_pending via CompleteReset.
func TestIdentityResetExpiryDoesNotLiftLoginBlock(t *testing.T) {
	issuedAt := instantAt(t, "2026-01-01T00:00:00Z")
	policy := DefaultResetPolicy()
	expiresAt := policy.ExpiresAt(issuedAt)
	tok := newTestToken(t, issuedAt, expiresAt, AuthEpoch(2))
	acc := newTestAccount(t, AccountStateResetPending, AuthEpoch(2))

	longAfterExpiry := expiresAt.Add(NewDuration(30 * 24 * time.Hour))

	if !tok.IsExpiredAt(longAfterExpiry) {
		t.Fatalf("token should be expired long after its 3h window")
	}
	// Even though the token is long expired, the account is still blocked:
	// only a successful CompleteReset (via a freshly issued link) lifts it.
	err := acc.CanLogin()
	requirePolicyError(t, err, ErrNotPermitted, "account_reset_pending")

	// Attempting to consume the expired token fails independently.
	err = tok.CanConsume(longAfterExpiry, ResetTokenAccountFacts{
		AccountID: acc.ID(),
		State:     acc.State(),
		AuthEpoch: acc.AuthEpoch(),
	})
	requirePolicyError(t, err, ErrExpired, "reset_token_expired")
}

// TestIdentityReissueInvalidatesPriorLink covers the "재발급 시 기존 미사용
// 링크를 모두 무효화" requirement end to end: BeginReset again, invalidate
// the old token, and confirm the old token can no longer be consumed while
// a newly issued one can.
func TestIdentityReissueInvalidatesPriorLink(t *testing.T) {
	issuedAt := instantAt(t, "2026-01-01T00:00:00Z")
	policy := DefaultResetPolicy()

	acc := newTestAccount(t, AccountStateActive, AuthEpoch(1))
	firstOutcome, err := acc.BeginReset()
	if err != nil {
		t.Fatalf("BeginReset: %v", err)
	}
	firstToken := newTestToken(t, issuedAt, policy.ExpiresAt(issuedAt), firstOutcome.Account.AuthEpoch())

	// Operator re-runs the CLI reset before the admin used the first link.
	reissueAt := issuedAt.Add(NewDuration(time.Hour))
	secondOutcome, err := firstOutcome.Account.BeginReset()
	if err != nil {
		t.Fatalf("second BeginReset: %v", err)
	}
	invalidatedFirst, err := firstToken.Invalidate(reissueAt)
	if err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	secondToken := newTestToken(t, reissueAt, policy.ExpiresAt(reissueAt), secondOutcome.Account.AuthEpoch())

	consumeAt := reissueAt.Add(NewDuration(time.Minute))
	currentAccountFacts := ResetTokenAccountFacts{
		AccountID: secondOutcome.Account.ID(),
		State:     secondOutcome.Account.State(),
		AuthEpoch: secondOutcome.Account.AuthEpoch(),
	}

	if err := invalidatedFirst.CanConsume(consumeAt, currentAccountFacts); err == nil {
		t.Fatalf("invalidated first link should not be consumable")
	} else {
		requirePolicyError(t, err, ErrNotPermitted, "reset_token_invalidated")
	}
	if err := secondToken.CanConsume(consumeAt, currentAccountFacts); err != nil {
		t.Fatalf("second link should be consumable, got %v", err)
	}
}

// requirePolicyError asserts err wraps base and, when code is non-empty,
// that it carries a PolicyError with that code.
func requirePolicyError(t *testing.T, err error, base error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error wrapping %v, got nil", base)
	}
	if base != nil && !errors.Is(err, base) {
		t.Fatalf("error %v does not wrap %v", err, base)
	}
	if code == "" {
		return
	}
	var pe *PolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("error %v is not a *PolicyError", err)
	}
	if pe.Code != code {
		t.Fatalf("policy error code = %q, want %q", pe.Code, code)
	}
}
