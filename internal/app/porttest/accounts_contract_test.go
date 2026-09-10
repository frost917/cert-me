// Package porttest_test is a black-box contract test for porttest.Store's
// account repository: it only imports exported API from cert-me/internal/app/port
// and cert-me/internal/app/porttest, the same surface a B03/B04
// IdentityService/SetupService in another package would use. This follows
// the shape of pki_contract_test.go's TestPKIRepository_IssueRotateRenew: a
// test living inside package porttest could reach into its private maps and
// paper over exactly the gap docs/backend-implementation.md §13 named --
// "계약 완결성 검토에는 로그인 이름 조회·rate-limit 읽기·세션 만료 갱신·reset
// token 소비 저장... 도 포함한다."
//
// Every assertion below depending on FindAccountByLoginName, GetRateLimit,
// SaveSession or SaveResetToken must fail to even compile against the
// pre-fix port.AccountRepository (none of those four methods existed), which
// is the "before" state captured in the PR report.
package porttest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

const (
	firstAdminID = domain.AccountID("c0000000-0000-0000-0000-000000000001")
	loginName    = "root@example.internal"
)

func accountInstant(t *testing.T, when time.Time) domain.Instant {
	t.Helper()
	return domain.NewInstant(when)
}

func passwordHash(t *testing.T, encoded string) domain.PasswordHash {
	t.Helper()
	h, err := domain.NewPasswordHash(encoded)
	if err != nil {
		t.Fatalf("NewPasswordHash: %v", err)
	}
	return h
}

func tokenHash(t *testing.T, seed byte) domain.TokenHash {
	t.Helper()
	fp := domain.NewFingerprint([]byte{seed, seed, seed, seed})
	h, err := domain.NewTokenHash(fp)
	if err != nil {
		t.Fatalf("NewTokenHash: %v", err)
	}
	return h
}

func subjectHash(t *testing.T, seed byte) domain.Fingerprint {
	t.Helper()
	return domain.NewFingerprint([]byte{seed, seed})
}

func newFirstAdmin(t *testing.T) domain.Account {
	t.Helper()
	a, err := domain.NewAccount(domain.AccountFacts{
		ID:                  firstAdminID,
		NormalizedLoginName: loginName,
		PasswordHash:        passwordHash(t, "argon2id$v=19$m=65536,t=3,p=4$salt$hash"),
		State:               domain.AccountStateActive,
		AuthEpoch:           domain.AuthEpoch(0),
		IsGlobalAdmin:       true,
		Version:             domain.Version(1),
	})
	if err != nil {
		t.Fatalf("NewAccount: %v", err)
	}
	return a
}

// TestAccountRepository_LoginRateLimitSessionRefreshReset drives the four
// gaps the reviewer named -- login-by-name, rate-limit read-back, session
// idle refresh and reset-token consumption -- end to end through TxStores
// alone, following the §8 commit rows for 최초 관리자/로그인/재설정 시작/
// 재설정 완료.
func TestAccountRepository_LoginRateLimitSessionRefreshReset(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()

	loginAt := accountInstant(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	// 1. 최초 관리자: create the first admin account.
	if err := store.Write(ctx, func(tx port.TxStores) error {
		return tx.Accounts().InsertAccount(ctx, newFirstAdmin(t))
	}); err != nil {
		t.Fatalf("create first admin: %v", err)
	}

	// 2. 로그인: resolve by login name (not ID), then insert a session.
	var sessionID domain.SessionID = domain.SessionID("d0000000-0000-0000-0000-000000000001")
	sHash := tokenHash(t, 0x01)
	if err := store.Write(ctx, func(tx port.TxStores) error {
		accounts := tx.Accounts()
		account, err := accounts.FindAccountByLoginName(ctx, loginName)
		if err != nil {
			return err
		}
		if account.ID() != firstAdminID {
			t.Fatalf("FindAccountByLoginName returned id %q, want %q", account.ID(), firstAdminID)
		}
		// Re-lock by ID inside the write, as the real flow would before
		// trusting the account for session issuance.
		locked, err := accounts.GetAccountForUpdate(ctx, account.ID())
		if err != nil {
			return err
		}
		session, err := domain.NewSessionState(domain.SessionStateFacts{
			ID:                sessionID,
			AccountID:         locked.ID(),
			TokenHash:         sHash,
			AuthEpoch:         locked.AuthEpoch(),
			LastSeenAt:        loginAt,
			AbsoluteExpiresAt: loginAt.Add(domain.NewDuration(24 * time.Hour)),
		})
		if err != nil {
			return err
		}
		return accounts.InsertSession(ctx, session)
	}); err != nil {
		t.Fatalf("login write: %v", err)
	}

	// 3. Failed login elsewhere: write a rate-limit failure counter, then
	// read it back in a separate transaction -- SaveRateLimit alone cannot
	// prove this round-trips.
	kind := "login_failure"
	subject := subjectHash(t, 0x02)
	windowStart := loginAt
	if err := store.Write(ctx, func(tx port.TxStores) error {
		return tx.Accounts().SaveRateLimit(ctx, port.RateLimitRecord{
			Kind:         kind,
			SubjectHash:  subject,
			WindowStart:  windowStart,
			FailureCount: 1,
			BlockedUntil: domain.Instant{},
		})
	}); err != nil {
		t.Fatalf("save rate limit: %v", err)
	}
	if err := store.Read(ctx, func(tx port.TxStores) error {
		rec, err := tx.Accounts().GetRateLimit(ctx, kind, subject, windowStart)
		if err != nil {
			return err
		}
		if rec.FailureCount != 1 {
			t.Fatalf("GetRateLimit FailureCount = %d, want 1", rec.FailureCount)
		}
		return nil
	}); err != nil {
		t.Fatalf("read rate limit: %v", err)
	}

	// 4. Session idle refresh: touch the session and persist it, then
	// prove the refreshed last_seen_at round-trips.
	touchedAt := loginAt.Add(domain.NewDuration(30 * time.Minute))
	if err := store.Write(ctx, func(tx port.TxStores) error {
		accounts := tx.Accounts()
		sess, err := accounts.GetSessionForUpdate(ctx, sessionID)
		if err != nil {
			return err
		}
		return accounts.SaveSession(ctx, sess.Touch(touchedAt))
	}); err != nil {
		t.Fatalf("session touch write: %v", err)
	}
	if err := store.Read(ctx, func(tx port.TxStores) error {
		sess, err := tx.Accounts().GetSessionForUpdate(ctx, sessionID)
		if err != nil {
			return err
		}
		if !sess.LastSeenAt().Equal(touchedAt) {
			t.Fatalf("session LastSeenAt = %v, want %v", sess.LastSeenAt(), touchedAt)
		}
		return nil
	}); err != nil {
		t.Fatalf("read session after touch: %v", err)
	}

	// 5. 재설정 시작: BeginReset, delete all sessions, issue a reset token.
	resetTokenID := domain.ResetTokenID("e0000000-0000-0000-0000-000000000001")
	rHash := tokenHash(t, 0x03)
	beginAt := loginAt.Add(domain.NewDuration(time.Hour))
	var beganAccount domain.Account
	if err := store.Write(ctx, func(tx port.TxStores) error {
		accounts := tx.Accounts()
		current, err := accounts.GetAccountForUpdate(ctx, firstAdminID)
		if err != nil {
			return err
		}
		outcome, err := current.BeginReset()
		if err != nil {
			return err
		}
		if err := accounts.SaveAccount(ctx, outcome.Account, current.Version()); err != nil {
			return err
		}
		if outcome.SessionsInvalidated {
			if err := accounts.DeleteAllSessions(ctx, firstAdminID); err != nil {
				return err
			}
		}
		token, err := domain.IssueAdminResetToken(resetTokenID, firstAdminID, rHash, outcome.Account.AuthEpoch(), beginAt, domain.DefaultResetPolicy())
		if err != nil {
			return err
		}
		beganAccount = outcome.Account
		return accounts.InsertResetToken(ctx, token)
	}); err != nil {
		t.Fatalf("begin reset write: %v", err)
	}

	// Sessions must really be gone: the earlier touched session cannot be
	// found any more.
	if err := store.Read(ctx, func(tx port.TxStores) error {
		if _, err := tx.Accounts().GetSessionForUpdate(ctx, sessionID); !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("session survived BeginReset (err=%v)", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after begin reset: %v", err)
	}

	// 6. 재설정 완료: consume the token exactly once, complete the reset.
	completeAt := beginAt.Add(domain.NewDuration(time.Minute))
	newHash := passwordHash(t, "argon2id$v=19$m=65536,t=3,p=4$salt2$hash2")
	if err := store.Write(ctx, func(tx port.TxStores) error {
		accounts := tx.Accounts()
		tok, err := accounts.GetResetToken(ctx, rHash)
		if err != nil {
			return err
		}
		acct, err := accounts.GetAccountForUpdate(ctx, firstAdminID)
		if err != nil {
			return err
		}
		consumed, err := tok.Consume(completeAt, domain.ResetTokenAccountFacts{
			AccountID: acct.ID(),
			State:     acct.State(),
			AuthEpoch: acct.AuthEpoch(),
		})
		if err != nil {
			return err
		}
		if err := accounts.SaveResetToken(ctx, consumed); err != nil {
			return err
		}
		outcome, err := acct.CompleteReset(newHash)
		if err != nil {
			return err
		}
		if err := accounts.SaveAccount(ctx, outcome.Account, acct.Version()); err != nil {
			return err
		}
		if outcome.SessionsInvalidated {
			if err := accounts.DeleteAllSessions(ctx, firstAdminID); err != nil {
				return err
			}
		}
		return accounts.InvalidateResetTokens(ctx, firstAdminID, completeAt)
	}); err != nil {
		t.Fatalf("complete reset write: %v", err)
	}
	_ = beganAccount

	// Assertion: the consumed_at must have persisted -- a second consume
	// attempt reading the same row back must be rejected as already
	// consumed. This is the exact assertion that cannot pass without
	// SaveResetToken: without it, GetResetToken would keep returning the
	// pre-consumption row forever.
	if err := store.Read(ctx, func(tx port.TxStores) error {
		tok, err := tx.Accounts().GetResetToken(ctx, rHash)
		if err != nil {
			return err
		}
		if !tok.IsConsumed() {
			t.Fatalf("reset token consumed_at did not persist")
		}
		acct, err := tx.Accounts().GetAccountForUpdate(ctx, firstAdminID)
		if err != nil {
			return err
		}
		_, err = tok.Consume(completeAt, domain.ResetTokenAccountFacts{
			AccountID: acct.ID(),
			State:     acct.State(),
			AuthEpoch: acct.AuthEpoch(),
		})
		if !errors.Is(err, domain.ErrAlreadyConsumed) {
			t.Fatalf("second Consume returned %v, want ErrAlreadyConsumed", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after complete reset: %v", err)
	}
}

// TestAccountRepository_SaveSessionAndSaveResetToken_RollBackOnCallbackError
// proves the two new write paths participate in the same copy-on-write
// rollback every other AccountRepository method already gets.
func TestAccountRepository_SaveSessionAndSaveResetToken_RollBackOnCallbackError(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()
	sentinel := errors.New("callback failed")

	loginAt := accountInstant(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	sessionID := domain.SessionID("f0000000-0000-0000-0000-000000000001")
	sHash := tokenHash(t, 0x09)
	resetTokenID := domain.ResetTokenID("f0000000-0000-0000-0000-000000000002")
	rHash := tokenHash(t, 0x0a)

	if err := store.Write(ctx, func(tx port.TxStores) error {
		accounts := tx.Accounts()
		if err := accounts.InsertAccount(ctx, newFirstAdmin(t)); err != nil {
			return err
		}
		session, err := domain.NewSessionState(domain.SessionStateFacts{
			ID:                sessionID,
			AccountID:         firstAdminID,
			TokenHash:         sHash,
			AuthEpoch:         0,
			LastSeenAt:        loginAt,
			AbsoluteExpiresAt: loginAt.Add(domain.NewDuration(24 * time.Hour)),
		})
		if err != nil {
			return err
		}
		if err := accounts.InsertSession(ctx, session); err != nil {
			return err
		}
		token, err := domain.IssueAdminResetToken(resetTokenID, firstAdminID, rHash, 0, loginAt, domain.DefaultResetPolicy())
		if err != nil {
			return err
		}
		return accounts.InsertResetToken(ctx, token)
	}); err != nil {
		t.Fatalf("setup write: %v", err)
	}

	touchedAt := loginAt.Add(domain.NewDuration(time.Hour))
	err := store.Write(ctx, func(tx port.TxStores) error {
		accounts := tx.Accounts()
		sess, err := accounts.GetSessionForUpdate(ctx, sessionID)
		if err != nil {
			return err
		}
		if err := accounts.SaveSession(ctx, sess.Touch(touchedAt)); err != nil {
			return err
		}
		tok, err := accounts.GetResetToken(ctx, rHash)
		if err != nil {
			return err
		}
		consumed, err := tok.Consume(touchedAt, domain.ResetTokenAccountFacts{
			AccountID: firstAdminID,
			State:     domain.AccountStateResetPending,
			AuthEpoch: 0,
		})
		if err != nil {
			return err
		}
		if err := accounts.SaveResetToken(ctx, consumed); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write returned %v, want the callback's error", err)
	}

	if err := store.Read(ctx, func(tx port.TxStores) error {
		sess, err := tx.Accounts().GetSessionForUpdate(ctx, sessionID)
		if err != nil {
			return err
		}
		if !sess.LastSeenAt().Equal(loginAt) {
			t.Fatalf("session touch survived rollback: LastSeenAt = %v, want unchanged %v", sess.LastSeenAt(), loginAt)
		}
		tok, err := tx.Accounts().GetResetToken(ctx, rHash)
		if err != nil {
			return err
		}
		if tok.IsConsumed() {
			t.Fatalf("reset token consumption survived rollback")
		}
		return nil
	}); err != nil {
		t.Fatalf("read after rollback: %v", err)
	}
}
