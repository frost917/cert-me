package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// movableClock is a Clock a test can step forward mid-request, to cross an
// expiry boundary without waiting for one.
type movableClock struct{ now domain.Instant }

func (c *movableClock) Now() domain.Instant { return c.now }

// signerAdvancingClock advances the clock while "signing", which is where a
// real request spends its time between reading the session and committing.
type signerAdvancingClock struct {
	*fakeSigner
	clock *movableClock
	by    time.Duration
}

func (s *signerAdvancingClock) Sign(ctx context.Context, request port.CertificateSigningRequest, key domain.EncryptedSecret) (domain.Certificate, error) {
	s.clock.now = s.clock.now.Add(domain.NewDuration(s.by))
	return s.fakeSigner.Sign(ctx, request, key)
}

// §2: the session must be validated against the time the commit actually
// happens. Validating against the preparation timestamp lets a session that
// expired while the request was signing and waiting for a lock through.
func TestIssueRejectsSessionThatExpiresDuringSigning(t *testing.T) {
	for _, tc := range []struct {
		name     string
		advance  time.Duration
		code     string
		lastSeen time.Duration // offset from testNow() for the seeded session
	}{
		{
			// Seeded LastSeenAt is testNow(); the idle window is one hour.
			// Start one second inside it and cross the boundary while
			// signing.
			name:    "idle timeout crossed while signing",
			advance: time.Hour + time.Second,
			code:    "session_idle_expired",
		},
		{
			// The seeded session's absolute lifetime is 24h. Its last-seen
			// time is placed 30 minutes before that, so the idle window is
			// still open when the absolute deadline passes -- otherwise the
			// idle rule fires first and this would not be testing the
			// absolute one at all.
			name:     "absolute lifetime crossed while signing",
			advance:  24*time.Hour + time.Second,
			code:     "session_absolute_expired",
			lastSeen: 23*time.Hour + 30*time.Minute,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			if tc.lastSeen != 0 {
				touchSession(t, f, testNow().Add(domain.NewDuration(tc.lastSeen)))
			}
			clock := &movableClock{now: testNow()}
			f.svc.deps.Clock = clock
			f.svc.deps.CertificateSigner = &signerAdvancingClock{fakeSigner: f.signer, clock: clock, by: tc.advance}

			_, err := f.svc.Issue(context.Background(), issueMutationMeta(t, issuanceTestIdempotencyKey), issueCommand(f.authorityID, "web-1"))

			var appErr *contract.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("issue succeeded with a session that expired while signing: err = %v", err)
			}
			if appErr.Kind() != contract.ErrorKindAuth {
				t.Fatalf("kind = %s (code %q), want auth", appErr.Kind(), appErr.Code())
			}
			if appErr.Code() != tc.code {
				t.Fatalf("code = %q, want %q", appErr.Code(), tc.code)
			}
		})
	}
}

// The same boundary applies to the early replay probe: a stored result must
// not be handed to a session that has since expired.
func TestReplayRejectsAnExpiredSession(t *testing.T) {
	f := newIssuanceFixture(t)
	clock := &movableClock{now: testNow()}
	f.svc.deps.Clock = clock

	meta := issueMutationMeta(t, issuanceTestIdempotencyKey)
	if _, err := f.svc.Issue(context.Background(), meta, issueCommand(f.authorityID, "web-1")); err != nil {
		t.Fatalf("first issue: %v", err)
	}

	// The session goes idle past its window, then the same request is
	// retried -- the replay path must refuse it.
	clock.now = testNow().Add(domain.NewDuration(time.Hour + time.Second))

	_, err := f.svc.Issue(context.Background(), meta, issueCommand(f.authorityID, "web-1"))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("replay succeeded for an expired session: err = %v", err)
	}
	if appErr.Kind() != contract.ErrorKindAuth {
		t.Fatalf("kind = %s (code %q), want auth", appErr.Kind(), appErr.Code())
	}
}

// touchSession moves the seeded session's last_seen_at, so a test can place
// the idle window where it needs it.
func touchSession(t *testing.T, f *issuanceFixture, lastSeenAt domain.Instant) {
	t.Helper()
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		session, err := tx.Accounts().GetSessionForUpdate(context.Background(), issuanceTestSessionID)
		if err != nil {
			return err
		}
		return tx.Accounts().SaveSession(context.Background(), session.Touch(lastSeenAt))
	}); err != nil {
		t.Fatalf("touch session: %v", err)
	}
}

// NOTE on the issuer's own eligibility check.
//
// commitIssue/commitRenew now evaluate Authority.CanIssue against the
// commit's clock rather than the preparation's, for the same reason the
// session check moved: "may this issuer still issue" is a current-state
// question. That change is deliberately NOT covered by a test here, because
// the condition cannot be isolated at this level:
//
//   - Crossing the issuer certificate's NotAfter requires advancing the
//     clock past it during the request.
//   - CanIssue also requires the issuer's window to COVER the requested leaf
//     window, and the shortest configurable leaf validity is a day, so any
//     issuer that is still eligible at preparation has at least a day left.
//   - Advancing a day always blows through the session's fixed one-hour idle
//     window first, so requireCurrentAuth rejects before CanIssue is ever
//     consulted.
//
// Writing a test that "passes" by tripping the authentication check instead
// would assert the wrong thing. The change is still made -- it is the same
// stale-clock defect -- and a mutation putting prep.now back is caught by
// TestIssueRejectsSessionThatExpiresDuringSigning only for the auth half.
// Flagged in the PR reply rather than covered by a misleading test.
// The issuer's own eligibility is a "current" check too: a CA certificate
// that expires while the request is signing must not still be committed
// against. §13-3 has app re-check CanIssue inside the transaction, and that
// re-check is only meaningful if it uses the commit's clock -- the plan's
// window stays the issuance-time fact it always was.
