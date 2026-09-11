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

// commitIssue's issuer-eligibility check is an invariant of the commit, so
// it is tested at the commit rather than through the whole public Issue
// path. Going through Issue cannot isolate it: CanIssue also requires the
// issuer's window to cover the requested leaf window, the shortest
// configurable leaf validity is a day, so any advance that expires an
// otherwise-eligible issuer also blows through the session's fixed one-hour
// idle window and requireCurrentAuth rejects first. This is deliberately NOT
// an end-to-end test of an issuance request.
//
// The fixture is honest about time: the issuer really was valid when the
// certificate was signed, the certificate's plan and DER are left exactly as
// signed, and the session is a genuinely live one at the commit's
// observation time -- nothing is stretched or switched off to reach the
// check.
func TestCommitIssueRejectsAnIssuerThatExpiredSincePreparation(t *testing.T) {
	// The issuer outlives the one-year leaf window by an hour, so the
	// preparation below is a legitimately eligible issuance.
	preparedAt := testNow()
	issuerExpiry := preparedAt.Add(domain.NewDuration(24*365*time.Hour + time.Hour))
	f := newIssuanceFixtureWithCAOptions(t, caSeedOptions{certificateNotAfter: issuerExpiry})

	clock := &movableClock{now: preparedAt}
	f.svc.deps.Clock = clock
	cmd := issueCommand(f.authorityID, "web-1")
	prepareMeta := issueMutationMeta(t, issuanceTestIdempotencyKey)
	_, prep := prepareIssueForCommitTest(t, f, prepareMeta, cmd, preparedAt, issuerExpiry)

	// The commit is observed after the issuer expired. A session seeded at
	// preparation time cannot still be live a year later -- its absolute
	// lifetime is 24 hours -- so the commit runs under a genuinely fresh
	// administrator session established at that later moment, exactly as a
	// real second request would. Nothing about session lifetime is stretched
	// and no check is switched off; CanIssue is left as the only thing that
	// can reject.
	commitAt := issuerExpiry.Add(domain.NewDuration(time.Minute))
	commitMeta := seedLiveSessionAt(t, f, commitAt, issuanceTestIdempotencyKey)
	clock.now = commitAt
	req, err := RequestKey(commitMeta, issuanceOperationIssue)
	if err != nil {
		t.Fatalf("request key: %v", err)
	}

	var result contract.IssuanceView
	err = f.store.Write(context.Background(), func(tx port.TxStores) error {
		return f.svc.commitIssue(context.Background(), tx, commitMeta, cmd, req, "input-hash-v1", prep, &result)
	})

	if err == nil {
		t.Fatal("commit accepted an issuer whose certificate expired after preparation")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Kind() == contract.ErrorKindAuth {
		t.Fatalf("the authentication check rejected first (code %q); this is not exercising CanIssue", appErr.Code())
	}
	if appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("kind = %s (code %q), want forbidden from CanIssue", appErr.Kind(), appErr.Code())
	}

	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		if _, findErr := tx.PKI().GetCertificate(context.Background(), prep.certificate.ID()); findErr == nil {
			t.Error("the certificate was stored despite the rejected commit")
		}
		if _, findErr := tx.PKI().GetLeafCertificateRecord(context.Background(), prep.certificate.ID()); findErr == nil {
			t.Error("the leaf subtype row was stored despite the rejected commit")
		}
		if _, findErr := tx.Requests().Find(context.Background(), req); findErr == nil {
			t.Error("a success result was recorded despite the rejected commit")
		}
		return nil
	}); err != nil {
		t.Fatalf("read back: %v", err)
	}
}

// prepareIssueForCommitTest runs the real preparation at preparedAt and
// asserts the issuer was genuinely eligible then -- otherwise the test above
// would prove nothing.
func prepareIssueForCommitTest(t *testing.T, f *issuanceFixture, meta contract.MutationMeta, cmd contract.IssuanceIssueCommand, preparedAt, issuerExpiry domain.Instant) (port.OperationRequestKey, issuePrepared) {
	t.Helper()
	profile, err := cmd.DomainProfile()
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	subject, err := cmd.Subject.Domain()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	sans, err := cmd.DomainSANs()
	if err != nil {
		t.Fatalf("sans: %v", err)
	}
	algorithm, err := cmd.DomainKeyAlgorithm()
	if err != nil {
		t.Fatalf("algorithm: %v", err)
	}
	rotateEvery, rotateEveryPresent := cmd.DomainRotateEvery()

	prep, err := f.svc.prepareIssue(context.Background(), meta, cmd,
		domain.IssuanceRequest{Profile: profile, Subject: subject, SANs: sans, KeyAlgorithm: algorithm},
		rotateEvery, rotateEveryPresent, cmd.AuthorityID, nil)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if !prep.now.Equal(preparedAt) {
		t.Fatalf("prepared at %v, want %v", prep.now.Time(), preparedAt.Time())
	}
	if prep.plan.Window.NotAfter().After(issuerExpiry) {
		t.Fatalf("the prepared leaf window %v outruns the issuer's expiry %v; the fixture is not modelling a legitimately prepared issuance",
			prep.plan.Window.NotAfter().Time(), issuerExpiry.Time())
	}
	key, err := RequestKey(meta, issuanceOperationIssue)
	if err != nil {
		t.Fatalf("request key: %v", err)
	}
	return key, prep
}

// seedLiveSessionAt establishes a fresh administrator session whose idle and
// absolute windows are both open at at, and returns mutation metadata naming
// it. It is an ordinary session with ordinary lifetimes -- the only thing
// special about it is when it started.
func seedLiveSessionAt(t *testing.T, f *issuanceFixture, at domain.Instant, idempotencyKey string) contract.MutationMeta {
	t.Helper()
	sessionID, err := domain.ParseSessionID("66666666-6666-4666-8666-666666666667")
	if err != nil {
		t.Fatalf("session id: %v", err)
	}
	digest, err := domain.ParseFingerprint("22222222222222222222222222222222222222222222222222222222222222cd")
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	tokenHash, err := domain.NewTokenHash(digest)
	if err != nil {
		t.Fatalf("token hash: %v", err)
	}
	session, err := domain.NewSessionState(domain.SessionStateFacts{
		ID:                sessionID,
		AccountID:         issuanceTestAdminAccountID,
		TokenHash:         tokenHash,
		AuthEpoch:         domain.AuthEpoch(1),
		LastSeenAt:        at,
		AbsoluteExpiresAt: at.Add(domain.NewDuration(24 * time.Hour)),
	})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Accounts().InsertSession(context.Background(), session)
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	principal, err := contract.NewAdminPrincipal(contract.AdminPrincipalFacts{
		AccountID: issuanceTestAdminAccountID,
		SessionID: sessionID,
		AuthEpoch: domain.AuthEpoch(1),
	})
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	return contract.MutationMeta{
		RequestMeta:    contract.RequestMeta{Principal: principal},
		IdempotencyKey: idempotencyKey,
	}
}

// clockAdvancingIssuerReads advances the clock inside GetIssuerForUpdate,
// modelling the wait for that row's lock. It is what separates "the clock is
// read at the top of the callback" from "the clock is read after the issuer
// is locked": only the latter sees the time the wait consumed.
type clockAdvancingIssuerReads struct {
	port.TxStores
	clock *movableClock
	by    time.Duration
}

func (t clockAdvancingIssuerReads) PKI() port.PKIRepository {
	return clockAdvancingPKI{PKIRepository: t.TxStores.PKI(), clock: t.clock, by: t.by}
}

type clockAdvancingPKI struct {
	port.PKIRepository
	clock *movableClock
	by    time.Duration
}

func (p clockAdvancingPKI) GetIssuerForUpdate(ctx context.Context, id domain.AuthorityID) (domain.Authority, error) {
	authority, err := p.PKIRepository.GetIssuerForUpdate(ctx, id)
	p.clock.now = p.clock.now.Add(domain.NewDuration(p.by))
	return authority, err
}

// The issuer-eligibility clock must be read AFTER the issuer row is locked:
// waiting for that lock takes time, and a value read at the top of the
// callback is already stale by the time the check runs.
func TestCommitIssueReadsTheIssuerClockAfterLocking(t *testing.T) {
	preparedAt := testNow()
	issuerExpiry := preparedAt.Add(domain.NewDuration(24*365*time.Hour + time.Hour))
	f := newIssuanceFixtureWithCAOptions(t, caSeedOptions{certificateNotAfter: issuerExpiry})

	clock := &movableClock{now: preparedAt}
	f.svc.deps.Clock = clock
	cmd := issueCommand(f.authorityID, "web-1")
	prepareMeta := issueMutationMeta(t, issuanceTestIdempotencyKey)
	_, prep := prepareIssueForCommitTest(t, f, prepareMeta, cmd, preparedAt, issuerExpiry)

	// The commit starts while the issuer is still valid; the issuer expires
	// during the wait for its own lock.
	commitStartsAt := issuerExpiry.Add(domain.NewDuration(-time.Minute))
	commitMeta := seedLiveSessionAt(t, f, commitStartsAt, issuanceTestIdempotencyKey)
	clock.now = commitStartsAt
	req, err := RequestKey(commitMeta, issuanceOperationIssue)
	if err != nil {
		t.Fatalf("request key: %v", err)
	}

	var result contract.IssuanceView
	err = f.store.Write(context.Background(), func(tx port.TxStores) error {
		return f.svc.commitIssue(context.Background(),
			clockAdvancingIssuerReads{TxStores: tx, clock: clock, by: 2 * time.Minute},
			commitMeta, cmd, req, "input-hash-v1", prep, &result)
	})

	if err == nil {
		t.Fatal("the issuer expired while its lock was awaited, and the commit accepted it anyway")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("kind = %s (code %q), want forbidden from CanIssue", appErr.Kind(), appErr.Code())
	}
}
