package service

import (
	"context"
	"errors"
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

// §2/§8: a request authenticated before a reset, a deactivation or a logout
// was committed must not go through afterwards -- and must not receive a
// stored result either. Each case is checked on the replay path, because a
// stored result is exactly what an early probe could have handed back
// without ever looking at the account.
func TestRenewRejectsSupersededAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name string
		code string
		kill func(t *testing.T, f *issuanceFixture)
	}{
		{
			name: "auth epoch advanced by a reset",
			code: "auth_epoch_superseded",
			kill: func(t *testing.T, f *issuanceFixture) {
				mutateAccount(t, f, func(account domain.Account) domain.Account {
					outcome, err := account.BeginReset()
					if err != nil {
						t.Fatalf("begin reset: %v", err)
					}
					return outcome.Account
				})
			},
		},
		{
			name: "session deleted by a logout",
			code: "session_not_found",
			kill: func(t *testing.T, f *issuanceFixture) {
				if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
					return tx.Accounts().DeleteSession(context.Background(), issuanceTestSessionID)
				}); err != nil {
					t.Fatalf("delete session: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			seriesID, certID, version := issueThenDeliver(t, f)
			meta := contract.MutationMeta{
				RequestMeta:     contract.RequestMeta{Principal: issuanceAdminPrincipal(t)},
				IdempotencyKey:  "99999999-9999-4999-8999-999999999999",
				ExpectedVersion: contract.WithExpectedVersion(version),
			}
			if _, err := f.svc.Renew(context.Background(), meta, renewCommand(seriesID, certID)); err != nil {
				t.Fatalf("first renew: %v", err)
			}

			tc.kill(t, f)

			_, err := f.svc.Renew(context.Background(), meta, renewCommand(seriesID, certID))
			var appErr *contract.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("replay after %s succeeded: err = %v", tc.name, err)
			}
			if appErr.Kind() != contract.ErrorKindAuth {
				t.Fatalf("kind = %s, want auth", appErr.Kind())
			}
			if appErr.Code() != tc.code {
				t.Fatalf("code = %q, want %q", appErr.Code(), tc.code)
			}
		})
	}
}

// mutateAccount applies a domain transition to the stored admin account.
func mutateAccount(t *testing.T, f *issuanceFixture, transition func(domain.Account) domain.Account) {
	t.Helper()
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		account, err := tx.Accounts().GetAccountForUpdate(context.Background(), issuanceTestAdminAccountID)
		if err != nil {
			return err
		}
		return tx.Accounts().SaveAccount(context.Background(), transition(account), account.Version())
	}); err != nil {
		t.Fatalf("mutate account: %v", err)
	}
}

// Reviewer finding #2: a Renew replay returned the stored result without
// ever calling the Authorizer, so a principal that has since lost permission
// still got the result.
func TestReproRenewReplayMustAuthorize(t *testing.T) {
	f := newIssuanceFixture(t)
	seriesID, certID, version := issueThenDeliver(t, f)
	meta := contract.MutationMeta{
		RequestMeta:     contract.RequestMeta{Principal: issuanceAdminPrincipal(t)},
		IdempotencyKey:  "99999999-9999-4999-8999-999999999999",
		ExpectedVersion: contract.WithExpectedVersion(version),
	}
	if _, err := f.svc.Renew(context.Background(), meta, renewCommand(seriesID, certID)); err != nil {
		t.Fatalf("first renew: %v", err)
	}

	f.authorizer.allow = false
	_, err := f.svc.Renew(context.Background(), meta, renewCommand(seriesID, certID))

	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("replay by an unauthorized principal succeeded: err = %v", err)
	}
	if appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("kind = %s, want forbidden", appErr.Kind())
	}
}

// Reviewer finding #1a: an ordinary renewal reused a key that had been
// marked compromised.
func TestReproRenewRejectsCompromisedKey(t *testing.T) {
	f := newIssuanceFixture(t)
	seriesID, certID, version := issueThenDeliver(t, f)

	keyID := currentLeafKeyMaterialID(t, f, seriesID)
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.PKI().MarkCompromised(context.Background(), keyID, testNow())
	}); err != nil {
		t.Fatalf("mark compromised: %v", err)
	}

	meta := contract.MutationMeta{
		RequestMeta:     contract.RequestMeta{Principal: issuanceAdminPrincipal(t)},
		IdempotencyKey:  "99999999-9999-4999-8999-999999999999",
		ExpectedVersion: contract.WithExpectedVersion(version),
	}
	// The ordinary path refuses outright: domain.PlanRenewal rejects an
	// ineligible key rather than turning the request into a rotation, and a
	// leaked key is reissued through the emergency path instead.
	_, err := f.svc.Renew(context.Background(), meta, renewCommand(seriesID, certID))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("an ordinary renewal reused a compromised key: err = %v", err)
	}
	if appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("kind = %s (code %q), want forbidden", appErr.Kind(), appErr.Code())
	}
	// The rejection must come from the PREPARATION's eligibility decision --
	// PlanRenewal refusing an ineligible key -- not from the commit-side
	// re-check. Both refuse, but only the preparation check stops the
	// request before a signature is produced.
	if appErr.Code() == "issuance_key_compromised" {
		t.Fatal("the compromise was only caught at commit time; preparation signed first")
	}
	if f.signer.calls != 1 {
		t.Fatalf("signer calls = %d, want 1 (the original issuance only)", f.signer.calls)
	}
	_ = keyID
}

// Reviewer finding #1b: a revocation recorded against the source certificate
// after preparation still committed as an ordinary renewal.
func TestReproRenewRejectsSourceRevokedAfterPreparation(t *testing.T) {
	f := newIssuanceFixture(t)
	seriesID, certID, version := issueThenDeliver(t, f)

	var cert domain.Certificate
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		var readErr error
		cert, readErr = tx.PKI().GetCertificate(context.Background(), certID)
		return readErr
	}); err != nil {
		t.Fatalf("read certificate: %v", err)
	}

	racing := &revokingStore{Store: f.store, t: t, cert: cert, ids: f.ids}
	f.svc.deps.UnitOfWork = racing

	meta := contract.MutationMeta{
		RequestMeta:     contract.RequestMeta{Principal: issuanceAdminPrincipal(t)},
		IdempotencyKey:  "99999999-9999-4999-8999-999999999999",
		ExpectedVersion: contract.WithExpectedVersion(version),
	}
	// Same rule for a revocation that lands between preparation and commit:
	// the commit re-checks under lock and refuses, rather than committing a
	// renewal planned against a certificate that is now revoked.
	_, err := f.svc.Renew(context.Background(), meta, renewCommand(seriesID, certID))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("an ordinary renewal reused the key of a revoked certificate: err = %v", err)
	}
	if appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("kind = %s (code %q), want forbidden", appErr.Kind(), appErr.Code())
	}
	if appErr.Code() != "issuance_source_certificate_revoked" {
		t.Fatalf("code = %q", appErr.Code())
	}
}

// revokingStore records a revocation against cert the moment the first Write
// opens -- after preparation read the ledger and found nothing.
type revokingStore struct {
	*porttest.Store
	t    *testing.T
	cert domain.Certificate
	ids  *seqIDs
	once bool
}

func (s *revokingStore) Write(ctx context.Context, fn func(port.TxStores) error) error {
	if !s.once {
		s.once = true
		revocationID, _ := domain.ParseRevocationID(s.ids.NewUUID())
		revocation, err := domain.NewRevocation(domain.RevocationFacts{
			ID:        revocationID,
			IssuerID:  s.cert.IssuerCAKeyGenerationID(),
			Serial:    s.cert.Serial(),
			RevokedAt: testNow(),
			Reason:    domain.RevocationReasonKeyCompromise,
			Source:    domain.RevocationSourceManual,
		})
		if err != nil {
			s.t.Fatalf("revocation: %v", err)
		}
		if err := s.Store.Write(ctx, func(tx port.TxStores) error {
			return tx.Revocations().Insert(ctx, revocation)
		}); err != nil {
			s.t.Fatalf("seed revocation: %v", err)
		}
	}
	return s.Store.Write(ctx, fn)
}

// §14.1 fixes the operational leaf's CRL distribution point exactly: the
// validated service_url with its trailing slash removed, plus
// /pki/ca-certificates/{issuer_certificate_id}/crl.der -- the CA certificate
// chosen for this signature, not the leaf's own id, and no /api/v1 segment.
func TestIssuanceSignsWithTheSettledCRLDistributionPoint(t *testing.T) {
	f := newIssuanceFixture(t)
	result, err := f.svc.Issue(context.Background(), issueMutationMeta(t, issuanceTestIdempotencyKey), issueCommand(f.authorityID, "web-1"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	request := f.signer.requests[len(f.signer.requests)-1]
	if len(request.CRLDistributionPoints) != 1 {
		t.Fatalf("CRL distribution points = %v, want exactly one", request.CRLDistributionPoints)
	}
	want := "https://cert.example.test/pki/ca-certificates/" + string(request.IssuerCertificate.ID()) + "/crl.der"
	if got := request.CRLDistributionPoints[0]; got != want {
		t.Fatalf("CRL distribution point = %q, want %q", got, want)
	}
	if request.IssuerCertificate.ID() == result.CertificateID {
		t.Fatal("the CRL URL must name the issuing CA certificate, not the leaf itself")
	}
}

// §14.1: a collision re-sign carries the same preparation snapshot's URL
// rather than rebuilding or dropping it.
func TestIssuanceKeepsCRLDistributionPointAcrossASerialCollision(t *testing.T) {
	f := newIssuanceFixture(t)
	f.serials.serials = []string{"10", "20"}

	var issuerKeyGenID domain.CAKeyGenerationID
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		a, err := tx.PKI().GetIssuerForUpdate(context.Background(), f.authorityID)
		issuerKeyGenID = a.KeyGenerationID()
		return err
	}); err != nil {
		t.Fatalf("read authority: %v", err)
	}
	revocationID, _ := domain.ParseRevocationID(f.ids.NewUUID())
	revocation, err := domain.NewRevocation(domain.RevocationFacts{
		ID: revocationID, IssuerID: issuerKeyGenID, Serial: serial(t, "10"),
		RevokedAt: testNow(), Reason: domain.RevocationReasonKeyCompromise, Source: domain.RevocationSourceImport,
	})
	if err != nil {
		t.Fatalf("revocation: %v", err)
	}
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Revocations().Insert(context.Background(), revocation)
	}); err != nil {
		t.Fatalf("seed revocation: %v", err)
	}

	if _, err := f.svc.Issue(context.Background(), issueMutationMeta(t, issuanceTestIdempotencyKey), issueCommand(f.authorityID, "web-1")); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if f.signer.calls != 2 {
		t.Fatalf("signer calls = %d, want 2", f.signer.calls)
	}
	if len(f.signer.requests[len(f.signer.requests)-1].CRLDistributionPoints) != 1 {
		t.Fatalf("the re-signed request lost its CRL distribution point: %v", f.signer.requests[len(f.signer.requests)-1].CRLDistributionPoints)
	}
}
