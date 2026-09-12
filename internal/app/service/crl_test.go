package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

// ---- fixture plumbing ----------------------------------------------------

// crlCA is one seeded, fully signable CA (self-signed root shape is enough
// for CRLService: publishing a CRL never needs a parent chain, only the CA's
// own key generation and its Authority row for CanSignCRL).
type crlCA struct {
	authorityID domain.AuthorityID
	keyGenID    domain.CAKeyGenerationID
}

func seedCRLTestCA(t *testing.T, store *porttest.Store, ids port.IDGenerator, now domain.Instant) crlCA {
	t.Helper()
	ctx := context.Background()

	authorityID := mustID(t, ids, domain.ParseAuthorityID)
	keyGenID := mustID(t, ids, domain.ParseCAKeyGenerationID)
	keyMaterialID := mustID(t, ids, domain.ParseKeyMaterialID)
	certID := mustID(t, ids, domain.ParseCertificateID)

	pub, err := domain.NewPublicKey(domain.KeyAlgorithmECDSAP256, []byte("crl-ca-pub-"+string(keyGenID)))
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	window, err := domain.NewValidityWindow(now.Add(domain.NewDuration(-time.Hour)), now.Add(domain.NewDuration(24*365*10*time.Hour)))
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "CRL Test CA"})
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	cert, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      certID,
		DER:                     []byte("crl-ca-der-" + string(certID)),
		KeyMaterialID:           keyMaterialID,
		IssuerCAKeyGenerationID: keyGenID,
		Serial:                  serial(t, "d001"),
		Validity:                window,
		Subject:                 subject,
		Kind:                    domain.CertificateKindCA,
		KeyAlgorithm:            domain.KeyAlgorithmECDSAP256,
		Origin:                  domain.CertificateOriginGenerated,
	})
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	secret, err := domain.NewEncryptedSecret(domain.EncryptedSecretFacts{
		OwnerKeyID:             keyMaterialID,
		Purpose:                domain.SecretPurposeCASigning,
		FormatVersion:          1,
		EncryptionGenerationID: "gen-1",
		Nonce:                  []byte("crl-ca-noncenonce1234"),
		Ciphertext:             []byte("crl-ca-ciphertext-" + string(keyGenID)),
	})
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	authority, err := domain.NewAuthority(domain.AuthorityFacts{
		ID:                    authorityID,
		Kind:                  domain.AuthorityKindRoot,
		Name:                  "CRL Test CA",
		IssuanceState:         domain.IssuanceStateEnabled,
		IssuanceCertificateID: certID,
		KeyGenerationID:       keyGenID,
		KeyAvailable:          true,
		CertificateWindow:     window,
	})
	if err != nil {
		t.Fatalf("authority: %v", err)
	}

	if err := store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{ID: keyMaterialID, PublicKey: pub, Origin: "generated"}); err != nil {
			return err
		}
		if err := tx.PKI().InsertKeyGeneration(ctx, port.CAKeyGeneration{ID: keyGenID, AuthorityID: authorityID, KeyMaterialID: keyMaterialID, GenerationNo: 1}); err != nil {
			return err
		}
		if err := tx.PKI().InsertCertificate(ctx, cert); err != nil {
			return err
		}
		if err := tx.PKI().InsertCACertificateRecord(ctx, port.CACertificateRecord{CertificateID: certID, CAKeyGenerationID: keyGenID}); err != nil {
			return err
		}
		if err := tx.Secrets().InsertEncrypted(ctx, secret); err != nil {
			return err
		}
		return tx.PKI().InsertAuthority(ctx, authority)
	}); err != nil {
		t.Fatalf("seed crl test ca: %v", err)
	}
	seedCRLState(t, store, keyGenID)
	return crlCA{authorityID: authorityID, keyGenID: keyGenID}
}

// fakeCRLSigner is a deterministic port.CRLSigner: it records every snapshot
// it was asked to sign and returns a DER whose bytes encode the input number,
// so a test can tell which reservation produced which signature without a
// second, independent bookkeeping structure.
type fakeCRLSigner struct {
	calls     int
	snapshots []port.CRLSnapshot
	fail      error
}

func (f *fakeCRLSigner) SignCRL(_ context.Context, snapshot port.CRLSnapshot, _ domain.EncryptedSecret) (port.SignedCRL, error) {
	f.calls++
	f.snapshots = append(f.snapshots, snapshot)
	if f.fail != nil {
		return port.SignedCRL{}, f.fail
	}
	der := []byte("crl-der-number-" + snapshot.Number.Hex())
	return port.SignedCRL{DER: der, DERSHA256: domain.NewFingerprint(der)}, nil
}

type crlFixture struct {
	store      *porttest.Store
	ids        *seqIDs
	authorizer *toggleAuthorizer
	clock      *movableClock
	signer     *fakeCRLSigner
	svc        *CRLService
}

func newCRLFixture(t *testing.T) *crlFixture {
	t.Helper()
	store := porttest.NewStore()
	seedAdminSessionForIssuance(t, store)
	seedDefaultSettings(t, store)
	ids := &seqIDs{}
	authorizer := &toggleAuthorizer{allow: true}
	clock := &movableClock{now: testNow()}
	signer := &fakeCRLSigner{}

	svc, err := NewCRLService(CRLDeps{
		CommonDeps: CommonDeps{UnitOfWork: store, ReadStore: store, Authorizer: authorizer, Clock: clock, IDs: ids},
		CRLSigner:  signer,
	})
	if err != nil {
		t.Fatalf("new crl service: %v", err)
	}
	return &crlFixture{store: store, ids: ids, authorizer: authorizer, clock: clock, signer: signer, svc: svc}
}

func mustCRLPublishPrincipal(t *testing.T) contract.Principal {
	t.Helper()
	factory, err := contract.NewInternalPrincipalFactory(contract.InternalOperationCRLPublish)
	if err != nil {
		t.Fatalf("internal principal factory: %v", err)
	}
	p, err := factory.Principal(contract.InternalOperationCRLPublish)
	if err != nil {
		t.Fatalf("internal principal: %v", err)
	}
	return p
}

func mustOtherInternalPrincipal(t *testing.T) contract.Principal {
	t.Helper()
	factory, err := contract.NewInternalPrincipalFactory(contract.InternalOperationAuditPrune)
	if err != nil {
		t.Fatalf("internal principal factory: %v", err)
	}
	p, err := factory.Principal(contract.InternalOperationAuditPrune)
	if err != nil {
		t.Fatalf("internal principal: %v", err)
	}
	return p
}

// claimCRLJob claims (in a real, committed Write, unlike revocations_test.go's
// read-only crlDemand probe) the single pending CRL job for issuer and
// returns it with a live lease, the shape CRLService.Publish expects to be
// handed by a worker's ClaimDue.
func claimCRLJob(t *testing.T, store *porttest.Store, issuer domain.CAKeyGenerationID) port.Job {
	t.Helper()
	var claimed port.Job
	found := false
	err := store.Write(context.Background(), func(tx port.TxStores) error {
		jobs, err := tx.Jobs().ClaimDue(context.Background(),
			domain.NewInstant(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
			domain.NewInstant(time.Date(2030, 1, 1, 1, 0, 0, 0, time.UTC)), 100)
		if err != nil {
			return err
		}
		for _, job := range jobs {
			if job.DedupKey == CRLDedupKey(issuer) {
				claimed = job
				found = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("claim crl job: %v", err)
	}
	if !found {
		t.Fatalf("no pending CRL job found for issuer %s", issuer)
	}
	return claimed
}

func readCRLState(t *testing.T, store *porttest.Store, issuer domain.CAKeyGenerationID) domain.CRLState {
	t.Helper()
	return crlState(t, store, issuer)
}

// ---- RequestPublication ---------------------------------------------------

func TestCRLServiceRequestPublicationRecordsDemand(t *testing.T) {
	f := newCRLFixture(t)
	ca := seedCRLTestCA(t, f.store, f.ids, testNow())

	apply(t, f.store, []RevocationChange{change(ca.keyGenID, serial(t, "e001"), domain.RevocationReasonUnspecified)}, testMeta(f.ids))

	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: mustAdminPrincipal()}}
	accepted, err := f.svc.RequestPublication(context.Background(), meta, contract.CRLRequestPublicationCommand{AuthorityID: ca.authorityID})
	if err != nil {
		t.Fatalf("RequestPublication: %v", err)
	}
	if accepted.JobID == "" {
		t.Fatal("want a non-empty JobID in the response")
	}

	job, ok := crlDemand(t, f.store, ca.keyGenID)
	if !ok {
		t.Fatal("expected a CRL demand to be recorded")
	}
	if job.ID != accepted.JobID {
		t.Fatalf("returned JobID = %s, want it to match the recorded job's own id %s", accepted.JobID, job.ID)
	}
	if requiredGeneration(t, job) != 1 {
		t.Fatalf("required generation = %d, want 1 (covering the revocation already recorded)", requiredGeneration(t, job))
	}

	found := false
	for _, event := range f.store.AuditEvents() {
		if event.Action == "crl.request_publication" {
			found = true
		}
	}
	if !found {
		t.Fatal("want a crl.request_publication audit event")
	}
}

func TestCRLServiceRequestPublicationRequiresAdmin(t *testing.T) {
	f := newCRLFixture(t)
	ca := seedCRLTestCA(t, f.store, f.ids, testNow())
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: contract.AnonymousPrincipal()}}
	_, err := f.svc.RequestPublication(context.Background(), meta, contract.CRLRequestPublicationCommand{AuthorityID: ca.authorityID})
	if err == nil {
		t.Fatal("want an error for a non-admin RequestPublication")
	}
}

func TestCRLServiceRequestPublicationRejectsIdleExpiredSession(t *testing.T) {
	f := newCRLFixture(t)
	ca := seedCRLTestCA(t, f.store, f.ids, testNow())
	touchAdminSession(t, f.store, testNow())
	f.clock.now = testNow().Add(domain.NewDuration(time.Hour + time.Second))
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: mustAdminPrincipal()}}
	_, err := f.svc.RequestPublication(context.Background(), meta, contract.CRLRequestPublicationCommand{AuthorityID: ca.authorityID})
	requireAuthError(t, err, "session_idle_expired")
}

func TestCRLServiceRequestPublicationRejectsAuthEpochSuperseded(t *testing.T) {
	f := newCRLFixture(t)
	ca := seedCRLTestCA(t, f.store, f.ids, testNow())
	bumpAccountAuthEpoch(t, f.store)
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: mustAdminPrincipal()}}
	_, err := f.svc.RequestPublication(context.Background(), meta, contract.CRLRequestPublicationCommand{AuthorityID: ca.authorityID})
	requireAuthError(t, err, "auth_epoch_superseded")
}

// ---- Publish: authorization ------------------------------------------------

// TestCRLServicePublishRequiresInternalCRLPublishOperation uses a REAL
// claimed job (claimCRLJob, going through the actual UpsertDemand/ClaimDue
// path) now that porttest mints validly-shaped uuid job ids
// (syntheticUUID), so CRLPublishCommand.Validate() no longer rejects every
// job this test double can produce the way it did before that fix.
func TestCRLServicePublishRequiresInternalCRLPublishOperation(t *testing.T) {
	f := newCRLFixture(t)
	ca := seedCRLTestCA(t, f.store, f.ids, testNow())
	apply(t, f.store, []RevocationChange{change(ca.keyGenID, serial(t, "e101"), domain.RevocationReasonUnspecified)}, testMeta(f.ids))
	job := claimCRLJob(t, f.store, ca.keyGenID)

	for _, principal := range []contract.Principal{contract.AnonymousPrincipal(), mustAdminPrincipal(), mustOtherInternalPrincipal(t)} {
		meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: principal}}
		_, err := f.svc.Publish(context.Background(), meta, contract.CRLPublishCommand{JobID: job.ID, CAKeyGenerationID: ca.keyGenID})
		var appErr *contract.AppError
		if !errors.As(err, &appErr) {
			t.Fatalf("principal %v: err = %v, want an AppError", principal.Kind(), err)
		}
		if appErr.Kind() != contract.ErrorKindForbidden {
			t.Fatalf("principal %v: kind = %v, want forbidden", principal.Kind(), appErr.Kind())
		}
	}
	if f.signer.calls != 0 {
		t.Fatalf("signer.calls = %d, want 0 (rejected principals must never reach signing)", f.signer.calls)
	}
}

// ---- Publish: happy path ---------------------------------------------------

// TestCRLServicePublishSignsAndPublishes now goes through the full public
// Publish method end to end (cmd.Validate → principal check → reserve →
// sign → finalize), which only became possible once porttest job ids became
// real, UUID-shaped values.
func TestCRLServicePublishSignsAndPublishes(t *testing.T) {
	f := newCRLFixture(t)
	ca := seedCRLTestCA(t, f.store, f.ids, testNow())
	apply(t, f.store, []RevocationChange{change(ca.keyGenID, serial(t, "e201"), domain.RevocationReasonUnspecified)}, testMeta(f.ids))
	job := claimCRLJob(t, f.store, ca.keyGenID)

	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: mustCRLPublishPrincipal(t)}}
	result, err := f.svc.Publish(context.Background(), meta, contract.CRLPublishCommand{JobID: job.ID, CAKeyGenerationID: ca.keyGenID})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !result.Published {
		t.Fatal("want Published = true")
	}
	if result.FollowupRequired {
		t.Fatal("want FollowupRequired = false (nothing arrived after the snapshot)")
	}
	if result.CoveredGeneration != 1 {
		t.Fatalf("covered generation = %d, want 1", result.CoveredGeneration)
	}
	if f.signer.calls != 1 {
		t.Fatalf("signer.calls = %d, want 1", f.signer.calls)
	}

	state := readCRLState(t, f.store, ca.keyGenID)
	if state.PublishedNumber() != result.Number {
		t.Fatalf("published number = %v, want %v", state.PublishedNumber(), result.Number)
	}
	if state.PublishedGeneration() != 1 {
		t.Fatalf("published generation = %d, want 1", state.PublishedGeneration())
	}

	doc, err := func() (port.CRLDocument, error) {
		var d port.CRLDocument
		err := f.store.Read(context.Background(), func(tx port.TxStores) error {
			var err error
			d, err = tx.CRLs().GetDocument(context.Background(), result.DocumentID)
			return err
		})
		return d, err
	}()
	if err != nil {
		t.Fatalf("read stored document: %v", err)
	}
	if len(doc.DER) == 0 {
		t.Fatal("stored document has no DER")
	}
}

// TestCRLServiceRequestPublicationThenPublishRoundTrips proves the JobID
// RequestPublication hands back is not merely non-empty but the SAME id
// Publish can actually be called with -- the exact round trip the earlier
// report flagged as impossible (porttest's job ids were not uuid-shaped)
// until the lead added JobRepository.GetByDedupKey and fixed porttest's id
// minting.
func TestCRLServiceRequestPublicationThenPublishRoundTrips(t *testing.T) {
	f := newCRLFixture(t)
	ca := seedCRLTestCA(t, f.store, f.ids, testNow())
	apply(t, f.store, []RevocationChange{change(ca.keyGenID, serial(t, "e211"), domain.RevocationReasonUnspecified)}, testMeta(f.ids))

	adminMeta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: mustAdminPrincipal()}}
	accepted, err := f.svc.RequestPublication(context.Background(), adminMeta, contract.CRLRequestPublicationCommand{AuthorityID: ca.authorityID})
	if err != nil {
		t.Fatalf("RequestPublication: %v", err)
	}

	workerMeta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: mustCRLPublishPrincipal(t)}}
	result, err := f.svc.Publish(context.Background(), workerMeta, contract.CRLPublishCommand{JobID: accepted.JobID, CAKeyGenerationID: ca.keyGenID})
	if err != nil {
		t.Fatalf("Publish(accepted.JobID): %v", err)
	}
	if !result.Published {
		t.Fatal("want Published = true")
	}
}

// ---- U12: completion-order reversal must never regress publication -------

// TestCRLServicePublishCompletionOrderReversalNeverRegressesPublication is
// U12's core claim: two overlapping generation attempts for the SAME CA key
// (a revocation arrives, a reservation is taken; another revocation arrives,
// a second reservation is taken; the SECOND, higher-numbered attempt
// finishes signing FIRST and publishes; the FIRST, lower-numbered attempt
// finishes LATE) must never let the later-arriving-but-lower-numbered result
// regress what is already published. reserveSnapshot/finalizePublish are
// called directly (both are this package's own, same-package helpers) so the
// interleaving is deterministic rather than a best-effort goroutine race.
func TestCRLServicePublishCompletionOrderReversalNeverRegressesPublication(t *testing.T) {
	f := newCRLFixture(t)
	ca := seedCRLTestCA(t, f.store, f.ids, testNow())

	// First revocation -> revocation generation 1.
	apply(t, f.store, []RevocationChange{change(ca.keyGenID, serial(t, "e301"), domain.RevocationReasonUnspecified)}, testMeta(f.ids))
	job := claimCRLJob(t, f.store, ca.keyGenID)

	ctx := context.Background()
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: mustCRLPublishPrincipal(t)}}

	// Reservation A: number 1, covering generation 1.
	reservationA, err := f.svc.reserveSnapshot(ctx, ca.keyGenID)
	if err != nil {
		t.Fatalf("reserveSnapshot A: %v", err)
	}
	if reservationA.snapshot.CoveredGeneration != 1 {
		t.Fatalf("reservation A covered generation = %d, want 1", reservationA.snapshot.CoveredGeneration)
	}

	// A NEW revocation arrives while A is still "in flight" (unsigned) --
	// U12's "생성 중 새 폐기" half. This bumps the issuer to generation 2 and
	// re-merges the SAME job's demand (still pending/running under one
	// dedup_key row).
	apply(t, f.store, []RevocationChange{change(ca.keyGenID, serial(t, "e302"), domain.RevocationReasonUnspecified)}, testMeta(f.ids))

	// Reservation B: number 2, covering generation 2.
	reservationB, err := f.svc.reserveSnapshot(ctx, ca.keyGenID)
	if err != nil {
		t.Fatalf("reserveSnapshot B: %v", err)
	}
	if reservationB.snapshot.Number.Compare(reservationA.snapshot.Number) <= 0 {
		t.Fatalf("reservation B number %v did not advance past A's %v", reservationB.snapshot.Number, reservationA.snapshot.Number)
	}

	signedA, err := f.svc.deps.CRLSigner.SignCRL(ctx, reservationA.snapshot, reservationA.caKey)
	if err != nil {
		t.Fatalf("sign A: %v", err)
	}
	signedB, err := f.svc.deps.CRLSigner.SignCRL(ctx, reservationB.snapshot, reservationB.caKey)
	if err != nil {
		t.Fatalf("sign B: %v", err)
	}

	// Completion order reversal: B (the later, higher-numbered reservation)
	// finishes and publishes FIRST.
	resultB, err := f.svc.finalizePublish(ctx, meta, job.ID, reservationB, signedB)
	if err != nil {
		t.Fatalf("finalizePublish B: %v", err)
	}
	if !resultB.Published {
		t.Fatal("want B published (nothing published yet, and B is the higher number)")
	}

	// A finishes LATE, after B already published a higher number/generation.
	resultA, err := f.svc.finalizePublish(ctx, meta, job.ID, reservationA, signedA)
	if err != nil {
		t.Fatalf("finalizePublish A must not error on a superseded attempt: %v", err)
	}
	if resultA.Published {
		t.Fatal("want A NOT published: a lower-numbered, later-completing CRL must never become the published one")
	}

	// The published state must still show B, never having regressed back to
	// A's lower number/generation.
	state := readCRLState(t, f.store, ca.keyGenID)
	if state.PublishedNumber().Compare(resultB.Number) != 0 {
		t.Fatalf("published number = %v, want unchanged at B's %v (must not regress to A's %v)",
			state.PublishedNumber(), resultB.Number, resultA.Number)
	}
	if state.PublishedGeneration() != resultB.CoveredGeneration {
		t.Fatalf("published generation = %d, want unchanged at B's %d", state.PublishedGeneration(), resultB.CoveredGeneration)
	}

	// A's own signed document is still stored (§8 "실패한 예약 번호는
	// 되돌리지 않는다") even though it never became the published one.
	err = f.store.Read(context.Background(), func(tx port.TxStores) error {
		_, err := tx.CRLs().GetDocument(context.Background(), resultA.DocumentID)
		return err
	})
	if err != nil {
		t.Fatalf("A's superseded document should still be stored: %v", err)
	}
}

func TestCRLServicePublishRejectsUnknownJob(t *testing.T) {
	f := newCRLFixture(t)
	ca := seedCRLTestCA(t, f.store, f.ids, testNow())
	apply(t, f.store, []RevocationChange{change(ca.keyGenID, serial(t, "e401"), domain.RevocationReasonUnspecified)}, testMeta(f.ids))
	unknownJobID, err := domain.ParseJobID("00000000-0000-4000-8000-000000000099")
	if err != nil {
		t.Fatalf("job id: %v", err)
	}
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: mustCRLPublishPrincipal(t)}}
	_, err = f.svc.Publish(context.Background(), meta, contract.CRLPublishCommand{JobID: unknownJobID, CAKeyGenerationID: ca.keyGenID})
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Code() != "crl_job_not_found" {
		t.Fatalf("code = %q, want crl_job_not_found", appErr.Code())
	}
}
