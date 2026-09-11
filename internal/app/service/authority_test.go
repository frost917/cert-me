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

// ---- fixture plumbing ----

// seedRootKeyGeneration inserts one ca_key_generations row (self-signed:
// IssuerCACertificateID is zero, IssuerCAKeyGenerationID on the certificate
// is the generation's own id) for authorityID, plus its key material,
// certificate and encrypted secret. It is split out from seedIssuableRoot so
// a test can also seed a SECOND generation for the same authority (a "the CA
// rotated its own key" scenario) without re-inserting the authority row.
func seedRootKeyGeneration(t *testing.T, store *porttest.Store, ids port.IDGenerator, authorityID domain.AuthorityID, generationNo int, serialHex string, now domain.Instant, keyDestroyedAt domain.Instant) (domain.CAKeyGenerationID, domain.CertificateID) {
	t.Helper()
	ctx := context.Background()

	keyGenID, err := domain.ParseCAKeyGenerationID(ids.NewUUID())
	if err != nil {
		t.Fatalf("ca key generation id: %v", err)
	}
	keyMaterialID, err := domain.ParseKeyMaterialID(ids.NewUUID())
	if err != nil {
		t.Fatalf("ca key material id: %v", err)
	}
	certID, err := domain.ParseCertificateID(ids.NewUUID())
	if err != nil {
		t.Fatalf("ca certificate id: %v", err)
	}
	pub, err := domain.NewPublicKey(domain.KeyAlgorithmECDSAP256, []byte("root-public-key-bytes-"+string(keyGenID)))
	if err != nil {
		t.Fatalf("root public key: %v", err)
	}
	notAfter := now.Add(domain.NewDuration(24 * 365 * 10 * time.Hour))
	window, err := domain.NewValidityWindow(now.Add(domain.NewDuration(-time.Hour)), notAfter)
	if err != nil {
		t.Fatalf("root window: %v", err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "Test Root CA"})
	if err != nil {
		t.Fatalf("root subject: %v", err)
	}
	rootCert, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      certID,
		DER:                     []byte("root-cert-der-" + string(certID)),
		KeyMaterialID:           keyMaterialID,
		IssuerCAKeyGenerationID: keyGenID,
		Serial:                  serial(t, serialHex),
		Validity:                window,
		Subject:                 subject,
		Kind:                    domain.CertificateKindCA,
		KeyAlgorithm:            domain.KeyAlgorithmECDSAP256,
		Origin:                  domain.CertificateOriginGenerated,
	})
	if err != nil {
		t.Fatalf("root certificate: %v", err)
	}
	secret, err := domain.NewEncryptedSecret(domain.EncryptedSecretFacts{
		OwnerKeyID:             keyMaterialID,
		Purpose:                domain.SecretPurposeCASigning,
		FormatVersion:          1,
		EncryptionGenerationID: "gen-1",
		Nonce:                  []byte("root-noncenonce123456"),
		Ciphertext:             []byte("root-ciphertext-" + string(keyGenID)),
	})
	if err != nil {
		t.Fatalf("root secret: %v", err)
	}

	if err := store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{ID: keyMaterialID, PublicKey: pub, Origin: "generated"}); err != nil {
			return err
		}
		if err := tx.PKI().InsertKeyGeneration(ctx, port.CAKeyGeneration{
			ID: keyGenID, AuthorityID: authorityID, KeyMaterialID: keyMaterialID, GenerationNo: generationNo,
			KeyDestroyedAt: keyDestroyedAt,
		}); err != nil {
			return err
		}
		if err := tx.PKI().InsertCertificate(ctx, rootCert); err != nil {
			return err
		}
		if err := tx.PKI().InsertCACertificateRecord(ctx, port.CACertificateRecord{
			CertificateID: certID, CAKeyGenerationID: keyGenID, // IssuerCACertificateID zero: self-signed
		}); err != nil {
			return err
		}
		return tx.Secrets().InsertEncrypted(ctx, secret)
	}); err != nil {
		t.Fatalf("seed root key generation: %v", err)
	}
	return keyGenID, certID
}

// seedIssuableRoot inserts a fully issuable, self-signed Root authority
// (issuance_state enabled, key available, valid certificate window), the
// parent every Intermediate-creation test in this file signs under.
func seedIssuableRoot(t *testing.T, store *porttest.Store, ids port.IDGenerator, now domain.Instant) domain.AuthorityID {
	t.Helper()
	ctx := context.Background()

	authorityID, err := domain.ParseAuthorityID(ids.NewUUID())
	if err != nil {
		t.Fatalf("authority id: %v", err)
	}
	keyGenID, certID := seedRootKeyGeneration(t, store, ids, authorityID, 1, "11", now, domain.Instant{})

	certRow, err := (func() (domain.Certificate, error) {
		var c domain.Certificate
		err := store.Write(ctx, func(tx port.TxStores) error {
			var err error
			c, err = tx.PKI().GetCertificate(ctx, certID)
			return err
		})
		return c, err
	})()
	if err != nil {
		t.Fatalf("re-read root certificate: %v", err)
	}

	authority, err := domain.NewAuthority(domain.AuthorityFacts{
		ID:                    authorityID,
		Kind:                  domain.AuthorityKindRoot,
		Name:                  "Test Root",
		IssuanceState:         domain.IssuanceStateEnabled,
		IssuanceCertificateID: certID,
		KeyGenerationID:       keyGenID,
		KeyAvailable:          true,
		CertificateWindow:     certRow.Validity(),
	})
	if err != nil {
		t.Fatalf("root authority: %v", err)
	}
	if err := store.Write(ctx, func(tx port.TxStores) error {
		return tx.PKI().InsertAuthority(ctx, authority)
	}); err != nil {
		t.Fatalf("seed root authority: %v", err)
	}
	return authorityID
}

type authorityFixture struct {
	store      *porttest.Store
	ids        *seqIDs
	keyEngine  *fakeKeyEngine
	signer     *fakeSigner
	serials    *fakeSerialGenerator
	authorizer *toggleAuthorizer
	svc        *AuthorityService
	rootID     domain.AuthorityID
}

func newAuthorityFixture(t *testing.T) *authorityFixture {
	t.Helper()
	store := porttest.NewStore()
	ids := &seqIDs{}
	rootID := seedIssuableRoot(t, store, ids, testNow())
	seedDefaultSettings(t, store)
	seedAdminSessionForIssuance(t, store)

	keyEngine := &fakeKeyEngine{}
	signer := &fakeSigner{}
	serials := &fakeSerialGenerator{}
	authorizer := &toggleAuthorizer{allow: true}

	svc, err := NewAuthorityService(AuthorityDeps{
		CommonDeps: CommonDeps{
			UnitOfWork: store,
			ReadStore:  store,
			Authorizer: authorizer,
			Clock:      fixedClock{now: testNow()},
			IDs:        ids,
		},
		KeyEngine:         keyEngine,
		CertificateSigner: signer,
		SerialGenerator:   serials,
		ProfileValidator:  noopProfileValidator{},
	})
	if err != nil {
		t.Fatalf("new authority service: %v", err)
	}
	return &authorityFixture{store: store, ids: ids, keyEngine: keyEngine, signer: signer, serials: serials, authorizer: authorizer, svc: svc, rootID: rootID}
}

func rootCreateCommand(name string) contract.AuthorityCreateCommand {
	return contract.AuthorityCreateCommand{
		Kind:    string(domain.AuthorityKindRoot),
		Name:    name,
		Subject: contract.SubjectInput{CommonName: name},
	}
}

func intermediateCreateCommand(parentID domain.AuthorityID, name string) contract.AuthorityCreateCommand {
	return contract.AuthorityCreateCommand{
		Kind:              string(domain.AuthorityKindIntermediate),
		Name:              name,
		ParentAuthorityID: parentID,
		Subject:           contract.SubjectInput{CommonName: name},
	}
}

func authorityCreateMeta(idempotencyKey string) contract.MutationMeta {
	return contract.MutationMeta{
		RequestMeta:    contract.RequestMeta{Principal: mustAdminPrincipal()},
		IdempotencyKey: idempotencyKey,
	}
}

func authorityVersionMeta(version domain.Version) contract.MutationMeta {
	return contract.MutationMeta{
		RequestMeta:     contract.RequestMeta{Principal: mustAdminPrincipal()},
		ExpectedVersion: contract.WithExpectedVersion(version),
	}
}

// ---- Create: happy paths ----

func TestAuthorityServiceCreateRootStoresKeyCertAuthorityAndCRLState(t *testing.T) {
	f := newAuthorityFixture(t)
	view, err := f.svc.Create(context.Background(), authorityCreateMeta("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), rootCreateCommand("New Root"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if view.Kind != domain.AuthorityKindRoot {
		t.Fatalf("kind = %q, want root", view.Kind)
	}
	if view.IssuanceState != domain.IssuanceStateInventory {
		t.Fatalf("issuance_state = %q, want inventory (a fresh CA starts inactive)", view.IssuanceState)
	}
	if !view.KeyAvailable {
		t.Fatal("want key_available true for a freshly created authority")
	}
	if view.ManagementParentID != nil {
		t.Fatalf("management_parent_id = %v, want nil for a Root", view.ManagementParentID)
	}
	if view.IssuanceCertificateID == nil {
		t.Fatal("want an issuance_certificate_id")
	}
	if f.keyEngine.generateCalls != 1 {
		t.Fatalf("keyEngine.generateCalls = %d, want 1", f.keyEngine.generateCalls)
	}
	if f.signer.calls != 1 {
		t.Fatalf("signer.calls = %d, want 1", f.signer.calls)
	}
	// The signed certificate is self-signed: no issuer certificate supplied.
	if !f.signer.requests[0].SelfSigned() {
		t.Fatal("want the Root's signing request to be self-signed")
	}

	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		state, err := tx.CRLs().GetStateForUpdate(context.Background(), view.KeyGenerationID)
		if err != nil {
			return err
		}
		if state.PublicationState() != domain.PublicationStateInactive {
			t.Fatalf("crl publication_state = %q, want inactive", state.PublicationState())
		}
		return nil
	}); err != nil {
		t.Fatalf("read crl state: %v", err)
	}
}

func TestAuthorityServiceCreateIntermediateUnderRoot(t *testing.T) {
	f := newAuthorityFixture(t)
	view, err := f.svc.Create(context.Background(), authorityCreateMeta("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), intermediateCreateCommand(f.rootID, "New Intermediate"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if view.ManagementParentID == nil || *view.ManagementParentID != f.rootID {
		t.Fatalf("management_parent_id = %v, want %q", view.ManagementParentID, f.rootID)
	}
	if f.signer.requests[0].SelfSigned() {
		t.Fatal("want the Intermediate's signing request to carry an issuer certificate, not be self-signed")
	}

	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		root, err := tx.PKI().GetIssuerForUpdate(context.Background(), f.rootID)
		if err != nil {
			return err
		}
		record, err := tx.PKI().GetCACertificateRecord(context.Background(), *view.IssuanceCertificateID)
		if err != nil {
			return err
		}
		if record.IssuerCACertificateID != root.IssuanceCertificateID() {
			t.Fatalf("issuer_ca_certificate_id = %q, want the root's own certificate %q", record.IssuerCACertificateID, root.IssuanceCertificateID())
		}
		return nil
	}); err != nil {
		t.Fatalf("read ca certificate record: %v", err)
	}
}

// ---- Create: idempotency ----

func TestAuthorityServiceCreateDuplicateRequestReplaysStoredResult(t *testing.T) {
	f := newAuthorityFixture(t)
	meta := authorityCreateMeta("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	cmd := rootCreateCommand("Replay Root")

	first, err := f.svc.Create(context.Background(), meta, cmd)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	second, err := f.svc.Create(context.Background(), meta, cmd)
	if err != nil {
		t.Fatalf("second create: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("replay id = %q, want %q", second.ID, first.ID)
	}
	if f.keyEngine.generateCalls != 1 {
		t.Fatalf("keyEngine.generateCalls = %d, want 1 (replay must not generate a second key)", f.keyEngine.generateCalls)
	}
	if f.signer.calls != 1 {
		t.Fatalf("signer.calls = %d, want 1 (replay must not sign a second certificate)", f.signer.calls)
	}
}

func TestAuthorityServiceCreateRejectsReusedIdempotencyKeyWithDifferentInput(t *testing.T) {
	f := newAuthorityFixture(t)
	meta := authorityCreateMeta("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
	if _, err := f.svc.Create(context.Background(), meta, rootCreateCommand("First Root")); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := f.svc.Create(context.Background(), meta, rootCreateCommand("Different Root"))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Code() != "idempotency_key_reused" {
		t.Fatalf("code = %q, want idempotency_key_reused", appErr.Code())
	}
}

// ---- Create: §14.10 serial collision retry ----

// TestAuthorityServiceCreateSerialCollisionRetriesWithSameKey forces the
// first serial SerialGenerator hands out to collide with the root's own
// self-signed certificate -- which already occupies that serial under the
// exact ca_key_generations namespace an Intermediate's plan signs into
// (docs/backend-implementation.md §8 "serial 충돌은 같은 요청 ID로 새
// serial을 만들어 제한 재준비할 수 있다").
func TestAuthorityServiceCreateSerialCollisionRetriesWithSameKey(t *testing.T) {
	f := newAuthorityFixture(t)
	f.serials.serials = []string{"11", "22"} // "11" is the root's own serial
	_, err := f.svc.Create(context.Background(), authorityCreateMeta("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"), intermediateCreateCommand(f.rootID, "Collide Intermediate"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if f.keyEngine.generateCalls != 1 {
		t.Fatalf("keyEngine.generateCalls = %d, want 1 (a collision retry must reuse the already-generated key)", f.keyEngine.generateCalls)
	}
	if f.signer.calls != 2 {
		t.Fatalf("signer.calls = %d, want 2 (one collision, one successful retry)", f.signer.calls)
	}
}

// ---- Create: §14.10 signer response must match the request ----

func TestAuthorityServiceCreateRejectsSignerFieldMismatch(t *testing.T) {
	f := newAuthorityFixture(t)
	f.signer.mutateFacts = func(facts domain.CertificateFacts) domain.CertificateFacts {
		facts.Serial = serial(t, "ff") // does not match the serial the request carried
		return facts
	}
	_, err := f.svc.Create(context.Background(), authorityCreateMeta("11111111-1111-4111-9111-111111111111"), rootCreateCommand("Mismatch Root"))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Code() != "issuance_signed_certificate_mismatch" {
		t.Fatalf("code = %q, want issuance_signed_certificate_mismatch", appErr.Code())
	}
}

// ---- Create: §14.9 parent key destroyed / stopped ----

func TestAuthorityServiceCreateRejectsWhenParentKeyAlreadyDestroyed(t *testing.T) {
	store := porttest.NewStore()
	ids := &seqIDs{}
	authorityID, err := domain.ParseAuthorityID(ids.NewUUID())
	if err != nil {
		t.Fatalf("authority id: %v", err)
	}
	// InsertKeyGeneration is the only way this test double can express a
	// destroyed key at all (see authority.go's DestroyKey gap comment: there
	// is no port method to destroy an EXISTING generation's key), so the
	// destroyed state is seeded directly at insert time.
	keyGenID, certID := seedRootKeyGeneration(t, store, ids, authorityID, 1, "11", testNow(), testNow())
	certRow, err := func() (domain.Certificate, error) {
		var c domain.Certificate
		err := store.Write(context.Background(), func(tx port.TxStores) error {
			var err error
			c, err = tx.PKI().GetCertificate(context.Background(), certID)
			return err
		})
		return c, err
	}()
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	authority, err := domain.NewAuthority(domain.AuthorityFacts{
		ID: authorityID, Kind: domain.AuthorityKindRoot, Name: "Destroyed-Key Root",
		IssuanceState: domain.IssuanceStateEnabled, IssuanceCertificateID: certID,
		KeyGenerationID: keyGenID, KeyAvailable: true, CertificateWindow: certRow.Validity(),
	})
	if err != nil {
		t.Fatalf("authority: %v", err)
	}
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.PKI().InsertAuthority(context.Background(), authority)
	}); err != nil {
		t.Fatalf("seed destroyed-key root authority: %v", err)
	}
	seedDefaultSettings(t, store)
	seedAdminSessionForIssuance(t, store)

	svc, err := NewAuthorityService(AuthorityDeps{
		CommonDeps: CommonDeps{UnitOfWork: store, ReadStore: store, Authorizer: &toggleAuthorizer{allow: true}, Clock: fixedClock{now: testNow()}, IDs: ids},
		KeyEngine:  &fakeKeyEngine{}, CertificateSigner: &fakeSigner{}, SerialGenerator: &fakeSerialGenerator{}, ProfileValidator: noopProfileValidator{},
	})
	if err != nil {
		t.Fatalf("new authority service: %v", err)
	}

	_, err = svc.Create(context.Background(), authorityCreateMeta("22222222-2222-4222-9222-222222222222"), intermediateCreateCommand(authorityID, "Blocked Intermediate"))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError (parent's CA key is destroyed)", err)
	}
	if appErr.Code() != "issuance_ca_key_destroyed" {
		t.Fatalf("code = %q, want issuance_ca_key_destroyed", appErr.Code())
	}
}

func TestAuthorityServiceCreateRejectsWhenParentIssuanceStopped(t *testing.T) {
	f := newAuthorityFixture(t)
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		root, err := tx.PKI().GetIssuerForUpdate(context.Background(), f.rootID)
		if err != nil {
			return err
		}
		stopped, err := root.StopIssuance()
		if err != nil {
			return err
		}
		return tx.PKI().SaveAuthority(context.Background(), stopped, root.Version())
	}); err != nil {
		t.Fatalf("stop root: %v", err)
	}

	_, err := f.svc.Create(context.Background(), authorityCreateMeta("33333333-3333-4333-9333-333333333333"), intermediateCreateCommand(f.rootID, "Blocked Intermediate"))
	if err == nil {
		t.Fatal("want an error creating an Intermediate under a stopped parent")
	}
}

// TestAuthorityServiceCreateRejectsWhenParentStopsBetweenPrepareAndCommit
// proves commitCreate re-checks the parent's CanIssue policy under lock,
// independent of what preparation saw (§14.9 "준비와 commit 양쪽에서
// 확인"): the parent is stopped by a UnitOfWork decorator right before the
// real commit runs, after preparation already succeeded against the
// still-enabled parent.
func TestAuthorityServiceCreateRejectsWhenParentStopsBetweenPrepareAndCommit(t *testing.T) {
	f := newAuthorityFixture(t)
	mutated := false
	f.svc.deps.UnitOfWork = &mutateOnceUoW{
		inner: f.store,
		mutate: func() {
			mutated = true
			if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
				root, err := tx.PKI().GetIssuerForUpdate(context.Background(), f.rootID)
				if err != nil {
					return err
				}
				stopped, err := root.StopIssuance()
				if err != nil {
					return err
				}
				return tx.PKI().SaveAuthority(context.Background(), stopped, root.Version())
			}); err != nil {
				t.Fatalf("stop root mid-flight: %v", err)
			}
		},
	}

	_, err := f.svc.Create(context.Background(), authorityCreateMeta("44444444-4444-4444-9444-444444444444"), intermediateCreateCommand(f.rootID, "Race Intermediate"))
	if !mutated {
		t.Fatal("mutateOnceUoW never ran; test is not exercising the intended race")
	}
	if err == nil {
		t.Fatal("want an error: parent was stopped between prepare and commit, commit must re-check rather than trust the stale prep")
	}
}

// ---- Create: §8 issuer key generation moved -> re-prepare ----

// TestAuthorityServiceCreateRepreparesWhenParentKeyGenerationRotatesBetweenPrepareAndCommit
// gives the root a SECOND ca_key_generation (as if it had already rotated
// its own signing key) and points the parent Authority row at it via a
// UnitOfWork decorator right before the real commit runs. commitCreate must
// detect that prep.plan.IssuerKeyGenerationID no longer matches the parent's
// current KeyGenerationID, discard the stale preparation (errRePrepare) and
// redo it -- the certificate that finally gets stored must be signed under
// the NEW generation, not the one prep #1 saw.
func TestAuthorityServiceCreateRepreparesWhenParentKeyGenerationRotatesBetweenPrepareAndCommit(t *testing.T) {
	f := newAuthorityFixture(t)
	newKeyGenID, newCertID := seedRootKeyGeneration(t, f.store, f.ids, f.rootID, 2, "22", testNow(), domain.Instant{})

	mutated := false
	f.svc.deps.UnitOfWork = &mutateOnceUoW{
		inner: f.store,
		mutate: func() {
			mutated = true
			if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
				root, err := tx.PKI().GetIssuerForUpdate(context.Background(), f.rootID)
				if err != nil {
					return err
				}
				rotated, err := domain.NewAuthority(domain.AuthorityFacts{
					ID: root.ID(), Kind: root.Kind(), Name: root.Name(), ManagementParentID: root.ManagementParentID(),
					IssuanceState: root.IssuanceState(), IssuanceCertificateID: newCertID, KeyGenerationID: newKeyGenID,
					KeyAvailable: true, CertificateWindow: root.CertificateWindow(), Version: root.Version(),
				})
				if err != nil {
					return err
				}
				return tx.PKI().SaveAuthority(context.Background(), rotated, root.Version())
			}); err != nil {
				t.Fatalf("rotate root key generation mid-flight: %v", err)
			}
		},
	}

	view, err := f.svc.Create(context.Background(), authorityCreateMeta("55555555-5555-4555-9555-555555555555"), intermediateCreateCommand(f.rootID, "Post-Rotation Intermediate"))
	if !mutated {
		t.Fatal("mutateOnceUoW never ran; test is not exercising the intended race")
	}
	if err != nil {
		t.Fatalf("Create: %v (a key-generation move must trigger a silent re-prepare, not a hard failure)", err)
	}
	if f.signer.calls != 2 {
		t.Fatalf("signer.calls = %d, want 2 (one stale prep, one re-prepared under the new generation)", f.signer.calls)
	}
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		record, err := tx.PKI().GetCACertificateRecord(context.Background(), *view.IssuanceCertificateID)
		if err != nil {
			return err
		}
		if record.IssuerCACertificateID != newCertID {
			t.Fatalf("issuer_ca_certificate_id = %q, want the NEW generation's certificate %q (stale prep must have been discarded)", record.IssuerCACertificateID, newCertID)
		}
		if record.CAKeyGenerationID != newKeyGenID {
			// sanity: this is the Intermediate's OWN generation, unrelated to the parent's.
		}
		return nil
	}); err != nil {
		t.Fatalf("read ca certificate record: %v", err)
	}
}

// ---- Create: §14.8 settings-derived defaults and re-preparation ----

// TestAuthorityServiceCreateRepreparesWhenSettingsVersionChangesBetweenPrepareAndCommit
// creates a Root with NO explicit validity (so it resolves RootValidity from
// Settings) and changes the settings row's RootValidity via a UnitOfWork
// decorator right before the real commit runs. The final stored certificate
// must reflect the NEW default, proving the commit redid preparation rather
// than committing a plan built against the stale snapshot.
func TestAuthorityServiceCreateRepreparesWhenSettingsVersionChangesBetweenPrepareAndCommit(t *testing.T) {
	f := newAuthorityFixture(t)
	newValidity, err := domain.NewCalendarValidity(20, domain.ValidityUnitYears)
	if err != nil {
		t.Fatalf("new validity: %v", err)
	}
	wantWindow, err := newValidity.Window(testNow())
	if err != nil {
		t.Fatalf("want window: %v", err)
	}

	mutated := false
	f.svc.deps.UnitOfWork = &mutateOnceUoW{
		inner: f.store,
		mutate: func() {
			mutated = true
			changed := defaultTestSettingsV1()
			changed.RootValidity = newValidity
			encoded, err := EncodeSettingsV1(changed)
			if err != nil {
				t.Fatalf("encode changed settings: %v", err)
			}
			if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
				return tx.Installation().SaveSettings(context.Background(), port.Settings{
					SchemaVersion: 1, SettingsJSON: encoded, Version: 1,
				}, 0)
			}); err != nil {
				t.Fatalf("change settings mid-flight: %v", err)
			}
		},
	}

	view, err := f.svc.Create(context.Background(), authorityCreateMeta("66666666-6666-4666-9666-666666666666"), rootCreateCommand("Repriced Root"))
	if !mutated {
		t.Fatal("mutateOnceUoW never ran; test is not exercising the intended race")
	}
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if f.signer.calls != 2 {
		t.Fatalf("signer.calls = %d, want 2 (settings changed mid-flight must trigger a re-prepare)", f.signer.calls)
	}
	if !view.NotAfter.Equal(wantWindow.NotAfter()) {
		t.Fatalf("not_after = %v, want %v (the NEW RootValidity default)", view.NotAfter, wantWindow.NotAfter())
	}
}

// TestAuthorityServiceCreateReplayDoesNotPickUpChangedSettingsDefaults is
// §14.8's other required case: a request that already succeeded keeps its
// original result even after Settings changes, rather than the replay
// re-deriving against whatever is current now (docs/backend-
// implementation.md §14.8 "이미 성공한 요청 재생에는 현재 기본값을 덮지
// 않는다").
func TestAuthorityServiceCreateReplayDoesNotPickUpChangedSettingsDefaults(t *testing.T) {
	f := newAuthorityFixture(t)
	meta := authorityCreateMeta("77777777-7777-4777-9777-777777777777")
	cmd := rootCreateCommand("Stable Root")

	first, err := f.svc.Create(context.Background(), meta, cmd)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	changed := defaultTestSettingsV1()
	changed.RootValidity, err = domain.NewCalendarValidity(25, domain.ValidityUnitYears)
	if err != nil {
		t.Fatalf("new validity: %v", err)
	}
	encoded, err := EncodeSettingsV1(changed)
	if err != nil {
		t.Fatalf("encode changed settings: %v", err)
	}
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Installation().SaveSettings(context.Background(), port.Settings{SchemaVersion: 1, SettingsJSON: encoded, Version: 1}, 0)
	}); err != nil {
		t.Fatalf("change settings: %v", err)
	}

	second, err := f.svc.Create(context.Background(), meta, cmd)
	if err != nil {
		t.Fatalf("replay create: %v", err)
	}
	if !second.NotAfter.Equal(first.NotAfter) {
		t.Fatalf("replay not_after = %v, want unchanged %v (must not pick up the new RootValidity default)", second.NotAfter, first.NotAfter)
	}
	if f.signer.calls != 1 {
		t.Fatalf("signer.calls = %d, want 1 (a replay must not sign a second certificate)", f.signer.calls)
	}
}

// ---- Rename ----

func TestAuthorityServiceRenameUpdatesName(t *testing.T) {
	f := newAuthorityFixture(t)
	view, err := f.svc.Rename(context.Background(), authorityVersionMeta(0), contract.AuthorityRenameCommand{AuthorityID: f.rootID, Name: "Renamed Root"})
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if view.Name != "Renamed Root" {
		t.Fatalf("name = %q, want %q", view.Name, "Renamed Root")
	}
	if view.Version != 1 {
		t.Fatalf("version = %d, want 1", view.Version)
	}
}

func TestAuthorityServiceRenameRequiresVersion(t *testing.T) {
	f := newAuthorityFixture(t)
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: mustAdminPrincipal()}}
	_, err := f.svc.Rename(context.Background(), meta, contract.AuthorityRenameCommand{AuthorityID: f.rootID, Name: "No Version"})
	if err == nil {
		t.Fatal("want an error when no version is supplied")
	}
}

func TestAuthorityServiceRenameRejectsVersionConflict(t *testing.T) {
	f := newAuthorityFixture(t)
	_, err := f.svc.Rename(context.Background(), authorityVersionMeta(99), contract.AuthorityRenameCommand{AuthorityID: f.rootID, Name: "Stale"})
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Kind() != contract.ErrorKindConflict {
		t.Fatalf("kind = %v, want conflict", appErr.Kind())
	}
	// Kind alone does not pin the app-layer check: the store's own
	// ErrVersionConflict from a rejected SaveAuthority maps to the same
	// conflict kind, so a test that stops at Kind() cannot tell whether the
	// app actually compared authority.Version() to expectedVersion before
	// calling SaveAuthority, or skipped that and the store caught it anyway.
	if appErr.Code() != "authority_version_conflict" {
		t.Fatalf("code = %q, want authority_version_conflict", appErr.Code())
	}
}

func TestAuthorityServiceRenameRequiresAdmin(t *testing.T) {
	f := newAuthorityFixture(t)
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: contract.AnonymousPrincipal()}, ExpectedVersion: contract.WithExpectedVersion(0)}
	_, err := f.svc.Rename(context.Background(), meta, contract.AuthorityRenameCommand{AuthorityID: f.rootID, Name: "Nope"})
	if err == nil {
		t.Fatal("want an error for a non-admin Rename")
	}
}

// ---- SetIssuanceState ----

func TestAuthorityServiceSetIssuanceStateEnablesInventoryAuthority(t *testing.T) {
	f := newAuthorityFixture(t)
	created, err := f.svc.Create(context.Background(), authorityCreateMeta("88888888-8888-4888-9888-888888888888"), rootCreateCommand("Inventory Root"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.IssuanceState != domain.IssuanceStateInventory {
		t.Fatalf("precondition: issuance_state = %q, want inventory", created.IssuanceState)
	}

	view, err := f.svc.SetIssuanceState(context.Background(), authorityVersionMeta(created.Version), contract.AuthoritySetIssuanceStateCommand{AuthorityID: created.ID, State: "enabled"})
	if err != nil {
		t.Fatalf("SetIssuanceState: %v", err)
	}
	if view.IssuanceState != domain.IssuanceStateEnabled {
		t.Fatalf("issuance_state = %q, want enabled", view.IssuanceState)
	}
}

func TestAuthorityServiceSetIssuanceStateStopsEnabledAuthority(t *testing.T) {
	f := newAuthorityFixture(t)
	view, err := f.svc.SetIssuanceState(context.Background(), authorityVersionMeta(0), contract.AuthoritySetIssuanceStateCommand{AuthorityID: f.rootID, State: "stopped"})
	if err != nil {
		t.Fatalf("SetIssuanceState: %v", err)
	}
	if view.IssuanceState != domain.IssuanceStateStopped {
		t.Fatalf("issuance_state = %q, want stopped", view.IssuanceState)
	}
}

func TestAuthorityServiceSetIssuanceStateRejectsDoubleEnable(t *testing.T) {
	f := newAuthorityFixture(t)
	// f.rootID is already enabled by seedIssuableRoot.
	_, err := f.svc.SetIssuanceState(context.Background(), authorityVersionMeta(0), contract.AuthoritySetIssuanceStateCommand{AuthorityID: f.rootID, State: "enabled"})
	if err == nil {
		t.Fatal("want an error enabling an already-enabled authority")
	}
}

func TestAuthorityServiceSetIssuanceStateRejectsVersionConflict(t *testing.T) {
	f := newAuthorityFixture(t)
	_, err := f.svc.SetIssuanceState(context.Background(), authorityVersionMeta(99), contract.AuthoritySetIssuanceStateCommand{AuthorityID: f.rootID, State: "stopped"})
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Kind() != contract.ErrorKindConflict {
		t.Fatalf("kind = %v, want conflict", appErr.Kind())
	}
	if appErr.Code() != "authority_version_conflict" {
		t.Fatalf("code = %q, want authority_version_conflict", appErr.Code())
	}
}

// This is Authority's half of U05: once stopped, IssuanceService (already
// merged, out of this developer's files) refuses new Leaf issuance/renewal
// against this authority the next time it reads the row, because
// Authority.CanIssue checks issuance_state == enabled unconditionally
// (internal/domain/authority.go). Verified end-to-end here using the
// already-merged IssuanceService, since the rejection this developer's
// SetIssuanceState is responsible for producing is only meaningful if it
// actually blocks the OTHER service, not just this one's own read-back.
func TestAuthorityServiceSetIssuanceStateStoppedBlocksLeafIssuance(t *testing.T) {
	f := newAuthorityFixture(t)
	intermediate, err := f.svc.Create(context.Background(), authorityCreateMeta("99999999-9999-4999-9999-999999999999"), intermediateCreateCommand(f.rootID, "Leaf-Issuing Intermediate"))
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	if _, err := f.svc.SetIssuanceState(context.Background(), authorityVersionMeta(intermediate.Version), contract.AuthoritySetIssuanceStateCommand{AuthorityID: intermediate.ID, State: "enabled"}); err != nil {
		t.Fatalf("enable intermediate: %v", err)
	}
	if _, err := f.svc.SetIssuanceState(context.Background(), authorityVersionMeta(intermediate.Version+1), contract.AuthoritySetIssuanceStateCommand{AuthorityID: intermediate.ID, State: "stopped"}); err != nil {
		t.Fatalf("stop intermediate: %v", err)
	}

	issuanceSvc, err := NewIssuanceService(IssuanceDeps{
		CommonDeps: CommonDeps{
			UnitOfWork: f.store, ReadStore: f.store, Authorizer: f.authorizer, Clock: fixedClock{now: testNow()}, IDs: f.ids,
		},
		KeyEngine: f.keyEngine, CertificateSigner: f.signer, SerialGenerator: f.serials, ProfileValidator: noopProfileValidator{},
	})
	if err != nil {
		t.Fatalf("new issuance service: %v", err)
	}
	_, err = issuanceSvc.Issue(context.Background(), issueMutationMeta(t, "abababab-abab-4bab-9bab-abababababab"), issueCommand(intermediate.ID, "blocked-leaf"))
	if err == nil {
		t.Fatal("want issuance to be rejected once the issuer is stopped")
	}
}

// mutateOnceUoW is shared with settings_service_test.go.

// ---- §8: requireCurrentAuth is not optional ----
//
// bumpAccountAuthEpoch/disableAccount/touchAdminSession/movableClock/
// requireAuthError are shared with settings_service_test.go.

func TestAuthorityServiceRenameRejectsAuthEpochSuperseded(t *testing.T) {
	f := newAuthorityFixture(t)
	bumpAccountAuthEpoch(t, f.store)
	_, err := f.svc.Rename(context.Background(), authorityVersionMeta(0), contract.AuthorityRenameCommand{AuthorityID: f.rootID, Name: "Renamed"})
	requireAuthError(t, err, "auth_epoch_superseded")
}

func TestAuthorityServiceRenameRejectsDisabledAccount(t *testing.T) {
	f := newAuthorityFixture(t)
	disableAccount(t, f.store)
	_, err := f.svc.Rename(context.Background(), authorityVersionMeta(0), contract.AuthorityRenameCommand{AuthorityID: f.rootID, Name: "Renamed"})
	requireAuthError(t, err, "account_not_active")
}

func TestAuthorityServiceRenameRejectsIdleExpiredSession(t *testing.T) {
	f := newAuthorityFixture(t)
	touchAdminSession(t, f.store, testNow())
	clock := &movableClock{now: testNow().Add(domain.NewDuration(time.Hour + time.Second))}
	f.svc.deps.Clock = clock
	_, err := f.svc.Rename(context.Background(), authorityVersionMeta(0), contract.AuthorityRenameCommand{AuthorityID: f.rootID, Name: "Renamed"})
	requireAuthError(t, err, "session_idle_expired")
}

// SetIssuanceState calls requireCurrentAuth at its own, separate call site
// (it does not go through Rename); one representative case is enough to
// prove THIS site is wired -- the three underlying checks (epoch/state/idle)
// are already exercised in depth by Rename and Update above.
func TestAuthorityServiceSetIssuanceStateRejectsAuthEpochSuperseded(t *testing.T) {
	f := newAuthorityFixture(t)
	bumpAccountAuthEpoch(t, f.store)
	_, err := f.svc.SetIssuanceState(context.Background(), authorityVersionMeta(0), contract.AuthoritySetIssuanceStateCommand{AuthorityID: f.rootID, State: "stopped"})
	requireAuthError(t, err, "auth_epoch_superseded")
}

// TestAuthorityServiceCreateCommitRejectsAuthEpochBumpedBetweenPrepareAndCommit
// proves commitCreate's own requireCurrentAuth call (separate from the early
// replayCreateBeforePreparation probe) is real: the account's auth_epoch is
// bumped by a UnitOfWork decorator right before the real commit Write runs,
// after Create was called with a session that was genuinely live then.
func TestAuthorityServiceCreateCommitRejectsAuthEpochBumpedBetweenPrepareAndCommit(t *testing.T) {
	f := newAuthorityFixture(t)
	mutated := false
	f.svc.deps.UnitOfWork = &mutateOnceUoW{inner: f.store, mutate: func() {
		mutated = true
		bumpAccountAuthEpoch(t, f.store)
	}}
	_, err := f.svc.Create(context.Background(), authorityCreateMeta("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"), rootCreateCommand("Race Root"))
	if !mutated {
		t.Fatal("mutateOnceUoW never ran; test is not exercising the intended race")
	}
	requireAuthError(t, err, "auth_epoch_superseded")
}

// TestAuthorityServiceCreateReplayRejectsAuthEpochSupersededBeforeReturningStoredResult
// is §8's explicit rule for the early replay probe: "현재 인증/권한이 없는
// 요청은 기존 결과도 받지 못한다". B03 had exactly this class of bug --
// Renew's early replay probe returned a stored result without ever reaching
// the Authorizer, because auth was checked in a different order than the
// probe ran (see issuance.go's replayBeforePreparation doc comment). This
// test proves AuthorityService.Create's own probe checks auth FIRST: the
// account's epoch is superseded after a successful create, then the exact
// same request (same idempotency key) is replayed. It must be rejected, not
// handed the original AuthorityView, and it must be rejected before ever
// touching KeyEngine/CertificateSigner again -- if the probe's auth check
// were missing or misordered, this would either succeed with a replay or
// (worse) fall through to a full re-preparation.
func TestAuthorityServiceCreateReplayRejectsAuthEpochSupersededBeforeReturningStoredResult(t *testing.T) {
	f := newAuthorityFixture(t)
	meta := authorityCreateMeta("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff")
	cmd := rootCreateCommand("Once Root")
	if _, err := f.svc.Create(context.Background(), meta, cmd); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if f.keyEngine.generateCalls != 1 || f.signer.calls != 1 {
		t.Fatalf("precondition: generateCalls=%d signer.calls=%d, want 1/1", f.keyEngine.generateCalls, f.signer.calls)
	}

	bumpAccountAuthEpoch(t, f.store)

	_, err := f.svc.Create(context.Background(), meta, cmd)
	requireAuthError(t, err, "auth_epoch_superseded")
	if f.keyEngine.generateCalls != 1 {
		t.Fatalf("keyEngine.generateCalls = %d, want still 1 (a rejected replay must not fall through to preparation)", f.keyEngine.generateCalls)
	}
	if f.signer.calls != 1 {
		t.Fatalf("signer.calls = %d, want still 1 (a rejected replay must not sign again)", f.signer.calls)
	}
}

func TestAuthorityServiceCreateReplayRejectsDisabledAccountBeforeReturningStoredResult(t *testing.T) {
	f := newAuthorityFixture(t)
	meta := authorityCreateMeta("cccccccc-dddd-4eee-8fff-000000000000")
	cmd := rootCreateCommand("Once More Root")
	if _, err := f.svc.Create(context.Background(), meta, cmd); err != nil {
		t.Fatalf("first create: %v", err)
	}

	disableAccount(t, f.store)

	_, err := f.svc.Create(context.Background(), meta, cmd)
	requireAuthError(t, err, "account_not_active")
	if f.signer.calls != 1 {
		t.Fatalf("signer.calls = %d, want still 1 (a rejected replay must not sign again)", f.signer.calls)
	}
}
