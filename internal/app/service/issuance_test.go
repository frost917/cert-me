package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

// ---- deterministic test doubles ----
//
// fixedClock, testNow, seqIDs, caKeyID and serial are already defined in
// revocations_test.go (same package); they are reused here rather than
// redefined.

// fakeKeyEngine is a deterministic port.KeyEngine: Generate always succeeds
// (unless failNext is set) and produces a fresh, valid-shaped key tied to
// spec.KeyMaterialID, so a test can assert both the resulting certificate's
// linkage and how many times a new key was actually generated.
type fakeKeyEngine struct {
	generateCalls int
	fail          error
}

func (e *fakeKeyEngine) Generate(_ context.Context, spec port.KeySpec) (port.GeneratedKey, error) {
	e.generateCalls++
	if e.fail != nil {
		return port.GeneratedKey{}, e.fail
	}
	pub, err := domain.NewPublicKey(spec.Algorithm, []byte("pub-"+string(spec.KeyMaterialID)))
	if err != nil {
		return port.GeneratedKey{}, err
	}
	secret, err := domain.NewEncryptedSecret(domain.EncryptedSecretFacts{
		OwnerKeyID:             spec.KeyMaterialID,
		Purpose:                spec.Purpose,
		FormatVersion:          1,
		EncryptionGenerationID: "gen-1",
		Nonce:                  []byte("nonce-0123456789012"),
		Ciphertext:             []byte("ciphertext-for-" + string(spec.KeyMaterialID)),
	})
	if err != nil {
		return port.GeneratedKey{}, err
	}
	return port.GeneratedKey{PublicKey: pub, EncryptedSecret: secret}, nil
}

func (e *fakeKeyEngine) ImportCA(context.Context, port.ValidatedCAKeyInput, port.KeySpec) (port.GeneratedKey, error) {
	return port.GeneratedKey{}, errors.New("fakeKeyEngine: ImportCA not supported")
}

func (e *fakeKeyEngine) ImportTLS(context.Context, port.ValidatedTLSKeyInput, port.KeySpec) (port.GeneratedKey, error) {
	return port.GeneratedKey{}, errors.New("fakeKeyEngine: ImportTLS not supported")
}

func (e *fakeKeyEngine) Reencrypt(context.Context, domain.EncryptedSecret, port.RotationKeys) (domain.EncryptedSecret, error) {
	return domain.EncryptedSecret{}, errors.New("fakeKeyEngine: Reencrypt not supported")
}

// fakeSigner is a deterministic port.CertificateSigner. serials, when set,
// names the hex serial each successive call returns (a repeated value lets a
// test force a collision); once exhausted it falls back to a counter-derived
// serial so an unconfigured test still gets distinct values.
type fakeSigner struct {
	calls   int
	serials []string
	fail    error
}

func (s *fakeSigner) Sign(_ context.Context, plan domain.IssuancePlan, _ domain.EncryptedSecret) (domain.Certificate, error) {
	idx := s.calls
	s.calls++
	if s.fail != nil {
		return domain.Certificate{}, s.fail
	}
	hex := fmt.Sprintf("%x", 1000+idx)
	if idx < len(s.serials) {
		hex = s.serials[idx]
	}
	ser, err := domain.ParseSerialNumber(hex)
	if err != nil {
		return domain.Certificate{}, err
	}
	// signCertificate only reads DER() and Serial() off this value -- every
	// other field is rebuilt from plan/keyMaterialID by the caller (see
	// certificate.go's signCertificate doc comment on the CertificateSigner
	// contract gap) -- so the placeholder id/key material below are never
	// observed by production code, only by this fake's own constructor.
	placeholderID, _ := domain.ParseCertificateID("00000000-0000-4000-8000-000000000000")
	placeholderKey, _ := domain.ParseKeyMaterialID("00000000-0000-4000-8000-000000000001")
	return domain.NewCertificate(domain.CertificateFacts{
		ID:                      placeholderID,
		DER:                     []byte(fmt.Sprintf("der-%d-%s", idx, hex)),
		KeyMaterialID:           placeholderKey,
		IssuerCAKeyGenerationID: plan.IssuerKeyGenerationID,
		Serial:                  ser,
		Validity:                plan.Window,
		Subject:                 plan.Subject,
		SANs:                    plan.SANs,
		Kind:                    domain.CertificateKindLeaf,
		Profile:                 plan.Profile,
		KeyAlgorithm:            plan.KeyAlgorithm,
		Origin:                  domain.CertificateOriginGenerated,
	})
}

// toggleAuthorizer lets a test flip authorization between calls, simulating
// a principal that loses permission between the original request and a
// replay attempt.
type toggleAuthorizer struct{ allow bool }

func (a *toggleAuthorizer) Authorize(context.Context, contract.Principal, port.Action, port.AuthorizationScope) error {
	if a.allow {
		return nil
	}
	return contract.NewAppError(contract.ErrorKindForbidden, "not_authorized", "principal is not authorized")
}

// noopProfileValidator satisfies the required ProfileValidator dependency.
// docs/backend-implementation.md §5 lists it for Authority/Issuance, but
// port.ProfileValidator's own doc comment says the operator-configurable
// policy it would check is not yet specified anywhere -- so IssuanceService
// holds the dependency (required at construction) without calling it, and
// this fake simply always allows.
type noopProfileValidator struct{}

func (noopProfileValidator) Validate(context.Context, domain.CertificateProfile, []domain.SAN, domain.KeyAlgorithm) error {
	return nil
}

// countingSecrets wraps a port.SecretRepository to count GetEncrypted calls,
// the U05/U06 evidence that a normal renewal never reads the leaf's own
// private key.
type countingSecrets struct {
	port.SecretRepository
	log *[]domain.KeyMaterialID
}

func (c countingSecrets) GetEncrypted(ctx context.Context, keyID domain.KeyMaterialID, purpose domain.SecretPurpose) (domain.EncryptedSecret, error) {
	*c.log = append(*c.log, keyID)
	return c.SecretRepository.GetEncrypted(ctx, keyID, purpose)
}

type countingTxStores struct {
	port.TxStores
	log *[]domain.KeyMaterialID
}

func (c countingTxStores) Secrets() port.SecretRepository {
	return countingSecrets{SecretRepository: c.TxStores.Secrets(), log: c.log}
}

// countingUoW decorates both the UnitOfWork and the ReadStore so a test can
// observe every SecretRepository.GetEncrypted call a renewal makes -- on the
// preparation reads as well as inside the write, since preparation is where
// signing input is gathered (docs/backend-implementation.md §8). Without
// covering both, a leaf private-key read moved into preparation would go
// unnoticed.
type countingUoW struct {
	inner      port.UnitOfWork
	reads      port.ReadStore
	secretGets []domain.KeyMaterialID
}

func (u *countingUoW) Write(ctx context.Context, fn func(port.TxStores) error) error {
	return u.inner.Write(ctx, func(tx port.TxStores) error {
		return fn(countingTxStores{TxStores: tx, log: &u.secretGets})
	})
}

func (u *countingUoW) Read(ctx context.Context, fn func(port.TxStores) error) error {
	return u.reads.Read(ctx, func(tx port.TxStores) error {
		return fn(countingTxStores{TxStores: tx, log: &u.secretGets})
	})
}

// ---- fixture plumbing ----

const (
	issuanceTestAdminAccountID = domain.AccountID("55555555-5555-4555-8555-555555555555")
	issuanceTestSessionID      = domain.SessionID("66666666-6666-4666-8666-666666666666")
	issuanceTestIdempotencyKey = "77777777-7777-4777-8777-777777777777"
)

func issuanceAdminPrincipal(t *testing.T) contract.Principal {
	t.Helper()
	p, err := contract.NewAdminPrincipal(contract.AdminPrincipalFacts{
		AccountID: issuanceTestAdminAccountID,
		SessionID: issuanceTestSessionID,
		AuthEpoch: domain.AuthEpoch(1),
	})
	if err != nil {
		t.Fatalf("admin principal: %v", err)
	}
	return p
}

func issueMutationMeta(t *testing.T, idempotencyKey string) contract.MutationMeta {
	t.Helper()
	return contract.MutationMeta{
		RequestMeta:    contract.RequestMeta{Principal: issuanceAdminPrincipal(t)},
		IdempotencyKey: idempotencyKey,
	}
}

// seedIssuableIntermediate inserts an Intermediate authority whose own
// signing certificate and encrypted CA key are stored, so
// Authority.CanIssue succeeds and issuerSigningSecret can resolve its key
// (see issuance.go's issuerSigningSecret doc comment for why that goes
// through GetCertificate rather than a CAKeyGeneration-by-id lookup).
func seedIssuableIntermediate(t *testing.T, store *porttest.Store, ids port.IDGenerator, now domain.Instant) domain.AuthorityID {
	t.Helper()
	ctx := context.Background()

	authorityID, err := domain.ParseAuthorityID(ids.NewUUID())
	if err != nil {
		t.Fatalf("authority id: %v", err)
	}
	parentID, err := domain.ParseAuthorityID(ids.NewUUID())
	if err != nil {
		t.Fatalf("parent id: %v", err)
	}
	caKeyGenID, err := domain.ParseCAKeyGenerationID(ids.NewUUID())
	if err != nil {
		t.Fatalf("ca key generation id: %v", err)
	}
	caKeyMaterialID, err := domain.ParseKeyMaterialID(ids.NewUUID())
	if err != nil {
		t.Fatalf("ca key material id: %v", err)
	}
	caCertID, err := domain.ParseCertificateID(ids.NewUUID())
	if err != nil {
		t.Fatalf("ca certificate id: %v", err)
	}

	pub, err := domain.NewPublicKey(domain.KeyAlgorithmECDSAP256, []byte("ca-public-key-bytes-0000000000000000"))
	if err != nil {
		t.Fatalf("ca public key: %v", err)
	}
	window, err := domain.NewValidityWindow(now.Add(domain.NewDuration(-time.Hour)), now.Add(domain.NewDuration(24*365*5*time.Hour)))
	if err != nil {
		t.Fatalf("ca window: %v", err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "Test Intermediate CA"})
	if err != nil {
		t.Fatalf("ca subject: %v", err)
	}
	caCert, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      caCertID,
		DER:                     []byte("ca-cert-der"),
		KeyMaterialID:           caKeyMaterialID,
		IssuerCAKeyGenerationID: caKeyGenID,
		Serial:                  serial(t, "11"),
		Validity:                window,
		Subject:                 subject,
		Kind:                    domain.CertificateKindCA,
		KeyAlgorithm:            domain.KeyAlgorithmECDSAP256,
		Origin:                  domain.CertificateOriginGenerated,
	})
	if err != nil {
		t.Fatalf("ca certificate: %v", err)
	}
	secret, err := domain.NewEncryptedSecret(domain.EncryptedSecretFacts{
		OwnerKeyID:             caKeyMaterialID,
		Purpose:                domain.SecretPurposeCASigning,
		FormatVersion:          1,
		EncryptionGenerationID: "gen-1",
		Nonce:                  []byte("noncenoncenonce12345"),
		Ciphertext:             []byte("ca-ciphertext"),
	})
	if err != nil {
		t.Fatalf("ca secret: %v", err)
	}
	authority, err := domain.NewAuthority(domain.AuthorityFacts{
		ID:                    authorityID,
		Kind:                  domain.AuthorityKindIntermediate,
		Name:                  "Test Intermediate",
		ManagementParentID:    parentID,
		IssuanceState:         domain.IssuanceStateEnabled,
		IssuanceCertificateID: caCertID,
		KeyGenerationID:       caKeyGenID,
		KeyAvailable:          true,
		CertificateWindow:     window,
	})
	if err != nil {
		t.Fatalf("authority: %v", err)
	}

	err = store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{ID: caKeyMaterialID, PublicKey: pub, Origin: "generated"}); err != nil {
			return err
		}
		if err := tx.PKI().InsertKeyGeneration(ctx, port.CAKeyGeneration{ID: caKeyGenID, AuthorityID: authorityID, KeyMaterialID: caKeyMaterialID, GenerationNo: 1}); err != nil {
			return err
		}
		if err := tx.PKI().InsertCertificate(ctx, caCert); err != nil {
			return err
		}
		if err := tx.Secrets().InsertEncrypted(ctx, secret); err != nil {
			return err
		}
		return tx.PKI().InsertAuthority(ctx, authority)
	})
	if err != nil {
		t.Fatalf("seed authority: %v", err)
	}
	return authorityID
}

// issuanceFixture bundles one IssuanceService with its deterministic
// dependencies and the store/authority it was built against.
type issuanceFixture struct {
	store       *porttest.Store
	ids         *seqIDs
	keyEngine   *fakeKeyEngine
	signer      *fakeSigner
	authorizer  *toggleAuthorizer
	svc         *IssuanceService
	authorityID domain.AuthorityID
}

func newIssuanceFixture(t *testing.T) *issuanceFixture {
	t.Helper()
	store := porttest.NewStore()
	ids := &seqIDs{}
	authorityID := seedIssuableIntermediate(t, store, ids, testNow())

	keyEngine := &fakeKeyEngine{}
	signer := &fakeSigner{}
	authorizer := &toggleAuthorizer{allow: true}

	svc, err := NewIssuanceService(IssuanceDeps{
		CommonDeps: CommonDeps{
			UnitOfWork: store,
			ReadStore:  store,
			Authorizer: authorizer,
			Clock:      fixedClock{now: testNow()},
			IDs:        ids,
		},
		KeyEngine:         keyEngine,
		CertificateSigner: signer,
		ProfileValidator:  noopProfileValidator{},
	})
	if err != nil {
		t.Fatalf("new issuance service: %v", err)
	}
	return &issuanceFixture{store: store, ids: ids, keyEngine: keyEngine, signer: signer, authorizer: authorizer, svc: svc, authorityID: authorityID}
}

func issueCommand(authorityID domain.AuthorityID, name string) contract.IssuanceIssueCommand {
	return contract.IssuanceIssueCommand{
		Name:        name,
		AuthorityID: authorityID,
		Profile:     string(domain.CertificateProfileServerTLS),
		Subject:     contract.SubjectInput{CommonName: "leaf.example.internal"},
		SANs:        []contract.SANInput{{Type: "dns", Value: "leaf.example.internal"}},
	}
}

// ---- required tests ----

func TestIssuanceIssueDuplicateRequestReplaysStoredResult(t *testing.T) {
	f := newIssuanceFixture(t)
	meta := issueMutationMeta(t, issuanceTestIdempotencyKey)
	cmd := issueCommand(f.authorityID, "web-1")

	first, err := f.svc.Issue(context.Background(), meta, cmd)
	if err != nil {
		t.Fatalf("first issue: %v", err)
	}
	if f.signer.calls != 1 || f.keyEngine.generateCalls != 1 {
		t.Fatalf("signer calls = %d, generate calls = %d, want 1 and 1", f.signer.calls, f.keyEngine.generateCalls)
	}

	second, err := f.svc.Issue(context.Background(), meta, cmd)
	if err != nil {
		t.Fatalf("second issue: %v", err)
	}
	if second.CertificateID != first.CertificateID || second.SeriesID != first.SeriesID {
		t.Fatalf("replay = %+v, want the same result as %+v", second, first)
	}
	// Fault check: a naive implementation without idempotency replay would
	// sign and generate a second time here.
	if f.signer.calls != 1 || f.keyEngine.generateCalls != 1 {
		t.Fatalf("after replay: signer calls = %d, generate calls = %d, want them to stay 1 and 1", f.signer.calls, f.keyEngine.generateCalls)
	}
}

func TestIssuanceIssueSameKeyDifferentFieldValueConflicts(t *testing.T) {
	f := newIssuanceFixture(t)
	meta := issueMutationMeta(t, issuanceTestIdempotencyKey)
	first := issueCommand(f.authorityID, "web-1")
	if _, err := f.svc.Issue(context.Background(), meta, first); err != nil {
		t.Fatalf("first issue: %v", err)
	}

	second := issueCommand(f.authorityID, "web-1")
	second.SANs = []contract.SANInput{{Type: "dns", Value: "different.example.internal"}}
	_, err := f.svc.Issue(context.Background(), meta, second)

	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindConflict {
		t.Fatalf("err = %v, want a conflict AppError", err)
	}
	if appErr.Code() != "idempotency_key_reused" {
		t.Fatalf("code = %q, want idempotency_key_reused", appErr.Code())
	}
}

// A field OMITTED on retry must hash differently from the same field
// EXPLICITLY given the first time (docs/backend-implementation.md §11.6
// "선택값 생략은 명시값과 구별해 보존한다"), so this must also conflict
// rather than silently replay.
func TestIssuanceIssueSameKeyFieldOmissionConflicts(t *testing.T) {
	f := newIssuanceFixture(t)
	meta := issueMutationMeta(t, issuanceTestIdempotencyKey)
	first := issueCommand(f.authorityID, "web-1")
	explicitRotate := 5
	first.RotateEvery = &explicitRotate
	if _, err := f.svc.Issue(context.Background(), meta, first); err != nil {
		t.Fatalf("first issue: %v", err)
	}

	second := issueCommand(f.authorityID, "web-1")
	// RotateEvery left nil (omitted) this time.
	_, err := f.svc.Issue(context.Background(), meta, second)

	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindConflict {
		t.Fatalf("err = %v, want a conflict AppError", err)
	}
	if appErr.Code() != "idempotency_key_reused" {
		t.Fatalf("code = %q, want idempotency_key_reused", appErr.Code())
	}
}

// A settings change AFTER a request already succeeded must not affect its
// replay: the stored result (including the value resolved from Settings at
// the time) is what comes back, not a value recomputed from the new
// settings (docs/backend-implementation.md §11.6 "이미 성공한 요청의 재생은
// 당시 결과를 유지한다").
func TestIssuanceIssueSettingsChangeAfterSuccessDoesNotAffectReplay(t *testing.T) {
	f := newIssuanceFixture(t)
	meta := issueMutationMeta(t, issuanceTestIdempotencyKey)
	cmd := issueCommand(f.authorityID, "web-1") // RotateEvery/Validity omitted -> resolved from Settings/factory default

	first, err := f.svc.Issue(context.Background(), meta, cmd)
	if err != nil {
		t.Fatalf("first issue: %v", err)
	}

	// Change installation settings after the fact.
	err = f.store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Installation().SaveSettings(context.Background(), port.Settings{
			SchemaVersion: 1,
			SettingsJSON:  []byte(`{"rotate_every":9}`),
		}, 0)
	})
	if err != nil {
		t.Fatalf("save settings: %v", err)
	}

	replayed, err := f.svc.Issue(context.Background(), meta, cmd)
	if err != nil {
		t.Fatalf("replay issue: %v", err)
	}
	if replayed.CertificateID != first.CertificateID {
		t.Fatalf("replayed certificate id = %s, want %s (same result, not a new issuance)", replayed.CertificateID, first.CertificateID)
	}
	if f.signer.calls != 1 || f.keyEngine.generateCalls != 1 {
		t.Fatalf("after settings change + replay: signer calls = %d, generate calls = %d, want them to stay 1 and 1", f.signer.calls, f.keyEngine.generateCalls)
	}
}

// A principal that is no longer authorized must not receive the stored
// result either (docs/backend-implementation.md §8 "현재 인증/권한이 없는
// 요청은 기존 결과도 받지 못한다").
func TestIssuanceIssueUnauthorizedPrincipalCannotReplay(t *testing.T) {
	f := newIssuanceFixture(t)
	meta := issueMutationMeta(t, issuanceTestIdempotencyKey)
	cmd := issueCommand(f.authorityID, "web-1")

	if _, err := f.svc.Issue(context.Background(), meta, cmd); err != nil {
		t.Fatalf("first issue: %v", err)
	}

	f.authorizer.allow = false
	_, err := f.svc.Issue(context.Background(), meta, cmd)

	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("err = %v, want a forbidden AppError", err)
	}
}

// A serial collision must be resolved by re-signing (a new random serial),
// never by editing the already-signed DER's serial field.
func TestIssuanceIssueSerialCollisionRetriesWithANewSignature(t *testing.T) {
	f := newIssuanceFixture(t)
	f.signer.serials = []string{"10", "10", "20"}

	// Pre-seed a certificate that already uses serial 0x10 under this
	// issuer, so the first two signing attempts collide.
	authorityID := f.authorityID
	var issuerKeyGenID domain.CAKeyGenerationID
	err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		a, err := tx.PKI().GetIssuerForUpdate(context.Background(), authorityID)
		issuerKeyGenID = a.KeyGenerationID()
		return err
	})
	if err != nil {
		t.Fatalf("read authority: %v", err)
	}
	collidingID, _ := domain.ParseCertificateID(f.ids.NewUUID())
	collidingKeyMat, _ := domain.ParseKeyMaterialID(f.ids.NewUUID())
	subject, _ := domain.NewSubject(domain.SubjectFacts{CommonName: "colliding.example.internal"})
	window, _ := domain.NewValidityWindow(testNow(), testNow().Add(domain.NewDuration(24*time.Hour)))
	colliding, err := domain.NewCertificate(domain.CertificateFacts{
		ID: collidingID, DER: []byte("colliding-der"), KeyMaterialID: collidingKeyMat,
		IssuerCAKeyGenerationID: issuerKeyGenID, Serial: serial(t, "10"), Validity: window,
		Subject: subject, Kind: domain.CertificateKindLeaf, Profile: domain.CertificateProfileServerTLS,
		SANs:         []domain.SAN{mustSAN(t, "dns", "colliding.example.internal")},
		KeyAlgorithm: domain.KeyAlgorithmECDSAP256, Origin: domain.CertificateOriginGenerated,
	})
	if err != nil {
		t.Fatalf("colliding cert: %v", err)
	}
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.PKI().InsertCertificate(context.Background(), colliding)
	}); err != nil {
		t.Fatalf("seed colliding cert: %v", err)
	}

	meta := issueMutationMeta(t, issuanceTestIdempotencyKey)
	cmd := issueCommand(f.authorityID, "web-1")
	result, err := f.svc.Issue(context.Background(), meta, cmd)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if f.signer.calls != 3 {
		t.Fatalf("signer calls = %d, want 3 (two collisions then success)", f.signer.calls)
	}
	var finalCert domain.Certificate
	err = f.store.Read(context.Background(), func(tx port.TxStores) error {
		var readErr error
		finalCert, readErr = tx.PKI().GetCertificate(context.Background(), result.CertificateID)
		return readErr
	})
	if err != nil {
		t.Fatalf("read final certificate: %v", err)
	}
	if finalCert.Serial().Hex() != "20" {
		t.Fatalf("final serial = %s, want 20", finalCert.Serial().Hex())
	}
	// The colliding certificate's own serial must be untouched.
	if colliding.Serial().Hex() != "10" {
		t.Fatalf("colliding certificate serial changed to %s", colliding.Serial().Hex())
	}
	// Re-preparing after a collision re-signs; it must not burn a second key
	// pair (§6's expensive-work budget).
	if f.keyEngine.generateCalls != 1 {
		t.Fatalf("generate calls = %d, want 1 across all three signing attempts", f.keyEngine.generateCalls)
	}
}

// §8 requires the commit to check a signed serial against BOTH certificates
// and the revocation ledger: a serial whose certificate row is gone but
// whose revocation is on record must never be handed out again.
func TestIssuanceIssueSerialCollidingWithARevocationIsReSigned(t *testing.T) {
	f := newIssuanceFixture(t)
	f.signer.serials = []string{"10", "20"}

	authorityID := f.authorityID
	var issuerKeyGenID domain.CAKeyGenerationID
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		a, err := tx.PKI().GetIssuerForUpdate(context.Background(), authorityID)
		issuerKeyGenID = a.KeyGenerationID()
		return err
	}); err != nil {
		t.Fatalf("read authority: %v", err)
	}

	revocationID, _ := domain.ParseRevocationID(f.ids.NewUUID())
	revocation, err := domain.NewRevocation(domain.RevocationFacts{
		ID:        revocationID,
		IssuerID:  issuerKeyGenID,
		Serial:    serial(t, "10"),
		RevokedAt: testNow(),
		Reason:    domain.RevocationReasonKeyCompromise,
		Source:    domain.RevocationSourceImport,
	})
	if err != nil {
		t.Fatalf("revocation: %v", err)
	}
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Revocations().Insert(context.Background(), revocation)
	}); err != nil {
		t.Fatalf("seed revocation: %v", err)
	}

	result, err := f.svc.Issue(context.Background(), issueMutationMeta(t, issuanceTestIdempotencyKey), issueCommand(f.authorityID, "web-1"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if f.signer.calls != 2 {
		t.Fatalf("signer calls = %d, want 2 (one revoked-serial collision then success)", f.signer.calls)
	}
	var finalCert domain.Certificate
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		var readErr error
		finalCert, readErr = tx.PKI().GetCertificate(context.Background(), result.CertificateID)
		return readErr
	}); err != nil {
		t.Fatalf("read final certificate: %v", err)
	}
	if finalCert.Serial().Hex() != "20" {
		t.Fatalf("final serial = %s, want 20", finalCert.Serial().Hex())
	}
}

func mustSAN(t *testing.T, kind, value string) domain.SAN {
	t.Helper()
	s, err := domain.NewSAN(domain.SANType(kind), value)
	if err != nil {
		t.Fatalf("san: %v", err)
	}
	return s
}

// issuerRejectionCase drives the "issuer stopped/유출/만료면 발급 거부" table.
func TestIssuanceIssueRejectsWhenIssuerCannotIssue(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(domain.Authority) domain.Authority
	}{
		{"stopped", func(a domain.Authority) domain.Authority {
			stopped, err := a.StopIssuance()
			if err != nil {
				t.Fatalf("stop issuance: %v", err)
			}
			return stopped
		}},
		{"affected_by_compromise", func(a domain.Authority) domain.Authority {
			rebuilt, err := domain.NewAuthority(domain.AuthorityFacts{
				ID: a.ID(), Kind: a.Kind(), Name: a.Name(), ManagementParentID: a.ManagementParentID(),
				IssuanceState: a.IssuanceState(), IssuanceCertificateID: a.IssuanceCertificateID(),
				KeyGenerationID: a.KeyGenerationID(), KeyAvailable: a.KeyAvailable(), Affected: true,
				CertificateWindow: a.CertificateWindow(), Version: a.Version(),
			})
			if err != nil {
				t.Fatalf("rebuild affected authority: %v", err)
			}
			return rebuilt
		}},
		{"certificate_expired", func(a domain.Authority) domain.Authority {
			expired, err := domain.NewValidityWindow(testNow().Add(domain.NewDuration(-48*time.Hour)), testNow().Add(domain.NewDuration(-time.Hour)))
			if err != nil {
				t.Fatalf("expired window: %v", err)
			}
			rebuilt, err := domain.NewAuthority(domain.AuthorityFacts{
				ID: a.ID(), Kind: a.Kind(), Name: a.Name(), ManagementParentID: a.ManagementParentID(),
				IssuanceState: a.IssuanceState(), IssuanceCertificateID: a.IssuanceCertificateID(),
				KeyGenerationID: a.KeyGenerationID(), KeyAvailable: a.KeyAvailable(),
				CertificateWindow: expired, Version: a.Version(),
			})
			if err != nil {
				t.Fatalf("rebuild expired authority: %v", err)
			}
			return rebuilt
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			err := f.store.Write(context.Background(), func(tx port.TxStores) error {
				a, err := tx.PKI().GetIssuerForUpdate(context.Background(), f.authorityID)
				if err != nil {
					return err
				}
				return tx.PKI().SaveAuthority(context.Background(), tc.mutate(a), a.Version())
			})
			if err != nil {
				t.Fatalf("mutate authority: %v", err)
			}

			meta := issueMutationMeta(t, issuanceTestIdempotencyKey)
			_, err = f.svc.Issue(context.Background(), meta, issueCommand(f.authorityID, "web-1"))
			var appErr *contract.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("err = %v, want an AppError", err)
			}
			if f.signer.calls != 0 {
				t.Fatalf("signer was called %d times, want 0 for a rejected issuer", f.signer.calls)
			}
		})
	}
}

// A failure anywhere inside the single Write must leave no certificate,
// delivery, series or audit trail behind.
func TestIssuanceIssueCallbackFailureLeavesNoTraces(t *testing.T) {
	f := newIssuanceFixture(t)
	f.signer.fail = errors.New("signing backend unavailable")

	meta := issueMutationMeta(t, issuanceTestIdempotencyKey)
	_, err := f.svc.Issue(context.Background(), meta, issueCommand(f.authorityID, "web-1"))
	if err == nil {
		t.Fatal("want an error when signing fails")
	}

	if len(f.store.AuditEvents()) != 0 {
		t.Fatalf("audit events = %d, want 0 after a failed issuance", len(f.store.AuditEvents()))
	}
	// A clean retry with a fresh idempotency key must succeed without
	// colliding with anything the failed attempt might have left behind
	// (it left nothing: the whole Write rolled back).
	f.signer.fail = nil
	result, err := f.svc.Issue(context.Background(), issueMutationMeta(t, "88888888-8888-4888-8888-888888888888"), issueCommand(f.authorityID, "web-1"))
	if err != nil {
		t.Fatalf("issue after prior failure: %v", err)
	}
	if result.CertificateID == "" {
		t.Fatal("want a certificate id from the clean retry")
	}
}

// A context canceled before the commit must produce no external result and
// must not invoke the signing dependencies at all (docs/backend-
// implementation.md §10 "요청 취소가 commit 전에 발생하면 외부 결과 없이
// rollback/정리한다"). IssuanceService launches no background goroutines
// during preparation, so there is no separate resource-release path beyond
// this.
func TestIssuanceIssueCanceledContextProducesNoResult(t *testing.T) {
	f := newIssuanceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	meta := issueMutationMeta(t, issuanceTestIdempotencyKey)
	_, err := f.svc.Issue(ctx, meta, issueCommand(f.authorityID, "web-1"))

	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindUnavailable {
		t.Fatalf("err = %v, want an unavailable AppError", err)
	}
	if f.signer.calls != 0 || f.keyEngine.generateCalls != 0 {
		t.Fatalf("signer calls = %d, generate calls = %d, want 0 and 0 for a pre-canceled request", f.signer.calls, f.keyEngine.generateCalls)
	}
	if len(f.store.AuditEvents()) != 0 {
		t.Fatalf("audit events = %d, want 0", len(f.store.AuditEvents()))
	}
}

// ---- renewal ----

func renewCommand(seriesID domain.SeriesID, sourceCertID domain.CertificateID) contract.IssuanceRenewCommand {
	return contract.IssuanceRenewCommand{SeriesID: seriesID, SourceCertificateID: sourceCertID}
}

// issueThenDeliver issues a fresh series through the service and then flips
// the resulting leaf key generation's custody to client_held directly in
// the store, producing a series ready for an ordinary renewal.
func issueThenDeliver(t *testing.T, f *issuanceFixture) (domain.SeriesID, domain.CertificateID, domain.Version) {
	t.Helper()
	meta := issueMutationMeta(t, issuanceTestIdempotencyKey)
	result, err := f.svc.Issue(context.Background(), meta, issueCommand(f.authorityID, "web-1"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	var version domain.Version
	err = f.store.Write(context.Background(), func(tx port.TxStores) error {
		snapshot, err := tx.PKI().GetSeriesForUpdate(context.Background(), result.SeriesID)
		if err != nil {
			return err
		}
		delivered, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
			ID:            snapshot.CurrentKeyGeneration.ID(),
			SeriesID:      snapshot.CurrentKeyGeneration.SeriesID(),
			KeyMaterialID: snapshot.CurrentKeyGeneration.KeyMaterialID(),
			GenerationNo:  snapshot.CurrentKeyGeneration.GenerationNo(),
			RenewalCount:  snapshot.CurrentKeyGeneration.RenewalCount(),
			Custody:       domain.KeyCustodyClientHeld,
		})
		if err != nil {
			return err
		}
		if err := tx.PKI().SaveLeafKeyGeneration(context.Background(), delivered); err != nil {
			return err
		}
		version = snapshot.Series.Version()
		return nil
	})
	if err != nil {
		t.Fatalf("mark delivered: %v", err)
	}
	return result.SeriesID, result.CertificateID, version
}

// Normal renewal must never read the leaf's own encrypted private key
// (docs/backend-implementation.md §11 U05/U06 "일반 갱신에 Leaf 개인키
// 조회 0회").
func TestIssuanceRenewNeverReadsTheLeafPrivateKey(t *testing.T) {
	f := newIssuanceFixture(t)
	seriesID, certID, version := issueThenDeliver(t, f)

	counting := &countingUoW{inner: f.store, reads: f.store}
	f.svc.deps.UnitOfWork = counting
	f.svc.deps.ReadStore = counting

	leafKeyMaterialID := currentLeafKeyMaterialID(t, f, seriesID)

	meta := contract.MutationMeta{
		RequestMeta:     contract.RequestMeta{Principal: issuanceAdminPrincipal(t)},
		IdempotencyKey:  "99999999-9999-4999-8999-999999999999",
		ExpectedVersion: contract.WithExpectedVersion(version),
	}
	result, err := f.svc.Renew(context.Background(), meta, renewCommand(seriesID, certID))
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if result.KeyRotated {
		t.Fatal("want a reuse renewal, not a rotation, on the first renewal with rotate_every=3")
	}
	for _, keyID := range counting.secretGets {
		if keyID == leafKeyMaterialID {
			t.Fatal("an ordinary renewal read the leaf's own private key")
		}
	}
	if len(counting.secretGets) != 1 {
		t.Fatalf("secret reads = %v, want exactly one (the issuer's CA key)", counting.secretGets)
	}
	if f.keyEngine.generateCalls != 1 {
		// generateCalls is 1 from the original Issue call; a reuse renewal
		// must not generate a second key.
		t.Fatalf("generate calls = %d, want 1 (only from the original issuance)", f.keyEngine.generateCalls)
	}
}

func TestIssuanceRenewRotatesKeyAtTheConfiguredCadence(t *testing.T) {
	f := newIssuanceFixture(t)
	seriesID, certID, version := issueThenDeliver(t, f)

	// rotate_every defaults to 3: renewals 1 and 2 reuse, renewal 3 rotates.
	for i, wantRotated := range []bool{false, false, true} {
		meta := contract.MutationMeta{
			RequestMeta:     contract.RequestMeta{Principal: issuanceAdminPrincipal(t)},
			IdempotencyKey:  fmt.Sprintf("a0000000-0000-4000-8000-00000000000%d", i),
			ExpectedVersion: contract.WithExpectedVersion(version),
		}
		result, err := f.svc.Renew(context.Background(), meta, renewCommand(seriesID, certID))
		if err != nil {
			t.Fatalf("renew %d: %v", i, err)
		}
		if result.KeyRotated != wantRotated {
			t.Fatalf("renew %d: rotated = %v, want %v", i, result.KeyRotated, wantRotated)
		}
		if wantRotated {
			// The newly rotated key is pending delivery, not yet client_held,
			// but the test only renews once more than rotate_every here so no
			// further renewal is attempted against it.
			if result.Delivery == nil {
				t.Fatalf("renew %d: want a delivery record for the rotated key", i)
			}
		} else {
			markKeyClientHeldForCurrent(t, f.store, seriesID)
		}
		certID = result.CertificateID
		version = version.Next()
	}
}

// markKeyClientHeldForCurrent flips the series' current key generation to
// client_held so the next renewal in a loop is eligible.
func markKeyClientHeldForCurrent(t *testing.T, store *porttest.Store, seriesID domain.SeriesID) {
	t.Helper()
	err := store.Write(context.Background(), func(tx port.TxStores) error {
		snapshot, err := tx.PKI().GetSeriesForUpdate(context.Background(), seriesID)
		if err != nil {
			return err
		}
		delivered, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
			ID:            snapshot.CurrentKeyGeneration.ID(),
			SeriesID:      snapshot.CurrentKeyGeneration.SeriesID(),
			KeyMaterialID: snapshot.CurrentKeyGeneration.KeyMaterialID(),
			GenerationNo:  snapshot.CurrentKeyGeneration.GenerationNo(),
			RenewalCount:  snapshot.CurrentKeyGeneration.RenewalCount(),
			Custody:       domain.KeyCustodyClientHeld,
		})
		if err != nil {
			return err
		}
		return tx.PKI().SaveLeafKeyGeneration(context.Background(), delivered)
	})
	if err != nil {
		t.Fatalf("mark delivered: %v", err)
	}
}

// currentLeafKeyMaterialID reads the series' current leaf key material id,
// the one an ordinary renewal must never ask the secret store for.
func currentLeafKeyMaterialID(t *testing.T, f *issuanceFixture, seriesID domain.SeriesID) domain.KeyMaterialID {
	t.Helper()
	var keyID domain.KeyMaterialID
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		snapshot, err := tx.PKI().GetSeriesForUpdate(context.Background(), seriesID)
		if err != nil {
			return err
		}
		keyID = snapshot.CurrentKeyGeneration.KeyMaterialID()
		return nil
	}); err != nil {
		t.Fatalf("read series: %v", err)
	}
	return keyID
}
