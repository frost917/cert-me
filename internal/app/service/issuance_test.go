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

// fakeSigner is a deterministic port.CertificateSigner. Per §14.10 the
// signer must return exactly the identifiers/serial/subject the request
// asked for, so by default this fake faithfully echoes request back into a
// domain.Certificate -- every "wrong signer" scenario is expressed instead
// through mutateFacts, which lets a test perturb exactly one field of the
// otherwise-faithful CertificateFacts before NewCertificate builds it
// (TestSignCertificateRejectsAMismatchedResponse in certificate_test.go).
type fakeSigner struct {
	calls       int
	fail        error
	mutateFacts func(domain.CertificateFacts) domain.CertificateFacts
	// requests records every CertificateSigningRequest this fake received,
	// so a test can assert what the app actually asked to be signed (§14.10
	// "B03은 recording signer 대역으로 public key·ID·serial 전달 ... 을
	// 검사").
	requests []port.CertificateSigningRequest
}

func (s *fakeSigner) Sign(_ context.Context, request port.CertificateSigningRequest, _ domain.EncryptedSecret) (domain.Certificate, error) {
	idx := s.calls
	s.calls++
	s.requests = append(s.requests, request)
	if s.fail != nil {
		return domain.Certificate{}, s.fail
	}
	facts := domain.CertificateFacts{
		ID:                      request.CertificateID,
		DER:                     []byte(fmt.Sprintf("der-%d-%s", idx, request.Serial.Hex())),
		KeyMaterialID:           request.KeyMaterialID,
		IssuerCAKeyGenerationID: request.Plan.IssuerKeyGenerationID,
		Serial:                  request.Serial,
		Validity:                request.Plan.Window,
		Subject:                 request.Plan.Subject,
		SANs:                    request.Plan.SANs,
		Kind:                    request.Kind,
		Profile:                 request.Plan.Profile,
		KeyAlgorithm:            request.Plan.KeyAlgorithm,
		Origin:                  domain.CertificateOriginGenerated,
	}
	if s.mutateFacts != nil {
		facts = s.mutateFacts(facts)
	}
	return domain.NewCertificate(facts)
}

// fakeSerialGenerator is a deterministic port.SerialGenerator. serials, when
// set, names the hex serial each successive call returns (a repeated value
// lets a test force a signing collision); once exhausted it falls back to a
// counter-derived serial so an unconfigured test still gets distinct values.
// Splitting this out from fakeSigner reflects §14.10: the serial is minted
// by SerialGenerator *before* signing, not chosen by the signer, so a fake
// signer can no longer substitute its own serial into the response --
// signCertificate would reject that as a mismatch.
type fakeSerialGenerator struct {
	calls   int
	serials []string
	fail    error
}

func (g *fakeSerialGenerator) NewSerial(context.Context) (domain.SerialNumber, error) {
	idx := g.calls
	g.calls++
	if g.fail != nil {
		return domain.SerialNumber{}, g.fail
	}
	hex := fmt.Sprintf("%x", 1000+idx)
	if idx < len(g.serials) {
		hex = g.serials[idx]
	}
	return domain.ParseSerialNumber(hex)
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
// signing certificate, CA key generation row, CA certificate subtype record
// and encrypted CA key are all stored, so Authority.CanIssue succeeds and
// caSigningSecret can resolve its key the §14.9 way (generation -> key
// material -> ca_signing secret, with the CA certificate record checked for
// generation/key-material consistency).
func seedIssuableIntermediate(t *testing.T, store *porttest.Store, ids port.IDGenerator, now domain.Instant) domain.AuthorityID {
	t.Helper()
	return seedIssuableIntermediateWithOptions(t, store, ids, now, caSeedOptions{})
}

// caSeedOptions lets a §14.9 test seed a CA whose key generation/certificate
// consistency is already broken, instead of seedIssuableIntermediate's
// always-consistent default.
type caSeedOptions struct {
	// keyDestroyedAt, when non-zero, is stored on the ca_key_generations row
	// so caSigningSecret's KeyDestroyedAt check rejects issuance.
	keyDestroyedAt domain.Instant
	// mismatchCACertificateRecord, when true, stores the CA certificate
	// record under a CA key generation id that is NOT the authority's own,
	// so caSigningSecret's generation/certificate consistency check rejects
	// issuance.
	mismatchCACertificateRecord bool
}

func seedIssuableIntermediateWithOptions(t *testing.T, store *porttest.Store, ids port.IDGenerator, now domain.Instant, opts caSeedOptions) domain.AuthorityID {
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
		if err := tx.PKI().InsertKeyGeneration(ctx, port.CAKeyGeneration{
			ID: caKeyGenID, AuthorityID: authorityID, KeyMaterialID: caKeyMaterialID, GenerationNo: 1,
			KeyDestroyedAt: opts.keyDestroyedAt,
		}); err != nil {
			return err
		}
		if err := tx.PKI().InsertCertificate(ctx, caCert); err != nil {
			return err
		}
		// §14.9's cross-check: the CA certificate record must name this same
		// CA key generation, or caSigningSecret rejects the pair as
		// mismatched. mismatchCACertificateRecord deliberately breaks this.
		recordGenID := caKeyGenID
		if opts.mismatchCACertificateRecord {
			recordGenID = caKeyID(t, 999999)
		}
		if err := tx.PKI().InsertCACertificateRecord(ctx, port.CACertificateRecord{
			CertificateID:     caCertID,
			CAKeyGenerationID: recordGenID,
		}); err != nil {
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

// defaultTestSettingsV1 is a fully-resolved, in-range SettingsV1 snapshot
// (§14.8): every issuance test seeds one, since resolveSeriesDefaults now
// requires a validated Settings row to exist before Issue/Renew can resolve
// PrivateDeliverySeconds (there is no factory-default fallback any more).
func defaultTestSettingsV1() SettingsV1 {
	leafValidity, _ := domain.NewCalendarValidity(1, domain.ValidityUnitYears)
	rootValidity, _ := domain.NewCalendarValidity(10, domain.ValidityUnitYears)
	intermediateValidity, _ := domain.NewCalendarValidity(5, domain.ValidityUnitYears)
	return SettingsV1{
		ServiceURL:             "https://cert.example.test",
		LeafValidity:           leafValidity,
		RootValidity:           rootValidity,
		IntermediateValidity:   intermediateValidity,
		RotateEvery:            3,
		PrivateDeliverySeconds: 3 * 60 * 60,
		PublicLinkSeconds:      600,
		CRLIntervalSeconds:     43200,
		CRLValiditySeconds:     172800,
		AuditRetentionDays:     365,
	}
}

// seedDefaultSettings writes defaultTestSettingsV1 as the installation's
// service_settings row, schema_version=1, through the same EncodeSettingsV1
// codec B04's SettingsService would use to write it for real.
func seedDefaultSettings(t *testing.T, store *porttest.Store) {
	t.Helper()
	encoded, err := EncodeSettingsV1(defaultTestSettingsV1())
	if err != nil {
		t.Fatalf("encode settings: %v", err)
	}
	err = store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Installation().SaveSettings(context.Background(), port.Settings{
			SchemaVersion: 1,
			SettingsJSON:  encoded,
		}, 0)
	})
	if err != nil {
		t.Fatalf("seed settings: %v", err)
	}
}

// issuanceFixture bundles one IssuanceService with its deterministic
// dependencies and the store/authority it was built against.
type issuanceFixture struct {
	store       *porttest.Store
	ids         *seqIDs
	keyEngine   *fakeKeyEngine
	signer      *fakeSigner
	serials     *fakeSerialGenerator
	authorizer  *toggleAuthorizer
	svc         *IssuanceService
	authorityID domain.AuthorityID
}

func newIssuanceFixture(t *testing.T) *issuanceFixture {
	t.Helper()
	return newIssuanceFixtureWithCAOptions(t, caSeedOptions{})
}

func newIssuanceFixtureWithCAOptions(t *testing.T, caOpts caSeedOptions) *issuanceFixture {
	t.Helper()
	store := porttest.NewStore()
	ids := &seqIDs{}
	authorityID := seedIssuableIntermediateWithOptions(t, store, ids, testNow(), caOpts)
	seedDefaultSettings(t, store)
	seedAdminSessionForIssuance(t, store)

	keyEngine := &fakeKeyEngine{}
	signer := &fakeSigner{}
	serials := &fakeSerialGenerator{}
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
		SerialGenerator:   serials,
		ProfileValidator:  noopProfileValidator{},
	})
	if err != nil {
		t.Fatalf("new issuance service: %v", err)
	}
	return &issuanceFixture{store: store, ids: ids, keyEngine: keyEngine, signer: signer, serials: serials, authorizer: authorizer, svc: svc, authorityID: authorityID}
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
	f.serials.serials = []string{"10", "10", "20"}

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
	f.serials.serials = []string{"10", "20"}

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

// ---- §14.10: recording signer pass-through ----

// TestIssuanceIssuePassesSigningInputToTheSigner is the recording-signer
// check §14.10 explicitly calls for at the B03 level: the app must actually
// hand the signer the resolved subject public key, the app-chosen
// certificate/key material ids, the minted serial and the issuer's
// certificate -- not some placeholder the signer is expected to overwrite.
func TestIssuanceIssuePassesSigningInputToTheSigner(t *testing.T) {
	f := newIssuanceFixture(t)
	result, err := f.svc.Issue(context.Background(), issueMutationMeta(t, issuanceTestIdempotencyKey), issueCommand(f.authorityID, "web-1"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(f.signer.requests) != 1 {
		t.Fatalf("signer received %d requests, want 1", len(f.signer.requests))
	}
	got := f.signer.requests[0]
	if got.SubjectPublicKey.IsZero() {
		t.Fatal("signer did not receive a non-zero subject public key")
	}
	if string(got.CertificateID) != string(result.CertificateID) {
		t.Fatalf("signer received certificate id %s, want %s", got.CertificateID, result.CertificateID)
	}
	if got.KeyMaterialID == "" {
		t.Fatal("signer did not receive a key material id")
	}
	if got.Serial.IsZero() {
		t.Fatal("signer received a zero serial")
	}
	if got.IssuerCertificate.ID() == "" {
		t.Fatal("signer did not receive an issuer certificate")
	}
}

// ---- §14.9: destroyed/mismatched CA key generation ----

func TestIssuanceIssueRejectsWhenCAKeyGenerationIsDestroyed(t *testing.T) {
	f := newIssuanceFixtureWithCAOptions(t, caSeedOptions{keyDestroyedAt: testNow().Add(domain.NewDuration(-time.Hour))})
	_, err := f.svc.Issue(context.Background(), issueMutationMeta(t, issuanceTestIdempotencyKey), issueCommand(f.authorityID, "web-1"))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("err = %v, want a forbidden AppError", err)
	}
	if appErr.Code() != "issuance_ca_key_destroyed" {
		t.Fatalf("code = %q, want issuance_ca_key_destroyed", appErr.Code())
	}
	if f.signer.calls != 0 {
		t.Fatalf("signer was called %d times, want 0 for a destroyed CA key", f.signer.calls)
	}
}

func TestIssuanceIssueRejectsWhenCACertificateGenerationMismatches(t *testing.T) {
	f := newIssuanceFixtureWithCAOptions(t, caSeedOptions{mismatchCACertificateRecord: true})
	_, err := f.svc.Issue(context.Background(), issueMutationMeta(t, issuanceTestIdempotencyKey), issueCommand(f.authorityID, "web-1"))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("err = %v, want a forbidden AppError", err)
	}
	if appErr.Code() != "issuance_ca_certificate_generation_mismatch" {
		t.Fatalf("code = %q, want issuance_ca_certificate_generation_mismatch", appErr.Code())
	}
	if f.signer.calls != 0 {
		t.Fatalf("signer was called %d times, want 0 for a mismatched CA certificate", f.signer.calls)
	}
}

// ---- §14.2/§14.4: leaf_certificates subtype row ----

// TestIssuanceIssueStoresTheLeafCertificateRecordWithTheCertificate checks
// that the leaf subtype row lands in the same commit as the certificate,
// with the fields §14.2/§14.4 require: the CA certificate that actually
// signed it, the series/key generation it belongs to, the initial operation,
// and a non-empty policy snapshot.
func TestIssuanceIssueStoresTheLeafCertificateRecordWithTheCertificate(t *testing.T) {
	f := newIssuanceFixture(t)
	result, err := f.svc.Issue(context.Background(), issueMutationMeta(t, issuanceTestIdempotencyKey), issueCommand(f.authorityID, "web-1"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	var record port.LeafCertificateRecord
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		var readErr error
		record, readErr = tx.PKI().GetLeafCertificateRecord(context.Background(), result.CertificateID)
		return readErr
	}); err != nil {
		t.Fatalf("read leaf certificate record: %v", err)
	}
	if record.SeriesID != result.SeriesID {
		t.Fatalf("record series id = %s, want %s", record.SeriesID, result.SeriesID)
	}
	if record.LeafKeyGenerationID != result.KeyGenerationID {
		t.Fatalf("record key generation id = %s, want %s", record.LeafKeyGenerationID, result.KeyGenerationID)
	}
	if record.Operation != port.CertificateOperationInitial {
		t.Fatalf("record operation = %q, want %q", record.Operation, port.CertificateOperationInitial)
	}
	if record.PreviousCertificateID != "" {
		t.Fatalf("record previous certificate id = %q, want empty for a series' first certificate", record.PreviousCertificateID)
	}
	if record.IssuerCACertificateID == "" {
		t.Fatal("record issuer CA certificate id is empty")
	}
	if len(record.PolicySnapshotJSON) == 0 {
		t.Fatal("record policy snapshot is empty")
	}
}

// TestIssuanceIssueRollbackLeavesNoLeafCertificateRecord is the rollback
// half of the same requirement: a failure inside the Write must leave
// neither the certificate nor its subtype row behind. It is checked by
// retrying with the SAME idempotency key after fixing the signer: if the
// failed attempt had left a certificate, series or leaf_certificates row
// behind under any id, the retry would either collide with it or replay a
// half-formed result instead of running a clean, brand-new issuance.
func TestIssuanceIssueRollbackLeavesNoLeafCertificateRecord(t *testing.T) {
	f := newIssuanceFixture(t)
	f.signer.fail = errors.New("signing backend unavailable")
	meta := issueMutationMeta(t, issuanceTestIdempotencyKey)
	cmd := issueCommand(f.authorityID, "web-1")

	if _, err := f.svc.Issue(context.Background(), meta, cmd); err == nil {
		t.Fatal("want an error when signing fails")
	}
	if len(f.store.AuditEvents()) != 0 {
		t.Fatalf("audit events = %d, want 0 after a failed issuance", len(f.store.AuditEvents()))
	}

	f.signer.fail = nil
	result, err := f.svc.Issue(context.Background(), meta, cmd)
	if err != nil {
		t.Fatalf("retry with the same idempotency key after the prior failure: %v", err)
	}
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		_, err := tx.PKI().GetLeafCertificateRecord(context.Background(), result.CertificateID)
		return err
	}); err != nil {
		t.Fatalf("clean retry's leaf certificate record should exist: %v", err)
	}
}

// ---- §14.7: stored replay DTO ----

// TestIssuanceIssueReplayRereadsCurrentDeliveryStatus is the delivery half of
// §14.7's replay rule: a replayed result must report the delivery's CURRENT
// state, not whatever it was at the moment of the original commit.
func TestIssuanceIssueReplayRereadsCurrentDeliveryStatus(t *testing.T) {
	f := newIssuanceFixture(t)
	meta := issueMutationMeta(t, issuanceTestIdempotencyKey)
	cmd := issueCommand(f.authorityID, "web-1")

	first, err := f.svc.Issue(context.Background(), meta, cmd)
	if err != nil {
		t.Fatalf("first issue: %v", err)
	}
	if first.Delivery == nil || first.Delivery.State != domain.DeliveryStatePending {
		t.Fatalf("first delivery = %+v, want a pending delivery", first.Delivery)
	}

	// Mutate the delivery's stored state directly, simulating a failure
	// recorded after the original issuance committed.
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		delivery, err := tx.Delivery().GetDeliveryForUpdate(context.Background(), first.Delivery.ID)
		if err != nil {
			return err
		}
		failed, err := delivery.Fail("transfer_failed", testNow())
		if err != nil {
			return err
		}
		return tx.Delivery().SaveDelivery(context.Background(), failed, delivery.Version())
	}); err != nil {
		t.Fatalf("fail delivery: %v", err)
	}

	replayed, err := f.svc.Issue(context.Background(), meta, cmd)
	if err != nil {
		t.Fatalf("replay issue: %v", err)
	}
	if replayed.CertificateID != first.CertificateID {
		t.Fatalf("replayed certificate id = %s, want %s", replayed.CertificateID, first.CertificateID)
	}
	// Fault check: a naive replay that decoded a frozen delivery snapshot
	// from the stored result DTO would still report "pending" here.
	if replayed.Delivery == nil || replayed.Delivery.State != domain.DeliveryStateFailed {
		t.Fatalf("replayed delivery = %+v, want the current failed state", replayed.Delivery)
	}
}

// TestIssuanceReplayRejectsAnUnsupportedStoredSchemaVersion is §14.7's other
// half: a stored request result whose schema_version this code does not
// understand must be an error, not a best-effort decode under the current
// field layout.
func TestIssuanceReplayRejectsAnUnsupportedStoredSchemaVersion(t *testing.T) {
	// decodeStoredIssuanceResult is exercised directly against a hand-built
	// port.OperationRequestResult: forcing an actual bad-version row through
	// the store is not possible (StoreRequestResult always writes the
	// current schema_version, and InsertResult never overwrites an existing
	// row), so this is the unit-level guarantee that a future schema bump
	// cannot be silently reinterpreted under today's field layout.
	badResult := port.OperationRequestResult{
		InputHash:  "irrelevant",
		ResultJSON: []byte(`{"schema_version":2,"series_id":"x","certificate_id":"y","key_generation_id":"z"}`),
	}
	_, err := decodeStoredIssuanceResult(badResult)
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Code() != "issuance_stored_result_schema_unsupported" {
		t.Fatalf("err = %v, want issuance_stored_result_schema_unsupported", err)
	}
}

// ---- §14.8: Settings required for issuance ----

// TestIssuanceIssueRejectsWhenSettingsAreNotConfigured is the "초기 미설정은
// Setup의 명시적 초기화 경로로만 처리" half of §14.8: a fresh install with no
// service_settings row at all must fail Issue rather than silently apply a
// factory default.
func TestIssuanceIssueRejectsWhenSettingsAreNotConfigured(t *testing.T) {
	store := porttest.NewStore()
	ids := &seqIDs{}
	authorityID := seedIssuableIntermediate(t, store, ids, testNow())
	// Deliberately do NOT seed settings.

	seedAdminSessionForIssuance(t, store)
	svc, err := NewIssuanceService(IssuanceDeps{
		CommonDeps: CommonDeps{
			UnitOfWork: store, ReadStore: store, Authorizer: &toggleAuthorizer{allow: true},
			Clock: fixedClock{now: testNow()}, IDs: ids,
		},
		KeyEngine: &fakeKeyEngine{}, CertificateSigner: &fakeSigner{}, SerialGenerator: &fakeSerialGenerator{},
		ProfileValidator: noopProfileValidator{},
	})
	if err != nil {
		t.Fatalf("new issuance service: %v", err)
	}

	_, err = svc.Issue(context.Background(), issueMutationMeta(t, issuanceTestIdempotencyKey), issueCommand(authorityID, "web-1"))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Code() != "issuance_settings_not_configured" {
		t.Fatalf("code = %q, want issuance_settings_not_configured", appErr.Code())
	}
}

// TestIssuanceIssueRejectsCorruptSettingsRatherThanDefaulting is the "깨진
// JSON·범위 오류를 공장 기본값으로 덮지 않는다" half: a Settings row that
// exists but does not decode/validate must fail Issue rather than fall back
// to a factory default.
func TestIssuanceIssueRejectsCorruptSettingsRatherThanDefaulting(t *testing.T) {
	f := newIssuanceFixture(t)
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Installation().SaveSettings(context.Background(), port.Settings{
			SchemaVersion: 1,
			SettingsJSON:  []byte(`{not json`),
		}, 0)
	}); err != nil {
		t.Fatalf("corrupt settings: %v", err)
	}

	_, err := f.svc.Issue(context.Background(), issueMutationMeta(t, issuanceTestIdempotencyKey), issueCommand(f.authorityID, "web-1"))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Code() != "settings_json_malformed" {
		t.Fatalf("code = %q, want settings_json_malformed", appErr.Code())
	}
	if f.signer.calls != 0 {
		t.Fatalf("signer was called %d times, want 0 when settings do not decode", f.signer.calls)
	}
}

// changeSettings writes a new settings snapshot, advancing the
// service_settings row's version the way SettingsService would.
func changeSettings(t *testing.T, store *porttest.Store, mutate func(*SettingsV1)) {
	t.Helper()
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		current, err := tx.Installation().GetSettings(context.Background())
		if err != nil {
			return err
		}
		snapshot, err := DecodeSettingsV1(current)
		if err != nil {
			return err
		}
		mutate(&snapshot)
		encoded, err := EncodeSettingsV1(snapshot)
		if err != nil {
			return err
		}
		return tx.Installation().SaveSettings(context.Background(), port.Settings{
			SchemaVersion: 1,
			SettingsJSON:  encoded,
			Version:       current.Version.Next(),
		}, current.Version)
	}); err != nil {
		t.Fatalf("change settings: %v", err)
	}
}

// settingsChangingStore advances the settings row once, at the moment the
// first Write opens -- i.e. after preparation resolved its defaults and
// before the commit can store anything. That is exactly the race §14.8
// names: "설정 version이 준비 후 바뀌면 commit 전에 다시 준비하되".
type settingsChangingStore struct {
	*porttest.Store
	t       *testing.T
	once    bool
	mutate  func(*SettingsV1)
	changes int
}

func (s *settingsChangingStore) Write(ctx context.Context, fn func(port.TxStores) error) error {
	if !s.once {
		s.once = true
		s.changes++
		changeSettings(s.t, s.Store, s.mutate)
	}
	return s.Store.Write(ctx, fn)
}

// §14.8: a preparation whose settings snapshot was superseded before the
// commit is redone against the new snapshot, not committed as planned.
func TestIssuanceIssueRePreparesWhenSettingsChangeBeforeCommit(t *testing.T) {
	f := newIssuanceFixture(t)
	racing := &settingsChangingStore{Store: f.store, t: t, mutate: func(s *SettingsV1) {
		s.RotateEvery = 7
	}}
	f.svc.deps.UnitOfWork = racing

	result, err := f.svc.Issue(context.Background(), issueMutationMeta(t, issuanceTestIdempotencyKey), issueCommand(f.authorityID, "web-1"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if racing.changes != 1 {
		t.Fatalf("settings changed %d times, want exactly 1", racing.changes)
	}
	// The stored series must carry the NEW rotation policy: the first
	// preparation's policy was thrown away, not committed.
	var series domain.LeafSeries
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		snapshot, readErr := tx.PKI().GetSeriesForUpdate(context.Background(), result.SeriesID)
		series = snapshot.Series
		return readErr
	}); err != nil {
		t.Fatalf("read series: %v", err)
	}
	if got := series.Policy().RotateEvery; got != 7 {
		t.Fatalf("stored rotate_every = %d, want the post-change value 7", got)
	}
	// Re-preparation re-signs rather than reusing the stale certificate.
	if f.signer.calls != 2 {
		t.Fatalf("signer calls = %d, want 2 (one discarded preparation, one committed)", f.signer.calls)
	}
}

// seedAdminSessionForIssuance stores the account and session
// issuanceAdminPrincipal names. Issue/Renew re-check the current account
// state, auth epoch and session under lock before replaying or committing
// anything (docs/backend-implementation.md §2), so a fixture without these
// rows is not an authenticated caller at all.
func seedAdminSessionForIssuance(t *testing.T, store *porttest.Store) {
	t.Helper()
	hash, err := domain.NewPasswordHash("$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA")
	if err != nil {
		t.Fatalf("password hash: %v", err)
	}
	account, err := domain.NewAccount(domain.AccountFacts{
		ID:                  issuanceTestAdminAccountID,
		NormalizedLoginName: "admin",
		PasswordHash:        hash,
		State:               domain.AccountStateActive,
		AuthEpoch:           domain.AuthEpoch(1),
		IsGlobalAdmin:       true,
	})
	if err != nil {
		t.Fatalf("account: %v", err)
	}
	digest, err := domain.ParseFingerprint("11111111111111111111111111111111111111111111111111111111111111ab")
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	tokenHash, err := domain.NewTokenHash(digest)
	if err != nil {
		t.Fatalf("token hash: %v", err)
	}
	session, err := domain.NewSessionState(domain.SessionStateFacts{
		ID:                issuanceTestSessionID,
		AccountID:         issuanceTestAdminAccountID,
		TokenHash:         tokenHash,
		AuthEpoch:         domain.AuthEpoch(1),
		LastSeenAt:        testNow(),
		AbsoluteExpiresAt: testNow().Add(domain.NewDuration(24 * time.Hour)),
	})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		if err := tx.Accounts().InsertAccount(context.Background(), account); err != nil {
			return err
		}
		return tx.Accounts().InsertSession(context.Background(), session)
	}); err != nil {
		t.Fatalf("seed admin session: %v", err)
	}
}
