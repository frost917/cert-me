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
	"cert-me/internal/secret"
)

// ---- test doubles specific to TLSService ---------------------------------
//
// fixedClock, movableClock, seqIDs, testNow, serial, mustID, mustAdminPrincipal,
// touchAdminSession, bumpAccountAuthEpoch, requireAuthError, requireAppError,
// fakeKeyEngine, fakeSigner, fakeSerialGenerator, toggleAuthorizer,
// signerAdvancingClock, seedDefaultSettings and seedIssuableIntermediate are
// all already defined elsewhere in this package (revocations_test.go,
// authtime_test.go, settings_service_test.go, issuance_test.go,
// transition_test.go, importing_test.go) and reused here rather than
// redefined.

// fakeChainValidator (port.ChainValidator) is already defined in
// importing_test.go and reused here rather than redefined.

// ---- UploadCandidate's own PKIParser/KeyEngine doubles -------------------
//
// importing_test.go's fakePKIParser cannot be reused as-is: its
// ParseInternalTLSKey unconditionally errors ("not supported"), since
// ImportService never calls it. tlsFakePKIParser below is this file's own
// double, matching the same "register facts for these exact input bytes"
// idiom fakePKIParser.addCert uses, but with a working ParseInternalTLSKey.
// Likewise issuance_test.go's fakeKeyEngine.ImportTLS is permanently
// unsupported (no other B04 fixture needs it); tlsImportingKeyEngine wraps
// it to add a working ImportTLS without touching issuance_test.go, a file
// outside this developer's assigned scope.

// tlsFakeKeyRecipe is what tlsFakePKIParser mints a *secret.Input from on
// each ParseInternalTLSKey call -- a recipe, not a pre-built secret.Input,
// because a real secret.Input is single-use (closed once by its owner) and
// a fixture may exercise the same registered key across more than one call.
type tlsFakeKeyRecipe struct {
	plaintext []byte
	publicKey domain.PublicKey
	algorithm domain.KeyAlgorithm
}

type tlsFakePKIParser struct {
	certs   map[string]port.CertificateBundleFacts
	keys    map[string]tlsFakeKeyRecipe
	certErr error
	keyErr  error

	// lastMintedKey is the exact *secret.Input the most recent successful
	// ParseInternalTLSKey call handed back, kept so a test can prove
	// UploadCandidate actually closed it (§10/§13 ruling 4) by calling
	// .Use() on this SAME instance afterward and observing secret.ErrClosed.
	lastMintedKey *secret.Input
}

func newTLSFakePKIParser() *tlsFakePKIParser {
	return &tlsFakePKIParser{certs: map[string]port.CertificateBundleFacts{}, keys: map[string]tlsFakeKeyRecipe{}}
}

func (p *tlsFakePKIParser) registerLeaf(data []byte, facts port.ParsedCertificateFacts) {
	facts.DER = data
	p.certs[string(data)] = port.CertificateBundleFacts{Certificates: []port.ParsedCertificateFacts{facts}}
}

func (p *tlsFakePKIParser) registerChain(data []byte, certs ...port.ParsedCertificateFacts) {
	p.certs[string(data)] = port.CertificateBundleFacts{Certificates: certs}
}

func (p *tlsFakePKIParser) registerKey(data []byte, recipe tlsFakeKeyRecipe) {
	p.keys[string(data)] = recipe
}

func (p *tlsFakePKIParser) ParseCertificateBundle(_ context.Context, input port.CertificateBundleInput) (port.CertificateBundleFacts, error) {
	if p.certErr != nil {
		return port.CertificateBundleFacts{}, p.certErr
	}
	b, ok := p.certs[string(input.Data)]
	if !ok {
		return port.CertificateBundleFacts{}, errors.New("tlsFakePKIParser: no certificate bundle registered for this data")
	}
	return b, nil
}

func (p *tlsFakePKIParser) ParseCRL(context.Context, port.CRLInput) (port.ParsedCRLFacts, error) {
	return port.ParsedCRLFacts{}, errors.New("tlsFakePKIParser: ParseCRL not supported")
}

func (p *tlsFakePKIParser) ParseCAKey(context.Context, port.CAKeyInput) (port.ValidatedCAKeyInput, error) {
	return port.ValidatedCAKeyInput{}, errors.New("tlsFakePKIParser: ParseCAKey not supported")
}

// ParseInternalTLSKey mints a FRESH *secret.Input on every call (never
// reused across calls, matching a real parser), and checks
// input.ExpectedPublicKey against the registered recipe's public key --
// the same "internal_tls 목적과 인증서 공개키 일치를 검증한다" (§13 ruling 4)
// a real parser performs.
func (p *tlsFakePKIParser) ParseInternalTLSKey(_ context.Context, input port.TLSKeyInput) (port.ValidatedTLSKeyInput, error) {
	if p.keyErr != nil {
		return port.ValidatedTLSKeyInput{}, p.keyErr
	}
	recipe, ok := p.keys[string(input.Data)]
	if !ok {
		return port.ValidatedTLSKeyInput{}, errors.New("tlsFakePKIParser: no key registered for this data")
	}
	if !input.ExpectedPublicKey.Equal(recipe.publicKey) {
		return port.ValidatedTLSKeyInput{}, errors.New("tlsFakePKIParser: key does not match the certificate's public key")
	}
	minted := secret.New(append([]byte(nil), recipe.plaintext...))
	p.lastMintedKey = minted
	return port.ValidatedTLSKeyInput{PrivateKey: minted, Algorithm: recipe.algorithm, PublicKey: recipe.publicKey}, nil
}

var _ port.PKIParser = (*tlsFakePKIParser)(nil)

// tlsImportingKeyEngine wraps a *fakeKeyEngine (whose own ImportTLS is
// permanently unsupported) to give UploadCandidate's tests a working
// ImportTLS, without modifying issuance_test.go. Generate/ImportCA/Reencrypt
// are promoted straight through to the embedded fakeKeyEngine, so existing
// fixture fields/counters (f.keyEngine.generateCalls etc.) keep working
// unchanged for IssueCandidate's tests.
type tlsImportingKeyEngine struct {
	*fakeKeyEngine
	importCalls int
	importFail  error
}

func (e *tlsImportingKeyEngine) ImportTLS(_ context.Context, input port.ValidatedTLSKeyInput, spec port.KeySpec) (port.GeneratedKey, error) {
	e.importCalls++
	if e.importFail != nil {
		return port.GeneratedKey{}, e.importFail
	}
	encrypted, err := domain.NewEncryptedSecret(domain.EncryptedSecretFacts{
		OwnerKeyID: spec.KeyMaterialID, Purpose: spec.Purpose, FormatVersion: 1,
		EncryptionGenerationID: "gen-1", Nonce: []byte("nonce-uploadupload01"),
		Ciphertext: []byte("ciphertext-for-" + string(spec.KeyMaterialID)),
	})
	if err != nil {
		return port.GeneratedKey{}, err
	}
	return port.GeneratedKey{PublicKey: input.PublicKey, EncryptedSecret: encrypted}, nil
}

var _ port.KeyEngine = (*tlsImportingKeyEngine)(nil)

// tlsPrepEntry is what fakeTLSInstaller's private registry keeps for one
// handle, mirroring the shape port_test's fakeInstaller (tls_prepare_seal_test.go)
// uses for the same reason: PreparedTLSConfig itself carries no payload, so
// the config has to live in the installer's own map, keyed by the handle's
// opaque ID().
type tlsPrepEntry struct {
	candidateID domain.TLSVersionID
	marker      string
}

// fakeTLSInstaller is this file's own port.TLSInstaller double (there is no
// reusable one in porttest -- see this file's package-comment-adjacent note;
// port_test's fakeInstaller in tls_prepare_seal_test.go lives in a different,
// internal test package and cannot be imported here).
//
// selfCleanOnFailure defaults to true, matching the documented contract
// ("실패 시 registry 항목을 제거하되 기존 listener를 유지한다"). Some tests
// flip it to false deliberately: a compliant installer already cleans up
// its own failed Apply, which would let TLSService's own
// `defer Discard(prepared)` line be deleted without any test noticing a
// leak. Setting selfCleanOnFailure=false models an installer whose Apply
// outcome is genuinely ambiguous (the commit_unknown-shaped case) and
// isolates what the SERVICE's own deferred Discard call is responsible for,
// independent of how tidy a particular installer implementation happens to
// be.
type fakeTLSInstaller struct {
	token    port.TLSPrepareToken
	registry map[any]tlsPrepEntry

	prepareErr         error
	applyErr           error
	applyPanic         bool
	selfCleanOnFailure bool

	prepareCount    int
	applyCount      int
	discardCalls    int
	discardReleased int

	lastAppliedCandidateID domain.TLSVersionID
	lastAppliedMarker      string
}

var _ port.TLSInstaller = (*fakeTLSInstaller)(nil)

func newFakeTLSInstaller() *fakeTLSInstaller {
	return &fakeTLSInstaller{
		token:              port.NewTLSPrepareToken(),
		registry:           map[any]tlsPrepEntry{},
		selfCleanOnFailure: true,
	}
}

func (f *fakeTLSInstaller) prepared() int { return len(f.registry) }

func (f *fakeTLSInstaller) Prepare(_ context.Context, candidate domain.TLSVersion, _ domain.EncryptedSecret) (port.PreparedTLSConfig, error) {
	f.prepareCount++
	if f.prepareErr != nil {
		return port.PreparedTLSConfig{}, f.prepareErr
	}
	handle := port.NewPreparedTLSConfig(f.token)
	f.registry[handle.ID()] = tlsPrepEntry{candidateID: candidate.ID(), marker: fmt.Sprintf("cfg-%d", f.prepareCount)}
	return handle, nil
}

func (f *fakeTLSInstaller) Apply(_ context.Context, prepared port.PreparedTLSConfig) error {
	if !f.token.Verify(prepared) {
		return errors.New("fakeTLSInstaller: handle was not produced by this installer")
	}
	entry, ok := f.registry[prepared.ID()]
	if !ok {
		return errors.New("fakeTLSInstaller: handle has no registered configuration")
	}
	if f.applyPanic {
		// Deliberately panics BEFORE removing the registry entry -- this is
		// the one gap in the handle's lifecycle that only a caller's own
		// deferred Discard can close, since Apply itself never reaches its
		// own cleanup code on this path.
		panic("fakeTLSInstaller: simulated apply panic")
	}
	if f.applyErr != nil {
		if f.selfCleanOnFailure {
			delete(f.registry, prepared.ID())
		}
		return f.applyErr
	}
	delete(f.registry, prepared.ID())
	f.applyCount++
	f.lastAppliedCandidateID = entry.candidateID
	f.lastAppliedMarker = entry.marker
	return nil
}

func (f *fakeTLSInstaller) Discard(prepared port.PreparedTLSConfig) {
	f.discardCalls++
	if !f.token.Verify(prepared) {
		return
	}
	if _, ok := f.registry[prepared.ID()]; ok {
		delete(f.registry, prepared.ID())
		f.discardReleased++
	}
}

// ---- fixture plumbing ------------------------------------------------

type tlsFixture struct {
	store       *porttest.Store
	ids         *seqIDs
	keyEngine   *fakeKeyEngine
	importer    *tlsImportingKeyEngine
	signer      *fakeSigner
	serials     *fakeSerialGenerator
	chain       *fakeChainValidator
	installer   *fakeTLSInstaller
	parser      *tlsFakePKIParser
	authorizer  *toggleAuthorizer
	svc         *TLSService
	authorityID domain.AuthorityID
}

func seedInstallationRow(t *testing.T, store *porttest.Store) {
	t.Helper()
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Installation().Save(context.Background(), port.Installation{Version: 0}, 0)
	}); err != nil {
		t.Fatalf("seed installation row: %v", err)
	}
}

func newTLSFixture(t *testing.T) *tlsFixture {
	t.Helper()
	store := porttest.NewStore()
	ids := &seqIDs{}
	authorityID := seedIssuableIntermediate(t, store, ids, testNow())
	seedDefaultSettings(t, store)
	seedAdminSessionForIssuance(t, store)
	seedInstallationRow(t, store)

	keyEngine := &fakeKeyEngine{}
	importer := &tlsImportingKeyEngine{fakeKeyEngine: keyEngine}
	signer := &fakeSigner{}
	serials := &fakeSerialGenerator{}
	chain := &fakeChainValidator{}
	installer := newFakeTLSInstaller()
	parser := newTLSFakePKIParser()
	authorizer := &toggleAuthorizer{allow: true}

	svc, err := NewTLSService(TLSDeps{
		CommonDeps: CommonDeps{
			UnitOfWork: store,
			ReadStore:  store,
			Authorizer: authorizer,
			Clock:      fixedClock{now: testNow()},
			IDs:        ids,
		},
		KeyEngine:         importer,
		CertificateSigner: signer,
		SerialGenerator:   serials,
		ChainValidator:    chain,
		TLSInstaller:      installer,
		PKIParser:         parser,
	})
	if err != nil {
		t.Fatalf("new tls service: %v", err)
	}
	return &tlsFixture{
		store: store, ids: ids, keyEngine: keyEngine, importer: importer, signer: signer, serials: serials,
		chain: chain, installer: installer, parser: parser, authorizer: authorizer, svc: svc, authorityID: authorityID,
	}
}

func tlsIssueCommand(authorityID domain.AuthorityID, cn string) contract.TLSIssueCandidateCommand {
	return contract.TLSIssueCandidateCommand{
		AuthorityID: authorityID,
		Subject:     contract.SubjectInput{CommonName: cn},
		SANs:        []contract.SANInput{{Type: "dns", Value: "cert.example.test"}},
	}
}

func tlsIssueMeta(idempotencyKey string) contract.MutationMeta {
	return contract.MutationMeta{
		RequestMeta:    contract.RequestMeta{Principal: mustAdminPrincipal()},
		IdempotencyKey: idempotencyKey,
	}
}

func tlsActivateMeta(version domain.Version) contract.MutationMeta {
	return contract.MutationMeta{
		RequestMeta:     contract.RequestMeta{Principal: mustAdminPrincipal()},
		ExpectedVersion: contract.WithExpectedVersion(version),
	}
}

func tlsStatusQueryMeta() contract.RequestMeta {
	return contract.RequestMeta{Principal: mustAdminPrincipal()}
}

func mustInternalPrincipal(t *testing.T, op contract.InternalOperation) contract.Principal {
	t.Helper()
	factory, err := contract.NewInternalPrincipalFactory(op)
	if err != nil {
		t.Fatalf("internal principal factory: %v", err)
	}
	p, err := factory.Principal(op)
	if err != nil {
		t.Fatalf("internal principal: %v", err)
	}
	return p
}

func tlsReconcileMeta(principal contract.Principal) contract.MutationMeta {
	return contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: principal}}
}

func (f *tlsFixture) issueCandidate(t *testing.T, idempotencyKey, cn string) contract.TLSVersionView {
	t.Helper()
	view, err := f.svc.IssueCandidate(context.Background(), tlsIssueMeta(idempotencyKey), tlsIssueCommand(f.authorityID, cn))
	if err != nil {
		t.Fatalf("IssueCandidate(%s): %v", cn, err)
	}
	return view
}

func (f *tlsFixture) activate(t *testing.T, candidateID domain.TLSVersionID, expectedVersion domain.Version) (contract.TLSStatusView, error) {
	t.Helper()
	return f.svc.Activate(context.Background(), tlsActivateMeta(expectedVersion), contract.TLSActivateCommand{CandidateID: candidateID})
}

func (f *tlsFixture) mustActivate(t *testing.T, candidateID domain.TLSVersionID, expectedVersion domain.Version) contract.TLSStatusView {
	t.Helper()
	view, err := f.activate(t, candidateID, expectedVersion)
	if err != nil {
		t.Fatalf("Activate(%s): %v", candidateID, err)
	}
	return view
}

func (f *tlsFixture) status(t *testing.T) contract.TLSStatusView {
	t.Helper()
	view, err := f.svc.Status(context.Background(), tlsStatusQueryMeta(), contract.TLSStatusQuery{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	return view
}

// requireErr asserts err is an *contract.AppError of exactly kind/code --
// used throughout this file so a version conflict, a validation failure and
// an internal-operation rejection are each pinned to their own stable code,
// not just their broad Kind() (per the assignment's "version 충돌은 Kind()가
// 아니라 오류 코드까지 단언" rule, applied here to every category of error
// this file checks, not only version conflicts).
func requireErr(t *testing.T, err error, kind contract.ErrorKind, code string) {
	t.Helper()
	appErr := requireAppError(t, err)
	if appErr.Kind() != kind {
		t.Fatalf("kind = %s (code %q), want %s", appErr.Kind(), appErr.Code(), kind)
	}
	if appErr.Code() != code {
		t.Fatalf("code = %q, want %q", appErr.Code(), code)
	}
}

// ---- direct low-level seeding for Reconcile's restart-recovery tests -----

// seedTLSVersionWithSecret inserts a standalone, bootstrap-sourced
// TLSVersion plus its encrypted internal_tls key, independent of
// IssueCandidate. Bootstrap source is used deliberately to keep these
// fixtures self-contained: buildValidationFacts' non-managed branch trusts
// the stored chain_bundle directly rather than resolving a PKI certificate
// chain, and a bootstrap candidate's ServiceAddressMatches is forced true by
// domain policy, so this helper needs no CA/certificate rows at all -- only
// TLSRepository/SecretRepository, matching the two ports Reconcile actually
// exercises here.
func seedTLSVersionWithSecret(t *testing.T, store *porttest.Store, ids port.IDGenerator, notAfter domain.Instant, marker string) domain.TLSVersionID {
	t.Helper()
	ctx := context.Background()
	versionID := mustID(t, ids, domain.ParseTLSVersionID)
	keyMaterialID := mustID(t, ids, domain.ParseKeyMaterialID)
	version, err := domain.NewTLSVersion(domain.TLSVersionFacts{
		ID: versionID, Source: domain.TLSSourceBootstrap, KeyMaterialID: keyMaterialID,
		LeafDER: []byte("leaf-der-" + marker), NotAfter: notAfter,
	})
	if err != nil {
		t.Fatalf("new tls version %s: %v", marker, err)
	}
	secret, err := domain.NewEncryptedSecret(domain.EncryptedSecretFacts{
		OwnerKeyID: keyMaterialID, Purpose: domain.SecretPurposeInternalTLS, FormatVersion: 1,
		EncryptionGenerationID: "gen-1", Nonce: []byte("noncenoncenonce12345"), Ciphertext: []byte("ciphertext-" + marker),
	})
	if err != nil {
		t.Fatalf("new secret %s: %v", marker, err)
	}
	if err := store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.TLS().InsertVersion(ctx, version); err != nil {
			return err
		}
		return tx.Secrets().InsertEncrypted(ctx, secret)
	}); err != nil {
		t.Fatalf("seed tls version %s: %v", marker, err)
	}
	return versionID
}

// seedRecoveryRequiredChange models a process restart after Activate's own
// "applied 기록 실패를 포함한 불명확한 변경" ambiguity (§9): the installation
// row's active pointer was already moved to candidateID (that DB write
// happened and is durable -- it is what makes the change ambiguous rather
// than simply failed), but the tls_changes row never advanced past
// recovery_required, exactly the state markRecoveryRequired leaves behind.
func seedRecoveryRequiredChange(t *testing.T, store *porttest.Store, candidateID, previousID domain.TLSVersionID) {
	t.Helper()
	ctx := context.Background()

	if previousID != "" {
		// port.TLSRepository.SetActive's own contract requires versionID to
		// already exist in BOTH the version and change tables (rollbackActivation's
		// doc comment in tls.go spells this out) -- which is realistic, not
		// an artifact of this fixture: the previous version could only have
		// become "previous" by having been the active, applied version at
		// some earlier point, so it always has its own terminal TLSChange
		// row in a real installation. Reconcile's rollback path needs this
		// row to exist for the exact same reason a real SetActive would.
		previousChange, err := domain.NewTLSChange(domain.TLSChangeFacts{
			CandidateVersionID: previousID, Phase: domain.TLSChangePhaseApplied, Validated: true,
		})
		if err != nil {
			t.Fatalf("new previous tls change: %v", err)
		}
		if err := store.Write(ctx, func(tx port.TxStores) error {
			return tx.TLS().SaveChange(ctx, previousChange, 0)
		}); err != nil {
			t.Fatalf("seed previous applied change: %v", err)
		}
	}

	change, err := domain.NewTLSChange(domain.TLSChangeFacts{
		PreviousVersionID: previousID, CandidateVersionID: candidateID,
		Phase: domain.TLSChangePhaseRecoveryRequired, Validated: true, ErrorCode: "tls_applied_record_failed",
	})
	if err != nil {
		t.Fatalf("new tls change: %v", err)
	}
	if err := store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.TLS().SaveChange(ctx, change, 0); err != nil {
			return err
		}
		inst, err := tx.Installation().GetForUpdate(ctx)
		if err != nil {
			return err
		}
		original := inst.Version
		inst.ActiveTLSVersionID = candidateID
		inst.Version = inst.Version.Next()
		return tx.Installation().Save(ctx, inst, original)
	}); err != nil {
		t.Fatalf("seed recovery_required change: %v", err)
	}
}

// ---- Status ------------------------------------------------------------

func TestTLSServiceStatusRequiresAdmin(t *testing.T) {
	f := newTLSFixture(t)
	_, err := f.svc.Status(context.Background(), contract.RequestMeta{Principal: contract.AnonymousPrincipal()}, contract.TLSStatusQuery{})
	requireErr(t, err, contract.ErrorKindForbidden, "tls_requires_admin")
}

func TestTLSServiceStatusReportsFreshInstallationAsEmpty(t *testing.T) {
	f := newTLSFixture(t)
	view := f.status(t)
	if view.Active != nil || view.Phase != nil || view.CandidateID != nil {
		t.Fatalf("fresh installation status = %+v, want no active version", view)
	}
}

// ---- IssueCandidate ------------------------------------------------------

const tlsIdemKeyA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
const tlsIdemKeyB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

func TestTLSServiceIssueCandidateStoresManagedCandidate(t *testing.T) {
	f := newTLSFixture(t)
	view := f.issueCandidate(t, tlsIdemKeyA, "tls-1")

	if view.Source != domain.TLSSourceManaged {
		t.Fatalf("source = %q, want managed", view.Source)
	}
	if view.CertificateID == nil || *view.CertificateID == "" {
		t.Fatalf("view has no certificate id: %+v", view)
	}
	if view.ValidatedServiceURL != "https://cert.example.test" {
		t.Fatalf("validated service url = %q, want the settings service url (SAN matched it)", view.ValidatedServiceURL)
	}
}

// TestTLSServiceIssueCandidateRequiresAdmin is U13-adjacent groundwork: a
// non-admin principal must never reach the expensive signing path at all.
func TestTLSServiceIssueCandidateRequiresAdmin(t *testing.T) {
	f := newTLSFixture(t)
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: contract.AnonymousPrincipal()}, IdempotencyKey: tlsIdemKeyA}
	_, err := f.svc.IssueCandidate(context.Background(), meta, tlsIssueCommand(f.authorityID, "tls-1"))
	requireErr(t, err, contract.ErrorKindForbidden, "tls_requires_admin")
	if f.signer.calls != 0 {
		t.Fatalf("signer was called for a non-admin request: %d calls", f.signer.calls)
	}
}

// TestTLSServiceIssueCandidateReplaysStoredResult is the idempotency
// contract §3 requires of IssueCandidate: retrying the same request under
// the same key/input must return the SAME candidate, not mint a second one.
func TestTLSServiceIssueCandidateReplaysStoredResult(t *testing.T) {
	f := newTLSFixture(t)
	first := f.issueCandidate(t, tlsIdemKeyA, "tls-1")
	second := f.issueCandidate(t, tlsIdemKeyA, "tls-1")

	if first.ID != second.ID {
		t.Fatalf("replay minted a different candidate: first=%s second=%s", first.ID, second.ID)
	}
	if f.signer.calls != 1 {
		t.Fatalf("signer calls = %d, want exactly 1 (replay must not re-sign)", f.signer.calls)
	}
}

// TestTLSServiceIssueCandidateNeverCreatesALeafDeliveryOrGrant is U13's
// fourth required scenario: internal TLS issuance must produce zero ordinary
// Leaf delivery/grant rows, structurally (§5 "계획의 custody가 처음부터
// internal이며 response에 download grant가 없다"), not merely by omission
// that a later refactor could silently reintroduce. This wraps the real
// store's DeliveryRepository so every InsertDelivery/InsertGrant call --
// on either the Write or the preparation Read path -- is counted directly,
// the same wrapping idiom issuance_test.go's countingSecrets/countingTxStores
// use for the parallel U05/U06 "no private key read" property.
func TestTLSServiceIssueCandidateNeverCreatesALeafDeliveryOrGrant(t *testing.T) {
	f := newTLSFixture(t)
	counter := &countingDeliveryUoW{inner: f.store, reads: f.store}
	svc, err := NewTLSService(TLSDeps{
		CommonDeps: CommonDeps{
			UnitOfWork: counter, ReadStore: counter, Authorizer: f.authorizer,
			Clock: fixedClock{now: testNow()}, IDs: f.ids,
		},
		KeyEngine: f.importer, CertificateSigner: f.signer, SerialGenerator: f.serials,
		ChainValidator: f.chain, TLSInstaller: f.installer, PKIParser: f.parser,
	})
	if err != nil {
		t.Fatalf("new tls service: %v", err)
	}

	_, err = svc.IssueCandidate(context.Background(), tlsIssueMeta(tlsIdemKeyA), tlsIssueCommand(f.authorityID, "tls-1"))
	if err != nil {
		t.Fatalf("IssueCandidate: %v", err)
	}
	if counter.inserts != 0 {
		t.Fatalf("IssueCandidate made %d Delivery/Grant insert calls, want 0 (internal custody must never create a leaf delivery)", counter.inserts)
	}
}

type countingDeliveries struct {
	port.DeliveryRepository
	inserts *int
}

func (c countingDeliveries) InsertDelivery(ctx context.Context, d domain.Delivery) error {
	*c.inserts++
	return c.DeliveryRepository.InsertDelivery(ctx, d)
}

func (c countingDeliveries) InsertGrant(ctx context.Context, g domain.DownloadGrant) error {
	*c.inserts++
	return c.DeliveryRepository.InsertGrant(ctx, g)
}

type countingDeliveryTxStores struct {
	port.TxStores
	inserts *int
}

func (c countingDeliveryTxStores) Delivery() port.DeliveryRepository {
	return countingDeliveries{DeliveryRepository: c.TxStores.Delivery(), inserts: c.inserts}
}

type countingDeliveryUoW struct {
	inner   port.UnitOfWork
	reads   port.ReadStore
	inserts int
}

func (u *countingDeliveryUoW) Write(ctx context.Context, fn func(port.TxStores) error) error {
	return u.inner.Write(ctx, func(tx port.TxStores) error { return fn(countingDeliveryTxStores{TxStores: tx, inserts: &u.inserts}) })
}

func (u *countingDeliveryUoW) Read(ctx context.Context, fn func(port.TxStores) error) error {
	return u.reads.Read(ctx, func(tx port.TxStores) error { return fn(countingDeliveryTxStores{TxStores: tx, inserts: &u.inserts}) })
}

// ---- IssueCandidate: auth re-check ---------------------------------------
//
// Every case below reproduces one of the two ways a session that was live
// when the request STARTED can stop being live before it finishes,
// mirroring authtime_test.go's precedent for IssuanceService and
// authority_test.go/settings_service_test.go's for the other B04 admin
// services. A planning-team fault injection found every earlier B04 service
// initially shipped without this coverage; these tests exist so the same
// finding cannot recur silently for TLSService.

func TestTLSServiceIssueCandidateRejectsIdleExpiredSessionAtReplay(t *testing.T) {
	f := newTLSFixture(t)
	touchAdminSession(t, f.store, testNow())
	f.svc.deps.Clock = &movableClock{now: testNow().Add(domain.NewDuration(time.Hour + time.Second))}

	_, err := f.svc.IssueCandidate(context.Background(), tlsIssueMeta(tlsIdemKeyA), tlsIssueCommand(f.authorityID, "tls-1"))
	requireAuthError(t, err, "session_idle_expired")
	if f.signer.calls != 0 {
		t.Fatalf("signer was called for an idle-expired session: %d calls", f.signer.calls)
	}
}

func TestTLSServiceIssueCandidateRejectsAuthEpochSupersededAtReplay(t *testing.T) {
	f := newTLSFixture(t)
	bumpAccountAuthEpoch(t, f.store)

	_, err := f.svc.IssueCandidate(context.Background(), tlsIssueMeta(tlsIdemKeyA), tlsIssueCommand(f.authorityID, "tls-1"))
	requireAuthError(t, err, "auth_epoch_superseded")
	if f.signer.calls != 0 {
		t.Fatalf("signer was called for a superseded epoch: %d calls", f.signer.calls)
	}
}

// TestTLSServiceIssueCandidateRejectsSessionThatExpiresDuringSigning proves
// commitIssueCandidate's OWN requireCurrentAuth call, not just the earlier
// replay-probe's -- the session is still valid when the request starts (so
// the replay-probe check passes) and only crosses the idle boundary while
// "signing" (mirroring authtime_test.go's signerAdvancingClock exactly).
func TestTLSServiceIssueCandidateRejectsSessionThatExpiresDuringSigning(t *testing.T) {
	f := newTLSFixture(t)
	clock := &movableClock{now: testNow()}
	f.svc.deps.Clock = clock
	f.svc.deps.CertificateSigner = &signerAdvancingClock{fakeSigner: f.signer, clock: clock, by: time.Hour + time.Second}

	_, err := f.svc.IssueCandidate(context.Background(), tlsIssueMeta(tlsIdemKeyA), tlsIssueCommand(f.authorityID, "tls-1"))
	requireAuthError(t, err, "session_idle_expired")
}

// signerBumpingEpoch advances the account's auth_epoch while "signing", the
// same idea as signerAdvancingClock but for the epoch check instead of the
// idle-timeout one.
type signerBumpingEpoch struct {
	*fakeSigner
	t     *testing.T
	store *porttest.Store
}

func (s *signerBumpingEpoch) Sign(ctx context.Context, request port.CertificateSigningRequest, key domain.EncryptedSecret) (domain.Certificate, error) {
	bumpAccountAuthEpoch(s.t, s.store)
	return s.fakeSigner.Sign(ctx, request, key)
}

func TestTLSServiceIssueCandidateRejectsAuthEpochBumpedDuringSigning(t *testing.T) {
	f := newTLSFixture(t)
	f.svc.deps.CertificateSigner = &signerBumpingEpoch{fakeSigner: f.signer, t: t, store: f.store}

	_, err := f.svc.IssueCandidate(context.Background(), tlsIssueMeta(tlsIdemKeyA), tlsIssueCommand(f.authorityID, "tls-1"))
	requireAuthError(t, err, "auth_epoch_superseded")
}

// TestTLSServiceIssueCandidateReplayRejectsExpiredSession is §8's "현재
// 인증/권한이 없는 요청은 기존 결과도 받지 못한다" applied to a SECOND call
// under the same idempotency key: a session that was valid for the original
// request but has since gone idle must not be handed the stored result
// either.
func TestTLSServiceIssueCandidateReplayRejectsExpiredSession(t *testing.T) {
	f := newTLSFixture(t)
	clock := &movableClock{now: testNow()}
	f.svc.deps.Clock = clock

	if _, err := f.svc.IssueCandidate(context.Background(), tlsIssueMeta(tlsIdemKeyA), tlsIssueCommand(f.authorityID, "tls-1")); err != nil {
		t.Fatalf("first issue: %v", err)
	}
	clock.now = testNow().Add(domain.NewDuration(time.Hour + time.Second))

	_, err := f.svc.IssueCandidate(context.Background(), tlsIssueMeta(tlsIdemKeyA), tlsIssueCommand(f.authorityID, "tls-1"))
	requireAuthError(t, err, "session_idle_expired")
}

// ---- Activate: U13-1 candidate validation failure leaves the active
// version unchanged ---------------------------------------------------

func TestTLSServiceActivateValidationFailureLeavesActiveVersionUnchanged(t *testing.T) {
	f := newTLSFixture(t)
	good := f.issueCandidate(t, tlsIdemKeyA, "tls-1")
	statusAfterFirst := f.mustActivate(t, good.ID, 0)
	if statusAfterFirst.Version != 1 {
		t.Fatalf("installation version after first activation = %v, want 1", statusAfterFirst.Version)
	}

	bad := f.issueCandidate(t, tlsIdemKeyB, "tls-2")
	f.chain.fail = errors.New("chain does not verify")

	_, err := f.activate(t, bad.ID, 1)
	requireErr(t, err, contract.ErrorKindValidation, "tls_candidate_chain_invalid")

	// The installer must never have been touched: a failing candidate is
	// rejected before Prepare/Apply, not after (§9's "실패 시 기존 인증서를
	// 유지" is achieved structurally here, not by rolling anything back).
	if f.installer.prepareCount != 1 || f.installer.applyCount != 1 {
		t.Fatalf("installer prepareCount=%d applyCount=%d, want exactly the ones from the first, successful activation (1 each)",
			f.installer.prepareCount, f.installer.applyCount)
	}

	status := f.status(t)
	if status.Active == nil || status.Active.ID != good.ID {
		t.Fatalf("active version changed after a failed candidate: %+v", status.Active)
	}
	if status.Version != 1 {
		t.Fatalf("installation version = %v, want unchanged at 1", status.Version)
	}
}

// ---- Activate: U13-2 Apply failure rolls back both DB and memory --------

func TestTLSServiceActivateApplyFailureRollsBackDBAndMemory(t *testing.T) {
	f := newTLSFixture(t)
	first := f.issueCandidate(t, tlsIdemKeyA, "tls-1")
	f.mustActivate(t, first.ID, 0)
	if f.installer.lastAppliedCandidateID != first.ID {
		t.Fatalf("setup: installer did not record the first candidate as applied")
	}

	second := f.issueCandidate(t, tlsIdemKeyB, "tls-2")
	f.installer.applyErr = errors.New("listener swap failed")

	_, err := f.activate(t, second.ID, 1)
	requireErr(t, err, contract.ErrorKindUnavailable, "tls_apply_failed")

	// In-memory half: the fake installer's own contract means a failed
	// Apply never updates lastApplied -- it must still read the FIRST
	// candidate, proving the previous listener kept serving.
	if f.installer.lastAppliedCandidateID != first.ID {
		t.Fatalf("live config changed to %s after a failed Apply, want it to stay on %s", f.installer.lastAppliedCandidateID, first.ID)
	}
	if f.installer.applyCount != 1 {
		t.Fatalf("applyCount = %d, want 1 (the failed attempt must not count as applied)", f.installer.applyCount)
	}

	// DB half: rollbackActivation must move the active pointer back to the
	// first candidate and leave its TLSChange terminal/applied.
	status := f.status(t)
	if status.Active == nil || status.Active.ID != first.ID {
		t.Fatalf("active version after a failed Apply = %+v, want it reverted to the first candidate %s", status.Active, first.ID)
	}
	if status.Phase == nil || *status.Phase != domain.TLSChangePhaseApplied {
		t.Fatalf("phase after rollback = %v, want applied (the surviving first candidate)", status.Phase)
	}
	if status.Version != 3 {
		// 0->1 (first SetActive), 1->2 (second SetActive, to the failed
		// candidate), 2->3 (rollbackActivation's SetActive back to first).
		t.Fatalf("installation version after rollback = %v, want 3", status.Version)
	}
}

// ---- Activate: happy path, version conflict, blocked-pending-reconcile --

func TestTLSServiceActivateAppliesFirstCandidate(t *testing.T) {
	f := newTLSFixture(t)
	candidate := f.issueCandidate(t, tlsIdemKeyA, "tls-1")
	status := f.mustActivate(t, candidate.ID, 0)

	if status.Active == nil || status.Active.ID != candidate.ID {
		t.Fatalf("active = %+v, want %s", status.Active, candidate.ID)
	}
	if status.Phase == nil || *status.Phase != domain.TLSChangePhaseApplied {
		t.Fatalf("phase = %v, want applied", status.Phase)
	}
	if status.Version != 1 {
		t.Fatalf("version = %v, want 1", status.Version)
	}
	if f.installer.applyCount != 1 || f.installer.prepared() != 0 {
		t.Fatalf("installer applyCount=%d prepared=%d, want 1 applied and an empty registry (Discard is a no-op after success)",
			f.installer.applyCount, f.installer.prepared())
	}
}

func TestTLSServiceActivateRejectsStaleExpectedVersion(t *testing.T) {
	f := newTLSFixture(t)
	first := f.issueCandidate(t, tlsIdemKeyA, "tls-1")
	f.mustActivate(t, first.ID, 0)

	second := f.issueCandidate(t, tlsIdemKeyB, "tls-2")
	_, err := f.activate(t, second.ID, 0) // stale: installation is already at version 1
	requireErr(t, err, contract.ErrorKindConflict, "tls_status_version_conflict")

	status := f.status(t)
	if status.Active == nil || status.Active.ID != first.ID {
		t.Fatalf("active version moved after a rejected stale-version Activate: %+v", status.Active)
	}
}

func TestTLSServiceActivateBlocksWhilePendingReconcile(t *testing.T) {
	f := newTLSFixture(t)
	candidate := seedTLSVersionWithSecret(t, f.store, f.ids, testNow().Add(domain.NewDuration(24*time.Hour)), "stuck")
	seedRecoveryRequiredChange(t, f.store, candidate, "")

	nextCandidate := f.issueCandidate(t, tlsIdemKeyA, "tls-next")
	_, err := f.activate(t, nextCandidate.ID, 1) // seedRecoveryRequiredChange bumped installation to version 1
	requireErr(t, err, contract.ErrorKindConflict, "tls_activation_blocked_pending_reconcile")
}

// ---- Activate: admin required, auth re-check -----------------------------

func TestTLSServiceActivateRequiresAdmin(t *testing.T) {
	f := newTLSFixture(t)
	candidate := f.issueCandidate(t, tlsIdemKeyA, "tls-1")
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: contract.AnonymousPrincipal()}, ExpectedVersion: contract.WithExpectedVersion(domain.Version(0))}
	_, err := f.svc.Activate(context.Background(), meta, contract.TLSActivateCommand{CandidateID: candidate.ID})
	requireErr(t, err, contract.ErrorKindForbidden, "tls_requires_admin")
}

func TestTLSServiceActivateRejectsIdleExpiredSession(t *testing.T) {
	f := newTLSFixture(t)
	candidate := f.issueCandidate(t, tlsIdemKeyA, "tls-1")
	touchAdminSession(t, f.store, testNow())
	f.svc.deps.Clock = &movableClock{now: testNow().Add(domain.NewDuration(time.Hour + time.Second))}

	_, err := f.activate(t, candidate.ID, 0)
	requireAuthError(t, err, "session_idle_expired")
	if f.installer.prepareCount != 0 {
		t.Fatalf("installer.Prepare was called for an idle-expired session")
	}
}

func TestTLSServiceActivateRejectsAuthEpochSuperseded(t *testing.T) {
	f := newTLSFixture(t)
	candidate := f.issueCandidate(t, tlsIdemKeyA, "tls-1")
	bumpAccountAuthEpoch(t, f.store)

	_, err := f.activate(t, candidate.ID, 0)
	requireAuthError(t, err, "auth_epoch_superseded")
	if f.installer.prepareCount != 0 {
		t.Fatalf("installer.Prepare was called for a superseded epoch")
	}
}

// ---- Activate: Discard defer -------------------------------------------

// TestTLSServiceActivateDiscardReleasesEntryWhenApplyPanics is the "panic"
// case the assignment names explicitly: Apply panics AFTER Prepare has
// registered a live entry and BEFORE Apply's own cleanup code would ever
// run, so the only thing that can still release the entry is TLSService's
// own `defer s.deps.TLSInstaller.Discard(prepared)`, immediately after
// Prepare (docs/backend-implementation.md §13). If that defer is removed,
// this test's recover() still catches the panic, but the registry assertion
// below fails.
func TestTLSServiceActivateDiscardReleasesEntryWhenApplyPanics(t *testing.T) {
	f := newTLSFixture(t)
	candidate := f.issueCandidate(t, tlsIdemKeyA, "tls-1")
	f.installer.applyPanic = true

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("Activate did not panic even though Apply was made to")
			}
		}()
		_, _ = f.activate(t, candidate.ID, 0)
	}()

	if f.installer.prepared() != 0 {
		t.Fatalf("%d registry entries survived a panicking Apply -- the deferred Discard did not run", f.installer.prepared())
	}
	if f.installer.discardReleased != 1 {
		t.Fatalf("discardReleased = %d, want 1", f.installer.discardReleased)
	}
}

// TestTLSServiceActivateDiscardCleansUpAnAmbiguousApplyFailure uses an
// installer whose Apply does NOT clean up its own registry entry on
// failure (selfCleanOnFailure=false) -- modeling the commit_unknown-shaped
// case where whether Apply's internal state is consistent is itself
// unknown. With a "tidy" installer (the default), a missing
// `defer Discard` would go unnoticed, because Apply's own failure path
// already deletes the entry; this test isolates what the SERVICE's own
// deferred call is responsible for, independent of that.
func TestTLSServiceActivateDiscardCleansUpAnAmbiguousApplyFailure(t *testing.T) {
	f := newTLSFixture(t)
	candidate := f.issueCandidate(t, tlsIdemKeyA, "tls-1")
	f.installer.applyErr = errors.New("ambiguous outcome")
	f.installer.selfCleanOnFailure = false

	_, err := f.activate(t, candidate.ID, 0)
	requireErr(t, err, contract.ErrorKindUnavailable, "tls_apply_failed")

	if f.installer.prepared() != 0 {
		t.Fatalf("%d registry entries survived an ambiguous Apply failure that the installer itself did not clean up -- the deferred Discard did not run", f.installer.prepared())
	}
}

// ---- Reconcile: U13-3 committed-interrupted restart recovery ------------

func TestTLSServiceReconcileAppliesReValidatedCandidate(t *testing.T) {
	f := newTLSFixture(t)
	previous := seedTLSVersionWithSecret(t, f.store, f.ids, testNow().Add(domain.NewDuration(24*time.Hour)), "previous")
	candidate := seedTLSVersionWithSecret(t, f.store, f.ids, testNow().Add(domain.NewDuration(48*time.Hour)), "candidate")
	seedRecoveryRequiredChange(t, f.store, candidate, previous)

	view, err := f.svc.Reconcile(context.Background(), tlsReconcileMeta(mustInternalPrincipal(t, contract.InternalOperationTLSReconcile)), contract.TLSReconcileCommand{})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if view.Active == nil || view.Active.ID != candidate {
		t.Fatalf("active = %+v, want the re-validated candidate %s", view.Active, candidate)
	}
	if view.Phase == nil || *view.Phase != domain.TLSChangePhaseApplied {
		t.Fatalf("phase = %v, want applied", view.Phase)
	}
	if f.installer.applyCount != 1 || f.installer.lastAppliedCandidateID != candidate {
		t.Fatalf("installer applyCount=%d lastApplied=%s, want the candidate applied exactly once", f.installer.applyCount, f.installer.lastAppliedCandidateID)
	}
	if f.installer.prepared() != 0 {
		t.Fatalf("%d registry entries survived Reconcile", f.installer.prepared())
	}
}

func TestTLSServiceReconcileRollsBackToPreviousWhenCandidateInvalid(t *testing.T) {
	f := newTLSFixture(t)
	previous := seedTLSVersionWithSecret(t, f.store, f.ids, testNow().Add(domain.NewDuration(24*time.Hour)), "previous")
	// Expired: WithinValidityPeriod fails, so the candidate cannot re-validate.
	candidate := seedTLSVersionWithSecret(t, f.store, f.ids, testNow().Add(domain.NewDuration(-time.Hour)), "candidate")
	seedRecoveryRequiredChange(t, f.store, candidate, previous)

	view, err := f.svc.Reconcile(context.Background(), tlsReconcileMeta(mustInternalPrincipal(t, contract.InternalOperationTLSReconcile)), contract.TLSReconcileCommand{})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if view.Active == nil || view.Active.ID != previous {
		t.Fatalf("active = %+v, want rollback to the previous version %s", view.Active, previous)
	}
	if view.Phase == nil || *view.Phase != domain.TLSChangePhaseRolledBack {
		t.Fatalf("phase = %v, want rolled_back", view.Phase)
	}
	if f.installer.lastAppliedCandidateID != previous {
		t.Fatalf("installer applied %s, want the previous version %s", f.installer.lastAppliedCandidateID, previous)
	}

	// SetActive must have moved the installation pointer back to previous.
	status := f.status(t)
	if status.Active == nil || status.Active.ID != previous {
		t.Fatalf("installation active pointer = %+v after rollback, want %s", status.Active, previous)
	}
}

func TestTLSServiceReconcileStaysRecoveryRequiredWhenNeitherRevalidates(t *testing.T) {
	f := newTLSFixture(t)
	previous := seedTLSVersionWithSecret(t, f.store, f.ids, testNow().Add(domain.NewDuration(-2*time.Hour)), "previous")
	candidate := seedTLSVersionWithSecret(t, f.store, f.ids, testNow().Add(domain.NewDuration(-time.Hour)), "candidate")
	seedRecoveryRequiredChange(t, f.store, candidate, previous)

	view, err := f.svc.Reconcile(context.Background(), tlsReconcileMeta(mustInternalPrincipal(t, contract.InternalOperationTLSReconcile)), contract.TLSReconcileCommand{})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if view.Phase == nil || *view.Phase != domain.TLSChangePhaseRecoveryRequired {
		t.Fatalf("phase = %v, want recovery_required (maintenance)", view.Phase)
	}
	if view.ErrorCode != "tls_recovery_unresolved" {
		t.Fatalf("error code = %q, want tls_recovery_unresolved", view.ErrorCode)
	}
	if f.installer.applyCount != 0 || f.installer.prepareCount != 0 {
		t.Fatalf("installer was touched even though neither version could re-validate: prepareCount=%d applyCount=%d", f.installer.prepareCount, f.installer.applyCount)
	}
}

func TestTLSServiceReconcileIsANoOpWhenNothingIsActive(t *testing.T) {
	f := newTLSFixture(t)
	view, err := f.svc.Reconcile(context.Background(), tlsReconcileMeta(mustInternalPrincipal(t, contract.InternalOperationTLSReconcile)), contract.TLSReconcileCommand{})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if view.Active != nil || view.Phase != nil {
		t.Fatalf("Reconcile on a fresh installation reported state: %+v", view)
	}
	if f.installer.prepareCount != 0 {
		t.Fatalf("installer touched with nothing to reconcile")
	}
}

func TestTLSServiceReconcileIsANoOpWhenAlreadyResolved(t *testing.T) {
	f := newTLSFixture(t)
	candidate := f.issueCandidate(t, tlsIdemKeyA, "tls-1")
	f.mustActivate(t, candidate.ID, 0)

	view, err := f.svc.Reconcile(context.Background(), tlsReconcileMeta(mustInternalPrincipal(t, contract.InternalOperationTLSReconcile)), contract.TLSReconcileCommand{})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if view.Active == nil || view.Active.ID != candidate.ID {
		t.Fatalf("active = %+v, want the already-applied candidate unchanged", view.Active)
	}
	if f.installer.prepareCount != 1 { // only from the earlier Activate
		t.Fatalf("Reconcile touched the installer for an already-resolved change: prepareCount=%d", f.installer.prepareCount)
	}
}

// TestTLSServiceReconcileDiscardIsHarmlessAfterADBRollback exercises the one
// place in this file's implementation where Prepare/Apply run INSIDE the
// same Write as later DB writes (Reconcile's simplified, single-Write
// shape -- see this file's Reconcile doc comment): if a write AFTER Apply
// succeeds (here, the audit append) fails, the whole callback returns an
// error and porttest.Store discards the entire working copy, rolling the
// TLSChange back to recovery_required even though Apply already ran.
//
// This does NOT prove Discard prevents a registry leak on this path --
// Apply's own success path already removed the entry before the audit
// append ever runs, so Discard is a harmless no-op here regardless of
// whether the defer is present. What it does prove is that the defer
// executes cleanly on a real DB-rollback return path without a double-free
// or a panic, and it documents a real, already-flagged consequence of
// Reconcile's one-Write shape: the live listener stays swapped to the
// candidate even though the persisted TLSChange reports recovery_required
// again. That divergence is called out in tls.go's own Reconcile doc
// comment as an accepted simplification for the lead to confirm, not
// something this test asserts is correct.
func TestTLSServiceReconcileDiscardIsHarmlessAfterADBRollback(t *testing.T) {
	f := newTLSFixture(t)
	previous := seedTLSVersionWithSecret(t, f.store, f.ids, testNow().Add(domain.NewDuration(24*time.Hour)), "previous")
	candidate := seedTLSVersionWithSecret(t, f.store, f.ids, testNow().Add(domain.NewDuration(48*time.Hour)), "candidate")
	seedRecoveryRequiredChange(t, f.store, candidate, previous)

	failingAudit := &failingAuditUoW{inner: f.store, reads: f.store}
	svc, err := NewTLSService(TLSDeps{
		CommonDeps: CommonDeps{
			UnitOfWork: failingAudit, ReadStore: failingAudit, Authorizer: f.authorizer,
			Clock: fixedClock{now: testNow()}, IDs: f.ids,
		},
		KeyEngine: f.importer, CertificateSigner: f.signer, SerialGenerator: f.serials,
		ChainValidator: f.chain, TLSInstaller: f.installer, PKIParser: f.parser,
	})
	if err != nil {
		t.Fatalf("new tls service: %v", err)
	}

	_, err = svc.Reconcile(context.Background(), tlsReconcileMeta(mustInternalPrincipal(t, contract.InternalOperationTLSReconcile)), contract.TLSReconcileCommand{})
	if err == nil {
		t.Fatalf("Reconcile succeeded despite the injected audit failure")
	}

	if f.installer.prepared() != 0 {
		t.Fatalf("%d registry entries survived (should be 0: Apply's own success path already released it, and Discard is a harmless no-op after)", f.installer.prepared())
	}

	// The DB half genuinely rolled back: the persisted change is still
	// recovery_required, not applied.
	status := f.status(t)
	if status.Phase == nil || *status.Phase != domain.TLSChangePhaseRecoveryRequired {
		t.Fatalf("persisted phase after the rolled-back write = %v, want recovery_required", status.Phase)
	}
}

// failingAuditUoW wraps a real UnitOfWork/ReadStore so every AuditRepository
// call fails, letting a test force a failure AFTER an installer Apply has
// already run inside the same Write, without needing a bespoke in-memory
// store implementation.
type failingAuditRepo struct{ port.AuditRepository }

func (failingAuditRepo) Append(context.Context, port.AuditEvent, []domain.AuthorityID) error {
	return errors.New("injected: audit append failed")
}

type failingAuditTxStores struct{ port.TxStores }

func (f failingAuditTxStores) Audit() port.AuditRepository {
	return failingAuditRepo{AuditRepository: f.TxStores.Audit()}
}

type failingAuditUoW struct {
	inner port.UnitOfWork
	reads port.ReadStore
}

func (u *failingAuditUoW) Write(ctx context.Context, fn func(port.TxStores) error) error {
	return u.inner.Write(ctx, func(tx port.TxStores) error { return fn(failingAuditTxStores{TxStores: tx}) })
}

func (u *failingAuditUoW) Read(ctx context.Context, fn func(port.TxStores) error) error {
	return u.reads.Read(ctx, func(tx port.TxStores) error { return fn(failingAuditTxStores{TxStores: tx}) })
}

// ---- Reconcile: §13 ruling 5 internal-operation gate ---------------------

func TestTLSServiceReconcileRejectsAdminPrincipal(t *testing.T) {
	f := newTLSFixture(t)
	_, err := f.svc.Reconcile(context.Background(), tlsReconcileMeta(mustAdminPrincipal()), contract.TLSReconcileCommand{})
	requireErr(t, err, contract.ErrorKindForbidden, "tls_internal_operation_required")
}

func TestTLSServiceReconcileRejectsAnonymousPrincipal(t *testing.T) {
	f := newTLSFixture(t)
	_, err := f.svc.Reconcile(context.Background(), tlsReconcileMeta(contract.AnonymousPrincipal()), contract.TLSReconcileCommand{})
	requireErr(t, err, contract.ErrorKindForbidden, "tls_internal_operation_required")
}

func TestTLSServiceReconcileRejectsInternalPrincipalWithWrongOperation(t *testing.T) {
	f := newTLSFixture(t)
	wrong := mustInternalPrincipal(t, contract.InternalOperationCRLPublish)
	_, err := f.svc.Reconcile(context.Background(), tlsReconcileMeta(wrong), contract.TLSReconcileCommand{})
	requireErr(t, err, contract.ErrorKindForbidden, "tls_internal_operation_required")
}

// ---- UploadCandidate ------------------------------------------------------

const (
	tlsUploadCertBytes = "PRETEND-CERT-BYTES"
	tlsUploadChainByte = "PRETEND-CHAIN-BYTES"
	tlsUploadKeyBytes  = "PRETEND-KEY-BYTES"
)

// tlsUploadLeafPublicKey/tlsUploadWrongPublicKey are two distinct
// domain.PublicKeys: registering the key recipe under the WRONG one lets a
// test force ParseInternalTLSKey's own public-key-match check to fail.
func tlsUploadLeafPublicKey(t *testing.T) domain.PublicKey {
	t.Helper()
	pk, err := domain.NewPublicKey(domain.KeyAlgorithmECDSAP256, []byte("upload-leaf-public-key-bytes-0001"))
	if err != nil {
		t.Fatalf("leaf public key: %v", err)
	}
	return pk
}

func tlsUploadWrongPublicKey(t *testing.T) domain.PublicKey {
	t.Helper()
	pk, err := domain.NewPublicKey(domain.KeyAlgorithmECDSAP256, []byte("upload-WRONG-public-key-bytes-9999"))
	if err != nil {
		t.Fatalf("wrong public key: %v", err)
	}
	return pk
}

// registerTLSUploadFixture registers the standard leaf cert (SAN matching
// the fixture's configured service URL, per serviceAddressMatchesSANs) and
// its correctly-matching key with f.parser.
func registerTLSUploadFixture(t *testing.T, f *tlsFixture) {
	t.Helper()
	san, err := domain.NewSAN(domain.SANTypeDNS, "cert.example.test")
	if err != nil {
		t.Fatalf("san: %v", err)
	}
	window, err := domain.NewValidityWindow(testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour)))
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "uploaded.example.test"})
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	f.parser.registerLeaf([]byte(tlsUploadCertBytes), port.ParsedCertificateFacts{
		PublicKey: tlsUploadLeafPublicKey(t), KeyAlgorithm: domain.KeyAlgorithmECDSAP256,
		Serial: serial(t, "beef"), Validity: window, Subject: subject, SANs: []domain.SAN{san},
		Kind: domain.CertificateKindLeaf,
	})
	f.parser.registerKey([]byte(tlsUploadKeyBytes), tlsFakeKeyRecipe{
		plaintext: []byte("plaintext-private-key-material"), publicKey: tlsUploadLeafPublicKey(t), algorithm: domain.KeyAlgorithmECDSAP256,
	})
}

func tlsUploadCommand() contract.TLSUploadCandidateCommand {
	return contract.TLSUploadCandidateCommand{Certificate: []byte(tlsUploadCertBytes), Key: []byte(tlsUploadKeyBytes)}
}

func TestTLSServiceUploadCandidateStoresExternalCandidate(t *testing.T) {
	f := newTLSFixture(t)
	registerTLSUploadFixture(t, f)

	view, err := f.svc.UploadCandidate(context.Background(), tlsIssueMeta(tlsIdemKeyA), tlsUploadCommand())
	if err != nil {
		t.Fatalf("UploadCandidate: %v", err)
	}
	if view.Source != domain.TLSSourceExternal {
		t.Fatalf("source = %q, want external", view.Source)
	}
	if view.CertificateID != nil {
		t.Fatalf("certificate id = %v, want nil (an uploaded candidate has no managed PKI certificate)", view.CertificateID)
	}
	if view.ValidatedServiceURL != "https://cert.example.test" {
		t.Fatalf("validated service url = %q, want the settings service url (SAN matched it)", view.ValidatedServiceURL)
	}
	if f.importer.importCalls != 1 {
		t.Fatalf("ImportTLS calls = %d, want 1", f.importer.importCalls)
	}

	// §10/§13 ruling 4: the secret.Input ParseInternalTLSKey minted must
	// already be closed by the time UploadCandidate returns.
	if err := f.parser.lastMintedKey.Use(func([]byte) error { return nil }); !errors.Is(err, secret.ErrClosed) {
		t.Fatalf("Use() on the parsed key after UploadCandidate returned = %v, want secret.ErrClosed", err)
	}
}

func TestTLSServiceUploadCandidateStoresChainBundle(t *testing.T) {
	f := newTLSFixture(t)
	registerTLSUploadFixture(t, f)
	window, err := domain.NewValidityWindow(testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*5*time.Hour)))
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "uploaded-intermediate"})
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	f.parser.registerChain([]byte(tlsUploadChainByte), port.ParsedCertificateFacts{
		DER: []byte("intermediate-der"), KeyAlgorithm: domain.KeyAlgorithmECDSAP256,
		Serial: serial(t, "cafe"), Validity: window, Subject: subject, Kind: domain.CertificateKindCA,
	})

	cmd := tlsUploadCommand()
	cmd.Chain = []byte(tlsUploadChainByte)
	view, err := f.svc.UploadCandidate(context.Background(), tlsIssueMeta(tlsIdemKeyA), cmd)
	if err != nil {
		t.Fatalf("UploadCandidate: %v", err)
	}

	var stored domain.TLSVersion
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		stored, err = tx.TLS().GetVersion(context.Background(), view.ID)
		return err
	}); err != nil {
		t.Fatalf("read stored version: %v", err)
	}
	chainDER, err := splitPEMChain(stored.ChainBundle())
	if err != nil {
		t.Fatalf("splitPEMChain: %v", err)
	}
	if len(chainDER) != 1 || string(chainDER[0]) != "intermediate-der" {
		t.Fatalf("stored chain = %v, want exactly the one registered intermediate DER", chainDER)
	}
}

func TestTLSServiceUploadCandidateRequiresAdmin(t *testing.T) {
	f := newTLSFixture(t)
	registerTLSUploadFixture(t, f)
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: contract.AnonymousPrincipal()}}
	_, err := f.svc.UploadCandidate(context.Background(), meta, tlsUploadCommand())
	requireErr(t, err, contract.ErrorKindForbidden, "tls_requires_admin")
	if f.parser.lastMintedKey != nil {
		t.Fatalf("the key was parsed for a non-admin request")
	}
}

// TestTLSServiceUploadCandidateRejectsKeyCertificateMismatch is the
// validation-failure half of U13's "검증 실패는 활성 버전 불변" property,
// applied to UploadCandidate: a key that does not match the certificate's
// public key must be rejected before anything is stored, so there is no
// half-written candidate and (a fortiori) no way it could ever affect the
// active version.
func TestTLSServiceUploadCandidateRejectsKeyCertificateMismatch(t *testing.T) {
	f := newTLSFixture(t)
	registerTLSUploadFixture(t, f)
	// Overwrite the registered key with one whose public key does NOT match
	// the certificate's.
	f.parser.registerKey([]byte(tlsUploadKeyBytes), tlsFakeKeyRecipe{
		plaintext: []byte("plaintext-private-key-material"), publicKey: tlsUploadWrongPublicKey(t), algorithm: domain.KeyAlgorithmECDSAP256,
	})

	_, err := f.svc.UploadCandidate(context.Background(), tlsIssueMeta(tlsIdemKeyA), tlsUploadCommand())
	requireErr(t, err, contract.ErrorKindValidation, "tls_upload_key_invalid")

	if f.importer.importCalls != 0 {
		t.Fatalf("ImportTLS was called despite a key/certificate mismatch")
	}
	// Nothing was stored: the fixture's fresh installation still reports no
	// active/candidate state at all.
	status := f.status(t)
	if status.Active != nil {
		t.Fatalf("active version = %+v after a rejected upload, want none (nothing was ever stored)", status.Active)
	}
}

// TestTLSServiceUploadCandidateNeverCreatesALeafDeliveryOrGrant is U13's
// zero-delivery property, applied to the upload path exactly like
// TestTLSServiceIssueCandidateNeverCreatesALeafDeliveryOrGrant is for
// internal issuance -- an uploaded certificate's key is stored for the
// installer's own use only, never queued as a one-shot leaf delivery.
func TestTLSServiceUploadCandidateNeverCreatesALeafDeliveryOrGrant(t *testing.T) {
	f := newTLSFixture(t)
	registerTLSUploadFixture(t, f)
	counter := &countingDeliveryUoW{inner: f.store, reads: f.store}
	svc, err := NewTLSService(TLSDeps{
		CommonDeps: CommonDeps{
			UnitOfWork: counter, ReadStore: counter, Authorizer: f.authorizer,
			Clock: fixedClock{now: testNow()}, IDs: f.ids,
		},
		KeyEngine: f.importer, CertificateSigner: f.signer, SerialGenerator: f.serials,
		ChainValidator: f.chain, TLSInstaller: f.installer, PKIParser: f.parser,
	})
	if err != nil {
		t.Fatalf("new tls service: %v", err)
	}

	if _, err := svc.UploadCandidate(context.Background(), tlsIssueMeta(tlsIdemKeyA), tlsUploadCommand()); err != nil {
		t.Fatalf("UploadCandidate: %v", err)
	}
	if counter.inserts != 0 {
		t.Fatalf("UploadCandidate made %d Delivery/Grant insert calls, want 0", counter.inserts)
	}
}

// TestTLSServiceUploadCandidateClosesTheParsedKeyEvenWhenImportFails is the
// failure half of §10/§13 ruling 4's secret lifecycle: the deferred Close
// must run on the error return path too, not only on success.
func TestTLSServiceUploadCandidateClosesTheParsedKeyEvenWhenImportFails(t *testing.T) {
	f := newTLSFixture(t)
	registerTLSUploadFixture(t, f)
	f.importer.importFail = errors.New("import boom")

	_, err := f.svc.UploadCandidate(context.Background(), tlsIssueMeta(tlsIdemKeyA), tlsUploadCommand())
	requireErr(t, err, contract.ErrorKindUnavailable, "tls_upload_key_import_failed")

	if err := f.parser.lastMintedKey.Use(func([]byte) error { return nil }); !errors.Is(err, secret.ErrClosed) {
		t.Fatalf("Use() on the parsed key after a failed ImportTLS = %v, want secret.ErrClosed", err)
	}
}

// ---- UploadCandidate: auth re-check ---------------------------------------

func TestTLSServiceUploadCandidateRejectsIdleExpiredSession(t *testing.T) {
	f := newTLSFixture(t)
	registerTLSUploadFixture(t, f)
	touchAdminSession(t, f.store, testNow())
	f.svc.deps.Clock = &movableClock{now: testNow().Add(domain.NewDuration(time.Hour + time.Second))}

	_, err := f.svc.UploadCandidate(context.Background(), tlsIssueMeta(tlsIdemKeyA), tlsUploadCommand())
	requireAuthError(t, err, "session_idle_expired")
}

func TestTLSServiceUploadCandidateRejectsAuthEpochSuperseded(t *testing.T) {
	f := newTLSFixture(t)
	registerTLSUploadFixture(t, f)
	bumpAccountAuthEpoch(t, f.store)

	_, err := f.svc.UploadCandidate(context.Background(), tlsIssueMeta(tlsIdemKeyA), tlsUploadCommand())
	requireAuthError(t, err, "auth_epoch_superseded")
}
