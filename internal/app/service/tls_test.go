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

type fakeTLSFileSource struct {
	input port.TLSFileSourceInput
	err   error
	calls int
}

func (s *fakeTLSFileSource) Load(context.Context) (port.TLSFileSourceInput, error) {
	s.calls++
	if s.err != nil {
		return port.TLSFileSourceInput{}, s.err
	}
	return s.input, nil
}

var _ port.TLSFileSource = (*fakeTLSFileSource)(nil)

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
	source      *fakeTLSFileSource
	gate        *fakeRuntimeGate
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
	source := &fakeTLSFileSource{}
	gate := &fakeRuntimeGate{}
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
		FileSource:        source,
		RuntimeGate:       gate,
	})
	if err != nil {
		t.Fatalf("new tls service: %v", err)
	}
	return &tlsFixture{
		store: store, ids: ids, keyEngine: keyEngine, importer: importer, signer: signer, serials: serials,
		chain: chain, installer: installer, parser: parser, source: source, gate: gate, authorizer: authorizer, svc: svc, authorityID: authorityID,
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

// seedCommittedChange models a restart immediately after the durable
// committed/pointer write and before Installer.Apply. Reconcile must turn this
// phase into recovery_required and then resolve it from the stored snapshots;
// treating it as an already-resolved terminal row would leave the listener
// unapplied after a restart.
func seedCommittedChange(t *testing.T, store *porttest.Store, candidateID, previousID domain.TLSVersionID) {
	t.Helper()
	ctx := context.Background()
	if previousID != "" {
		previousChange, err := domain.NewTLSChange(domain.TLSChangeFacts{
			CandidateVersionID: previousID, Phase: domain.TLSChangePhaseApplied, Validated: true,
		})
		if err != nil {
			t.Fatalf("new previous committed-test change: %v", err)
		}
		if err := store.Write(ctx, func(tx port.TxStores) error {
			return tx.TLS().SaveChange(ctx, previousChange, 0)
		}); err != nil {
			t.Fatalf("seed previous committed-test change: %v", err)
		}
	}
	change, err := domain.NewTLSChange(domain.TLSChangeFacts{
		PreviousVersionID: previousID, CandidateVersionID: candidateID,
		Phase: domain.TLSChangePhaseCommitted, Validated: true,
	})
	if err != nil {
		t.Fatalf("new committed tls change: %v", err)
	}
	if err := store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.TLS().SaveChange(ctx, change, 0); err != nil {
			return err
		}
		installation, err := tx.Installation().GetForUpdate(ctx)
		if err != nil {
			return err
		}
		original := installation.Version
		installation.ActiveTLSVersionID = candidateID
		installation.Version = installation.Version.Next()
		return tx.Installation().Save(ctx, installation, original)
	}); err != nil {
		t.Fatalf("seed committed tls change: %v", err)
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

type tlsBootstrapGraph struct {
	authority       domain.Authority
	rootGeneration  port.CAKeyGeneration
	rootCertificate domain.Certificate
	rootRecord      port.CACertificateRecord
	leafCertificate domain.Certificate
	leafRecord      port.LeafCertificateRecord
	series          domain.LeafSeries
	crlState        domain.CRLState
	versions        []domain.TLSVersion
	secrets         []domain.EncryptedSecret
}

func readTLSBootstrapGraph(t *testing.T, f *tlsFixture) tlsBootstrapGraph {
	t.Helper()
	ctx := context.Background()
	var graph tlsBootstrapGraph
	if err := f.store.Read(ctx, func(tx port.TxStores) error {
		page, err := tx.Queries().ListAuthorities(ctx, contract.AuthorityListQuery{Page: contract.PageRequest{Limit: 200}}, port.QueryScope{All: true})
		if err != nil {
			return err
		}
		for _, authority := range page.Items {
			if authority.Kind() == domain.AuthorityKindBootstrap {
				if graph.authority.ID() != "" {
					return fmt.Errorf("more than one bootstrap authority")
				}
				graph.authority = authority
			}
		}
		if graph.authority.ID() == "" {
			return fmt.Errorf("bootstrap authority not found")
		}
		graph.rootGeneration, err = tx.PKI().GetCAKeyGeneration(ctx, graph.authority.KeyGenerationID())
		if err != nil {
			return err
		}
		graph.rootCertificate, err = tx.PKI().GetCertificate(ctx, graph.authority.IssuanceCertificateID())
		if err != nil {
			return err
		}
		graph.rootRecord, err = tx.PKI().GetCACertificateRecord(ctx, graph.rootCertificate.ID())
		if err != nil {
			return err
		}
		installation, err := tx.Installation().GetForUpdate(ctx)
		if err != nil {
			return err
		}
		var activeVersion domain.TLSVersion
		if installation.ActiveTLSVersionID != "" {
			activeVersion, err = tx.TLS().GetVersion(ctx, installation.ActiveTLSVersionID)
			if err != nil {
				return err
			}
		}
		seriesPage, err := tx.Queries().ListSeries(ctx, contract.SeriesListQuery{
			AuthorityID: ptrAuthorityID(graph.authority.ID()), Page: contract.PageRequest{Limit: 200},
		}, port.QueryScope{All: true})
		if err != nil {
			return err
		}
		for _, snapshot := range seriesPage.Items {
			certificate, err := tx.PKI().GetCertificate(ctx, snapshot.Series.CurrentCertificateID())
			if err != nil {
				return err
			}
			if activeVersion.ID() == "" || string(certificate.DER()) == string(activeVersion.LeafDER()) || certificate.IssuerCAKeyGenerationID() == graph.rootGeneration.ID {
				if graph.series.ID() != "" {
					return fmt.Errorf("more than one current bootstrap series")
				}
				graph.series = snapshot.Series
			}
		}
		if graph.series.ID() == "" {
			return fmt.Errorf("current bootstrap series not found among %d history rows", len(seriesPage.Items))
		}
		graph.leafCertificate, err = tx.PKI().GetCertificate(ctx, graph.series.CurrentCertificateID())
		if err != nil {
			return err
		}
		graph.leafRecord, err = tx.PKI().GetLeafCertificateRecord(ctx, graph.leafCertificate.ID())
		if err != nil {
			return err
		}
		graph.crlState, err = tx.CRLs().GetStateForUpdate(ctx, graph.rootGeneration.ID)
		if err != nil {
			return err
		}
		graph.versions, err = tx.TLS().ListVersions(ctx)
		if err != nil {
			return err
		}
		graph.secrets, err = tx.Secrets().ListEncrypted(ctx)
		return err
	}); err != nil {
		t.Fatalf("read bootstrap graph: %v", err)
	}
	return graph
}

func ptrAuthorityID(id domain.AuthorityID) *domain.AuthorityID { return &id }

func TestTLSServiceBootstrapCreatesFixedGraphAndApplies(t *testing.T) {
	f := newTLSFixture(t)
	view, err := f.svc.Bootstrap(context.Background(), tlsReconcileMeta(mustInternalPrincipal(t, contract.InternalOperationTLSBootstrap)), contract.TLSBootstrapCommand{})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if view.Active == nil || view.Active.Source != domain.TLSSourceBootstrap || view.Active.ValidatedServiceURL != "" {
		t.Fatalf("bootstrap active view = %+v, want a bootstrap snapshot without service URL", view.Active)
	}
	if view.Phase == nil || *view.Phase != domain.TLSChangePhaseApplied || view.Version != 1 {
		t.Fatalf("bootstrap status = %+v, want applied at installation version 1", view)
	}
	if f.keyEngine.generateCalls != 2 || len(f.signer.requests) != 2 {
		t.Fatalf("bootstrap generated keys=%d signer requests=%d, want two of each", f.keyEngine.generateCalls, len(f.signer.requests))
	}
	rootRequest, leafRequest := f.signer.requests[0], f.signer.requests[1]
	if rootRequest.Plan.Subject.CommonName() != "cert-me" || rootRequest.Plan.Profile != "" || len(rootRequest.Plan.SANs) != 0 || rootRequest.Plan.KeyAlgorithm != domain.KeyAlgorithmECDSAP256 {
		t.Fatalf("root signing request = %+v, want fixed CN/no SAN/CA profile/P-256", rootRequest.Plan)
	}
	if leafRequest.Plan.Subject.CommonName() != "cert-me" || leafRequest.Plan.Profile != domain.CertificateProfileServerTLS || len(leafRequest.Plan.SANs) != 1 || leafRequest.Plan.SANs[0].Value() != "cert-me" || leafRequest.Plan.KeyAlgorithm != domain.KeyAlgorithmECDSAP256 {
		t.Fatalf("leaf signing request = %+v, want fixed serverAuth cert-me SAN/P-256", leafRequest.Plan)
	}
	if !sameWindow(rootRequest.Plan.Window, leafRequest.Plan.Window) || rootRequest.Plan.Window.Duration() != domain.NewDuration(30*24*time.Hour) {
		t.Fatalf("bootstrap validity root=%v leaf=%v, want the same 30-day window", rootRequest.Plan.Window, leafRequest.Plan.Window)
	}
	if f.installer.prepareCount != 1 || f.installer.applyCount != 1 || f.installer.prepared() != 0 {
		t.Fatalf("bootstrap installer prepare=%d apply=%d prepared=%d, want 1/1/0", f.installer.prepareCount, f.installer.applyCount, f.installer.prepared())
	}

	graph := readTLSBootstrapGraph(t, f)
	if graph.authority.Name() != "cert-me" || graph.authority.IssuanceState() != domain.IssuanceStateEnabled || graph.authority.KeyGenerationID() != graph.rootGeneration.ID {
		t.Fatalf("bootstrap authority = %+v, want enabled and linked to its root generation", graph.authority)
	}
	if graph.rootGeneration.GenerationNo != 1 || graph.rootGeneration.AuthorityID != graph.authority.ID() || graph.rootGeneration.KeyMaterialID != rootRequest.KeyMaterialID {
		t.Fatalf("root generation = %+v, want generation 1 linked to bootstrap authority/root key", graph.rootGeneration)
	}
	if graph.rootCertificate.Kind() != domain.CertificateKindCA || graph.rootCertificate.Profile() != "" || len(graph.rootCertificate.SANs()) != 0 || graph.rootCertificate.Subject().CommonName() != "cert-me" || !sameWindow(graph.rootCertificate.Validity(), graph.leafCertificate.Validity()) {
		t.Fatalf("root certificate = %+v, want fixed CA snapshot matching leaf window", graph.rootCertificate)
	}
	if graph.rootRecord.CAKeyGenerationID != graph.rootGeneration.ID || graph.rootRecord.IssuerCACertificateID != "" {
		t.Fatalf("root CA record = %+v, want self-signed record for its generation", graph.rootRecord)
	}
	if graph.leafCertificate.Kind() != domain.CertificateKindLeaf || graph.leafCertificate.Profile() != domain.CertificateProfileServerTLS || len(graph.leafCertificate.SANs()) != 1 || graph.leafCertificate.SANs()[0].Value() != "cert-me" {
		t.Fatalf("leaf certificate = %+v, want serverAuth cert-me leaf", graph.leafCertificate)
	}
	if graph.leafRecord.IssuerCACertificateID != graph.rootCertificate.ID() || graph.leafRecord.Operation != port.CertificateOperationInitial || graph.series.Purpose() != domain.SeriesPurposeBootstrapTLS || graph.series.CurrentCertificateID() != graph.leafCertificate.ID() {
		t.Fatalf("bootstrap leaf graph is inconsistent: record=%+v series=%+v", graph.leafRecord, graph.series)
	}
	if graph.crlState.CAKeyGenerationID() != graph.rootGeneration.ID || graph.crlState.PublicationState() != domain.PublicationStateInactive || graph.crlState.SigningCACertificateID() != graph.rootCertificate.ID() {
		t.Fatalf("bootstrap CRL state = %+v, want inactive state signed by root", graph.crlState)
	}
	bootstrapCASecrets, bootstrapTLSSecrets := 0, 0
	for _, stored := range graph.secrets {
		switch stored.Purpose() {
		case domain.SecretPurposeBootstrapCA:
			bootstrapCASecrets++
		case domain.SecretPurposeInternalTLS:
			for _, version := range graph.versions {
				if version.Source() == domain.TLSSourceBootstrap && version.KeyMaterialID() == stored.OwnerKeyID() {
					bootstrapTLSSecrets++
				}
			}
		}
	}
	if bootstrapCASecrets != 1 || bootstrapTLSSecrets != 1 {
		t.Fatalf("bootstrap secrets: bootstrap_ca=%d bootstrap_tls=%d, want 1/1", bootstrapCASecrets, bootstrapTLSSecrets)
	}
}

func TestTLSServiceBootstrapRegeneratesOneAuthorityAndPreservesHistory(t *testing.T) {
	f := newTLSFixture(t)
	internal := tlsReconcileMeta(mustInternalPrincipal(t, contract.InternalOperationTLSBootstrap))
	first, err := f.svc.Bootstrap(context.Background(), internal, contract.TLSBootstrapCommand{})
	if err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}
	firstGraph := readTLSBootstrapGraph(t, f)
	firstRootID := firstGraph.rootCertificate.ID()
	firstSeriesID := firstGraph.series.ID()

	second, err := f.svc.Bootstrap(context.Background(), internal, contract.TLSBootstrapCommand{})
	if err != nil {
		t.Fatalf("regeneration Bootstrap: %v", err)
	}
	if second.Active == nil || second.Active.ID == first.Active.ID || second.Version != 2 {
		t.Fatalf("regenerated status = %+v, want a new active snapshot at version 2", second)
	}
	graph := readTLSBootstrapGraph(t, f)
	if graph.authority.ID() != firstGraph.authority.ID() || graph.authority.Version() != 1 {
		t.Fatalf("bootstrap authority after regeneration = %+v, want the same row at version 1", graph.authority)
	}
	if graph.rootGeneration.GenerationNo != 2 || graph.rootCertificate.ID() == firstRootID || graph.series.ID() == firstSeriesID {
		t.Fatalf("regenerated graph generation=%d root=%s series=%s, want generation 2 and fresh public snapshots", graph.rootGeneration.GenerationNo, graph.rootCertificate.ID(), graph.series.ID())
	}
	if len(graph.versions) != 2 {
		t.Fatalf("TLS version history length = %d, want both bootstrap snapshots retained", len(graph.versions))
	}
	if _, err := func() (domain.Certificate, error) {
		var old domain.Certificate
		err := f.store.Read(context.Background(), func(tx port.TxStores) error {
			var err error
			old, err = tx.PKI().GetCertificate(context.Background(), firstRootID)
			return err
		})
		return old, err
	}(); err != nil {
		t.Fatalf("old root public history was not retained: %v", err)
	}
	if f.keyEngine.generateCalls != 4 || f.installer.applyCount != 2 {
		t.Fatalf("regeneration key/apply counts = %d/%d, want 4/2", f.keyEngine.generateCalls, f.installer.applyCount)
	}
}

func TestTLSServiceBootstrapRejectsOperationalActiveVersion(t *testing.T) {
	f := newTLSFixture(t)
	candidate := f.issueCandidate(t, tlsIdemKeyA, "tls-operational")
	f.mustActivate(t, candidate.ID, 0)

	_, err := f.svc.Bootstrap(context.Background(), tlsReconcileMeta(mustInternalPrincipal(t, contract.InternalOperationTLSBootstrap)), contract.TLSBootstrapCommand{})
	requireErr(t, err, contract.ErrorKindConflict, "tls_bootstrap_operational_active")
	status := f.status(t)
	if status.Active == nil || status.Active.ID != candidate.ID {
		t.Fatalf("active version after blocked bootstrap = %+v, want operational candidate %s", status.Active, candidate.ID)
	}
}

func TestTLSServiceOperationalActivationDeletesBootstrapSecretsAndKeepsHistory(t *testing.T) {
	f := newTLSFixture(t)
	internal := tlsReconcileMeta(mustInternalPrincipal(t, contract.InternalOperationTLSBootstrap))
	bootstrap, err := f.svc.Bootstrap(context.Background(), internal, contract.TLSBootstrapCommand{})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	candidate := f.issueCandidate(t, tlsIdemKeyA, "tls-operational")
	f.mustActivate(t, candidate.ID, bootstrap.Version)

	graph := readTLSBootstrapGraph(t, f)
	var managed domain.TLSVersion
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		managed, err = tx.TLS().GetVersion(context.Background(), candidate.ID)
		return err
	}); err != nil {
		t.Fatalf("read managed version: %v", err)
	}
	bootstrapSecrets := 0
	for _, stored := range graph.secrets {
		if stored.Purpose() == domain.SecretPurposeBootstrapCA {
			bootstrapSecrets++
		}
	}
	if bootstrapSecrets != 0 {
		t.Fatalf("bootstrap_ca secrets after operational activation = %d, want 0", bootstrapSecrets)
	}
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		for _, version := range graph.versions {
			if version.Source() != domain.TLSSourceBootstrap {
				continue
			}
			if _, err := tx.Secrets().GetEncrypted(context.Background(), version.KeyMaterialID(), domain.SecretPurposeInternalTLS); !errors.Is(err, port.ErrNotFound) {
				return fmt.Errorf("bootstrap leaf secret for version %s = %v, want ErrNotFound", version.ID(), err)
			}
		}
		if _, err := tx.Secrets().GetEncrypted(context.Background(), managed.KeyMaterialID(), domain.SecretPurposeInternalTLS); err != nil {
			return fmt.Errorf("managed TLS secret: %w", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTLSServiceReloadStoresConfiguredCandidateWithoutActivation(t *testing.T) {
	f := newTLSFixture(t)
	registerTLSUploadFixture(t, f)
	passphrase := secret.New([]byte("reload-passphrase"))
	f.source.input = port.TLSFileSourceInput{
		Certificate: []byte(tlsUploadCertBytes), Key: []byte(tlsUploadKeyBytes), Passphrase: passphrase,
	}

	view, err := f.svc.Reload(context.Background(), tlsIssueMeta(tlsIdemKeyA), contract.TLSReloadCommand{})
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if view.Source != domain.TLSSourceExternal || f.source.calls != 1 || f.installer.prepareCount != 0 || f.installer.applyCount != 0 {
		t.Fatalf("reload result/source/calls = %+v/%d/%d/%d, want external, one source read and no installer call", view, f.source.calls, f.installer.prepareCount, f.installer.applyCount)
	}
	if err := passphrase.Use(func([]byte) error { return nil }); !errors.Is(err, secret.ErrClosed) {
		t.Fatalf("source passphrase after Reload = %v, want secret.ErrClosed", err)
	}
	if err := f.parser.lastMintedKey.Use(func([]byte) error { return nil }); !errors.Is(err, secret.ErrClosed) {
		t.Fatalf("parsed key after Reload = %v, want secret.ErrClosed", err)
	}
	status := f.status(t)
	if status.Active != nil {
		t.Fatalf("Reload activated candidate unexpectedly: %+v", status.Active)
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
		FileSource:  f.source,
		RuntimeGate: f.gate,
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

func TestTLSServiceActivateFirstCandidateApplyFailureClearsActivePointer(t *testing.T) {
	f := newTLSFixture(t)
	candidate := f.issueCandidate(t, tlsIdemKeyA, "tls-first-failure")
	f.installer.applyErr = errors.New("listener swap failed")

	_, err := f.activate(t, candidate.ID, 0)
	requireErr(t, err, contract.ErrorKindUnavailable, "tls_apply_failed")
	status := f.status(t)
	if status.Active != nil || status.Phase != nil {
		t.Fatalf("first activation failure left active status = %+v, want no active pointer", status)
	}
	if status.Version != 2 {
		t.Fatalf("installation version after first activation rollback = %v, want 2 (set then clear)", status.Version)
	}
	if f.gate.callCount() != 0 {
		t.Fatalf("runtime gate calls after a clean first-activation rollback = %v, want none", f.gate.codes)
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

func TestTLSServiceReconcileRecoversCommittedChange(t *testing.T) {
	f := newTLSFixture(t)
	candidate := seedTLSVersionWithSecret(t, f.store, f.ids, testNow().Add(domain.NewDuration(48*time.Hour)), "committed")
	seedCommittedChange(t, f.store, candidate, "")

	view, err := f.svc.Reconcile(context.Background(), tlsReconcileMeta(mustInternalPrincipal(t, contract.InternalOperationTLSReconcile)), contract.TLSReconcileCommand{})
	if err != nil {
		t.Fatalf("Reconcile committed change: %v", err)
	}
	if view.Active == nil || view.Active.ID != candidate || view.Phase == nil || *view.Phase != domain.TLSChangePhaseApplied {
		t.Fatalf("reconciled committed status = %+v, want applied candidate", view)
	}
	if f.installer.applyCount != 1 || f.installer.lastAppliedCandidateID != candidate {
		t.Fatalf("installer after committed recovery = prepare=%d apply=%d candidate=%s, want one apply of %s", f.installer.prepareCount, f.installer.applyCount, f.installer.lastAppliedCandidateID, candidate)
	}
	if f.gate.callCount() != 0 {
		t.Fatalf("runtime gate calls after successful committed recovery = %v, want none", f.gate.codes)
	}
}

func TestTLSServiceReconcileFailsClosedWhenActiveChangeIsMissing(t *testing.T) {
	f := newTLSFixture(t)
	candidate := seedTLSVersionWithSecret(t, f.store, f.ids, testNow().Add(domain.NewDuration(48*time.Hour)), "missing-change")
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		installation, err := tx.Installation().GetForUpdate(context.Background())
		if err != nil {
			return err
		}
		original := installation.Version
		installation.ActiveTLSVersionID = candidate
		installation.Version = installation.Version.Next()
		return tx.Installation().Save(context.Background(), installation, original)
	}); err != nil {
		t.Fatalf("seed missing active change: %v", err)
	}

	_, err := f.svc.Reconcile(context.Background(), tlsReconcileMeta(mustInternalPrincipal(t, contract.InternalOperationTLSReconcile)), contract.TLSReconcileCommand{})
	requireErr(t, err, contract.ErrorKindUnavailable, "tls_active_change_missing")
	if f.gate.callCount() != 1 || f.gate.lastCode() != "tls_active_change_missing" {
		t.Fatalf("runtime gate calls = %v, want one tls_active_change_missing call", f.gate.codes)
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

	_, err := f.svc.Reconcile(context.Background(), tlsReconcileMeta(mustInternalPrincipal(t, contract.InternalOperationTLSReconcile)), contract.TLSReconcileCommand{})
	requireErr(t, err, contract.ErrorKindUnavailable, "tls_recovery_unresolved")
	if f.gate.callCount() != 1 || f.gate.lastCode() != "tls_recovery_unresolved" {
		t.Fatalf("runtime gate calls = %v, want one tls_recovery_unresolved call", f.gate.codes)
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
// This does NOT attempt to make a database rollback undo an already-applied
// listener change. It verifies the required fail-closed behavior: when the
// post-Apply audit write fails, the persisted change is recoverable but the
// runtime gate refuses normal operation until reconciliation repairs the
// divergence.
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
		FileSource:  f.source,
		RuntimeGate: f.gate,
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
	if f.gate.callCount() != 1 || f.gate.lastCode() != "tls_reconcile_audit_failed" {
		t.Fatalf("runtime gate calls after post-Apply audit failure = %v, want one tls_reconcile_audit_failed call", f.gate.codes)
	}
}

// failingAuditUoW wraps a real UnitOfWork/ReadStore so every AuditRepository
// call fails, letting a test force a failure AFTER an installer Apply has
// already run inside the same Write, without needing a bespoke in-memory
// store implementation.
type failingAuditRepo struct{ port.AuditRepository }

func (failingAuditRepo) Append(context.Context, port.AuditEvent, port.AuditScope) error {
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
	leafPublicKey := tlsUploadLeafPublicKey(t)
	f.parser.registerLeaf([]byte(tlsUploadCertBytes), port.ParsedCertificateFacts{
		PublicKey: leafPublicKey, SPKIFingerprint: leafPublicKey.Fingerprint(), KeyAlgorithm: domain.KeyAlgorithmECDSAP256,
		Serial: serial(t, "beef"), Validity: window, Subject: subject, SANs: []domain.SAN{san},
		Kind: domain.CertificateKindLeaf, Profile: domain.CertificateProfileServerTLS,
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
	chainPublicKey, err := domain.NewPublicKey(domain.KeyAlgorithmECDSAP256, []byte("upload-chain-public-key"))
	if err != nil {
		t.Fatalf("chain public key: %v", err)
	}
	f.parser.registerChain([]byte(tlsUploadChainByte), port.ParsedCertificateFacts{
		DER: []byte("intermediate-der"), PublicKey: chainPublicKey, SPKIFingerprint: chainPublicKey.Fingerprint(), KeyAlgorithm: domain.KeyAlgorithmECDSAP256,
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
		FileSource:  f.source,
		RuntimeGate: f.gate,
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
