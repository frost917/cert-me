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

// ---- fakes ----

// fakePKIParser is a fully-controllable port.PKIParser test double.
// ParseCertificateBundle returns exactly the facts registered via addCert,
// keyed by the raw uploaded bytes, so a test can hand crafted domain facts
// straight through without real ASN.1/crypto parsing -- matching how
// fakeSigner/fakeKeyEngine avoid real crypto elsewhere in this package.
type fakePKIParser struct {
	bundles map[string]port.CertificateBundleFacts
	crls    map[string]port.ParsedCRLFacts
	caKeys  map[string]domain.PublicKey
}

func newFakePKIParser() *fakePKIParser {
	return &fakePKIParser{
		bundles: map[string]port.CertificateBundleFacts{},
		crls:    map[string]port.ParsedCRLFacts{},
		caKeys:  map[string]domain.PublicKey{},
	}
}

// addCert registers facts for data, forcing facts.DER = data so a caller
// only needs to set the OTHER fields (PublicKey, SPKIFingerprint, Subject,
// IssuerSubject, Serial, Validity, KeyAlgorithm, Kind).
func (p *fakePKIParser) addCert(data []byte, facts port.ParsedCertificateFacts) {
	facts.DER = data
	p.bundles[string(data)] = port.CertificateBundleFacts{Certificates: []port.ParsedCertificateFacts{facts}}
}

func (p *fakePKIParser) registerChain(data []byte, facts ...port.ParsedCertificateFacts) {
	p.bundles[string(data)] = port.CertificateBundleFacts{Certificates: facts}
}

func (p *fakePKIParser) ParseCertificateBundle(_ context.Context, input port.CertificateBundleInput) (port.CertificateBundleFacts, error) {
	b, ok := p.bundles[string(input.Data)]
	if !ok {
		return port.CertificateBundleFacts{}, errors.New("fakePKIParser: no certificate registered for this data")
	}
	return b, nil
}

func (p *fakePKIParser) addCRL(data []byte, facts port.ParsedCRLFacts) {
	facts.DER = data
	p.crls[string(data)] = facts
}

func (p *fakePKIParser) addCAKey(data []byte, publicKey domain.PublicKey) {
	p.caKeys[string(data)] = publicKey
}

func (p *fakePKIParser) ParseCRL(_ context.Context, input port.CRLInput) (port.ParsedCRLFacts, error) {
	crl, ok := p.crls[string(input.Data)]
	if !ok {
		return port.ParsedCRLFacts{}, errors.New("fakePKIParser: no CRL registered for this data")
	}
	return crl, nil
}

func (p *fakePKIParser) ParseCAKey(_ context.Context, input port.CAKeyInput) (port.ValidatedCAKeyInput, error) {
	publicKey, ok := p.caKeys[string(input.Data)]
	if !ok || !publicKey.Equal(input.ExpectedPublicKey) {
		return port.ValidatedCAKeyInput{}, errors.New("fakePKIParser: CA key does not match expected public key")
	}
	return port.ValidatedCAKeyInput{
		PrivateKey: secret.FromString("fake-ca-private-key"),
		Algorithm:  publicKey.Algorithm(),
		PublicKey:  publicKey,
	}, nil
}

func (p *fakePKIParser) ParseInternalTLSKey(context.Context, port.TLSKeyInput) (port.ValidatedTLSKeyInput, error) {
	return port.ValidatedTLSKeyInput{}, errors.New("fakePKIParser: ParseInternalTLSKey not supported")
}

var _ port.PKIParser = (*fakePKIParser)(nil)

// fakeChainValidator is a deterministic port.ChainValidator: it records every
// call and fails only when told to (fail != nil).
type fakeChainValidator struct {
	calls int
	fail  error
}

func (v *fakeChainValidator) Validate(_ context.Context, _ []byte, _ [][]byte, _ domain.Instant) error {
	v.calls++
	return v.fail
}

var _ port.ChainValidator = (*fakeChainValidator)(nil)

type fakeCRLVerifier struct {
	calls int
	fail  error
}

func (v *fakeCRLVerifier) Verify(_ context.Context, _ []byte, _ []byte) error {
	v.calls++
	return v.fail
}

var _ port.CRLVerifier = (*fakeCRLVerifier)(nil)

// ---- fixture plumbing ----

type importFixture struct {
	store          *porttest.Store
	ids            *seqIDs
	parser         *fakePKIParser
	chainValidator *fakeChainValidator
	crlVerifier    *fakeCRLVerifier
	keyEngine      *fakeKeyEngine
	authorizer     *toggleAuthorizer
	svc            *ImportService
}

func newImportFixture(t *testing.T) *importFixture {
	t.Helper()
	store := porttest.NewStore()
	seedAdminSessionForIssuance(t, store)

	ids := &seqIDs{}
	parser := newFakePKIParser()
	chainValidator := &fakeChainValidator{}
	crlVerifier := &fakeCRLVerifier{}
	keyEngine := &fakeKeyEngine{}
	authorizer := &toggleAuthorizer{allow: true}

	svc, err := NewImportService(ImportDeps{
		CommonDeps: CommonDeps{
			UnitOfWork: store,
			ReadStore:  store,
			Authorizer: authorizer,
			Clock:      fixedClock{now: testNow()},
			IDs:        ids,
		},
		PKIParser:      parser,
		ChainValidator: chainValidator,
		CRLVerifier:    crlVerifier,
		KeyEngine:      keyEngine,
	})
	if err != nil {
		t.Fatalf("new import service: %v", err)
	}
	return &importFixture{store: store, ids: ids, parser: parser, chainValidator: chainValidator, crlVerifier: crlVerifier, keyEngine: keyEngine, authorizer: authorizer, svc: svc}
}

func importMeta(idempotencyKey string) contract.MutationMeta {
	return contract.MutationMeta{
		RequestMeta:    contract.RequestMeta{Principal: mustAdminPrincipal()},
		IdempotencyKey: idempotencyKey,
	}
}

func importVersionMeta(version domain.Version) contract.MutationMeta {
	return contract.MutationMeta{
		RequestMeta:     contract.RequestMeta{Principal: mustAdminPrincipal()},
		ExpectedVersion: contract.WithExpectedVersion(version),
	}
}

// caFacts builds a self-signed CA's ParsedCertificateFacts. spkiSeed drives
// both PublicKey and SPKIFingerprint so two certs sharing a seed share a
// public key, and two different seeds never collide.
func caFacts(t *testing.T, commonName, spkiSeed, serialHex string, notBefore, notAfter domain.Instant) port.ParsedCertificateFacts {
	t.Helper()
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: commonName})
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	spkiBytes := []byte("spki-" + spkiSeed)
	pub, err := domain.NewPublicKey(domain.KeyAlgorithmECDSAP256, spkiBytes)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	window, err := domain.NewValidityWindow(notBefore, notAfter)
	if err != nil {
		t.Fatalf("validity window: %v", err)
	}
	return port.ParsedCertificateFacts{
		PublicKey:       pub,
		SPKIFingerprint: domain.NewFingerprint(spkiBytes),
		KeyAlgorithm:    domain.KeyAlgorithmECDSAP256,
		Serial:          serial(t, serialHex),
		Validity:        window,
		Subject:         subject,
		Kind:            domain.CertificateKindCA,
		IssuerSubject:   subject, // self-signed by default; callers override for an intermediate
	}
}

func uploadOneCert(fileName string, data []byte) contract.ImportUploadCommand {
	cmd := contract.ImportUploadCommand{
		Files: []contract.UploadedFile{{FileName: fileName, Data: data}},
		Metadata: contract.ImportMetadataInput{
			SchemaVersion: 1,
			Files:         []contract.ImportFileMetadataInput{{FileName: fileName, Kind: contract.ImportFileKindCertificate}},
		},
	}
	cmd.Metadata.PreviewManifest = manifestFor(cmd.Files...)
	return cmd
}

func importCommand(files []contract.UploadedFile, metadata []contract.ImportFileMetadataInput, hashes map[string]string) contract.ImportUploadCommand {
	cmd := contract.ImportUploadCommand{
		Files: files,
		Metadata: contract.ImportMetadataInput{
			SchemaVersion: 1,
			Files:         metadata,
		},
	}
	manifestFiles := make([]contract.ImportManifestFileInput, len(metadata))
	for i, m := range metadata {
		manifestFiles[i] = contract.ImportManifestFileInput{
			FileID:              m.FileName,
			Kind:                m.Kind,
			SHA256Hex:           hashes[m.FileName],
			IssuerCertificateID: m.IssuerCertificateID,
		}
	}
	cmd.Metadata.PreviewManifest = &contract.ImportPreviewManifestInput{SchemaVersion: 1, Files: manifestFiles}
	return cmd
}

func manifestFor(files ...contract.UploadedFile) *contract.ImportPreviewManifestInput {
	entries := make([]contract.ImportManifestFileInput, len(files))
	for i, f := range files {
		entries[i] = contract.ImportManifestFileInput{
			FileID:    f.FileName,
			Kind:      contract.ImportFileKindCertificate,
			SHA256Hex: domain.NewFingerprint(f.Data).Hex(),
		}
	}
	return &contract.ImportPreviewManifestInput{SchemaVersion: 1, Files: entries}
}

func requireAppError(t *testing.T, err error) *contract.AppError {
	t.Helper()
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	return appErr
}

func requireConflict(t *testing.T, err error, code string) {
	t.Helper()
	appErr := requireAppError(t, err)
	if appErr.Kind() != contract.ErrorKindConflict {
		t.Fatalf("kind = %s (code %q), want conflict", appErr.Kind(), appErr.Code())
	}
	if appErr.Code() != code {
		t.Fatalf("code = %q, want %q", appErr.Code(), code)
	}
}

// ---- Preview: does not persist ----

func TestImportServicePreviewDoesNotPersist(t *testing.T) {
	f := newImportFixture(t)
	rootDER := []byte("root-der-1")
	f.parser.addCert(rootDER, caFacts(t, "Test Root", "root-1", "10", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour))))

	preview, err := f.svc.Preview(context.Background(), importMeta("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), uploadOneCert("root.pem", rootDER))
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if len(preview.Items) != 1 || preview.Items[0].Status != contract.ImportItemStatusNew {
		t.Fatalf("items = %+v, want exactly one New item", preview.Items)
	}

	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		_, err := tx.PKI().FindCertificateByDER(context.Background(), domain.NewFingerprint(rootDER))
		if !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("FindCertificateByDER after Preview: err = %v, want ErrNotFound (Preview must not persist)", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after preview: %v", err)
	}
}

// ---- Commit: happy path ----

func TestImportServiceCommitStoresNewRootAuthority(t *testing.T) {
	f := newImportFixture(t)
	rootDER := []byte("root-der-2")
	f.parser.addCert(rootDER, caFacts(t, "New Root", "root-2", "11", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour))))

	result, err := f.svc.Commit(context.Background(), importMeta("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), uploadOneCert("root.pem", rootDER))
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if result.State != contract.ImportResultStateCommitted {
		t.Fatalf("state = %q, want committed", result.State)
	}
	if len(result.CertificateIDs) != 1 {
		t.Fatalf("certificate_ids = %v, want exactly one", result.CertificateIDs)
	}
	if len(result.AuthorityIDs) != 1 {
		t.Fatalf("authority_ids = %v, want exactly one", result.AuthorityIDs)
	}
	if len(result.Items) != 1 || result.Items[0].Status != contract.ImportItemStatusNew {
		t.Fatalf("items = %+v, want exactly one New item", result.Items)
	}

	authorityID := result.AuthorityIDs[0]
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		authority, err := tx.PKI().GetIssuerForUpdate(context.Background(), authorityID)
		if err != nil {
			t.Fatalf("read authority: %v", err)
		}
		if authority.Kind() != domain.AuthorityKindRoot {
			t.Fatalf("kind = %q, want root", authority.Kind())
		}
		if authority.KeyAvailable() {
			t.Fatal("want key_available=false for a certificate-only import (no private key was imported)")
		}
		if authority.IssuanceState() != domain.IssuanceStateStopped {
			t.Fatalf("issuance_state = %q, want stopped", authority.IssuanceState())
		}
		return nil
	}); err != nil {
		t.Fatalf("read after commit: %v", err)
	}
}

func TestImportServiceCommitImportsCAKeyWithOrderIndependentBundle(t *testing.T) {
	f := newImportFixture(t)
	rootDER := []byte("root-der-with-key")
	keyDER := []byte("root-private-key")
	facts := caFacts(t, "Keyed Root", "keyed-root", "18", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour)))
	f.parser.addCert(rootDER, facts)
	f.parser.addCAKey(keyDER, facts.PublicKey)
	cmd := importCommand(
		[]contract.UploadedFile{{FileName: "ca-key.pem", Data: keyDER}, {FileName: "root.pem", Data: rootDER}},
		[]contract.ImportFileMetadataInput{{FileName: "ca-key.pem", Kind: contract.ImportFileKindCAKey}, {FileName: "root.pem", Kind: contract.ImportFileKindCertificate}},
		map[string]string{
			"ca-key.pem": facts.PublicKey.Fingerprint().Hex(),
			"root.pem":   domain.NewFingerprint(rootDER).Hex(),
		},
	)

	preview, err := f.svc.Preview(context.Background(), importMeta("18181818-1818-4818-8818-181818181818"), cmd)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if len(preview.Items) != 2 || preview.Items[0].SHA256 != facts.PublicKey.Fingerprint() {
		t.Fatalf("preview items = %+v, want key item normalized to the SPKI fingerprint", preview.Items)
	}

	result, err := f.svc.Commit(context.Background(), importMeta("19191919-1919-4919-8919-191919191919"), cmd)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if len(result.CertificateIDs) != 1 || len(result.AuthorityIDs) != 1 {
		t.Fatalf("result = %+v, want one imported CA and authority", result)
	}
	if f.keyEngine.importCalls != 1 {
		t.Fatalf("ImportCA calls = %d, want 1", f.keyEngine.importCalls)
	}

	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		authority, err := tx.PKI().GetIssuerForUpdate(context.Background(), result.AuthorityIDs[0])
		if err != nil {
			return err
		}
		if !authority.KeyAvailable() {
			t.Fatal("want the same-batch CA key to make the authority key available")
		}
		generation, err := tx.PKI().GetCAKeyGeneration(context.Background(), authority.KeyGenerationID())
		if err != nil {
			return err
		}
		if _, err := tx.Secrets().GetEncrypted(context.Background(), generation.KeyMaterialID, domain.SecretPurposeCASigning); err != nil {
			t.Fatalf("stored CA secret: %v", err)
		}
		material, err := tx.PKI().GetKeyMaterial(context.Background(), generation.KeyMaterialID)
		if err != nil {
			return err
		}
		if !material.PublicKey.Equal(facts.PublicKey) {
			t.Fatalf("stored public key = %v, want %v", material.PublicKey, facts.PublicKey)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after keyed import: %v", err)
	}
}

func TestImportServiceCommitAcceptsPEMCertificateBundle(t *testing.T) {
	f := newImportFixture(t)
	seedDefaultSettings(t, f.store)
	now := testNow()
	rootDER := []byte("bundle-root-der")
	rootFacts := caFacts(t, "Bundle Root", "bundle-root", "1e", now.Add(domain.NewDuration(-time.Hour)), now.Add(domain.NewDuration(365*24*time.Hour)))
	rootFacts.DER = rootDER

	intermediateDER := []byte("bundle-intermediate-der")
	intermediateFacts := caFacts(t, "Bundle Intermediate", "bundle-intermediate", "1f", now.Add(domain.NewDuration(-time.Hour)), now.Add(domain.NewDuration(180*24*time.Hour)))
	intermediateFacts.DER = intermediateDER
	intermediateFacts.IssuerSubject = rootFacts.Subject

	leafDER := []byte("bundle-leaf-der")
	leafFacts := caFacts(t, "Bundle Leaf", "bundle-leaf", "20", now.Add(domain.NewDuration(-time.Hour)), now.Add(domain.NewDuration(30*24*time.Hour)))
	leafFacts.DER = leafDER
	leafFacts.Kind = domain.CertificateKindLeaf
	leafFacts.Profile = domain.CertificateProfileServerTLS
	leafFacts.IssuerSubject = intermediateFacts.Subject
	san, err := domain.NewSAN(domain.SANTypeDNS, "bundle.example.test")
	if err != nil {
		t.Fatalf("leaf SAN: %v", err)
	}
	leafFacts.SANs = []domain.SAN{san}

	bundleDER := []byte("root-and-intermediate-and-leaf.pem")
	f.parser.registerChain(bundleDER, rootFacts, intermediateFacts, leafFacts)
	cmd := contract.ImportUploadCommand{
		Files: []contract.UploadedFile{{FileName: "pki-bundle.pem", Data: bundleDER}},
		Metadata: contract.ImportMetadataInput{
			SchemaVersion: 1,
			Files:         []contract.ImportFileMetadataInput{{FileName: "pki-bundle.pem", Kind: contract.ImportFileKindCertificate}},
			PreviewManifest: &contract.ImportPreviewManifestInput{
				SchemaVersion: 1,
				Files: []contract.ImportManifestFileInput{
					{FileID: "pki-bundle.pem", Kind: contract.ImportFileKindCertificate, SHA256Hex: domain.NewFingerprint(rootDER).Hex()},
					{FileID: "pki-bundle.pem", Kind: contract.ImportFileKindCertificate, SHA256Hex: domain.NewFingerprint(intermediateDER).Hex()},
					{FileID: "pki-bundle.pem", Kind: contract.ImportFileKindCertificate, SHA256Hex: domain.NewFingerprint(leafDER).Hex()},
				},
			},
		},
	}

	preview, err := f.svc.Preview(context.Background(), importMeta("28282828-2828-4828-8828-282828282828"), cmd)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if len(preview.Items) != 3 || len(preview.Manifest.Files) != 3 {
		t.Fatalf("preview = %+v, want three logical certificate items", preview)
	}
	for _, item := range preview.Items {
		if item.FileID != "pki-bundle.pem" || item.Status != contract.ImportItemStatusNew {
			t.Fatalf("preview item = %+v, want new item projected to the uploaded file", item)
		}
	}

	result, err := f.svc.Commit(context.Background(), importMeta("29292929-2929-4929-8929-292929292929"), cmd)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if len(result.CertificateIDs) != 3 || len(result.AuthorityIDs) != 2 || len(result.Items) != 3 {
		t.Fatalf("result = %+v, want root/intermediate/leaf and two authorities", result)
	}
	for _, item := range result.Items {
		if item.FileID != "pki-bundle.pem" {
			t.Fatalf("result item = %+v, want original bundle file id", item)
		}
	}
}

func TestImportServiceAttachSigningKeyReusesExistingGeneration(t *testing.T) {
	f := newImportFixture(t)
	rootDER := []byte("root-der-attach")
	facts := caFacts(t, "Attach Root", "attach-root", "19", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour)))
	f.parser.addCert(rootDER, facts)
	result, err := f.svc.Commit(context.Background(), importMeta("20202020-2020-4020-8020-202020202020"), uploadOneCert("root.pem", rootDER))
	if err != nil {
		t.Fatalf("seed Commit: %v", err)
	}
	authorityID := result.AuthorityIDs[0]
	keyDER := []byte("attach-private-key")
	f.parser.addCAKey(keyDER, facts.PublicKey)

	var originalGeneration domain.CAKeyGenerationID
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		authority, err := tx.PKI().GetIssuerForUpdate(context.Background(), authorityID)
		if err != nil {
			return err
		}
		originalGeneration = authority.KeyGenerationID()
		return nil
	}); err != nil {
		t.Fatalf("read authority: %v", err)
	}

	view, err := f.svc.AttachSigningKey(context.Background(), importVersionMeta(0), contract.ImportAttachSigningKeyCommand{
		AuthorityID: authorityID,
		Key:         keyDER,
	})
	if err != nil {
		t.Fatalf("AttachSigningKey: %v", err)
	}
	if !view.KeyAvailable || view.KeyGenerationID != originalGeneration || view.Version != 1 {
		t.Fatalf("view = %+v, want the existing generation attached with authority version 1", view)
	}
	if f.keyEngine.importCalls != 1 {
		t.Fatalf("ImportCA calls = %d, want 1", f.keyEngine.importCalls)
	}
}

func TestImportServiceCommitImportsCRLAndRetainsExpiredHistory(t *testing.T) {
	f := newImportFixture(t)
	rootDER := []byte("root-der-crl")
	facts := caFacts(t, "CRL Root", "crl-root", "1a", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour)))
	f.parser.addCert(rootDER, facts)
	rootResult, err := f.svc.Commit(context.Background(), importMeta("21212121-2121-4121-8121-212121212121"), uploadOneCert("root.pem", rootDER))
	if err != nil {
		t.Fatalf("seed Commit: %v", err)
	}
	crlDER := []byte("expired-crl-der")
	crlNumber, err := domain.ParseCRLNumber("2a")
	if err != nil {
		t.Fatalf("CRL number: %v", err)
	}
	crlFacts := port.ParsedCRLFacts{
		IssuerSubject: facts.Subject,
		Number:        crlNumber,
		ThisUpdate:    testNow().Add(domain.NewDuration(-2 * time.Hour)),
		NextUpdate:    testNow().Add(domain.NewDuration(-time.Hour)),
		Revoked: []port.RevokedEntryFacts{{
			Serial:    serial(t, "dead"),
			RevokedAt: testNow().Add(domain.NewDuration(-90 * time.Minute)),
			Reason:    domain.RevocationReasonCessationOfOperation,
		}},
	}
	f.parser.addCRL(crlDER, crlFacts)
	cmd := importCommand(
		[]contract.UploadedFile{{FileName: "root.crl", Data: crlDER}},
		[]contract.ImportFileMetadataInput{{FileName: "root.crl", Kind: contract.ImportFileKindCRL, IssuerCertificateID: rootResult.CertificateIDs[0]}},
		map[string]string{"root.crl": domain.NewFingerprint(crlDER).Hex()},
	)
	preview, err := f.svc.Preview(context.Background(), importMeta("22222222-2222-4222-8222-222222222222"), cmd)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if preview.Items[0].Status != contract.ImportItemStatusNew || preview.Items[0].ErrorCode != "import_crl_expired" {
		t.Fatalf("preview item = %+v, want new with expired warning", preview.Items[0])
	}
	if f.crlVerifier.calls != 1 {
		t.Fatalf("CRL verifier calls after Preview = %d, want 1", f.crlVerifier.calls)
	}
	result, err := f.svc.Commit(context.Background(), importMeta("23232323-2323-4323-8323-232323232323"), cmd)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if result.Items[0].ErrorCode != "import_crl_expired" {
		t.Fatalf("result item = %+v, want expired warning preserved", result.Items[0])
	}
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		authority, err := tx.PKI().GetIssuerForUpdate(context.Background(), rootResult.AuthorityIDs[0])
		if err != nil {
			return err
		}
		revocation, err := tx.Revocations().FindForUpdate(context.Background(), authority.KeyGenerationID(), serial(t, "dead"))
		if err != nil {
			return err
		}
		if revocation.Source() != domain.RevocationSourceImport || revocation.CertificateID() != "" {
			t.Fatalf("revocation = %+v, want imported certificate-less history", revocation)
		}
		state, err := tx.CRLs().GetStateForUpdate(context.Background(), authority.KeyGenerationID())
		if err != nil {
			return err
		}
		if state.MaxReservedNumber().Compare(crlNumber) != 0 {
			t.Fatalf("max reserved CRL number = %s, want %s", state.MaxReservedNumber(), crlNumber)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after CRL import: %v", err)
	}
}

func TestImportServiceCommitImportsLeafWithoutSecretAndRejectsRootDirectLeaf(t *testing.T) {
	f := newImportFixture(t)
	seedDefaultSettings(t, f.store)
	rootDER := []byte("root-der-leaf-import")
	rootFacts := caFacts(t, "Leaf Root", "leaf-root", "1b", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour)))
	f.parser.addCert(rootDER, rootFacts)
	rootResult, err := f.svc.Commit(context.Background(), importMeta("24242424-2424-4424-8424-242424242424"), uploadOneCert("root.pem", rootDER))
	if err != nil {
		t.Fatalf("root Commit: %v", err)
	}

	leafSubject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "Imported Leaf"})
	if err != nil {
		t.Fatalf("leaf subject: %v", err)
	}
	leafSAN, err := domain.NewSAN(domain.SANTypeDNS, "leaf.example.test")
	if err != nil {
		t.Fatalf("leaf SAN: %v", err)
	}
	leafDER := []byte("leaf-direct-root")
	leafFacts := caFacts(t, "unused", "leaf-key", "1c", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(30*24*time.Hour)))
	leafFacts.Subject = leafSubject
	leafFacts.IssuerSubject = rootFacts.Subject
	leafFacts.Kind = domain.CertificateKindLeaf
	leafFacts.Profile = domain.CertificateProfileServerTLS
	leafFacts.SANs = []domain.SAN{leafSAN}
	f.parser.addCert(leafDER, leafFacts)
	leafCmd := uploadOneCert("leaf.pem", leafDER)
	leafCmd.Metadata.Files[0].IssuerCertificateID = rootResult.CertificateIDs[0]
	leafCmd.Metadata.PreviewManifest.Files[0].IssuerCertificateID = rootResult.CertificateIDs[0]
	if _, err := f.svc.Commit(context.Background(), importMeta("25252525-2525-4525-8525-252525252525"), leafCmd); err == nil {
		t.Fatal("expected a leaf directly below a Root to be rejected")
	} else {
		requireConflict(t, err, "import_batch_conflict")
	}

	intermediateDER := []byte("intermediate-for-leaf")
	intermediateFacts := caFacts(t, "Leaf Intermediate", "leaf-intermediate", "1d", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(90*24*time.Hour)))
	intermediateFacts.IssuerSubject = rootFacts.Subject
	f.parser.addCert(intermediateDER, intermediateFacts)
	intermediateCmd := uploadOneCert("intermediate.pem", intermediateDER)
	intermediateCmd.Metadata.Files[0].IssuerCertificateID = rootResult.CertificateIDs[0]
	intermediateCmd.Metadata.PreviewManifest.Files[0].IssuerCertificateID = rootResult.CertificateIDs[0]
	intermediateResult, err := f.svc.Commit(context.Background(), importMeta("26262626-2626-4626-8626-262626262626"), intermediateCmd)
	if err != nil {
		t.Fatalf("intermediate Commit: %v", err)
	}

	leafFacts.IssuerSubject = intermediateFacts.Subject
	f.parser.addCert(leafDER, leafFacts)
	leafCmd.Metadata.Files[0].IssuerCertificateID = intermediateResult.CertificateIDs[0]
	leafCmd.Metadata.PreviewManifest.Files[0].IssuerCertificateID = intermediateResult.CertificateIDs[0]
	leafResult, err := f.svc.Commit(context.Background(), importMeta("27272727-2727-4727-8727-272727272727"), leafCmd)
	if err != nil {
		t.Fatalf("leaf Commit: %v", err)
	}
	if len(leafResult.CertificateIDs) != 1 {
		t.Fatalf("leaf certificate_ids = %v, want one", leafResult.CertificateIDs)
	}
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		cert, err := tx.PKI().GetCertificate(context.Background(), leafResult.CertificateIDs[0])
		if err != nil {
			return err
		}
		record, err := tx.PKI().GetLeafCertificateRecord(context.Background(), cert.ID())
		if err != nil {
			return err
		}
		if record.IssuerCACertificateID != intermediateResult.CertificateIDs[0] || record.RenewalCountAtIssue != 0 {
			t.Fatalf("leaf record = %+v, want intermediate issuer and renewal count 0", record)
		}
		snapshot, err := tx.PKI().GetSeriesForUpdate(context.Background(), record.SeriesID)
		if err != nil {
			return err
		}
		generation := snapshot.CurrentKeyGeneration
		if generation.RenewalCount() != 0 || !generation.PriorHistoryUnknown() || generation.Custody() != domain.KeyCustodyClientHeld {
			t.Fatalf("leaf generation = %+v, want imported history markers", generation)
		}
		if _, err := tx.Secrets().GetEncrypted(context.Background(), cert.KeyMaterialID(), domain.SecretPurposeLeafDelivery); !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("leaf secret lookup = %v, want ErrNotFound", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after leaf import: %v", err)
	}
}

// ---- U10: exact-DER re-registration returns the existing certificate ----

func TestImportServiceCommitDuplicateDERReturnsExistingCertificate(t *testing.T) {
	f := newImportFixture(t)
	rootDER := []byte("root-der-3")
	f.parser.addCert(rootDER, caFacts(t, "Dup Root", "root-3", "12", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour))))

	first, err := f.svc.Commit(context.Background(), importMeta("cccccccc-cccc-4ccc-8ccc-cccccccccccc"), uploadOneCert("root.pem", rootDER))
	if err != nil {
		t.Fatalf("first Commit: %v", err)
	}

	// A SECOND, independent commit (different idempotency key -> no replay)
	// of the byte-identical file must return the SAME certificate id and
	// must not mint a second authority.
	second, err := f.svc.Commit(context.Background(), importMeta("dddddddd-dddd-4ddd-8ddd-dddddddddddd"), uploadOneCert("root.pem", rootDER))
	if err != nil {
		t.Fatalf("second Commit: %v", err)
	}
	if len(second.CertificateIDs) != 0 {
		t.Fatalf("second commit certificate_ids = %v, want none minted (pure duplicate)", second.CertificateIDs)
	}
	if len(second.Items) != 1 || second.Items[0].Status != contract.ImportItemStatusDuplicate {
		t.Fatalf("second commit items = %+v, want exactly one Duplicate item", second.Items)
	}
	if second.Items[0].ExistingID == nil || *second.Items[0].ExistingID != first.CertificateIDs[0] {
		t.Fatalf("second commit existing_id = %v, want %v", second.Items[0].ExistingID, first.CertificateIDs[0])
	}
	if len(second.AuthorityIDs) != 1 || second.AuthorityIDs[0] != first.AuthorityIDs[0] {
		t.Fatalf("second commit authority_ids = %v, want the SAME authority as the first commit (%v)", second.AuthorityIDs, first.AuthorityIDs)
	}
}

// ---- U10: a different DER reusing an existing certificate's public key is
// rejected, and no partial state is left behind ----

func TestImportServiceCommitRejectsDifferentDERSameSPKI(t *testing.T) {
	f := newImportFixture(t)
	rootDER := []byte("root-der-4")
	f.parser.addCert(rootDER, caFacts(t, "Shared Key Root", "shared-key", "13", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour))))
	if _, err := f.svc.Commit(context.Background(), importMeta("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"), uploadOneCert("root.pem", rootDER)); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

	// A DIFFERENT certificate (different DER, different serial/subject) that
	// reuses the SAME public key must be rejected outright.
	otherDER := []byte("root-der-4-reissued")
	f.parser.addCert(otherDER, caFacts(t, "Reissued Root", "shared-key", "14", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour))))

	_, err := f.svc.Commit(context.Background(), importMeta("ffffffff-ffff-4fff-8fff-ffffffffffff"), uploadOneCert("root2.pem", otherDER))
	requireConflict(t, err, "import_batch_conflict")

	// Nothing from the rejected batch was persisted.
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		_, err := tx.PKI().FindCertificateByDER(context.Background(), domain.NewFingerprint(otherDER))
		if !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("FindCertificateByDER for the rejected cert: err = %v, want ErrNotFound", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after rejected commit: %v", err)
	}
}

// ---- U10: preview says "new"; the same upload conflicts by the time it is
// actually committed, and Commit must re-check rather than trust the
// earlier preview ----

func TestImportServiceCommitRecheckesConflictAfterPreview(t *testing.T) {
	f := newImportFixture(t)
	laterDER := []byte("root-der-5-later")
	f.parser.addCert(laterDER, caFacts(t, "Later Root", "shared-key-2", "15", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour))))

	previewCmd := uploadOneCert("later.pem", laterDER)
	preview, err := f.svc.Preview(context.Background(), importMeta("11111111-1111-4111-8111-000000000001"), previewCmd)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if preview.Items[0].Status != contract.ImportItemStatusNew {
		t.Fatalf("preview status = %q, want new (nothing conflicting exists yet)", preview.Items[0].Status)
	}

	// Between preview and commit, another import claims the same public key
	// under a different certificate.
	earlierDER := []byte("root-der-5-earlier")
	f.parser.addCert(earlierDER, caFacts(t, "Earlier Root", "shared-key-2", "16", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour))))
	if _, err := f.svc.Commit(context.Background(), importMeta("22222222-2222-4222-8222-000000000002"), uploadOneCert("earlier.pem", earlierDER)); err != nil {
		t.Fatalf("intervening commit: %v", err)
	}

	// Committing the ORIGINAL (previewed-as-new) upload must now fail: the
	// preview's "new" verdict is stale, and Commit re-verifies against the
	// CURRENT store rather than trusting it.
	_, err = f.svc.Commit(context.Background(), importMeta("33333333-3333-4333-8333-000000000003"), previewCmd)
	requireConflict(t, err, "import_batch_conflict")
}

// ---- U09: a certificate imported under an ALREADY-compromised public key
// is revoked immediately, not silently registered as trustworthy ----

func TestImportServiceCommitRevokesCertificateWithCompromisedKey(t *testing.T) {
	f := newImportFixture(t)
	compromisedSPKI := []byte("spki-precompromised")
	compromisedPub, err := domain.NewPublicKey(domain.KeyAlgorithmECDSAP256, compromisedSPKI)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	keyMaterialID, err := domain.ParseKeyMaterialID(f.ids.NewUUID())
	if err != nil {
		t.Fatalf("key material id: %v", err)
	}
	compromisedAt := testNow().Add(domain.NewDuration(-24 * time.Hour))
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		if err := tx.PKI().InsertKeyMaterial(context.Background(), port.KeyMaterial{ID: keyMaterialID, PublicKey: compromisedPub, Origin: "generated"}); err != nil {
			return err
		}
		return tx.PKI().MarkCompromised(context.Background(), keyMaterialID, compromisedAt)
	}); err != nil {
		t.Fatalf("seed compromised key material: %v", err)
	}

	rootDER := []byte("root-der-compromised")
	facts := caFacts(t, "Compromised Root", "unused", "17", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour)))
	facts.PublicKey = compromisedPub
	facts.SPKIFingerprint = domain.NewFingerprint(compromisedSPKI)
	f.parser.addCert(rootDER, facts)

	result, err := f.svc.Commit(context.Background(), importMeta("44444444-4444-4444-8444-000000000004"), uploadOneCert("compromised.pem", rootDER))
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if len(result.CertificateIDs) != 1 {
		t.Fatalf("certificate_ids = %v, want exactly one (the compromised key does not block registration, only trust)", result.CertificateIDs)
	}
	certID := result.CertificateIDs[0]

	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		cert, err := tx.PKI().GetCertificate(context.Background(), certID)
		if err != nil {
			t.Fatalf("read certificate: %v", err)
		}
		revocation, err := tx.Revocations().FindForUpdate(context.Background(), cert.IssuerCAKeyGenerationID(), cert.Serial())
		if err != nil {
			t.Fatalf("FindForUpdate: %v, want a revocation created by the compromise cascade", err)
		}
		if revocation.Reason() != domain.RevocationReasonKeyCompromise {
			t.Fatalf("reason = %q, want key_compromise", revocation.Reason())
		}
		if revocation.Source() != domain.RevocationSourceCascade {
			t.Fatalf("source = %q, want cascade", revocation.Source())
		}
		if revocation.CertificateID() != certID {
			t.Fatalf("certificate_id = %q, want %q", revocation.CertificateID(), certID)
		}
		if !revocation.RevokedAt().Equal(compromisedAt) {
			t.Fatalf("revoked_at = %v, want the key's own compromised_at %v", revocation.RevokedAt(), compromisedAt)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after commit: %v", err)
	}
}

// ---- U10: a certificate-less revocation history entry survives an
// unrelated import untouched, and is linked (not overwritten) once the
// matching certificate is imported ----

func TestImportServiceCommitPreservesAndLinksCertificatelessRevocationHistory(t *testing.T) {
	f := newImportFixture(t)
	rootDER := []byte("root-der-history")
	f.parser.addCert(rootDER, caFacts(t, "History Root", "history-root", "20", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour))))
	rootResult, err := f.svc.Commit(context.Background(), importMeta("55555555-5555-4555-8555-000000000005"), uploadOneCert("root.pem", rootDER))
	if err != nil {
		t.Fatalf("seed root commit: %v", err)
	}
	rootAuthorityID := rootResult.AuthorityIDs[0]

	var rootKeyGenID domain.CAKeyGenerationID
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		authority, err := tx.PKI().GetIssuerForUpdate(context.Background(), rootAuthorityID)
		if err != nil {
			return err
		}
		rootKeyGenID = authority.KeyGenerationID()
		return nil
	}); err != nil {
		t.Fatalf("read root authority: %v", err)
	}

	// Simulate a previously-imported CRL that revoked a serial for which no
	// certificate file was ever provided (pki-import.md "인증서 파일이 없는
	// 항목도 보존한다").
	historySerial := serial(t, "cafe")
	historyRevokedAt := testNow().Add(domain.NewDuration(-48 * time.Hour))
	revocationID, err := domain.ParseRevocationID(f.ids.NewUUID())
	if err != nil {
		t.Fatalf("revocation id: %v", err)
	}
	historyRevocation, err := domain.NewRevocation(domain.RevocationFacts{
		ID: revocationID, IssuerID: rootKeyGenID, Serial: historySerial,
		RevokedAt: historyRevokedAt, Reason: domain.RevocationReasonCessationOfOperation, Source: domain.RevocationSourceImport,
	})
	if err != nil {
		t.Fatalf("history revocation: %v", err)
	}
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Revocations().Insert(context.Background(), historyRevocation)
	}); err != nil {
		t.Fatalf("seed history revocation: %v", err)
	}

	// An UNRELATED import (a different intermediate, different serial) must
	// not disturb the certificate-less history entry.
	unrelatedDER := []byte("intermediate-der-unrelated")
	unrelated := caFacts(t, "Unrelated Intermediate", "unrelated-intermediate", "21", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*30*time.Hour)))
	unrelated.IssuerSubject, _ = domain.NewSubject(domain.SubjectFacts{CommonName: "History Root"})
	f.parser.addCert(unrelatedDER, unrelated)
	unrelatedCmd := uploadOneCert("unrelated.pem", unrelatedDER)
	unrelatedCmd.Metadata.Files[0].IssuerCertificateID = domain.CertificateID(rootResult.CertificateIDs[0])
	unrelatedCmd.Metadata.PreviewManifest.Files[0].IssuerCertificateID = domain.CertificateID(rootResult.CertificateIDs[0])
	if _, err := f.svc.Commit(context.Background(), importMeta("66666666-6666-4666-8666-000000000006"), unrelatedCmd); err != nil {
		t.Fatalf("unrelated commit: %v", err)
	}

	assertHistoryUnchanged := func(t *testing.T, wantCertID domain.CertificateID) {
		t.Helper()
		if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
			r, err := tx.Revocations().FindForUpdate(context.Background(), rootKeyGenID, historySerial)
			if err != nil {
				t.Fatalf("FindForUpdate: %v", err)
			}
			if r.Reason() != domain.RevocationReasonCessationOfOperation {
				t.Fatalf("reason = %q, want the ORIGINAL reason preserved", r.Reason())
			}
			if !r.RevokedAt().Equal(historyRevokedAt) {
				t.Fatalf("revoked_at = %v, want the ORIGINAL time preserved", r.RevokedAt())
			}
			if r.CertificateID() != wantCertID {
				t.Fatalf("certificate_id = %q, want %q", r.CertificateID(), wantCertID)
			}
			return nil
		}); err != nil {
			t.Fatalf("read history revocation: %v", err)
		}
	}
	assertHistoryUnchanged(t, "")

	// Now import the certificate that actually matches the historical
	// serial: the entry must be LINKED (certificate_id filled in) while its
	// reason/time stay exactly as they were -- not overwritten, not dropped.
	matchingDER := []byte("intermediate-der-matching")
	matching := caFacts(t, "Matching Intermediate", "matching-intermediate", "cafe", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*30*time.Hour)))
	matching.IssuerSubject, _ = domain.NewSubject(domain.SubjectFacts{CommonName: "History Root"})
	f.parser.addCert(matchingDER, matching)
	matchingCmd := uploadOneCert("matching.pem", matchingDER)
	matchingCmd.Metadata.Files[0].IssuerCertificateID = domain.CertificateID(rootResult.CertificateIDs[0])
	matchingCmd.Metadata.PreviewManifest.Files[0].IssuerCertificateID = domain.CertificateID(rootResult.CertificateIDs[0])
	matchResult, err := f.svc.Commit(context.Background(), importMeta("77777777-7777-4777-8777-000000000007"), matchingCmd)
	if err != nil {
		t.Fatalf("matching commit: %v", err)
	}
	assertHistoryUnchanged(t, matchResult.CertificateIDs[0])
}

// ---- ConfirmTakeover ----

func validTakeoverConfirmation(caDERSHA256 string) contract.ImportTakeoverConfirmationInput {
	return contract.ImportTakeoverConfirmationInput{
		CACertificateSHA256Hex: caDERSHA256,
		Confirmation: contract.TakeoverInput{
			HistoryAssertion:        contract.TakeoverHistoryNoPreviousRevocations,
			PreviousMaxNumberHex:    "0",
			ExternalIssuerStoppedAt: testNow().Time().Format(time.RFC3339),
			Evidence: contract.TakeoverEvidence{
				SchemaVersion:          1,
				IssuanceRecordsChecked: true,
				CRLRoutesChecked:       true,
			},
		},
	}
}

// commitRootWithPendingTakeover imports one self-signed root CA together
// with a takeover declaration, returning its CA key generation id (the
// ConfirmTakeover path target) and the authority's current version.
func commitRootWithPendingTakeover(t *testing.T, f *importFixture, fileName string, der []byte, spkiSeed, serialHex string) (domain.CAKeyGenerationID, domain.AuthorityID, domain.Version) {
	t.Helper()
	f.parser.addCert(der, caFacts(t, "Takeover Root "+spkiSeed, spkiSeed, serialHex, testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour))))
	cmd := uploadOneCert(fileName, der)
	cmd.Metadata.Takeovers = []contract.ImportTakeoverConfirmationInput{validTakeoverConfirmation(domain.NewFingerprint(der).Hex())}

	result, err := f.svc.Commit(context.Background(), importMeta(f.ids.NewUUID()), cmd)
	if err != nil {
		t.Fatalf("commit root with takeover: %v", err)
	}
	authorityID := result.AuthorityIDs[0]

	var keyGenID domain.CAKeyGenerationID
	var version domain.Version
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		authority, err := tx.PKI().GetIssuerForUpdate(context.Background(), authorityID)
		if err != nil {
			return err
		}
		if !authority.PendingTakeover() {
			t.Fatal("want pending_takeover=true for an import that carried a takeover declaration")
		}
		keyGenID = authority.KeyGenerationID()
		version = authority.Version()
		return nil
	}); err != nil {
		t.Fatalf("read seeded authority: %v", err)
	}
	return keyGenID, authorityID, version
}

func TestImportServiceConfirmTakeoverFlipsPendingToConfirmed(t *testing.T) {
	f := newImportFixture(t)
	keyGenID, authorityID, version := commitRootWithPendingTakeover(t, f, "takeover-root.pem", []byte("root-der-takeover-1"), "takeover-1", "30")

	cmd := contract.ImportConfirmTakeoverCommand{TakeoverInput: contract.TakeoverInput{
		CAKeyGenerationID:       keyGenID,
		HistoryAssertion:        contract.TakeoverHistoryNoPreviousRevocations,
		PreviousMaxNumberHex:    "0",
		ExternalIssuerStoppedAt: testNow().Time().Format(time.RFC3339),
		Evidence: contract.TakeoverEvidence{
			SchemaVersion: 1, IssuanceRecordsChecked: true, CRLRoutesChecked: true,
		},
	}}
	view, err := f.svc.ConfirmTakeover(context.Background(), importVersionMeta(version), cmd)
	if err != nil {
		t.Fatalf("ConfirmTakeover: %v", err)
	}
	if view.State != contract.TakeoverStateConfirmed {
		t.Fatalf("state = %q, want confirmed", view.State)
	}
	if view.ConfirmedAt == nil {
		t.Fatal("want confirmed_at set")
	}
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		authority, err := tx.PKI().GetIssuerForUpdate(context.Background(), authorityID)
		if err != nil {
			return err
		}
		if authority.PendingTakeover() {
			return fmt.Errorf("authority still has pending takeover")
		}
		if authority.IssuanceState() != domain.IssuanceStateStopped {
			return fmt.Errorf("issuance state = %s, want stopped", authority.IssuanceState())
		}
		if authority.Version() != version+1 {
			return fmt.Errorf("authority version = %d, want %d", authority.Version(), version+1)
		}
		return nil
	}); err != nil {
		t.Fatalf("read authority after confirm: %v", err)
	}

	// A second confirmation attempt against the now-stale version is
	// rejected as a version conflict (Takeover's own version, re-read).
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		_, err := tx.Imports().GetPendingTakeoverForUpdate(context.Background(), keyGenID)
		if !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("GetPendingTakeoverForUpdate after confirmation: err = %v, want ErrNotFound", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after confirm: %v", err)
	}
}

func TestImportServiceConfirmTakeoverRejectsAuthorityVersionConflict(t *testing.T) {
	f := newImportFixture(t)
	keyGenID, _, version := commitRootWithPendingTakeover(t, f, "takeover-root-2.pem", []byte("root-der-takeover-2"), "takeover-2", "31")

	cmd := contract.ImportConfirmTakeoverCommand{TakeoverInput: contract.TakeoverInput{
		CAKeyGenerationID:       keyGenID,
		HistoryAssertion:        contract.TakeoverHistoryNoPreviousRevocations,
		PreviousMaxNumberHex:    "0",
		ExternalIssuerStoppedAt: testNow().Time().Format(time.RFC3339),
		Evidence:                contract.TakeoverEvidence{SchemaVersion: 1, IssuanceRecordsChecked: true, CRLRoutesChecked: true},
	}}
	_, err := f.svc.ConfirmTakeover(context.Background(), importVersionMeta(version+1), cmd)
	requireConflict(t, err, "takeover_authority_version_conflict")
}

func TestImportServiceConfirmTakeoverRejectsWhenNotPending(t *testing.T) {
	f := newImportFixture(t)
	keyGenID, _, version := commitRootWithPendingTakeover(t, f, "takeover-root-3.pem", []byte("root-der-takeover-3"), "takeover-3", "32")
	cmd := contract.ImportConfirmTakeoverCommand{TakeoverInput: contract.TakeoverInput{
		CAKeyGenerationID:       keyGenID,
		HistoryAssertion:        contract.TakeoverHistoryNoPreviousRevocations,
		PreviousMaxNumberHex:    "0",
		ExternalIssuerStoppedAt: testNow().Time().Format(time.RFC3339),
		Evidence:                contract.TakeoverEvidence{SchemaVersion: 1, IssuanceRecordsChecked: true, CRLRoutesChecked: true},
	}}
	if _, err := f.svc.ConfirmTakeover(context.Background(), importVersionMeta(version), cmd); err != nil {
		t.Fatalf("first confirm: %v", err)
	}

	// Re-reading the (now-stopped) authority for its CURRENT version so this
	// second attempt fails on the TAKEOVER precondition, not a stale
	// authority version.
	var currentVersion domain.Version
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		gen, err := tx.PKI().GetCAKeyGeneration(context.Background(), keyGenID)
		if err != nil {
			return err
		}
		authority, err := tx.PKI().GetIssuerForUpdate(context.Background(), gen.AuthorityID)
		if err != nil {
			return err
		}
		currentVersion = authority.Version()
		return nil
	}); err != nil {
		t.Fatalf("re-read authority: %v", err)
	}

	_, err := f.svc.ConfirmTakeover(context.Background(), importVersionMeta(currentVersion), cmd)
	appErr := requireAppError(t, err)
	if appErr.Kind() != contract.ErrorKindValidation {
		t.Fatalf("kind = %s (code %q), want validation", appErr.Kind(), appErr.Code())
	}
	if appErr.Code() != "takeover_not_pending" {
		t.Fatalf("code = %q, want takeover_not_pending", appErr.Code())
	}
}

// ---- §8: requireCurrentAuth is not optional (Commit) ----

func TestImportServiceCommitRejectsAuthEpochSuperseded(t *testing.T) {
	f := newImportFixture(t)
	bumpAccountAuthEpoch(t, f.store)
	rootDER := []byte("root-der-epoch")
	f.parser.addCert(rootDER, caFacts(t, "Epoch Root", "epoch-root", "40", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour))))
	_, err := f.svc.Commit(context.Background(), importMeta("99999999-9999-4999-8999-000000000001"), uploadOneCert("root.pem", rootDER))
	requireAuthError(t, err, "auth_epoch_superseded")
}

func TestImportServiceCommitRejectsIdleExpiredSession(t *testing.T) {
	f := newImportFixture(t)
	touchAdminSession(t, f.store, testNow())
	clock := &movableClock{now: testNow().Add(domain.NewDuration(time.Hour + time.Second))}
	f.svc.deps.Clock = clock
	rootDER := []byte("root-der-idle")
	f.parser.addCert(rootDER, caFacts(t, "Idle Root", "idle-root", "41", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour))))
	_, err := f.svc.Commit(context.Background(), importMeta("99999999-9999-4999-8999-000000000002"), uploadOneCert("root.pem", rootDER))
	requireAuthError(t, err, "session_idle_expired")
}

// TestImportServiceCommitReplayRequiresCurrentAuth proves the replay path
// itself re-checks auth: a request that already succeeded once must NOT
// hand back its stored result to a principal whose session has since gone
// stale (§8 "현재 인증/권한이 없는 요청은 기존 결과도 받지 못한다"). If
// requireCurrentAuth were missing from replayCommit specifically, this is
// the only test that would catch it -- Commit's normal happy-path tests
// never exercise the replay branch at all.
func TestImportServiceCommitReplayRequiresCurrentAuth(t *testing.T) {
	f := newImportFixture(t)
	rootDER := []byte("root-der-replay")
	f.parser.addCert(rootDER, caFacts(t, "Replay Root", "replay-root", "42", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour))))
	cmd := uploadOneCert("root.pem", rootDER)
	meta := importMeta("99999999-9999-4999-8999-000000000003")

	if _, err := f.svc.Commit(context.Background(), meta, cmd); err != nil {
		t.Fatalf("first commit: %v", err)
	}

	bumpAccountAuthEpoch(t, f.store)

	// Same idempotency key, same content: this would replay the stored
	// result if auth were not re-checked on the replay path.
	_, err := f.svc.Commit(context.Background(), meta, cmd)
	requireAuthError(t, err, "auth_epoch_superseded")
}

// ---- §8: requireCurrentAuth is not optional (ConfirmTakeover) ----

func TestImportServiceConfirmTakeoverRejectsAuthEpochSuperseded(t *testing.T) {
	f := newImportFixture(t)
	keyGenID, _, version := commitRootWithPendingTakeover(t, f, "takeover-root-epoch.pem", []byte("root-der-takeover-epoch"), "takeover-epoch", "43")
	bumpAccountAuthEpoch(t, f.store)

	cmd := contract.ImportConfirmTakeoverCommand{TakeoverInput: contract.TakeoverInput{
		CAKeyGenerationID:       keyGenID,
		HistoryAssertion:        contract.TakeoverHistoryNoPreviousRevocations,
		PreviousMaxNumberHex:    "0",
		ExternalIssuerStoppedAt: testNow().Time().Format(time.RFC3339),
		Evidence:                contract.TakeoverEvidence{SchemaVersion: 1, IssuanceRecordsChecked: true, CRLRoutesChecked: true},
	}}
	_, err := f.svc.ConfirmTakeover(context.Background(), importVersionMeta(version), cmd)
	requireAuthError(t, err, "auth_epoch_superseded")
}

func TestImportServiceConfirmTakeoverRejectsIdleExpiredSession(t *testing.T) {
	f := newImportFixture(t)
	keyGenID, _, version := commitRootWithPendingTakeover(t, f, "takeover-root-idle.pem", []byte("root-der-takeover-idle"), "takeover-idle", "44")
	touchAdminSession(t, f.store, testNow())
	clock := &movableClock{now: testNow().Add(domain.NewDuration(time.Hour + time.Second))}
	f.svc.deps.Clock = clock

	cmd := contract.ImportConfirmTakeoverCommand{TakeoverInput: contract.TakeoverInput{
		CAKeyGenerationID:       keyGenID,
		HistoryAssertion:        contract.TakeoverHistoryNoPreviousRevocations,
		PreviousMaxNumberHex:    "0",
		ExternalIssuerStoppedAt: testNow().Time().Format(time.RFC3339),
		Evidence:                contract.TakeoverEvidence{SchemaVersion: 1, IssuanceRecordsChecked: true, CRLRoutesChecked: true},
	}}
	_, err := f.svc.ConfirmTakeover(context.Background(), importVersionMeta(version), cmd)
	requireAuthError(t, err, "session_idle_expired")
}

// ---- §8: requireCurrentAuth inside commitImport's OWN Write, not just the
// early replay probe ----
//
// Commit's early replayCommit (a ReadStore.Read, never touching
// UnitOfWork.Write) already calls requireCurrentAuth once, before any
// parsing. Every test above that "kills" auth BEFORE calling Commit is
// caught there and never reaches commitImport at all -- proven by disabling
// commitImport's own requireCurrentAuth call and re-running the whole suite:
// every test above still passed. These three tests mutate auth state from
// INSIDE the UnitOfWork.Write call itself (via mutateOnceUoW/movableClock),
// after the early probe has already run with genuinely-valid auth, so only
// commitImport's own requireCurrentAuth call can catch them.

func TestImportServiceCommitRejectsAuthEpochBumpedBetweenPrepareAndCommit(t *testing.T) {
	f := newImportFixture(t)
	rootDER := []byte("root-der-race-epoch")
	f.parser.addCert(rootDER, caFacts(t, "Race Epoch Root", "race-epoch-root", "50", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour))))
	mutated := false
	f.svc.deps.UnitOfWork = &mutateOnceUoW{inner: f.store, mutate: func() {
		mutated = true
		bumpAccountAuthEpoch(t, f.store)
	}}
	_, err := f.svc.Commit(context.Background(), importMeta("99999999-9999-4999-8999-000000000010"), uploadOneCert("root.pem", rootDER))
	if !mutated {
		t.Fatal("mutateOnceUoW never ran; test is not exercising the intended race")
	}
	requireAuthError(t, err, "auth_epoch_superseded")
}

func TestImportServiceCommitRejectsAccountDisabledBetweenPrepareAndCommit(t *testing.T) {
	f := newImportFixture(t)
	rootDER := []byte("root-der-race-disabled")
	f.parser.addCert(rootDER, caFacts(t, "Race Disabled Root", "race-disabled-root", "51", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour))))
	mutated := false
	f.svc.deps.UnitOfWork = &mutateOnceUoW{inner: f.store, mutate: func() {
		mutated = true
		disableAccount(t, f.store)
	}}
	_, err := f.svc.Commit(context.Background(), importMeta("99999999-9999-4999-8999-000000000011"), uploadOneCert("root.pem", rootDER))
	if !mutated {
		t.Fatal("mutateOnceUoW never ran; test is not exercising the intended race")
	}
	requireAuthError(t, err, "account_not_active")
}

func TestImportServiceCommitRejectsSessionIdleExpiredAtCommitTime(t *testing.T) {
	f := newImportFixture(t)
	rootDER := []byte("root-der-race-idle")
	f.parser.addCert(rootDER, caFacts(t, "Race Idle Root", "race-idle-root", "52", testNow().Add(domain.NewDuration(-time.Hour)), testNow().Add(domain.NewDuration(24*365*time.Hour))))
	clock := &movableClock{now: testNow()}
	f.svc.deps.Clock = clock
	mutated := false
	f.svc.deps.UnitOfWork = &mutateOnceUoW{inner: f.store, mutate: func() {
		mutated = true
		clock.now = clock.now.Add(domain.NewDuration(time.Hour + time.Second))
	}}
	_, err := f.svc.Commit(context.Background(), importMeta("99999999-9999-4999-8999-000000000012"), uploadOneCert("root.pem", rootDER))
	if !mutated {
		t.Fatal("mutateOnceUoW never ran; test is not exercising the intended race")
	}
	requireAuthError(t, err, "session_idle_expired")
}
