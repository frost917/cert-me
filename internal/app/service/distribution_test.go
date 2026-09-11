package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

// ---- deterministic test doubles ----------------------------------------

// fakeTokenCodec hashes a raw token the same way for every call, so a grant
// seeded with domain.NewFingerprint(rawTokenBytes) is found by Hash(rawToken).
type fakeTokenCodec struct{}

func (fakeTokenCodec) NewToken(context.Context) (*secret.Input, domain.TokenHash, error) {
	return nil, domain.TokenHash{}, errors.New("fakeTokenCodec: NewToken not used by Deliver")
}

func (fakeTokenCodec) Hash(_ context.Context, token *secret.Input) (domain.TokenHash, error) {
	var out domain.TokenHash
	err := token.Use(func(b []byte) error {
		h, err := domain.NewTokenHash(domain.NewFingerprint(b))
		if err != nil {
			return err
		}
		out = h
		return nil
	})
	return out, err
}

func tokenHashFor(raw string) domain.TokenHash {
	h, err := domain.NewTokenHash(domain.NewFingerprint([]byte(raw)))
	if err != nil {
		panic(err)
	}
	return h
}

// fakeDeliveryEncoder counts calls (encoding-failure-consumes-nothing needs
// to show the encoder ran but nothing else did) and returns whatever the
// test configured.
type fakeDeliveryEncoder struct {
	mu    sync.Mutex
	calls int
	// inputs records every call's input, so a test can inspect what this
	// package actually handed the encoder (e.g. ChainDER's order per §14.2)
	// without needing a second, purpose-built double.
	inputs []port.DeliveryEncodeInput
	fn     func(port.DeliveryEncodeInput) (port.EncodedBundle, error)
}

func (f *fakeDeliveryEncoder) Encode(_ context.Context, in port.DeliveryEncodeInput) (port.EncodedBundle, error) {
	f.mu.Lock()
	f.calls++
	f.inputs = append(f.inputs, in)
	f.mu.Unlock()
	return f.fn(in)
}

func (f *fakeDeliveryEncoder) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeDeliveryEncoder) lastInput() port.DeliveryEncodeInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.inputs[len(f.inputs)-1]
}

func okEncoder(payload string) *fakeDeliveryEncoder {
	return &fakeDeliveryEncoder{fn: func(port.DeliveryEncodeInput) (port.EncodedBundle, error) {
		return port.NewEncodedBundle([]byte(payload), "application/x-pem-file"), nil
	}}
}

func failingEncoder(err error) *fakeDeliveryEncoder {
	return &fakeDeliveryEncoder{fn: func(port.DeliveryEncodeInput) (port.EncodedBundle, error) {
		return port.EncodedBundle{}, err
	}}
}

// fakeRuntimeGate records every FailClosed call; a real implementation would
// also shut down admission, which is outside what DistributionService can
// exercise in isolation (see report: this test double is the "관측" §12/§11
// asks for, not a substitute for the real runtime).
type fakeRuntimeGate struct {
	mu    sync.Mutex
	codes []string
}

func (g *fakeRuntimeGate) FailClosed(code string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.codes = append(g.codes, code)
}

func (g *fakeRuntimeGate) callCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.codes)
}

func (g *fakeRuntimeGate) lastCode() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.codes) == 0 {
		return ""
	}
	return g.codes[len(g.codes)-1]
}

// fakeSink is the DownloadSink test double. panicVal, if set, makes Send
// panic instead of returning. capturedReader lets a test try reading after
// Send has returned, to check the "unusable after return" contract.
type fakeSink struct {
	outcome  port.TransferOutcome
	err      error
	panicVal any

	mu             sync.Mutex
	calls          int
	capturedReader io.Reader
}

func (s *fakeSink) Send(_ context.Context, _ port.FileDescriptor, r io.Reader) (port.TransferOutcome, error) {
	s.mu.Lock()
	s.calls++
	s.capturedReader = r
	s.mu.Unlock()
	if s.panicVal != nil {
		panic(s.panicVal)
	}
	return s.outcome, s.err
}

func (s *fakeSink) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *fakeSink) readerAfterReturn() io.Reader {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.capturedReader
}

// stagedUoW wraps a real porttest.Store and lets a test intercept the Nth
// Write call: force it to report commit_unknown despite having actually
// committed, or run a side effect immediately after a real commit (used to
// simulate "something else changed the row before the next Write", which is
// how this suite reproduces a definite rollback in the *second* Write
// without needing to fake TxStores by hand).
type stagedUoW struct {
	inner          port.UnitOfWork
	mu             sync.Mutex
	stage          int
	forceUnknownAt map[int]bool
	afterCommit    map[int]func()
}

func newStagedUoW(inner port.UnitOfWork) *stagedUoW {
	return &stagedUoW{inner: inner, forceUnknownAt: map[int]bool{}, afterCommit: map[int]func(){}}
}

func (u *stagedUoW) Write(ctx context.Context, fn func(port.TxStores) error) error {
	u.mu.Lock()
	u.stage++
	stage := u.stage
	u.mu.Unlock()

	err := u.inner.Write(ctx, fn)
	if err != nil {
		return err
	}
	if hook := u.afterCommit[stage]; hook != nil {
		hook()
	}
	if u.forceUnknownAt[stage] {
		return port.ErrCommitUnknown
	}
	return nil
}

func (u *stagedUoW) Read(ctx context.Context, fn func(port.TxStores) error) error {
	if rs, ok := u.inner.(port.ReadStore); ok {
		return rs.Read(ctx, fn)
	}
	return fmt.Errorf("stagedUoW: inner store is not a ReadStore")
}

// ---- fixtures ------------------------------------------------------------

func distTestNow() domain.Instant {
	return domain.NewInstant(time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC))
}

func distID36(prefix byte, n int) string {
	return fmt.Sprintf("%c%c%c%c%c%c%c%c-%c%c%c%c-4%c%c%c-8%c%c%c-%012d",
		prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix,
		prefix, prefix, prefix, prefix,
		prefix, prefix, prefix,
		prefix, prefix, prefix,
		n)
}

func distCertID(t *testing.T, n int) domain.CertificateID {
	t.Helper()
	id, err := domain.ParseCertificateID(distID36('1', n))
	if err != nil {
		t.Fatalf("certificate id: %v", err)
	}
	return id
}

func distKeyMaterialID(t *testing.T, n int) domain.KeyMaterialID {
	t.Helper()
	id, err := domain.ParseKeyMaterialID(distID36('2', n))
	if err != nil {
		t.Fatalf("key material id: %v", err)
	}
	return id
}

func distIssuerID(t *testing.T, n int) domain.CAKeyGenerationID {
	t.Helper()
	id, err := domain.ParseCAKeyGenerationID(distID36('3', n))
	if err != nil {
		t.Fatalf("ca key generation id: %v", err)
	}
	return id
}

func distSeriesID(t *testing.T, n int) domain.SeriesID {
	t.Helper()
	id, err := domain.ParseSeriesID(distID36('9', n))
	if err != nil {
		t.Fatalf("series id: %v", err)
	}
	return id
}

func distManagementAuthorityID(t *testing.T, n int) domain.AuthorityID {
	t.Helper()
	id, err := domain.ParseAuthorityID(distID36('8', n))
	if err != nil {
		t.Fatalf("authority id: %v", err)
	}
	return id
}

func distCACertID(t *testing.T, n int) domain.CertificateID {
	t.Helper()
	id, err := domain.ParseCertificateID(distID36('7', n))
	if err != nil {
		t.Fatalf("ca certificate id: %v", err)
	}
	return id
}

func distDeliveryID(t *testing.T, n int) domain.DeliveryID {
	t.Helper()
	id, err := domain.ParseDeliveryID(distID36('4', n))
	if err != nil {
		t.Fatalf("delivery id: %v", err)
	}
	return id
}

func distGrantID(t *testing.T, n int) domain.GrantID {
	t.Helper()
	id, err := domain.ParseGrantID(distID36('5', n))
	if err != nil {
		t.Fatalf("grant id: %v", err)
	}
	return id
}

func distSubject(t *testing.T) domain.Subject {
	t.Helper()
	s, err := domain.NewSubject(domain.SubjectFacts{CommonName: "svc.example.internal"})
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	return s
}

func distSAN(t *testing.T) domain.SAN {
	t.Helper()
	s, err := domain.NewSAN(domain.SANTypeDNS, "svc.example.internal")
	if err != nil {
		t.Fatalf("san: %v", err)
	}
	return s
}

func distSerial(t *testing.T, hex string) domain.SerialNumber {
	t.Helper()
	s, err := domain.ParseSerialNumber(hex)
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return s
}

func distValidity(t *testing.T) domain.ValidityWindow {
	t.Helper()
	w, err := domain.NewValidityWindow(
		domain.NewInstant(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		domain.NewInstant(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)),
	)
	if err != nil {
		t.Fatalf("validity: %v", err)
	}
	return w
}

func distCertificate(t *testing.T, certN, keyN, issuerN int, serialHex string) domain.Certificate {
	t.Helper()
	cert, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      distCertID(t, certN),
		DER:                     []byte{0xDE, 0xAD, 0xBE, 0xEF, byte(certN)},
		KeyMaterialID:           distKeyMaterialID(t, keyN),
		IssuerCAKeyGenerationID: distIssuerID(t, issuerN),
		Serial:                  distSerial(t, serialHex),
		Validity:                distValidity(t),
		Subject:                 distSubject(t),
		SANs:                    []domain.SAN{distSAN(t)},
		Kind:                    domain.CertificateKindLeaf,
		Profile:                 domain.CertificateProfileServerTLS,
		KeyAlgorithm:            domain.KeyAlgorithmECDSAP256,
		Origin:                  domain.CertificateOriginGenerated,
		Version:                 1,
	})
	if err != nil {
		t.Fatalf("new certificate: %v", err)
	}
	return cert
}

func distEncryptedSecret(t *testing.T, keyMaterialID domain.KeyMaterialID) domain.EncryptedSecret {
	t.Helper()
	s, err := domain.NewEncryptedSecret(domain.EncryptedSecretFacts{
		OwnerKeyID:             keyMaterialID,
		Purpose:                domain.SecretPurposeLeafDelivery,
		FormatVersion:          1,
		EncryptionGenerationID: "gen-1",
		Nonce:                  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
		Ciphertext:             []byte{0xAA, 0xBB, 0xCC, 0xDD},
	})
	if err != nil {
		t.Fatalf("new encrypted secret: %v", err)
	}
	return s
}

func distGrant(t *testing.T, n int, purpose domain.GrantPurpose, certID domain.CertificateID, deliveryID domain.DeliveryID, tokenHash domain.TokenHash, expiresAt domain.Instant) domain.DownloadGrant {
	t.Helper()
	g, err := domain.NewDownloadGrant(domain.DownloadGrantFacts{
		ID:            distGrantID(t, n),
		TokenHash:     tokenHash,
		Purpose:       purpose,
		CertificateID: certID,
		DeliveryID:    deliveryID,
		ExpiresAt:     expiresAt,
		Version:       1,
	})
	if err != nil {
		t.Fatalf("new grant: %v", err)
	}
	return g
}

func distDelivery(t *testing.T, n int, leafKeyGenN int, certID domain.CertificateID, expiresAt domain.Instant) domain.Delivery {
	t.Helper()
	leafKeyGenID, err := domain.ParseLeafKeyGenerationID(distID36('6', leafKeyGenN))
	if err != nil {
		t.Fatalf("leaf key generation id: %v", err)
	}
	d, err := domain.NewDelivery(domain.DeliveryFacts{
		ID:                  distDeliveryID(t, n),
		LeafKeyGenerationID: leafKeyGenID,
		CertificateID:       certID,
		ExpiresAt:           expiresAt,
		State:               domain.DeliveryStatePending,
		Version:             1,
	})
	if err != nil {
		t.Fatalf("new delivery: %v", err)
	}
	return d
}

func distSeries(t *testing.T, n int, managementAuthorityID domain.AuthorityID) domain.LeafSeries {
	t.Helper()
	validity, err := domain.NewCalendarValidity(1, domain.ValidityUnitYears)
	if err != nil {
		t.Fatalf("calendar validity: %v", err)
	}
	series, err := domain.NewLeafSeries(domain.LeafSeriesFacts{
		ID:                    distSeriesID(t, n),
		Name:                  "svc.example.internal",
		Purpose:               domain.SeriesPurposeDistributed,
		ManagementAuthorityID: managementAuthorityID,
		Policy: domain.SeriesPolicy{
			RotateEvery:         3,
			CertificateValidity: validity,
		},
		Version: 1,
	})
	if err != nil {
		t.Fatalf("new series: %v", err)
	}
	return series
}

// distRootCACert builds the self-signed Root CA certificate a leaf fixture's
// stored issuer chain (§14.2) terminates at: its own CAKeyGenerationID
// signs it (self-signed), and it carries no issuer certificate of its own.
func distRootCACert(t *testing.T, n int, caKeyGenID domain.CAKeyGenerationID) domain.Certificate {
	t.Helper()
	cert, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      distCACertID(t, n),
		DER:                     []byte{0xCA, 0xCA, 0xCA, byte(n)},
		KeyMaterialID:           distKeyMaterialID(t, 900+n),
		IssuerCAKeyGenerationID: caKeyGenID, // self-signed: it names its own generation
		Serial:                  distSerial(t, fmt.Sprintf("c%d", n)),
		Validity:                distValidity(t),
		Subject:                 distSubject(t),
		Kind:                    domain.CertificateKindCA,
		KeyAlgorithm:            domain.KeyAlgorithmECDSAP256,
		Origin:                  domain.CertificateOriginGenerated,
		Version:                 1,
	})
	if err != nil {
		t.Fatalf("new ca certificate: %v", err)
	}
	return cert
}

// seedChainAndScope stores everything buildChainDER (§14.2) and
// distributionManagementAuthority (§14.6) need for one leaf certificate: a
// one-level stored issuer chain terminating at a self-signed Root, and a
// leaf series recording the management authority. n selects distinct
// deterministic ids so private/public fixtures do not collide.
func seedChainAndScope(t *testing.T, store *porttest.Store, n int, certID domain.CertificateID, caKeyGenID domain.CAKeyGenerationID, managementAuthorityID domain.AuthorityID) domain.SeriesID {
	t.Helper()
	series := distSeries(t, n, managementAuthorityID)
	caCert := distRootCACert(t, n, caKeyGenID)

	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		if err := tx.PKI().InsertSeries(context.Background(), series); err != nil {
			return err
		}
		if err := tx.PKI().InsertCertificate(context.Background(), caCert); err != nil {
			return err
		}
		if err := tx.PKI().InsertCACertificateRecord(context.Background(), port.CACertificateRecord{
			CertificateID:     caCert.ID(),
			CAKeyGenerationID: caKeyGenID,
		}); err != nil {
			return err
		}
		return tx.PKI().InsertLeafCertificateRecord(context.Background(), port.LeafCertificateRecord{
			CertificateID:         certID,
			SeriesID:              series.ID(),
			IssuerCACertificateID: caCert.ID(),
			Operation:             port.CertificateOperationInitial,
		})
	}); err != nil {
		t.Fatalf("seed chain and scope: %v", err)
	}
	return series.ID()
}

func seedCRLStateFor(t *testing.T, store *porttest.Store, issuer domain.CAKeyGenerationID) {
	t.Helper()
	state, err := domain.NewCRLState(domain.CRLStateFacts{
		CAKeyGenerationID: issuer,
		PublicationState:  domain.PublicationStateActive,
	})
	if err != nil {
		t.Fatalf("new crl state: %v", err)
	}
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.CRLs().SaveState(context.Background(), state, state.Version())
	}); err != nil {
		t.Fatalf("seed crl state: %v", err)
	}
}

// distFixture bundles a seeded store plus the raw token/expected ids a test
// needs to build a DownloadCommand and make assertions.
type distFixture struct {
	store                 *porttest.Store
	certID                domain.CertificateID
	keyMatID              domain.KeyMaterialID
	issuerID              domain.CAKeyGenerationID
	deliverID             domain.DeliveryID
	grantID               domain.GrantID
	rawToken              string
	seriesID              domain.SeriesID
	managementAuthorityID domain.AuthorityID
}

const privateRawToken = "private-fixture-raw-token-0123456789ABCDEF"
const publicRawToken = "public--fixture-raw-token-0123456789ABCDEF"

func seedPrivateFixture(t *testing.T, expiresAt domain.Instant, deliveryState domain.DeliveryState) distFixture {
	t.Helper()
	store := porttest.NewStore()
	cert := distCertificate(t, 1, 1, 1, "a1")
	delivery := distDelivery(t, 1, 1, cert.ID(), expiresAt)
	if deliveryState != domain.DeliveryStatePending {
		var err error
		switch deliveryState {
		case domain.DeliveryStateTransferring:
			delivery, err = delivery.Consume(expiresAt.Add(domain.NewDuration(-time.Hour)))
		case domain.DeliveryStateFailed:
			delivery, err = delivery.Fail("seeded", expiresAt)
		case domain.DeliveryStateExpired:
			delivery, err = delivery.Expire(expiresAt.Add(domain.NewDuration(time.Hour)))
		}
		if err != nil {
			t.Fatalf("seed delivery state: %v", err)
		}
	}
	grant := distGrant(t, 1, domain.GrantPurposeLeafPrivate, cert.ID(), delivery.ID(), tokenHashFor(privateRawToken), expiresAt)
	secretRow := distEncryptedSecret(t, cert.KeyMaterialID())

	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		if err := tx.PKI().InsertCertificate(context.Background(), cert); err != nil {
			return err
		}
		if err := tx.Delivery().InsertDelivery(context.Background(), delivery); err != nil {
			return err
		}
		if err := tx.Delivery().InsertGrant(context.Background(), grant); err != nil {
			return err
		}
		return tx.Secrets().InsertEncrypted(context.Background(), secretRow)
	}); err != nil {
		t.Fatalf("seed private fixture: %v", err)
	}
	managementAuthorityID := distManagementAuthorityID(t, 1)
	seriesID := seedChainAndScope(t, store, 1, cert.ID(), cert.IssuerCAKeyGenerationID(), managementAuthorityID)

	return distFixture{
		store: store, certID: cert.ID(), keyMatID: cert.KeyMaterialID(), issuerID: cert.IssuerCAKeyGenerationID(),
		deliverID: delivery.ID(), grantID: grant.ID(), rawToken: privateRawToken,
		seriesID: seriesID, managementAuthorityID: managementAuthorityID,
	}
}

func seedPublicFixture(t *testing.T, expiresAt domain.Instant) distFixture {
	t.Helper()
	store := porttest.NewStore()
	cert := distCertificate(t, 2, 2, 2, "a2")
	grant := distGrant(t, 2, domain.GrantPurposeLeafPublic, cert.ID(), "", tokenHashFor(publicRawToken), expiresAt)

	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		if err := tx.PKI().InsertCertificate(context.Background(), cert); err != nil {
			return err
		}
		return tx.Delivery().InsertGrant(context.Background(), grant)
	}); err != nil {
		t.Fatalf("seed public fixture: %v", err)
	}
	managementAuthorityID := distManagementAuthorityID(t, 2)
	seriesID := seedChainAndScope(t, store, 2, cert.ID(), cert.IssuerCAKeyGenerationID(), managementAuthorityID)

	return distFixture{
		store: store, certID: cert.ID(), keyMatID: cert.KeyMaterialID(), issuerID: cert.IssuerCAKeyGenerationID(),
		grantID: grant.ID(), rawToken: publicRawToken,
		seriesID: seriesID, managementAuthorityID: managementAuthorityID,
	}
}

// advancingClock is a Clock double whose Now() can be moved forward by a
// test between calls -- used to model real wall-clock delay (e.g. slow
// encoding) between Deliver's prepare step and its consuming commit.
type advancingClock struct {
	mu  sync.Mutex
	now domain.Instant
}

func (c *advancingClock) Now() domain.Instant {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *advancingClock) advanceTo(t domain.Instant) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// withClock overrides just the Clock dependency distDeps otherwise defaults
// to a fixedClock, the same pattern withPublicEncoder/withOperationalLogger
// use below.
func withClock(deps DistributionDeps, clock port.Clock) DistributionDeps {
	deps.Clock = clock
	return deps
}

func distDeps(t *testing.T, uow port.UnitOfWork, readStore port.ReadStore, encoder port.DeliveryEncoder, gate port.RuntimeGate) DistributionDeps {
	t.Helper()
	return DistributionDeps{
		CommonDeps: CommonDeps{
			UnitOfWork: uow,
			ReadStore:  readStore,
			Authorizer: alwaysAllow{},
			Clock:      fixedClock{now: distTestNow()},
			IDs:        &seqIDs{},
		},
		TokenCodec:               fakeTokenCodec{},
		DeliveryEncoder:          encoder,
		PublicCertificateEncoder: okPublicEncoder("public-payload"),
		OperationalLogger:        &fakeOperationalLogger{},
		RuntimeGate:              gate,
	}
}

// fakePublicCertificateEncoder is PublicCertificateEncoder's test double: it
// records every call's input (so a test can assert the ChainDER order §14.2
// requires) and returns whatever fn produces.
type fakePublicCertificateEncoder struct {
	mu    sync.Mutex
	calls []port.PublicEncodeInput
	fn    func(port.PublicEncodeInput) (port.EncodedBundle, error)
}

func (f *fakePublicCertificateEncoder) Encode(_ context.Context, in port.PublicEncodeInput) (port.EncodedBundle, error) {
	f.mu.Lock()
	f.calls = append(f.calls, in)
	f.mu.Unlock()
	return f.fn(in)
}

func (f *fakePublicCertificateEncoder) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakePublicCertificateEncoder) lastInput() port.PublicEncodeInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func okPublicEncoder(payload string) *fakePublicCertificateEncoder {
	return &fakePublicCertificateEncoder{fn: func(port.PublicEncodeInput) (port.EncodedBundle, error) {
		return port.NewEncodedBundle([]byte(payload), "application/x-pem-file"), nil
	}}
}

func failingPublicEncoder(err error) *fakePublicCertificateEncoder {
	return &fakePublicCertificateEncoder{fn: func(port.PublicEncodeInput) (port.EncodedBundle, error) {
		return port.EncodedBundle{}, err
	}}
}

// fakeOperationalLogger records every event §14.5 hands it, so a test can
// assert both that a code/stage/id was recorded and that nothing secret ever
// reaches it (the struct has no field to smuggle one into in the first
// place, but a test still checks the values it does carry).
type fakeOperationalLogger struct {
	mu     sync.Mutex
	events []port.OperationalEvent
}

func (l *fakeOperationalLogger) Record(event port.OperationalEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *fakeOperationalLogger) recorded() []port.OperationalEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]port.OperationalEvent(nil), l.events...)
}

// withPublicEncoder/withOperationalLogger let a test override just one
// dependency distDeps otherwise defaults sensibly, without having to repeat
// every other field distDeps already wires up.
func withPublicEncoder(deps DistributionDeps, enc port.PublicCertificateEncoder) DistributionDeps {
	deps.PublicCertificateEncoder = enc
	return deps
}

func withOperationalLogger(deps DistributionDeps, logger port.OperationalLogger) DistributionDeps {
	deps.OperationalLogger = logger
	return deps
}

// auditScopeCapture records every scope slice passed to tx.Audit().Append
// across a store's lifetime, letting a test assert §14.6 without porttest
// exposing scopes on its own (porttest is out of this developer's assigned
// files, so this wraps port.TxStores/UnitOfWork/ReadStore instead of adding
// a method there).
type auditScopeCapture struct {
	mu     sync.Mutex
	scopes [][]domain.AuthorityID
}

func (c *auditScopeCapture) record(scope []domain.AuthorityID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scopes = append(c.scopes, append([]domain.AuthorityID(nil), scope...))
}

func (c *auditScopeCapture) all() [][]domain.AuthorityID {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]domain.AuthorityID(nil), c.scopes...)
}

type scopeCapturingStore struct {
	inner   *porttest.Store
	capture *auditScopeCapture
}

func (s *scopeCapturingStore) Write(ctx context.Context, fn func(port.TxStores) error) error {
	return s.inner.Write(ctx, func(tx port.TxStores) error {
		return fn(scopeCapturingTx{TxStores: tx, capture: s.capture})
	})
}

func (s *scopeCapturingStore) Read(ctx context.Context, fn func(port.TxStores) error) error {
	return s.inner.Read(ctx, func(tx port.TxStores) error {
		return fn(scopeCapturingTx{TxStores: tx, capture: s.capture})
	})
}

type scopeCapturingTx struct {
	port.TxStores
	capture *auditScopeCapture
}

func (t scopeCapturingTx) Audit() port.AuditRepository {
	return scopeCapturingAudit{AuditRepository: t.TxStores.Audit(), capture: t.capture}
}

type scopeCapturingAudit struct {
	port.AuditRepository
	capture *auditScopeCapture
}

func (a scopeCapturingAudit) Append(ctx context.Context, event port.AuditEvent, scopes []domain.AuthorityID) error {
	a.capture.record(scopes)
	return a.AuditRepository.Append(ctx, event, scopes)
}

type alwaysAllow struct{}

func (alwaysAllow) Authorize(context.Context, contract.Principal, port.Action, port.AuthorizationScope) error {
	return nil
}

func distCmd(t *testing.T, rawToken string) contract.DownloadCommand {
	t.Helper()
	return contract.DownloadCommand{
		RawToken: secret.New([]byte(rawToken)),
		Format:   contract.DownloadFormatPEM,
	}
}

func distMeta() contract.RequestMeta {
	return contract.RequestMeta{Principal: contract.AnonymousPrincipal()}
}

func newDistributionService(t *testing.T, deps DistributionDeps) *DistributionService {
	t.Helper()
	svc, err := NewDistributionService(deps)
	if err != nil {
		t.Fatalf("NewDistributionService: %v", err)
	}
	return svc
}

func countRevocations(t *testing.T, store *porttest.Store, issuer domain.CAKeyGenerationID, serial domain.SerialNumber) int {
	t.Helper()
	n := 0
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		_, err := tx.Revocations().FindForUpdate(context.Background(), issuer, serial)
		if err == nil {
			n = 1
		} else if !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("find revocation: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("read revocations: %v", err)
	}
	return n
}

func countAuditEvents(t *testing.T, store *porttest.Store) int {
	t.Helper()
	// The AuditRepository does not expose a raw count; DeleteBefore with a
	// past cutoff and limit=0 would delete nothing, so instead we rely on
	// the fixed test clock: query with a very high cutoff and a large limit,
	// counting deletions, then treat the store as a scratch copy. We must not
	// do that on a store still under test, so this helper is intentionally
	// unused for shared stores -- see the per-test audit assertions using
	// applyRevocations' own Changed counters and grant/delivery state
	// instead.
	return -1
}

func deliveryState(t *testing.T, store *porttest.Store, id domain.DeliveryID) domain.DeliveryState {
	t.Helper()
	var state domain.DeliveryState
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		d, err := tx.Delivery().GetDeliveryForUpdate(context.Background(), id)
		if err != nil {
			return err
		}
		state = d.State()
		return nil
	}); err != nil {
		t.Fatalf("read delivery state: %v", err)
	}
	return state
}

func jobCount(t *testing.T, store *porttest.Store) int {
	t.Helper()
	n := 0
	// store.Read clones the published snapshot and never publishes the
	// result, so calling the mutating ClaimDue here is safe: it can only
	// ever affect the throwaway clone, never the real store.
	future := distTestNow().Add(domain.NewDuration(24 * time.Hour))
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		jobs, err := tx.Jobs().ClaimDue(context.Background(), future, future, 1000)
		if err != nil {
			return err
		}
		n = len(jobs)
		return nil
	}); err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	return n
}

// ---- required tests -------------------------------------------------------

func TestDeliver_EncodingFailure_ConsumesNothing(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	encoder := failingEncoder(contract.NewAppError(contract.ErrorKindValidation, "encode_boom", "encoding failed"))
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{}
	deps := distDeps(t, fx.store, fx.store, encoder, gate)
	svc := newDistributionService(t, deps)

	_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err == nil {
		t.Fatal("expected an encoding error")
	}
	if encoder.callCount() != 1 {
		t.Fatalf("expected the encoder to run exactly once, got %d", encoder.callCount())
	}
	if sink.callCount() != 0 {
		t.Fatalf("expected 0 Send calls, got %d", sink.callCount())
	}
	if got := deliveryState(t, fx.store, fx.deliverID); got != domain.DeliveryStatePending {
		t.Fatalf("expected delivery to remain pending, got %s", got)
	}
	if gate.callCount() != 0 {
		t.Fatalf("expected no FailClosed call, got %d", gate.callCount())
	}
}

// raceBeforeFirstWrite lets a test model a genuine "commit loser": prepare()
// (a Read) sees the grant looking fine, but a concurrent winner consumes it
// for real between that read and this request's own consuming Write. The
// race hook runs exactly once, immediately before the first Write call is
// delegated to the real store, so commitConsumption's own re-check (not
// prepare's) is what catches it -- exercising the actual commit-time code
// path rather than a validation failure that never reaches a Write at all.
type raceBeforeFirstWrite struct {
	inner port.UnitOfWork
	once  sync.Once
	race  func()
}

func (u *raceBeforeFirstWrite) Write(ctx context.Context, fn func(port.TxStores) error) error {
	u.once.Do(u.race)
	return u.inner.Write(ctx, fn)
}

func TestDeliver_ConsumeCommitFails_NoSendCall(t *testing.T) {
	// A concurrent winner consumes the grant for real between this request's
	// prepare() read and its own consuming Write, so commitConsumption's
	// own re-check hits a definite already-consumed rejection -- a real
	// "commit loser", not merely a preparation-time validation failure.
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	racingUoW := &raceBeforeFirstWrite{inner: fx.store, race: func() {
		if err := fx.store.Write(context.Background(), func(tx port.TxStores) error {
			g, err := tx.Delivery().GetGrantForUpdate(context.Background(), tokenHashFor(fx.rawToken))
			if err != nil {
				return err
			}
			consumed, err := g.Consume(distTestNow())
			if err != nil {
				return err
			}
			return tx.Delivery().SaveGrant(context.Background(), consumed, g.Version())
		}); err != nil {
			t.Fatalf("race-consume grant: %v", err)
		}
	}}

	encoder := okEncoder("payload")
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{}
	svc := newDistributionService(t, distDeps(t, racingUoW, fx.store, encoder, gate))

	_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err == nil {
		t.Fatal("expected an already-consumed error")
	}
	appErr, ok := contract.AsAppError(err)
	if !ok {
		t.Fatalf("expected an AppError, got %T: %v", err, err)
	}
	if appErr.Kind() == contract.ErrorKindCommitUnknown {
		t.Fatalf("expected a definite rejection, got commit_unknown: %v", err)
	}
	if sink.callCount() != 0 {
		t.Fatalf("expected 0 Send calls for a commit loser, got %d", sink.callCount())
	}
	if gate.callCount() != 0 {
		t.Fatalf("a definite consumption rollback must not FailClosed, got %d calls", gate.callCount())
	}
}

func TestDeliver_ConsumeCommitUnknown_Private_NoSendAndFailClosed(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	staged := newStagedUoW(fx.store)
	staged.forceUnknownAt[1] = true

	gate := &fakeRuntimeGate{}
	sink := &fakeSink{}
	svc := newDistributionService(t, distDeps(t, staged, fx.store, okEncoder("payload"), gate))

	_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err == nil {
		t.Fatal("expected a commit_unknown error")
	}
	appErr, ok := contract.AsAppError(err)
	if !ok || appErr.Kind() != contract.ErrorKindCommitUnknown {
		t.Fatalf("expected ErrorKindCommitUnknown, got %#v", err)
	}
	if sink.callCount() != 0 {
		t.Fatalf("expected 0 Send calls when consumption commit is unknown, got %d", sink.callCount())
	}
	if gate.callCount() != 1 {
		t.Fatalf("expected exactly 1 FailClosed call, got %d", gate.callCount())
	}
}

func TestDeliver_ConsumeCommitUnknown_Public_NoSendNoFailClosed(t *testing.T) {
	fx := seedPublicFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)))
	staged := newStagedUoW(fx.store)
	staged.forceUnknownAt[1] = true

	gate := &fakeRuntimeGate{}
	sink := &fakeSink{}
	svc := newDistributionService(t, distDeps(t, staged, fx.store, okEncoder("payload"), gate))

	_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err == nil {
		t.Fatal("expected a commit_unknown error")
	}
	if sink.callCount() != 0 {
		t.Fatalf("expected 0 Send calls, got %d", sink.callCount())
	}
	if gate.callCount() != 0 {
		t.Fatalf("public commit_unknown must not FailClosed, got %d", gate.callCount())
	}
}

// runPrivateSendMatrix drives one Send outcome x postprocessing outcome
// combination for the private path and returns the fixture, gate and sink
// for assertions.
type privateMatrixCase struct {
	name             string
	sendOutcome      port.TransferOutcome
	sendErr          error
	sendPanic        any
	forcePostFail    bool // corrupt delivery state between the two Writes so recordPrivateOutcome's Write hits a definite rollback
	forcePostUnknown bool // second Write reports commit_unknown despite committing
}

func TestDeliver_Private_SendXPostprocessMatrix(t *testing.T) {
	cases := []privateMatrixCase{
		{
			name:        "send success, postprocess success",
			sendOutcome: port.TransferOutcome{Completed: true, BytesWritten: 42, FinishedAt: distTestNow()},
		},
		{
			name:          "send success, postprocess rollback",
			sendOutcome:   port.TransferOutcome{Completed: true, BytesWritten: 42, FinishedAt: distTestNow()},
			forcePostFail: true,
		},
		{
			name:             "send success, postprocess commit_unknown",
			sendOutcome:      port.TransferOutcome{Completed: true, BytesWritten: 42, FinishedAt: distTestNow()},
			forcePostUnknown: true,
		},
		{
			name:    "send failure, postprocess success",
			sendErr: errors.New("client aborted"),
		},
		{
			name:          "send failure, postprocess rollback",
			sendErr:       errors.New("client aborted"),
			forcePostFail: true,
		},
		{
			name:             "send failure, postprocess commit_unknown",
			sendErr:          errors.New("client aborted"),
			forcePostUnknown: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
			seedCRLStateFor(t, fx.store, fx.issuerID)

			staged := newStagedUoW(fx.store)
			if tc.forcePostFail {
				// Simulate a definite rollback at the recording stage: put the
				// delivery into an already-terminal state right after the
				// consumption commit, so recordPrivateOutcome's own
				// Complete/Fail call hits ErrInvalidTransition instead of
				// succeeding.
				staged.afterCommit[1] = func() {
					if err := fx.store.Write(context.Background(), func(tx port.TxStores) error {
						d, err := tx.Delivery().GetDeliveryForUpdate(context.Background(), fx.deliverID)
						if err != nil {
							return err
						}
						failed, err := d.Fail("raced_to_failure", distTestNow())
						if err != nil {
							return err
						}
						return tx.Delivery().SaveDelivery(context.Background(), failed, d.Version())
					}); err != nil {
						t.Fatalf("force postprocess rollback: %v", err)
					}
				}
			}
			if tc.forcePostUnknown {
				staged.forceUnknownAt[2] = true
			}

			gate := &fakeRuntimeGate{}
			sink := &fakeSink{outcome: tc.sendOutcome, err: tc.sendErr, panicVal: tc.sendPanic}
			svc := newDistributionService(t, distDeps(t, staged, fx.store, okEncoder("private-payload"), gate))

			summary, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)

			postProblem := tc.forcePostFail || tc.forcePostUnknown
			if postProblem {
				if gate.callCount() != 1 {
					t.Fatalf("expected exactly 1 FailClosed call, got %d", gate.callCount())
				}
				if err == nil {
					t.Fatal("expected an error when postprocessing could not be recorded")
				}
				return
			}

			if gate.callCount() != 0 {
				t.Fatalf("expected no FailClosed call, got %d", gate.callCount())
			}
			if tc.sendErr != nil {
				if err == nil {
					t.Fatal("expected the send failure to be reported")
				}
				if got := deliveryState(t, fx.store, fx.deliverID); got != domain.DeliveryStateFailed {
					t.Fatalf("expected delivery failed, got %s", got)
				}
				if n := countRevocations(t, fx.store, fx.issuerID, distSerial(t, "a1")); n != 1 {
					t.Fatalf("expected exactly 1 revocation row, got %d", n)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !summary.Completed {
				t.Fatal("expected TransferSummary.Completed=true")
			}
			if got := deliveryState(t, fx.store, fx.deliverID); got != domain.DeliveryStateServerCompleted {
				t.Fatalf("expected delivery server_completed, got %s", got)
			}
			if n := countRevocations(t, fx.store, fx.issuerID, distSerial(t, "a1")); n != 0 {
				t.Fatalf("expected 0 revocation rows on success, got %d", n)
			}
		})
	}
}

func TestDeliver_PrivateFailure_RevokeAndCRLJobAndAudit_SameCommit(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	// Deliberately do NOT seed a CRLState for the issuer, so applyRevocations
	// fails inside recordPrivateOutcome's Write (revocation_issuer_unknown),
	// after SaveDelivery(failed) already ran earlier in the same closure.
	// The whole Write must roll back together: delivery stays "transferring",
	// no revocation row appears.
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{err: errors.New("client aborted")}
	svc := newDistributionService(t, distDeps(t, fx.store, fx.store, okEncoder("private-payload"), gate))

	_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err == nil {
		t.Fatal("expected an error: postprocessing could not commit")
	}
	if gate.callCount() != 1 {
		t.Fatalf("expected FailClosed once, got %d", gate.callCount())
	}
	if got := deliveryState(t, fx.store, fx.deliverID); got != domain.DeliveryStateTransferring {
		t.Fatalf("expected the whole postprocess commit to roll back (delivery still transferring), got %s", got)
	}
	if n := countRevocations(t, fx.store, fx.issuerID, distSerial(t, "a1")); n != 0 {
		t.Fatalf("expected 0 revocation rows after an all-or-nothing rollback, got %d", n)
	}
}

func TestDeliver_PrivateFailure_HappyPath_RevokesAndJobsAndAudits(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	seedCRLStateFor(t, fx.store, fx.issuerID)

	gate := &fakeRuntimeGate{}
	sink := &fakeSink{err: errors.New("client aborted")}
	svc := newDistributionService(t, distDeps(t, fx.store, fx.store, okEncoder("private-payload"), gate))

	_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err == nil {
		t.Fatal("expected the send failure to be reported")
	}
	if gate.callCount() != 0 {
		t.Fatalf("a successfully-recorded failure must not FailClosed, got %d", gate.callCount())
	}
	if got := deliveryState(t, fx.store, fx.deliverID); got != domain.DeliveryStateFailed {
		t.Fatalf("expected delivery failed, got %s", got)
	}
	if n := countRevocations(t, fx.store, fx.issuerID, distSerial(t, "a1")); n != 1 {
		t.Fatalf("expected exactly 1 revocation row, got %d", n)
	}
	if n := jobCount(t, fx.store); n != 1 {
		t.Fatalf("expected exactly 1 CRL job demand, got %d", n)
	}
}

func TestDeliver_PublicFailure_NoRevocation_AuditOnly(t *testing.T) {
	fx := seedPublicFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)))
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{err: errors.New("client aborted")}
	svc := newDistributionService(t, distDeps(t, fx.store, fx.store, okEncoder("public-payload"), gate))

	_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err == nil {
		t.Fatal("expected the send failure to be reported")
	}
	if gate.callCount() != 0 {
		t.Fatalf("a public transfer failure must never FailClosed, got %d", gate.callCount())
	}
	if n := countRevocations(t, fx.store, fx.issuerID, distSerial(t, "a2")); n != 0 {
		t.Fatalf("expected 0 revocation rows for a public failure, got %d", n)
	}
	if n := jobCount(t, fx.store); n != 0 {
		t.Fatalf("expected 0 CRL job demands for a public failure, got %d", n)
	}
}

func TestDeliver_SendPanic_CleansUpPayloadAndFailsClosed(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	seedCRLStateFor(t, fx.store, fx.issuerID)

	gate := &fakeRuntimeGate{}
	sink := &fakeSink{panicVal: "boom"}
	staged := newStagedUoW(fx.store)
	// Force the postprocessing write (stage 2, which must still run after a
	// panic) to fail, since a panic alone -- successfully recorded as a
	// failure -- is not itself a FailClosed trigger under §7 step 6; what
	// must be proven here is that recording is *attempted* (and payload
	// cleaned up) even after a panic, and that if that recording cannot
	// complete, FailClosed still fires.
	staged.forceUnknownAt[2] = true

	svc := newDistributionService(t, distDeps(t, staged, fx.store, okEncoder("private-payload"), gate))

	_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err == nil {
		t.Fatal("expected an error after a Send panic with unrecordable postprocessing")
	}
	if gate.callCount() != 1 {
		t.Fatalf("expected FailClosed once, got %d", gate.callCount())
	}
	if sink.callCount() != 1 {
		t.Fatalf("expected exactly 1 Send call, got %d", sink.callCount())
	}
}

func TestDeliver_SendPanic_RecordedFailure_NoFailClosed(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	seedCRLStateFor(t, fx.store, fx.issuerID)

	gate := &fakeRuntimeGate{}
	sink := &fakeSink{panicVal: "boom"}
	svc := newDistributionService(t, distDeps(t, fx.store, fx.store, okEncoder("private-payload"), gate))

	_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err == nil {
		t.Fatal("expected the panic to surface as an error")
	}
	if gate.callCount() != 0 {
		t.Fatalf("a panic whose failure was successfully recorded must not FailClosed, got %d", gate.callCount())
	}
	if got := deliveryState(t, fx.store, fx.deliverID); got != domain.DeliveryStateFailed {
		t.Fatalf("expected delivery failed, got %s", got)
	}
	if n := countRevocations(t, fx.store, fx.issuerID, distSerial(t, "a1")); n != 1 {
		t.Fatalf("expected exactly 1 revocation row, got %d", n)
	}
}

func TestDeliver_SinkCannotReadAfterSendReturns(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	seedCRLStateFor(t, fx.store, fx.issuerID)

	gate := &fakeRuntimeGate{}
	sink := &fakeSink{outcome: port.TransferOutcome{Completed: true, BytesWritten: 3, FinishedAt: distTestNow()}}
	svc := newDistributionService(t, distDeps(t, fx.store, fx.store, okEncoder("abc"), gate))

	_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := sink.readerAfterReturn()
	if r == nil {
		t.Fatal("sink never captured a reader")
	}
	buf := make([]byte, 1)
	if _, err := r.Read(buf); !errors.Is(err, errPayloadReaderClosed) {
		t.Fatalf("expected errPayloadReaderClosed reading after Send returned, got %v", err)
	}
}

func TestDeliver_PostProcessTimeout_ReleasesBackgroundWork(t *testing.T) {
	// §12: "timeout 후 background 계산을 방치하지 않는 자원 해제도
	// 확인한다." We shrink the (test-overridable) post-processing deadline
	// and give it a Write that blocks past that deadline, then assert the
	// goroutine actually observes ctx.Done() and returns instead of leaking
	// forever -- i.e. the context this package builds is real and is not
	// silently ignored.
	old := deliverPostProcessTimeout
	deliverPostProcessTimeout = 20 * time.Millisecond
	defer func() { deliverPostProcessTimeout = old }()

	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	seedCRLStateFor(t, fx.store, fx.issuerID)

	blockingUoW := newBlockingWriteOnce(fx.store)
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{err: errors.New("client aborted")}
	svc := newDistributionService(t, distDeps(t, blockingUoW, fx.store, okEncoder("private-payload"), gate))

	done := make(chan struct{})
	go func() {
		_, _ = svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
		close(done)
	}()

	select {
	case <-blockingUoW.observedDone:
		// The postprocessing Write's ctx was canceled once the shrunk
		// deadline elapsed, proving the background work does not run
		// unbounded.
	case <-time.After(2 * time.Second):
		t.Fatal("postprocessing context was never canceled after its deadline")
	}
	close(blockingUoW.block)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Deliver never returned after the blocked write unblocked")
	}
}

// blockingWriteOnce lets the FIRST Write (consumption) run normally, then
// blocks the SECOND Write (postprocessing) until either `block` is closed or
// its context is canceled -- reporting the latter on observedDone so the
// test can assert the timeout was actually enforced rather than merely
// hoped for.
type blockingWriteOnce struct {
	inner        port.UnitOfWork
	stage        int
	mu           sync.Mutex
	block        chan struct{}
	observedDone chan struct{}
}

func newBlockingWriteOnce(inner port.UnitOfWork) *blockingWriteOnce {
	return &blockingWriteOnce{inner: inner, block: make(chan struct{}), observedDone: make(chan struct{})}
}

func (u *blockingWriteOnce) Write(ctx context.Context, fn func(port.TxStores) error) error {
	u.mu.Lock()
	u.stage++
	stage := u.stage
	u.mu.Unlock()

	if stage == 1 {
		return u.inner.Write(ctx, fn)
	}
	select {
	case <-ctx.Done():
		close(u.observedDone)
		return ctx.Err()
	case <-u.block:
		return u.inner.Write(context.Background(), fn)
	}
}

func (u *blockingWriteOnce) Read(ctx context.Context, fn func(port.TxStores) error) error {
	if rs, ok := u.inner.(port.ReadStore); ok {
		return rs.Read(ctx, fn)
	}
	return fmt.Errorf("blockingWriteOnce: inner store is not a ReadStore")
}

// TestDeliver_PublicSuccess_NoSecondWrite is a smoke test for the ordinary
// public happy path, since every other test above exercises a failure or
// error branch.
func TestDeliver_PublicSuccess_HappyPath(t *testing.T) {
	fx := seedPublicFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)))
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{outcome: port.TransferOutcome{Completed: true, BytesWritten: 7, FinishedAt: distTestNow()}}
	svc := newDistributionService(t, distDeps(t, fx.store, fx.store, okEncoder("cert-bytes"), gate))

	summary, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !summary.Completed || summary.BytesWritten != 7 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if summary.DeliveryID != "" {
		t.Fatalf("expected a zero DeliveryID for a public transfer, got %q", summary.DeliveryID)
	}
	if gate.callCount() != 0 {
		t.Fatalf("expected no FailClosed call, got %d", gate.callCount())
	}
}

var _ = bytes.MinRead // keep bytes imported if only used indirectly in future edits

// TestDeliver_PrivateTokenRequestingCertificateOnlyIsRejected covers a gap
// this file's original version left open and which distribution.go's
// prepare() has since been fixed to close: docs/api-contract.md states
// "private 토큰으로 공개 자료만 받는 조합은 422이며 소비하지 않는다", but
// nothing checked Format/PEMPart against the grant's purpose before the
// encoder ran -- a private grant could have been redeemed for a
// certificate-only PEM, silently burning its one-shot custody without ever
// transferring the key. Confirmed failing before the fix (the encoder ran
// and the request succeeded) and passing after it.
func TestDeliver_PrivateTokenRequestingCertificateOnlyIsRejected(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	encoder := okEncoder("should-not-be-used")
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{}
	svc := newDistributionService(t, distDeps(t, fx.store, fx.store, encoder, gate))

	cmd := contract.DownloadCommand{
		RawToken: secret.New([]byte(fx.rawToken)),
		Format:   contract.DownloadFormatPEM,
		PEMPart:  contract.DownloadPartCertificate,
	}
	_, err := svc.Deliver(context.Background(), distMeta(), cmd, sink)
	if err == nil {
		t.Fatal("want a validation error for a private token requesting certificate-only content")
	}
	appErr, ok := contract.AsAppError(err)
	if !ok || appErr.Kind() != contract.ErrorKindValidation {
		t.Fatalf("err = %v, want a validation AppError", err)
	}
	if encoder.callCount() != 0 {
		t.Fatalf("encoder must not run when the request is rejected before encoding, got %d calls", encoder.callCount())
	}
	if sink.callCount() != 0 {
		t.Fatalf("sink calls = %d, want 0", sink.callCount())
	}
	if got := deliveryState(t, fx.store, fx.deliverID); got != domain.DeliveryStatePending {
		t.Fatalf("delivery state = %s, want pending (nothing consumed)", got)
	}
}

// TestDeliver_PrivateTokenRequestingChainOnlyIsRejected is the chain-only
// half of the same rule.
func TestDeliver_PrivateTokenRequestingChainOnlyIsRejected(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	encoder := okEncoder("should-not-be-used")
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{}
	svc := newDistributionService(t, distDeps(t, fx.store, fx.store, encoder, gate))

	cmd := contract.DownloadCommand{
		RawToken: secret.New([]byte(fx.rawToken)),
		Format:   contract.DownloadFormatPEM,
		PEMPart:  contract.DownloadPartChain,
	}
	_, err := svc.Deliver(context.Background(), distMeta(), cmd, sink)
	if err == nil {
		t.Fatal("want a validation error for a private token requesting chain-only content")
	}
	if encoder.callCount() != 0 {
		t.Fatalf("encoder must not run when the request is rejected before encoding, got %d calls", encoder.callCount())
	}
}

// TestDeliver_PublicTokenRequestingPrivateKeyIsRejected checks the existing
// (already present before this file's changes) symmetric protection on the
// public side still holds: a public grant must never be able to yield key
// material. This is not a new fix -- encodePublicBundle already rejects
// PEMPart=private_key -- but is asserted here explicitly at the Deliver
// level since no test in this file named it directly.
func TestDeliver_PublicTokenRequestingPrivateKeyIsRejected(t *testing.T) {
	fx := seedPublicFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)))
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{}
	svc := newDistributionService(t, distDeps(t, fx.store, fx.store, okEncoder("unused"), gate))

	cmd := contract.DownloadCommand{
		RawToken: secret.New([]byte(fx.rawToken)),
		Format:   contract.DownloadFormatPEM,
		PEMPart:  contract.DownloadPartPrivateKey,
	}
	_, err := svc.Deliver(context.Background(), distMeta(), cmd, sink)
	if err == nil {
		t.Fatal("want a validation error for a public token requesting the private key")
	}
	if sink.callCount() != 0 {
		t.Fatalf("sink calls = %d, want 0", sink.callCount())
	}
}

// ---- §14 required tests ---------------------------------------------------

// TestDeliver_PublicUsesPublicCertificateEncoder_NotServiceBuiltPEM proves
// the public download path now goes through the injected
// PublicCertificateEncoder instead of this package building PEM/ZIP bytes
// itself (§14.3). Before the fix, distribution.go's own encodePublicBundle/
// encodePublicZIP built the payload directly and no PublicCertificateEncoder
// dependency existed at all, so this test would not even compile against
// the old code -- confirming the fix is exercised, not merely present.
func TestDeliver_PublicUsesPublicCertificateEncoder_NotServiceBuiltPEM(t *testing.T) {
	fx := seedPublicFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)))
	publicEncoder := okPublicEncoder("from-the-injected-encoder")
	privateEncoder := okEncoder("must-not-be-used")
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{outcome: port.TransferOutcome{Completed: true, BytesWritten: 1, FinishedAt: distTestNow()}}
	deps := withPublicEncoder(distDeps(t, fx.store, fx.store, privateEncoder, gate), publicEncoder)
	svc := newDistributionService(t, deps)

	_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if publicEncoder.callCount() != 1 {
		t.Fatalf("PublicCertificateEncoder calls = %d, want 1", publicEncoder.callCount())
	}
	if privateEncoder.callCount() != 0 {
		t.Fatalf("DeliveryEncoder (private) calls = %d, want 0 for a public download", privateEncoder.callCount())
	}
}

// TestDeliver_PublicPKCS12IsRejected_PublicEncoderNeverCalled is §14.4: a
// public PKCS#12 request is refused before consumption and before the
// public encoder ever runs.
func TestDeliver_PublicPKCS12IsRejected_PublicEncoderNeverCalled(t *testing.T) {
	fx := seedPublicFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)))
	publicEncoder := okPublicEncoder("must-not-be-used")
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{}
	deps := withPublicEncoder(distDeps(t, fx.store, fx.store, okEncoder("unused"), gate), publicEncoder)
	svc := newDistributionService(t, deps)

	cmd := contract.DownloadCommand{RawToken: secret.New([]byte(fx.rawToken)), Format: contract.DownloadFormatPKCS12}
	_, err := svc.Deliver(context.Background(), distMeta(), cmd, sink)
	if err == nil {
		t.Fatal("want a validation error for a public pkcs12 request")
	}
	appErr, ok := contract.AsAppError(err)
	if !ok || appErr.Kind() != contract.ErrorKindValidation {
		t.Fatalf("err = %v, want a validation AppError", err)
	}
	if publicEncoder.callCount() != 0 {
		t.Fatalf("PublicCertificateEncoder calls = %d, want 0", publicEncoder.callCount())
	}
	if sink.callCount() != 0 {
		t.Fatalf("sink calls = %d, want 0", sink.callCount())
	}
}

// TestDeliver_ChainDER_IsIssuerExcludedIssuerToRoot proves buildChainDER's
// output reaches both encoders in the §14.2 shape: issuer→Root, excluding
// the target certificate. Confirmed failing before this fix (ChainDER was
// hard-coded nil in prepare()) and passing after it.
func TestDeliver_ChainDER_IsIssuerExcludedIssuerToRoot(t *testing.T) {
	t.Run("public", func(t *testing.T) {
		fx := seedPublicFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)))
		publicEncoder := okPublicEncoder("payload")
		gate := &fakeRuntimeGate{}
		sink := &fakeSink{outcome: port.TransferOutcome{Completed: true, BytesWritten: 1, FinishedAt: distTestNow()}}
		deps := withPublicEncoder(distDeps(t, fx.store, fx.store, okEncoder("unused"), gate), publicEncoder)
		svc := newDistributionService(t, deps)

		if _, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		in := publicEncoder.lastInput()
		if len(in.ChainDER) != 1 {
			t.Fatalf("ChainDER length = %d, want 1 (the Root, target excluded)", len(in.ChainDER))
		}
		wantRootDER := distRootCACert(t, 2, fx.issuerID).DER()
		if !bytes.Equal(in.ChainDER[0], wantRootDER) {
			t.Fatalf("ChainDER[0] does not match the seeded Root certificate DER")
		}
		if bytes.Equal(in.ChainDER[0], in.Certificate.DER()) {
			t.Fatal("ChainDER must not include the target certificate itself")
		}
	})

	t.Run("private", func(t *testing.T) {
		fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
		privateEncoder := okEncoder("payload")
		gate := &fakeRuntimeGate{}
		sink := &fakeSink{outcome: port.TransferOutcome{Completed: true, BytesWritten: 1, FinishedAt: distTestNow()}}
		svc := newDistributionService(t, distDeps(t, fx.store, fx.store, privateEncoder, gate))

		if _, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if privateEncoder.callCount() != 1 {
			t.Fatalf("DeliveryEncoder calls = %d, want 1", privateEncoder.callCount())
		}
		in := privateEncoder.lastInput()
		if len(in.ChainDER) != 1 {
			t.Fatalf("ChainDER length = %d, want 1 (the Root, target excluded)", len(in.ChainDER))
		}
		wantRootDER := distRootCACert(t, 1, fx.issuerID).DER()
		if !bytes.Equal(in.ChainDER[0], wantRootDER) {
			t.Fatalf("ChainDER[0] does not match the seeded Root certificate DER")
		}
	})
}

// TestDeliver_ChainMissing_ConsumesNothing is §14.2 + the "encoding failure
// consumes nothing" rule applied to chain resolution: a certificate with no
// stored leaf_certificates row cannot resolve a chain, and that failure must
// happen before any Write. Confirmed failing before the fix (ChainDER was
// simply nil, so a missing chain record was never even looked at) and
// passing after it -- the request now fails, with the delivery still
// pending and neither encoder ever called.
func TestDeliver_ChainMissing_ConsumesNothing(t *testing.T) {
	store := porttest.NewStore()
	cert := distCertificate(t, 11, 11, 11, "b1")
	delivery := distDelivery(t, 11, 11, cert.ID(), distTestNow().Add(domain.NewDuration(time.Hour)))
	grant := distGrant(t, 11, domain.GrantPurposeLeafPrivate, cert.ID(), delivery.ID(), tokenHashFor("chain-missing-raw-token-0123456789AB"), distTestNow().Add(domain.NewDuration(time.Hour)))
	secretRow := distEncryptedSecret(t, cert.KeyMaterialID())
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		if err := tx.PKI().InsertCertificate(context.Background(), cert); err != nil {
			return err
		}
		if err := tx.Delivery().InsertDelivery(context.Background(), delivery); err != nil {
			return err
		}
		if err := tx.Delivery().InsertGrant(context.Background(), grant); err != nil {
			return err
		}
		return tx.Secrets().InsertEncrypted(context.Background(), secretRow)
	}); err != nil {
		t.Fatalf("seed fixture with no chain record: %v", err)
	}
	// Deliberately NOT calling seedChainAndScope: no leaf_certificates row
	// exists for this certificate.

	privateEncoder := okEncoder("must-not-run")
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{}
	svc := newDistributionService(t, distDeps(t, store, store, privateEncoder, gate))

	cmd := contract.DownloadCommand{RawToken: secret.New([]byte("chain-missing-raw-token-0123456789AB")), Format: contract.DownloadFormatPEM}
	_, err := svc.Deliver(context.Background(), distMeta(), cmd, sink)
	if err == nil {
		t.Fatal("want an error when the stored issuer chain cannot be resolved")
	}
	if privateEncoder.callCount() != 0 {
		t.Fatalf("encoder calls = %d, want 0", privateEncoder.callCount())
	}
	if sink.callCount() != 0 {
		t.Fatalf("sink calls = %d, want 0", sink.callCount())
	}
	if got := deliveryState(t, store, delivery.ID()); got != domain.DeliveryStatePending {
		t.Fatalf("delivery state = %s, want pending (nothing consumed)", got)
	}
}

// TestDeliver_ChainIssuerKeyMismatch_ConsumesNothing is §14.2's issuer-key-
// mismatch case: the stored issuer certificate's CA key generation does not
// match the one the certificate itself claims to be signed by.
func TestDeliver_ChainIssuerKeyMismatch_ConsumesNothing(t *testing.T) {
	store := porttest.NewStore()
	// InsertLeafCertificateRecord/InsertCACertificateRecord have no matching
	// Save method (§14.2's port surface is insert-once for these subtype
	// rows), so this test seeds its own certificate/grant pair pointed at a
	// deliberately mismatched chain rather than mutating an existing fixture.
	wrongIssuer := distIssuerID(t, 999)

	cert2 := distCertificate(t, 12, 12, 12, "b2")
	delivery2 := distDelivery(t, 12, 12, cert2.ID(), distTestNow().Add(domain.NewDuration(time.Hour)))
	grant2 := distGrant(t, 12, domain.GrantPurposeLeafPrivate, cert2.ID(), delivery2.ID(), tokenHashFor("mismatch-raw-token-0123456789ABCDE"), distTestNow().Add(domain.NewDuration(time.Hour)))
	secretRow2 := distEncryptedSecret(t, cert2.KeyMaterialID())
	mismatchedCACert := distRootCACert(t, 51, wrongIssuer)
	series := distSeries(t, 12, distManagementAuthorityID(t, 12))
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		if err := tx.PKI().InsertCertificate(context.Background(), cert2); err != nil {
			return err
		}
		if err := tx.Delivery().InsertDelivery(context.Background(), delivery2); err != nil {
			return err
		}
		if err := tx.Delivery().InsertGrant(context.Background(), grant2); err != nil {
			return err
		}
		if err := tx.Secrets().InsertEncrypted(context.Background(), secretRow2); err != nil {
			return err
		}
		if err := tx.PKI().InsertSeries(context.Background(), series); err != nil {
			return err
		}
		if err := tx.PKI().InsertCertificate(context.Background(), mismatchedCACert); err != nil {
			return err
		}
		// The CA record claims a DIFFERENT key generation than cert2's own
		// IssuerCAKeyGenerationID (cert2 was built with distIssuerID(t, 12)).
		if err := tx.PKI().InsertCACertificateRecord(context.Background(), port.CACertificateRecord{
			CertificateID:     mismatchedCACert.ID(),
			CAKeyGenerationID: wrongIssuer,
		}); err != nil {
			return err
		}
		return tx.PKI().InsertLeafCertificateRecord(context.Background(), port.LeafCertificateRecord{
			CertificateID:         cert2.ID(),
			SeriesID:              series.ID(),
			IssuerCACertificateID: mismatchedCACert.ID(),
			Operation:             port.CertificateOperationInitial,
		})
	}); err != nil {
		t.Fatalf("seed mismatch fixture: %v", err)
	}

	privateEncoder := okEncoder("must-not-run")
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{}
	svc := newDistributionService(t, distDeps(t, store, store, privateEncoder, gate))

	cmd := contract.DownloadCommand{RawToken: secret.New([]byte("mismatch-raw-token-0123456789ABCDE")), Format: contract.DownloadFormatPEM}
	_, err := svc.Deliver(context.Background(), distMeta(), cmd, sink)
	if err == nil {
		t.Fatal("want an error for a chain whose issuer certificate does not certify the recorded signing key generation")
	}
	if privateEncoder.callCount() != 0 {
		t.Fatalf("encoder calls = %d, want 0", privateEncoder.callCount())
	}
	if sink.callCount() != 0 {
		t.Fatalf("sink calls = %d, want 0", sink.callCount())
	}
	if got := deliveryState(t, store, delivery2.ID()); got != domain.DeliveryStatePending {
		t.Fatalf("delivery state = %s, want pending (nothing consumed)", got)
	}
}

// TestDeliver_PublicPostProcessFailure_LogsOperationalEvent is §14.5: a
// public transfer's post-processing failure is recorded through
// OperationalLogger with only the fixed code/request id/stage/ids, never
// FailClosed, and no revocation. Confirmed failing before the fix (the
// branch discarded the error with `_ =` and no OperationalLogger dependency
// existed) and passing after it.
func TestDeliver_PublicPostProcessFailure_LogsOperationalEvent(t *testing.T) {
	fx := seedPublicFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)))
	logger := &fakeOperationalLogger{}
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{err: errors.New("client aborted")}
	meta := contract.RequestMeta{Principal: contract.AnonymousPrincipal(), RequestID: "req-public-1"}
	deps := withOperationalLogger(distDeps(t, fx.store, fx.store, okEncoder("unused"), gate), logger)
	svc := newDistributionService(t, deps)

	_, err := svc.Deliver(context.Background(), meta, distCmd(t, fx.rawToken), sink)
	if err == nil {
		t.Fatal("expected the send failure to be reported")
	}
	if gate.callCount() != 0 {
		t.Fatalf("a public post-process failure must never FailClosed, got %d", gate.callCount())
	}
	if n := countRevocations(t, fx.store, fx.issuerID, distSerial(t, "a2")); n != 0 {
		t.Fatalf("expected 0 revocation rows for a public failure, got %d", n)
	}

	events := logger.recorded()
	if len(events) != 1 {
		t.Fatalf("OperationalLogger.Record calls = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Stage != port.OperationalStagePublicPostProcess {
		t.Fatalf("Stage = %q, want %q", ev.Stage, port.OperationalStagePublicPostProcess)
	}
	if ev.RequestID != "req-public-1" {
		t.Fatalf("RequestID = %q, want %q", ev.RequestID, "req-public-1")
	}
	if ev.CertificateID != fx.certID {
		t.Fatalf("CertificateID = %q, want %q", ev.CertificateID, fx.certID)
	}
	if ev.GrantID == "" {
		t.Fatal("GrantID must not be empty")
	}
	if ev.Code == "" {
		t.Fatal("Code must not be empty")
	}
}

// TestDeliver_OperationalEvent_CarriesNoSecrets checks the §14.5 "never a
// raw error/URL/token/private key" rule two ways: structurally (the typed
// event has no field capable of holding one) and by value (the fields it
// does carry are exactly the fixed identifiers, not the sink's error text).
func TestDeliver_OperationalEvent_CarriesNoSecrets(t *testing.T) {
	fx := seedPublicFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)))
	logger := &fakeOperationalLogger{}
	gate := &fakeRuntimeGate{}
	secretishErr := errors.New("client aborted while holding token=SUPER-SECRET-RAW-TOKEN-VALUE")
	sink := &fakeSink{err: secretishErr}
	deps := withOperationalLogger(distDeps(t, fx.store, fx.store, okEncoder("unused"), gate), logger)
	svc := newDistributionService(t, deps)

	if _, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink); err == nil {
		t.Fatal("expected the send failure to be reported")
	}

	events := logger.recorded()
	if len(events) != 1 {
		t.Fatalf("OperationalLogger.Record calls = %d, want 1", len(events))
	}
	// port.OperationalEvent (internal/app/port/signing.go) has exactly
	// Code/RequestID/Stage/GrantID/DeliveryID/CertificateID -- struct
	// reflection is unnecessary; %+v on the recorded value is enough to
	// prove the secret-looking error text a real sink might produce never
	// appears in what was recorded, since there is no field it could have
	// been written into.
	rendered := fmt.Sprintf("%+v", events[0])
	if bytes.Contains([]byte(rendered), []byte("SUPER-SECRET-RAW-TOKEN-VALUE")) {
		t.Fatalf("recorded operational event leaked sink error text: %s", rendered)
	}
}

// TestDeliver_DownloadAuditScope_IsManagementAuthority_NotEmpty is §14.6:
// the start/success/failure audit rows for both a private and a public
// transfer are scoped to the certificate's stored management authority
// (LeafSeries.ManagementAuthorityID), never left empty and never the
// certificate's cryptographic issuer (which §14.2's buildChainDER resolves
// to a different id entirely in this fixture). Confirmed failing before the
// fix: appendDistributionAudit used to hard-code scope nil (there was no
// distributionManagementAuthority function to call at all).
func TestDeliver_DownloadAuditScope_IsManagementAuthority_NotEmpty(t *testing.T) {
	t.Run("private start and completed", func(t *testing.T) {
		fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
		seedCRLStateFor(t, fx.store, fx.issuerID)
		capture := &auditScopeCapture{}
		wrapped := &scopeCapturingStore{inner: fx.store, capture: capture}
		gate := &fakeRuntimeGate{}
		sink := &fakeSink{outcome: port.TransferOutcome{Completed: true, BytesWritten: 1, FinishedAt: distTestNow()}}
		svc := newDistributionService(t, distDeps(t, wrapped, wrapped, okEncoder("payload"), gate))

		if _, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertAllScopesAreManagementAuthority(t, capture, fx.managementAuthorityID, fx.issuerID)
	})

	t.Run("private failed", func(t *testing.T) {
		fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
		seedCRLStateFor(t, fx.store, fx.issuerID)
		capture := &auditScopeCapture{}
		wrapped := &scopeCapturingStore{inner: fx.store, capture: capture}
		gate := &fakeRuntimeGate{}
		sink := &fakeSink{err: errors.New("client aborted")}
		svc := newDistributionService(t, distDeps(t, wrapped, wrapped, okEncoder("payload"), gate))

		if _, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink); err == nil {
			t.Fatal("expected the send failure to be reported")
		}
		assertAllScopesAreManagementAuthority(t, capture, fx.managementAuthorityID, fx.issuerID)
	})

	t.Run("public start and failed", func(t *testing.T) {
		fx := seedPublicFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)))
		capture := &auditScopeCapture{}
		wrapped := &scopeCapturingStore{inner: fx.store, capture: capture}
		gate := &fakeRuntimeGate{}
		sink := &fakeSink{err: errors.New("client aborted")}
		svc := newDistributionService(t, distDeps(t, wrapped, wrapped, okEncoder("unused"), gate))

		if _, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink); err == nil {
			t.Fatal("expected the send failure to be reported")
		}
		assertAllScopesAreManagementAuthority(t, capture, fx.managementAuthorityID, fx.issuerID)
	})
}

// assertAllScopesAreManagementAuthority fails the test unless every captured
// audit scope is non-empty, equals exactly the management authority (never
// the unrelated CA key generation id buildChainDER walks), and at least one
// scope was actually captured.
func assertAllScopesAreManagementAuthority(t *testing.T, capture *auditScopeCapture, wantAuthority domain.AuthorityID, notIssuer domain.CAKeyGenerationID) {
	t.Helper()
	scopes := capture.all()
	if len(scopes) == 0 {
		t.Fatal("no audit events were recorded at all")
	}
	for i, scope := range scopes {
		if len(scope) == 0 {
			t.Fatalf("audit event %d has an empty scope, want %q", i, wantAuthority)
		}
		for _, id := range scope {
			if id != wantAuthority {
				t.Fatalf("audit event %d scope = %v, want exactly [%q]", i, scope, wantAuthority)
			}
			if string(id) == string(notIssuer) {
				t.Fatalf("audit event %d scope leaked the cryptographic issuer id instead of the management authority", i)
			}
		}
	}
}

// ---- PR #3 final-review findings -----------------------------------------

// TestDeliver_GrantExpiresDuringEncoding_RejectedAtConsumeTime is finding #1:
// commitConsumption used to reuse Deliver's single, prepare-time now for its
// own Validate/CanConsume/Consume calls. A grant/delivery valid when prepare
// read it but expired by the time the consuming Write actually acquires its
// row lock (e.g. because encoding took real wall-clock time) must still be
// rejected -- not waved through on a stale now. This encoder advances a
// shared clock past the grant/delivery deadline before returning, modeling
// exactly the delayed-encoder-plus-advancing-clock reproduction the reviewer
// used.
func TestDeliver_GrantExpiresDuringEncoding_RejectedAtConsumeTime(t *testing.T) {
	prepTime := distTestNow()
	expiresAt := prepTime.Add(domain.NewDuration(time.Millisecond))
	consumeTime := expiresAt.Add(domain.NewDuration(time.Hour))

	fx := seedPrivateFixture(t, expiresAt, domain.DeliveryStatePending)
	clock := &advancingClock{now: prepTime}
	encoder := &fakeDeliveryEncoder{fn: func(port.DeliveryEncodeInput) (port.EncodedBundle, error) {
		// Simulate encoding taking long enough that the grant/delivery
		// deadline passes before the consuming commit runs.
		clock.advanceTo(consumeTime)
		return port.NewEncodedBundle([]byte("payload"), "application/x-pem-file"), nil
	}}
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{outcome: port.TransferOutcome{Completed: true, BytesWritten: 1, FinishedAt: consumeTime}}
	deps := withClock(distDeps(t, fx.store, fx.store, encoder, gate), clock)
	svc := newDistributionService(t, deps)

	_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err == nil {
		t.Fatal("expected the request to be rejected as expired at consume time")
	}
	if sink.callCount() != 0 {
		t.Fatalf("expected 0 Send calls, got %d", sink.callCount())
	}
	if got := deliveryState(t, fx.store, fx.deliverID); got != domain.DeliveryStatePending {
		t.Fatalf("expected delivery to remain pending (0 consumptions), got %s", got)
	}
}

// TestDeliver_EncoderReturnsBundleWithError_BundleIsClosed is finding #2's
// private-side reproduction: an encoder that hands back both a bundle and an
// error used to leave that bundle open, because prepare's own encErr return
// happens before Deliver installs its `defer prep.bundle.Close()`. This
// keeps a reference to the bundle the misbehaving encoder produced and
// checks it is unusable once Deliver has returned its error.
func TestDeliver_EncoderReturnsBundleWithError_BundleIsClosed(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	var leaked port.EncodedBundle
	encoder := &fakeDeliveryEncoder{fn: func(port.DeliveryEncodeInput) (port.EncodedBundle, error) {
		leaked = port.NewEncodedBundle([]byte("leaked-private-plaintext"), "application/x-pem-file")
		return leaked, errors.New("encode failed but returned a bundle anyway")
	}}
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{}
	svc := newDistributionService(t, distDeps(t, fx.store, fx.store, encoder, gate))

	_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err == nil {
		t.Fatal("expected the encoding error to surface")
	}
	if useErr := leaked.Use(func([]byte) error { return nil }); useErr == nil {
		t.Fatal("expected the bundle returned alongside an encoder error to be closed, but Use still succeeded")
	}
}

// TestDeliver_PublicEncoderReturnsBundleWithError_BundleIsClosed is finding
// #2's public-side counterpart: PublicCertificateEncoder must get the same
// treatment as the private DeliveryEncoder.
func TestDeliver_PublicEncoderReturnsBundleWithError_BundleIsClosed(t *testing.T) {
	fx := seedPublicFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)))
	var leaked port.EncodedBundle
	publicEncoder := &fakePublicCertificateEncoder{fn: func(port.PublicEncodeInput) (port.EncodedBundle, error) {
		leaked = port.NewEncodedBundle([]byte("leaked-public-plaintext"), "application/x-pem-file")
		return leaked, errors.New("public encode failed but returned a bundle anyway")
	}}
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{}
	deps := withPublicEncoder(distDeps(t, fx.store, fx.store, okEncoder("unused"), gate), publicEncoder)
	svc := newDistributionService(t, deps)

	_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err == nil {
		t.Fatal("expected the public encoding error to surface")
	}
	if useErr := leaked.Use(func([]byte) error { return nil }); useErr == nil {
		t.Fatal("expected the public bundle returned alongside an encoder error to be closed, but Use still succeeded")
	}
}

// TestDeliver_PublicSuccess_ResultAuditRecorded is finding #3: a public
// transfer that completes cleanly used to leave only a "start" audit row.
// This checks a second, result audit row now appears, scoped to the
// management authority (§14.6), with no FailClosed and no revocation.
func TestDeliver_PublicSuccess_ResultAuditRecorded(t *testing.T) {
	fx := seedPublicFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)))
	capture := &auditScopeCapture{}
	wrapped := &scopeCapturingStore{inner: fx.store, capture: capture}
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{outcome: port.TransferOutcome{Completed: true, BytesWritten: 5, FinishedAt: distTestNow()}}
	svc := newDistributionService(t, distDeps(t, wrapped, wrapped, okEncoder("unused"), gate))

	if _, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	scopes := capture.all()
	if len(scopes) < 2 {
		t.Fatalf("expected at least 2 audit rows (start + result) for a successful public transfer, got %d", len(scopes))
	}
	assertAllScopesAreManagementAuthority(t, capture, fx.managementAuthorityID, fx.issuerID)
	if gate.callCount() != 0 {
		t.Fatalf("a public success audit must never FailClosed, got %d", gate.callCount())
	}
	if n := countRevocations(t, fx.store, fx.issuerID, distSerial(t, "a2")); n != 0 {
		t.Fatalf("a public success must never revoke, got %d", n)
	}
}

// TestDeliver_PublicSuccess_ResultAuditFails_LogsOnly checks the failure mode
// of the new result audit: if the post-process transaction that writes it
// cannot commit, Deliver still reports the transfer as completed, never
// FailCloses, never revokes, and records exactly one OperationalLogger event
// -- the same non-escalating treatment the existing public-failure audit
// path gets.
func TestDeliver_PublicSuccess_ResultAuditFails_LogsOnly(t *testing.T) {
	fx := seedPublicFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)))
	staged := newStagedUoW(fx.store)
	// Stage 1 is the consuming commit; stage 2 is the new success-audit
	// post-process write this fix adds.
	staged.forceUnknownAt[2] = true
	logger := &fakeOperationalLogger{}
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{outcome: port.TransferOutcome{Completed: true, BytesWritten: 5, FinishedAt: distTestNow()}}
	deps := withOperationalLogger(distDeps(t, staged, fx.store, okEncoder("unused"), gate), logger)
	svc := newDistributionService(t, deps)

	summary, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err != nil {
		t.Fatalf("a public post-process audit failure must not fail Deliver itself, got %v", err)
	}
	if !summary.Completed {
		t.Fatal("expected the transfer to still report completed")
	}
	if gate.callCount() != 0 {
		t.Fatalf("a public success audit failure must never FailClosed, got %d", gate.callCount())
	}
	if n := countRevocations(t, fx.store, fx.issuerID, distSerial(t, "a2")); n != 0 {
		t.Fatalf("a public success audit failure must never revoke, got %d", n)
	}
	events := logger.recorded()
	if len(events) != 1 {
		t.Fatalf("OperationalLogger.Record calls = %d, want 1", len(events))
	}
}
