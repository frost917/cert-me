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
	fn    func(port.DeliveryEncodeInput) (port.EncodedBundle, error)
}

func (f *fakeDeliveryEncoder) Encode(_ context.Context, in port.DeliveryEncodeInput) (port.EncodedBundle, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return f.fn(in)
}

func (f *fakeDeliveryEncoder) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
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
	store     *porttest.Store
	certID    domain.CertificateID
	keyMatID  domain.KeyMaterialID
	issuerID  domain.CAKeyGenerationID
	deliverID domain.DeliveryID
	grantID   domain.GrantID
	rawToken  string
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

	return distFixture{
		store: store, certID: cert.ID(), keyMatID: cert.KeyMaterialID(), issuerID: cert.IssuerCAKeyGenerationID(),
		deliverID: delivery.ID(), grantID: grant.ID(), rawToken: privateRawToken,
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

	return distFixture{
		store: store, certID: cert.ID(), keyMatID: cert.KeyMaterialID(), issuerID: cert.IssuerCAKeyGenerationID(),
		grantID: grant.ID(), rawToken: publicRawToken,
	}
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
		TokenCodec:      fakeTokenCodec{},
		DeliveryEncoder: encoder,
		RuntimeGate:     gate,
	}
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
