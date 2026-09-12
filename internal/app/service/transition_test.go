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

// ---- fixture plumbing --------------------------------------------------

// transitionCA names the three ids a seeded CA's fixtures need to hand
// forward: its own authority row, its signing certificate and its CA key
// generation.
type transitionCA struct {
	authorityID domain.AuthorityID
	certID      domain.CertificateID
	keyGenID    domain.CAKeyGenerationID
}

func mustID[T ~string](t *testing.T, ids port.IDGenerator, parse func(string) (T, error)) T {
	t.Helper()
	v, err := parse(ids.NewUUID())
	if err != nil {
		t.Fatalf("mint id: %v", err)
	}
	return v
}

// seedTransitionRoot inserts a fully issuable, self-signed Root -- the same
// shape as authority_test.go's seedRootKeyGeneration/seedIssuableRoot, but
// returning the certificate and key generation ids too, since revokeUnderParent
// walks the stored CA certificate chain and this file's fixtures need to
// wire an Intermediate's issuer link to a REAL Root row (unlike
// issuance_test.go's seedIssuableIntermediate, whose ManagementParentID
// points at an authority id that is never actually inserted -- fine for
// issuance tests, which never walk the chain, but not for this file's
// parent-revocation tests).
func seedTransitionRoot(t *testing.T, store *porttest.Store, ids port.IDGenerator, now domain.Instant) transitionCA {
	t.Helper()
	ctx := context.Background()

	authorityID := mustID(t, ids, domain.ParseAuthorityID)
	keyGenID := mustID(t, ids, domain.ParseCAKeyGenerationID)
	keyMaterialID := mustID(t, ids, domain.ParseKeyMaterialID)
	certID := mustID(t, ids, domain.ParseCertificateID)

	pub, err := domain.NewPublicKey(domain.KeyAlgorithmECDSAP256, []byte("root-pub-"+string(keyGenID)))
	if err != nil {
		t.Fatalf("root public key: %v", err)
	}
	window, err := domain.NewValidityWindow(now.Add(domain.NewDuration(-time.Hour)), now.Add(domain.NewDuration(24*365*10*time.Hour)))
	if err != nil {
		t.Fatalf("root window: %v", err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "Transition Test Root"})
	if err != nil {
		t.Fatalf("root subject: %v", err)
	}
	cert, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      certID,
		DER:                     []byte("root-der-" + string(certID)),
		KeyMaterialID:           keyMaterialID,
		IssuerCAKeyGenerationID: keyGenID, // self-signed
		Serial:                  serial(t, "aa01"),
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
	authority, err := domain.NewAuthority(domain.AuthorityFacts{
		ID:                    authorityID,
		Kind:                  domain.AuthorityKindRoot,
		Name:                  "Transition Test Root",
		IssuanceState:         domain.IssuanceStateEnabled,
		IssuanceCertificateID: certID,
		KeyGenerationID:       keyGenID,
		KeyAvailable:          true,
		CertificateWindow:     window,
	})
	if err != nil {
		t.Fatalf("root authority: %v", err)
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
		t.Fatalf("seed transition root: %v", err)
	}
	seedCRLState(t, store, keyGenID)
	return transitionCA{authorityID: authorityID, certID: certID, keyGenID: keyGenID}
}

// seedTransitionIntermediate inserts an Intermediate whose own certificate is
// genuinely signed under root (IssuerCAKeyGenerationID = root.keyGenID on the
// certificate row, and the CA certificate record's IssuerCACertificateID
// points at root.certID), so buildChainDER-style walks and
// revokeUnderParent's own chain walk resolve to the real parent.
func seedTransitionIntermediate(t *testing.T, store *porttest.Store, ids port.IDGenerator, root transitionCA, now domain.Instant, serialHex string, enabled bool) transitionCA {
	t.Helper()
	ctx := context.Background()

	authorityID := mustID(t, ids, domain.ParseAuthorityID)
	keyGenID := mustID(t, ids, domain.ParseCAKeyGenerationID)
	keyMaterialID := mustID(t, ids, domain.ParseKeyMaterialID)
	certID := mustID(t, ids, domain.ParseCertificateID)

	pub, err := domain.NewPublicKey(domain.KeyAlgorithmECDSAP256, []byte("intermediate-pub-"+string(keyGenID)))
	if err != nil {
		t.Fatalf("intermediate public key: %v", err)
	}
	window, err := domain.NewValidityWindow(now.Add(domain.NewDuration(-time.Hour)), now.Add(domain.NewDuration(24*365*5*time.Hour)))
	if err != nil {
		t.Fatalf("intermediate window: %v", err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "Transition Test Intermediate " + serialHex})
	if err != nil {
		t.Fatalf("intermediate subject: %v", err)
	}
	cert, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      certID,
		DER:                     []byte("intermediate-der-" + string(certID)),
		KeyMaterialID:           keyMaterialID,
		IssuerCAKeyGenerationID: root.keyGenID, // signed BY the root
		Serial:                  serial(t, serialHex),
		Validity:                window,
		Subject:                 subject,
		Kind:                    domain.CertificateKindCA,
		KeyAlgorithm:            domain.KeyAlgorithmECDSAP256,
		Origin:                  domain.CertificateOriginGenerated,
	})
	if err != nil {
		t.Fatalf("intermediate certificate: %v", err)
	}
	secret, err := domain.NewEncryptedSecret(domain.EncryptedSecretFacts{
		OwnerKeyID:             keyMaterialID,
		Purpose:                domain.SecretPurposeCASigning,
		FormatVersion:          1,
		EncryptionGenerationID: "gen-1",
		Nonce:                  []byte("intermediate-nonce12345"),
		Ciphertext:             []byte("intermediate-ct-" + string(keyGenID)),
	})
	if err != nil {
		t.Fatalf("intermediate secret: %v", err)
	}
	state := domain.IssuanceStateStopped
	if enabled {
		state = domain.IssuanceStateEnabled
	}
	authority, err := domain.NewAuthority(domain.AuthorityFacts{
		ID:                    authorityID,
		Kind:                  domain.AuthorityKindIntermediate,
		Name:                  "Transition Test Intermediate " + serialHex,
		ManagementParentID:    root.authorityID,
		IssuanceState:         state,
		IssuanceCertificateID: certID,
		KeyGenerationID:       keyGenID,
		KeyAvailable:          true,
		CertificateWindow:     window,
	})
	if err != nil {
		t.Fatalf("intermediate authority: %v", err)
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
		if err := tx.PKI().InsertCACertificateRecord(ctx, port.CACertificateRecord{
			CertificateID: certID, CAKeyGenerationID: keyGenID, IssuerCACertificateID: root.certID,
		}); err != nil {
			return err
		}
		if err := tx.Secrets().InsertEncrypted(ctx, secret); err != nil {
			return err
		}
		return tx.PKI().InsertAuthority(ctx, authority)
	}); err != nil {
		t.Fatalf("seed transition intermediate: %v", err)
	}
	seedCRLState(t, store, keyGenID)
	return transitionCA{authorityID: authorityID, certID: certID, keyGenID: keyGenID}
}

// seedTransitionLeaf inserts one leaf certificate managed by
// managementAuthorityID and (nominally) issued under issuerCAKeyGenID/
// issuerCACertID, the minimum QueryRepository.ListCertificates and
// leafManagementAuthority need to see it.
func seedTransitionLeaf(t *testing.T, store *porttest.Store, ids port.IDGenerator, managementAuthorityID domain.AuthorityID, issuerCAKeyGenID domain.CAKeyGenerationID, issuerCACertID domain.CertificateID, now domain.Instant, serialHex string) domain.CertificateID {
	t.Helper()
	window, err := domain.NewValidityWindow(now.Add(domain.NewDuration(-time.Hour)), now.Add(domain.NewDuration(24*90*time.Hour)))
	if err != nil {
		t.Fatalf("leaf window: %v", err)
	}
	return seedTransitionLeafWithWindow(t, store, ids, managementAuthorityID, issuerCAKeyGenID, issuerCACertID, window, serialHex)
}

// seedTransitionLeafWithWindow is seedTransitionLeaf with an explicit
// validity window, so a test can seed a certificate that is ALREADY expired
// at the fixture's "now" -- Complete's "already expired" branch of
// AllImpactsAddressed (gatherClosureFacts in transition.go) needs exactly
// this to exercise the expired-not-resolved path, which
// seedTransitionLeaf's always-in-the-future window cannot produce.
func seedTransitionLeafWithWindow(t *testing.T, store *porttest.Store, ids port.IDGenerator, managementAuthorityID domain.AuthorityID, issuerCAKeyGenID domain.CAKeyGenerationID, issuerCACertID domain.CertificateID, window domain.ValidityWindow, serialHex string) domain.CertificateID {
	t.Helper()
	ctx := context.Background()

	certID := mustID(t, ids, domain.ParseCertificateID)
	seriesID := mustID(t, ids, domain.ParseSeriesID)
	keyMaterialID := mustID(t, ids, domain.ParseKeyMaterialID)

	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "leaf-" + serialHex + ".example.test"})
	if err != nil {
		t.Fatalf("leaf subject: %v", err)
	}
	san, err := domain.NewSAN(domain.SANTypeDNS, "leaf-"+serialHex+".example.test")
	if err != nil {
		t.Fatalf("leaf san: %v", err)
	}
	cert, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      certID,
		DER:                     []byte("leaf-der-" + serialHex),
		KeyMaterialID:           keyMaterialID,
		IssuerCAKeyGenerationID: issuerCAKeyGenID,
		Serial:                  serial(t, serialHex),
		Validity:                window,
		Subject:                 subject,
		SANs:                    []domain.SAN{san},
		Kind:                    domain.CertificateKindLeaf,
		Profile:                 domain.CertificateProfileServerTLS,
		KeyAlgorithm:            domain.KeyAlgorithmECDSAP256,
		Origin:                  domain.CertificateOriginGenerated,
	})
	if err != nil {
		t.Fatalf("leaf certificate: %v", err)
	}
	validity, err := domain.NewCalendarValidity(1, domain.ValidityUnitYears)
	if err != nil {
		t.Fatalf("calendar validity: %v", err)
	}
	series, err := domain.NewLeafSeries(domain.LeafSeriesFacts{
		ID:                    seriesID,
		Name:                  "leaf-" + serialHex,
		Purpose:               domain.SeriesPurposeDistributed,
		ManagementAuthorityID: managementAuthorityID,
		Policy:                domain.SeriesPolicy{RotateEvery: 3, CertificateValidity: validity},
	})
	if err != nil {
		t.Fatalf("leaf series: %v", err)
	}

	if err := store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.PKI().InsertSeries(ctx, series); err != nil {
			return err
		}
		if err := tx.PKI().InsertCertificate(ctx, cert); err != nil {
			return err
		}
		return tx.PKI().InsertLeafCertificateRecord(ctx, port.LeafCertificateRecord{
			CertificateID: certID, SeriesID: seriesID, IssuerCACertificateID: issuerCACertID,
			Operation: port.CertificateOperationInitial,
		})
	}); err != nil {
		t.Fatalf("seed transition leaf: %v", err)
	}
	return certID
}

type transitionFixture struct {
	store      *porttest.Store
	ids        *seqIDs
	authorizer *toggleAuthorizer
	clock      *movableClock
	svc        *TransitionService
}

func newTransitionFixture(t *testing.T) *transitionFixture {
	t.Helper()
	store := porttest.NewStore()
	seedAdminSessionForIssuance(t, store)
	ids := &seqIDs{}
	authorizer := &toggleAuthorizer{allow: true}
	clock := &movableClock{now: testNow()}

	svc, err := NewTransitionService(TransitionDeps{CommonDeps: CommonDeps{
		UnitOfWork: store,
		ReadStore:  store,
		Authorizer: authorizer,
		Clock:      clock,
		IDs:        ids,
	}})
	if err != nil {
		t.Fatalf("new transition service: %v", err)
	}
	return &transitionFixture{store: store, ids: ids, authorizer: authorizer, clock: clock, svc: svc}
}

func createCommand(source, target domain.AuthorityID, mode domain.TransitionMode) contract.TransitionCreateCommand {
	return contract.TransitionCreateCommand{
		SourceAuthorityID: source,
		TargetAuthorityID: target,
		Mode:              contract.TransitionModeInput(mode),
		Reason:            "test transition",
	}
}

func transitionMeta() contract.MutationMeta {
	return contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: mustAdminPrincipal()}}
}

func transitionVersionMeta(version domain.Version) contract.MutationMeta {
	return contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: mustAdminPrincipal()}, ExpectedVersion: contract.WithExpectedVersion(version)}
}

// ---- read-side test helpers --------------------------------------------

func authorityIssuanceState(t *testing.T, store *porttest.Store, id domain.AuthorityID) domain.IssuanceState {
	t.Helper()
	var st domain.IssuanceState
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		a, err := tx.PKI().GetIssuerForUpdate(context.Background(), id)
		if err != nil {
			return err
		}
		st = a.IssuanceState()
		return nil
	})
	if err != nil {
		t.Fatalf("read authority %s: %v", id, err)
	}
	return st
}

func readTransitionImpacts(t *testing.T, store *porttest.Store, id domain.TransitionID) []domain.TransitionImpact {
	t.Helper()
	var out []domain.TransitionImpact
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		out, err = tx.Transitions().ListImpacts(context.Background(), id)
		return err
	})
	if err != nil {
		t.Fatalf("list impacts: %v", err)
	}
	return out
}

func assertNoRevocation(t *testing.T, store *porttest.Store, issuer domain.CAKeyGenerationID, s domain.SerialNumber) {
	t.Helper()
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		_, err := tx.Revocations().FindForUpdate(context.Background(), issuer, s)
		return err
	})
	if !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("expected no revocation for issuer=%s serial=%s, got err=%v", issuer, s.Hex(), err)
	}
}

// ---- Create: normal mode ------------------------------------------------

func TestTransitionServiceCreateNormalStopsSourceOnlyAndRecordsNoImpactsOrRevocation(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	intermediate := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b001", true)
	leafSerial := "c001"
	leafCertID := seedTransitionLeaf(t, f.store, f.ids, intermediate.authorityID, intermediate.keyGenID, intermediate.certID, testNow(), leafSerial)

	view, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(intermediate.authorityID, "", domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if view.Mode != domain.TransitionModeNormal {
		t.Fatalf("mode = %s, want normal", view.Mode)
	}
	if view.State != contract.TransitionStateViewInProgress {
		t.Fatalf("state = %s, want in_progress", view.State)
	}
	if view.TargetAuthorityID != nil {
		t.Fatalf("target = %v, want nil (none given)", view.TargetAuthorityID)
	}

	if got := authorityIssuanceState(t, f.store, intermediate.authorityID); got != domain.IssuanceStateStopped {
		t.Fatalf("source issuance state = %s, want stopped", got)
	}
	if impacts := readTransitionImpacts(t, f.store, view.ID); len(impacts) != 0 {
		t.Fatalf("normal transition recorded %d impacts, want 0 (certificate-lifecycle.md: 정상 교체는 즉시 폐기하지 않는다, no impact-list language)", len(impacts))
	}
	assertNoRevocation(t, f.store, intermediate.keyGenID, serial(t, leafSerial))
	_ = leafCertID
}

// ---- Create: emergency mode, Root source (U11) --------------------------

// TestTransitionServiceCreateEmergencyRootBlocksDescendantsAndRecordsImpactsWithoutRevocation
// is U11's core claim for a Root-source report: new issuance is blocked for
// the source AND its managed descendant (backend-implementation.md §8
// "긴급 전환" row, data-model.md's ListAffectedDescendants doc comment), the
// descendant's leaves are recorded as impacted, and NONE of that produces an
// automatic individual revocation for those leaves (planning.md "상위 영향이
// 자동 개별 폐기로 표시되지 않는다").
func TestTransitionServiceCreateEmergencyRootBlocksDescendantsAndRecordsImpactsWithoutRevocation(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	intermediate := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b101", true)
	leaf1Serial, leaf2Serial := "c101", "c102"
	leaf1 := seedTransitionLeaf(t, f.store, f.ids, intermediate.authorityID, intermediate.keyGenID, intermediate.certID, testNow(), leaf1Serial)
	leaf2 := seedTransitionLeaf(t, f.store, f.ids, intermediate.authorityID, intermediate.keyGenID, intermediate.certID, testNow(), leaf2Serial)

	view, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(root.authorityID, "", domain.TransitionModeEmergency))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if view.Mode != domain.TransitionModeEmergency {
		t.Fatalf("mode = %s, want emergency", view.Mode)
	}

	// 새 발급 차단: both the reported Root and its managed Intermediate.
	if got := authorityIssuanceState(t, f.store, root.authorityID); got != domain.IssuanceStateStopped {
		t.Fatalf("root issuance state = %s, want stopped", got)
	}
	if got := authorityIssuanceState(t, f.store, intermediate.authorityID); got != domain.IssuanceStateStopped {
		t.Fatalf("descendant intermediate issuance state = %s, want stopped", got)
	}

	impacts := readTransitionImpacts(t, f.store, view.ID)
	impacted := map[domain.CertificateID]bool{}
	for _, imp := range impacts {
		impacted[imp.CertificateID()] = true
		if imp.IsResolved() {
			t.Fatalf("impact for %s already resolved, want unresolved (freshly reported)", imp.CertificateID())
		}
	}
	if !impacted[leaf1] || !impacted[leaf2] {
		t.Fatalf("impacts = %v, want both %s and %s recorded", impacts, leaf1, leaf2)
	}

	// 상위 영향이 자동 개별 폐기로 표시되지 않음: neither leaf gets a
	// revocation from this report.
	assertNoRevocation(t, f.store, intermediate.keyGenID, serial(t, leaf1Serial))
	assertNoRevocation(t, f.store, intermediate.keyGenID, serial(t, leaf2Serial))
	// Root has no parent, so there is nothing to revoke under either.
}

// ---- Create: emergency mode, Intermediate source (U11 parent revoke) ----

// TestTransitionServiceCreateEmergencyIntermediateRevokesUnderParentWithoutLeafRevocation
// covers the other half of §5's "Intermediate라면 부모 폐기": the compromised
// Intermediate's OWN certificate is revoked under the CA that actually
// signed it (certificate-lifecycle.md "Intermediate 유출은 부모에서
// caCompromise 사유로 폐기한다"), while its leaves only get impact rows, not
// revocations.
func TestTransitionServiceCreateEmergencyIntermediateRevokesUnderParentWithoutLeafRevocation(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	intermediate := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b201", true)
	leafSerial := "c201"
	leaf := seedTransitionLeaf(t, f.store, f.ids, intermediate.authorityID, intermediate.keyGenID, intermediate.certID, testNow(), leafSerial)

	view, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(intermediate.authorityID, "", domain.TransitionModeEmergency))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if got := authorityIssuanceState(t, f.store, intermediate.authorityID); got != domain.IssuanceStateStopped {
		t.Fatalf("intermediate issuance state = %s, want stopped", got)
	}

	// The intermediate's own certificate is revoked under the ROOT's ledger.
	var rev domain.Revocation
	err = f.store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		rev, err = tx.Revocations().FindForUpdate(context.Background(), root.keyGenID, serial(t, "b201"))
		return err
	})
	if err != nil {
		t.Fatalf("expected the intermediate's own certificate to be revoked under the parent: %v", err)
	}
	if rev.Reason() != domain.RevocationReasonCACompromise {
		t.Fatalf("reason = %s, want ca_compromise", rev.Reason())
	}
	if rev.Source() != domain.RevocationSourceCascade {
		t.Fatalf("source = %s, want cascade", rev.Source())
	}
	if rev.CertificateID() != intermediate.certID {
		t.Fatalf("certificate_id = %s, want %s", rev.CertificateID(), intermediate.certID)
	}

	// The CRL job demand landed on the PARENT's (root's) dedup key, since
	// that is the ledger the revocation was filed under.
	if job, ok := crlDemand(t, f.store, root.keyGenID); !ok {
		t.Fatal("expected a CRL demand recorded for the root's key generation")
	} else if requiredGeneration(t, job) != 1 {
		t.Fatalf("required generation = %d, want 1", requiredGeneration(t, job))
	}

	// The leaf under the compromised intermediate is only impacted, never
	// individually revoked.
	impacts := readTransitionImpacts(t, f.store, view.ID)
	found := false
	for _, imp := range impacts {
		if imp.CertificateID() == leaf {
			found = true
		}
	}
	if !found {
		t.Fatalf("impacts = %v, want %s recorded", impacts, leaf)
	}
	assertNoRevocation(t, f.store, intermediate.keyGenID, serial(t, leafSerial))
}

func TestTransitionServiceCreateRequiresAdmin(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: contract.AnonymousPrincipal()}}
	_, err := f.svc.Create(context.Background(), meta, createCommand(root.authorityID, "", domain.TransitionModeNormal))
	if err == nil {
		t.Fatal("want an error for a non-admin Create")
	}
}

func TestTransitionServiceCreateRejectsUnknownSource(t *testing.T) {
	f := newTransitionFixture(t)
	unknown, err := domain.ParseAuthorityID("00000000-0000-4000-8000-000000000000")
	if err != nil {
		t.Fatalf("authority id: %v", err)
	}
	_, err = f.svc.Create(context.Background(), transitionMeta(), createCommand(unknown, "", domain.TransitionModeNormal))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Code() != "transition_source_not_found" {
		t.Fatalf("code = %q, want transition_source_not_found", appErr.Code())
	}
}

// ---- SetTarget -----------------------------------------------------------

func TestTransitionServiceSetTargetAdoptsSuccessor(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b301", true)
	successor := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b302", false)

	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, "", domain.TransitionModeEmergency))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	cmd := contract.TransitionSetTargetCommand{TransitionID: created.ID, TargetAuthorityID: successor.authorityID}
	view, err := f.svc.SetTarget(context.Background(), transitionVersionMeta(created.Version), cmd)
	if err != nil {
		t.Fatalf("SetTarget: %v", err)
	}
	if view.TargetAuthorityID == nil || *view.TargetAuthorityID != successor.authorityID {
		t.Fatalf("target = %v, want %s", view.TargetAuthorityID, successor.authorityID)
	}
	if view.Version != created.Version+1 {
		t.Fatalf("version = %d, want %d", view.Version, created.Version+1)
	}
}

func TestTransitionServiceSetTargetRejectsVersionConflict(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b311", true)
	successor := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b312", false)
	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, "", domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	cmd := contract.TransitionSetTargetCommand{TransitionID: created.ID, TargetAuthorityID: successor.authorityID}
	_, err = f.svc.SetTarget(context.Background(), transitionVersionMeta(created.Version+99), cmd)
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Kind() != contract.ErrorKindConflict {
		t.Fatalf("kind = %v, want conflict", appErr.Kind())
	}
	// Kind alone does not pin the app-layer version check: the store's own
	// ErrVersionConflict from a rejected Save maps to the same conflict
	// kind, so pin the app-layer code too.
	if appErr.Code() != "transition_version_conflict" {
		t.Fatalf("code = %q, want transition_version_conflict", appErr.Code())
	}
}

func TestTransitionServiceSetTargetRejectsUnknownTarget(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b321", true)
	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, "", domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	unknown, err := domain.ParseAuthorityID("00000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatalf("authority id: %v", err)
	}
	cmd := contract.TransitionSetTargetCommand{TransitionID: created.ID, TargetAuthorityID: unknown}
	_, err = f.svc.SetTarget(context.Background(), transitionVersionMeta(created.Version), cmd)
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Code() != "transition_target_not_found" {
		t.Fatalf("code = %q, want transition_target_not_found", appErr.Code())
	}
}

// ---- ConfirmDeployment ----------------------------------------------------

func TestTransitionServiceConfirmDeploymentRecordsConfirmation(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b331", true)
	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, "", domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	cmd := contract.TransitionConfirmDeploymentCommand{
		TransitionID: created.ID,
		TargetLabel:  "edge-lb-01",
		Action:       contract.DeploymentActionInputCertificateInstalled,
	}
	view, err := f.svc.ConfirmDeployment(context.Background(), transitionVersionMeta(created.Version), cmd)
	if err != nil {
		t.Fatalf("ConfirmDeployment: %v", err)
	}
	if view.TargetLabel != "edge-lb-01" {
		t.Fatalf("target_label = %q, want edge-lb-01", view.TargetLabel)
	}
	if view.Action != contract.DeploymentActionInputCertificateInstalled {
		t.Fatalf("action = %q, want certificate_installed", view.Action)
	}
	if view.ID == "" {
		t.Fatal("want a non-empty display id")
	}

	confirmations := f.store.DeploymentConfirmations()
	if len(confirmations) != 1 {
		t.Fatalf("stored confirmations = %d, want 1", len(confirmations))
	}
	if confirmations[0].TransitionID() != created.ID {
		t.Fatalf("confirmation transition id = %s, want %s", confirmations[0].TransitionID(), created.ID)
	}

	// ConfirmDeployment validates but does not itself change the transition
	// row (domain.Transition.ConfirmDeployment returns only an error, no new
	// value) -- so the transition's own version must be unchanged.
	err = f.store.Read(context.Background(), func(tx port.TxStores) error {
		reread, err := tx.Transitions().GetForUpdate(context.Background(), created.ID)
		if err != nil {
			return err
		}
		if reread.Version() != created.Version {
			t.Fatalf("transition version changed to %d, want unchanged %d", reread.Version(), created.Version)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("re-read transition: %v", err)
	}
}

func TestTransitionServiceConfirmDeploymentRejectsVersionConflict(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b341", true)
	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, "", domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cmd := contract.TransitionConfirmDeploymentCommand{
		TransitionID: created.ID, TargetLabel: "edge-lb-01", Action: contract.DeploymentActionInputTrustAdded,
	}
	_, err = f.svc.ConfirmDeployment(context.Background(), transitionVersionMeta(created.Version+1), cmd)
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Kind() != contract.ErrorKindConflict {
		t.Fatalf("kind = %v, want conflict", appErr.Kind())
	}
	if appErr.Code() != "transition_version_conflict" {
		t.Fatalf("code = %q, want transition_version_conflict", appErr.Code())
	}
}

// ---- §8 auth re-check: requireCurrentAuth wiring, per admin method -------
//
// Wave 1's fault-injection finding (both prior developers' PRs rejected for
// this exact gap): removing requireCurrentAuth entirely from a service left
// every prior test green. Each admin-mutating method here (Create,
// SetTarget, ConfirmDeployment) gets both of requireCurrentAuth's two
// distinct failure sources: an idle-expired session and a superseded auth
// epoch. These reuse settings_service_test.go's shared §8 helpers
// (bumpAccountAuthEpoch/touchAdminSession/requireAuthError) rather than
// re-implementing them.

func TestTransitionServiceCreateRejectsIdleExpiredSession(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	touchAdminSession(t, f.store, testNow())
	f.clock.now = testNow().Add(domain.NewDuration(time.Hour + time.Second))
	_, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(root.authorityID, "", domain.TransitionModeNormal))
	requireAuthError(t, err, "session_idle_expired")
}

func TestTransitionServiceCreateRejectsAuthEpochSuperseded(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	bumpAccountAuthEpoch(t, f.store)
	_, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(root.authorityID, "", domain.TransitionModeNormal))
	requireAuthError(t, err, "auth_epoch_superseded")
}

func TestTransitionServiceSetTargetRejectsIdleExpiredSession(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b351", true)
	successor := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b352", false)
	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, "", domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	touchAdminSession(t, f.store, testNow())
	f.clock.now = testNow().Add(domain.NewDuration(time.Hour + time.Second))
	cmd := contract.TransitionSetTargetCommand{TransitionID: created.ID, TargetAuthorityID: successor.authorityID}
	_, err = f.svc.SetTarget(context.Background(), transitionVersionMeta(created.Version), cmd)
	requireAuthError(t, err, "session_idle_expired")
}

func TestTransitionServiceSetTargetRejectsAuthEpochSuperseded(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b361", true)
	successor := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b362", false)
	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, "", domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	bumpAccountAuthEpoch(t, f.store)
	cmd := contract.TransitionSetTargetCommand{TransitionID: created.ID, TargetAuthorityID: successor.authorityID}
	_, err = f.svc.SetTarget(context.Background(), transitionVersionMeta(created.Version), cmd)
	requireAuthError(t, err, "auth_epoch_superseded")
}

func TestTransitionServiceConfirmDeploymentRejectsIdleExpiredSession(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b371", true)
	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, "", domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	touchAdminSession(t, f.store, testNow())
	f.clock.now = testNow().Add(domain.NewDuration(time.Hour + time.Second))
	cmd := contract.TransitionConfirmDeploymentCommand{TransitionID: created.ID, TargetLabel: "x", Action: contract.DeploymentActionInputTrustAdded}
	_, err = f.svc.ConfirmDeployment(context.Background(), transitionVersionMeta(created.Version), cmd)
	requireAuthError(t, err, "session_idle_expired")
}

func TestTransitionServiceConfirmDeploymentRejectsAuthEpochSuperseded(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b381", true)
	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, "", domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	bumpAccountAuthEpoch(t, f.store)
	cmd := contract.TransitionConfirmDeploymentCommand{TransitionID: created.ID, TargetLabel: "x", Action: contract.DeploymentActionInputTrustAdded}
	_, err = f.svc.ConfirmDeployment(context.Background(), transitionVersionMeta(created.Version), cmd)
	requireAuthError(t, err, "auth_epoch_superseded")
}

// ---- Complete / Close test plumbing --------------------------------------

// addImpact directly inserts an unresolved TransitionImpact row, bypassing
// Create's own impact-gathering (which only runs for emergency mode) so a
// test can put a specific certificate under test into a transition's impact
// ledger regardless of which mode created it.
func addImpact(t *testing.T, store *porttest.Store, transitionID domain.TransitionID, certID domain.CertificateID) {
	t.Helper()
	impact, err := domain.NewTransitionImpact(domain.TransitionImpactFacts{TransitionID: transitionID, CertificateID: certID})
	if err != nil {
		t.Fatalf("new impact: %v", err)
	}
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Transitions().AddImpact(context.Background(), impact)
	}); err != nil {
		t.Fatalf("add impact: %v", err)
	}
}

// closeCRLState drives domain.CRLState.Close directly against the store, the
// stored fact TestTransitionServiceCloseSucceeds... needs Close (transition.go)
// to observe via CRLState.PublicationState.
func closeCRLState(t *testing.T, store *porttest.Store, keyGenID domain.CAKeyGenerationID) {
	t.Helper()
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		state, err := tx.CRLs().GetStateForUpdate(context.Background(), keyGenID)
		if err != nil {
			return err
		}
		closed, err := state.Close(domain.CRLClosureFacts{AllCoveredCertificatesExpired: true, FinalCRLCoversLastExpiry: true})
		if err != nil {
			return err
		}
		return tx.CRLs().SaveState(context.Background(), closed, state.Version())
	}); err != nil {
		t.Fatalf("close crl state: %v", err)
	}
}

func closeCommand(transitionID domain.TransitionID) TransitionCloseCommand {
	return TransitionCloseCommand{TransitionID: transitionID}
}

func appError(t *testing.T, err error) *contract.AppError {
	t.Helper()
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	return appErr
}

// ---- Complete --------------------------------------------------------------

func TestTransitionServiceCompleteRejectsUnresolvedNonExpiredImpact(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b401", true)
	target := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b402", false)
	leaf := seedTransitionLeaf(t, f.store, f.ids, source.authorityID, source.keyGenID, source.certID, testNow(), "c401")

	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, target.authorityID, domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	addImpact(t, f.store, created.ID, leaf)
	confirmCmd := contract.TransitionConfirmDeploymentCommand{TransitionID: created.ID, TargetLabel: "x", Action: contract.DeploymentActionInputCertificateInstalled}
	if _, err := f.svc.ConfirmDeployment(context.Background(), transitionVersionMeta(created.Version), confirmCmd); err != nil {
		t.Fatalf("ConfirmDeployment: %v", err)
	}

	_, err = f.svc.Complete(context.Background(), transitionVersionMeta(created.Version), contract.TransitionCompleteCommand{TransitionID: created.ID})
	appErr := appError(t, err)
	if appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("kind = %v, want forbidden", appErr.Kind())
	}
	if appErr.Code() != "transition_impacts_pending" {
		t.Fatalf("code = %q, want transition_impacts_pending", appErr.Code())
	}
}

// TestTransitionServiceCompleteTreatsExpiredImpactAsAddressed exercises
// gatherClosureFacts' "already expired" branch: an unresolved impact whose
// certificate has passed its own not_after does not block Complete
// (domain.TransitionClosureFacts' doc comment names exactly this case).
func TestTransitionServiceCompleteTreatsExpiredImpactAsAddressed(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b411", true)
	target := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b412", false)
	expiredWindow, err := domain.NewValidityWindow(
		testNow().Add(domain.NewDuration(-48*time.Hour)),
		testNow().Add(domain.NewDuration(-time.Hour)),
	)
	if err != nil {
		t.Fatalf("expired window: %v", err)
	}
	leaf := seedTransitionLeafWithWindow(t, f.store, f.ids, source.authorityID, source.keyGenID, source.certID, expiredWindow, "c411")

	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, target.authorityID, domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	addImpact(t, f.store, created.ID, leaf)
	confirmCmd := contract.TransitionConfirmDeploymentCommand{TransitionID: created.ID, TargetLabel: "x", Action: contract.DeploymentActionInputCertificateInstalled}
	if _, err := f.svc.ConfirmDeployment(context.Background(), transitionVersionMeta(created.Version), confirmCmd); err != nil {
		t.Fatalf("ConfirmDeployment: %v", err)
	}

	view, err := f.svc.Complete(context.Background(), transitionVersionMeta(created.Version), contract.TransitionCompleteCommand{TransitionID: created.ID})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if view.State != contract.TransitionStateViewExternallyCompleted {
		t.Fatalf("state = %s, want externally_completed", view.State)
	}
}

func TestTransitionServiceCompleteRejectsUnconfirmedDeployment(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b421", true)
	target := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b422", false)
	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, target.authorityID, domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = f.svc.Complete(context.Background(), transitionVersionMeta(created.Version), contract.TransitionCompleteCommand{TransitionID: created.ID})
	appErr := appError(t, err)
	if appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("kind = %v, want forbidden", appErr.Kind())
	}
	if appErr.Code() != "transition_deployment_unconfirmed" {
		t.Fatalf("code = %q, want transition_deployment_unconfirmed", appErr.Code())
	}
}

func TestTransitionServiceCompleteSucceedsWhenImpactsAddressedAndDeploymentConfirmed(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b431", true)
	target := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b432", false)
	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, target.authorityID, domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	confirmCmd := contract.TransitionConfirmDeploymentCommand{TransitionID: created.ID, TargetLabel: "edge-01", Action: contract.DeploymentActionInputCertificateInstalled}
	if _, err := f.svc.ConfirmDeployment(context.Background(), transitionVersionMeta(created.Version), confirmCmd); err != nil {
		t.Fatalf("ConfirmDeployment: %v", err)
	}

	view, err := f.svc.Complete(context.Background(), transitionVersionMeta(created.Version), contract.TransitionCompleteCommand{TransitionID: created.ID})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if view.State != contract.TransitionStateViewExternallyCompleted {
		t.Fatalf("state = %s, want externally_completed", view.State)
	}
	if !view.ExternalTransitionComplete {
		t.Fatal("want ExternalTransitionComplete = true")
	}
	if view.CAPublicationClosed {
		t.Fatal("want CAPublicationClosed = false (Complete alone must never imply closed, §13 ruling 1)")
	}
	if view.Version != created.Version+1 {
		t.Fatalf("version = %d, want %d", view.Version, created.Version+1)
	}
}

func TestTransitionServiceCompleteRejectsVersionConflict(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b441", true)
	target := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b442", false)
	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, target.authorityID, domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	confirmCmd := contract.TransitionConfirmDeploymentCommand{TransitionID: created.ID, TargetLabel: "edge-01", Action: contract.DeploymentActionInputCertificateInstalled}
	if _, err := f.svc.ConfirmDeployment(context.Background(), transitionVersionMeta(created.Version), confirmCmd); err != nil {
		t.Fatalf("ConfirmDeployment: %v", err)
	}

	_, err = f.svc.Complete(context.Background(), transitionVersionMeta(created.Version+1), contract.TransitionCompleteCommand{TransitionID: created.ID})
	appErr := appError(t, err)
	if appErr.Kind() != contract.ErrorKindConflict {
		t.Fatalf("kind = %v, want conflict", appErr.Kind())
	}
	if appErr.Code() != "transition_version_conflict" {
		t.Fatalf("code = %q, want transition_version_conflict", appErr.Code())
	}
}

func TestTransitionServiceCompleteRejectsIdleExpiredSession(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b451", true)
	target := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b452", false)
	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, target.authorityID, domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	confirmCmd := contract.TransitionConfirmDeploymentCommand{TransitionID: created.ID, TargetLabel: "edge-01", Action: contract.DeploymentActionInputCertificateInstalled}
	if _, err := f.svc.ConfirmDeployment(context.Background(), transitionVersionMeta(created.Version), confirmCmd); err != nil {
		t.Fatalf("ConfirmDeployment: %v", err)
	}

	touchAdminSession(t, f.store, testNow())
	f.clock.now = testNow().Add(domain.NewDuration(time.Hour + time.Second))
	_, err = f.svc.Complete(context.Background(), transitionVersionMeta(created.Version), contract.TransitionCompleteCommand{TransitionID: created.ID})
	requireAuthError(t, err, "session_idle_expired")
}

func TestTransitionServiceCompleteRejectsAuthEpochSuperseded(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b461", true)
	target := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b462", false)
	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, target.authorityID, domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	confirmCmd := contract.TransitionConfirmDeploymentCommand{TransitionID: created.ID, TargetLabel: "edge-01", Action: contract.DeploymentActionInputCertificateInstalled}
	if _, err := f.svc.ConfirmDeployment(context.Background(), transitionVersionMeta(created.Version), confirmCmd); err != nil {
		t.Fatalf("ConfirmDeployment: %v", err)
	}

	bumpAccountAuthEpoch(t, f.store)
	_, err = f.svc.Complete(context.Background(), transitionVersionMeta(created.Version), contract.TransitionCompleteCommand{TransitionID: created.ID})
	requireAuthError(t, err, "auth_epoch_superseded")
}

// ---- Close ------------------------------------------------------------------

func completeTransitionForClose(t *testing.T, f *transitionFixture, source, target transitionCA, serialHex string) contract.TransitionView {
	t.Helper()
	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, target.authorityID, domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	confirmCmd := contract.TransitionConfirmDeploymentCommand{TransitionID: created.ID, TargetLabel: "edge-" + serialHex, Action: contract.DeploymentActionInputCertificateInstalled}
	if _, err := f.svc.ConfirmDeployment(context.Background(), transitionVersionMeta(created.Version), confirmCmd); err != nil {
		t.Fatalf("ConfirmDeployment: %v", err)
	}
	view, err := f.svc.Complete(context.Background(), transitionVersionMeta(created.Version), contract.TransitionCompleteCommand{TransitionID: created.ID})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	return view
}

func TestTransitionServiceCloseRejectsBeforeExternallyCompleted(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b501", true)
	created, err := f.svc.Create(context.Background(), transitionMeta(), createCommand(source.authorityID, "", domain.TransitionModeNormal))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = f.svc.Close(context.Background(), transitionVersionMeta(created.Version), closeCommand(created.ID))
	appErr := appError(t, err)
	if appErr.Code() != "transition_not_externally_completed" {
		t.Fatalf("code = %q, want transition_not_externally_completed", appErr.Code())
	}
}

func TestTransitionServiceCloseRejectsWhenSourcePublicationNotEnded(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b511", true)
	target := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b512", false)
	completed := completeTransitionForClose(t, f, source, target, "b511")

	_, err := f.svc.Close(context.Background(), transitionVersionMeta(completed.Version), closeCommand(completed.ID))
	appErr := appError(t, err)
	if appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("kind = %v, want forbidden", appErr.Kind())
	}
	if appErr.Code() != "transition_publication_not_ended" {
		t.Fatalf("code = %q, want transition_publication_not_ended", appErr.Code())
	}
}

func TestTransitionServiceCloseSucceedsWhenSourcePublicationEnded(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b521", true)
	target := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b522", false)
	completed := completeTransitionForClose(t, f, source, target, "b521")

	closeCRLState(t, f.store, source.keyGenID)

	view, err := f.svc.Close(context.Background(), transitionVersionMeta(completed.Version), closeCommand(completed.ID))
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if view.State != contract.TransitionStateViewClosed {
		t.Fatalf("state = %s, want closed", view.State)
	}
	if !view.CAPublicationClosed {
		t.Fatal("want CAPublicationClosed = true")
	}
}

func TestTransitionServiceCloseRejectsVersionConflict(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b531", true)
	target := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b532", false)
	completed := completeTransitionForClose(t, f, source, target, "b531")
	closeCRLState(t, f.store, source.keyGenID)

	_, err := f.svc.Close(context.Background(), transitionVersionMeta(completed.Version+1), closeCommand(completed.ID))
	appErr := appError(t, err)
	if appErr.Kind() != contract.ErrorKindConflict {
		t.Fatalf("kind = %v, want conflict", appErr.Kind())
	}
	if appErr.Code() != "transition_version_conflict" {
		t.Fatalf("code = %q, want transition_version_conflict", appErr.Code())
	}
}

func TestTransitionServiceCloseRejectsIdleExpiredSession(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b541", true)
	target := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b542", false)
	completed := completeTransitionForClose(t, f, source, target, "b541")
	closeCRLState(t, f.store, source.keyGenID)

	touchAdminSession(t, f.store, testNow())
	f.clock.now = testNow().Add(domain.NewDuration(time.Hour + time.Second))
	_, err := f.svc.Close(context.Background(), transitionVersionMeta(completed.Version), closeCommand(completed.ID))
	requireAuthError(t, err, "session_idle_expired")
}

func TestTransitionServiceCloseRejectsAuthEpochSuperseded(t *testing.T) {
	f := newTransitionFixture(t)
	root := seedTransitionRoot(t, f.store, f.ids, testNow())
	source := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b551", true)
	target := seedTransitionIntermediate(t, f.store, f.ids, root, testNow(), "b552", false)
	completed := completeTransitionForClose(t, f, source, target, "b551")
	closeCRLState(t, f.store, source.keyGenID)

	bumpAccountAuthEpoch(t, f.store)
	_, err := f.svc.Close(context.Background(), transitionVersionMeta(completed.Version), closeCommand(completed.ID))
	requireAuthError(t, err, "auth_epoch_superseded")
}
