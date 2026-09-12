package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

// ---- shared test doubles --------------------------------------------------

// recordedAuthCall is one Authorizer.Authorize invocation a
// recordingAuthorizer captured.
type recordedAuthCall struct {
	action port.Action
	scope  port.AuthorizationScope
}

// recordingAuthorizer is a port.Authorizer double that remembers every
// (action, scope) pair it was asked to decide, so a test can assert which
// Action a method actually used -- the §13 ruling 5 property that List and
// Get on the same noun must use two DISTINCT actions is only checkable if
// something records what was actually called, not just whether the call
// eventually succeeded.
type recordingAuthorizer struct {
	calls []recordedAuthCall
	deny  map[port.Action]bool
}

func (a *recordingAuthorizer) Authorize(_ context.Context, _ contract.Principal, action port.Action, scope port.AuthorizationScope) error {
	a.calls = append(a.calls, recordedAuthCall{action: action, scope: scope})
	if a.deny != nil && a.deny[action] {
		return contract.NewAppError(contract.ErrorKindForbidden, "denied_for_test", "denied by recordingAuthorizer")
	}
	return nil
}

func (a *recordingAuthorizer) lastAction() port.Action {
	if len(a.calls) == 0 {
		return ""
	}
	return a.calls[len(a.calls)-1].action
}

// ---- fixture ---------------------------------------------------------------

// queryFixture is one seeded store plus a QueryService wired against it,
// shared by every test in this file.
type queryFixture struct {
	store      *porttest.Store
	ids        *seqIDs
	authorizer *recordingAuthorizer
	clock      *movableClock
	svc        *QueryService

	authorityID   domain.AuthorityID
	caCertID      domain.CertificateID
	caKeyGenID    domain.CAKeyGenerationID
	seriesID      domain.SeriesID
	leafCertID    domain.CertificateID
	revocationID  domain.RevocationID
	transitionID  domain.TransitionID
	importBatchID domain.ImportBatchID
	jobID         domain.JobID
	now           domain.Instant
}

func newQueryFixture(t *testing.T) *queryFixture {
	t.Helper()
	store := porttest.NewStore()
	seedAdminSessionForIssuance(t, store)
	ids := &seqIDs{}
	now := testNow()

	ca := seedTransitionRoot(t, store, ids, now)
	leafCertID, seriesID := seedQuerySeries(t, store, ids, ca.authorityID, ca.keyGenID, ca.certID, now)
	revocationID := seedQueryRevocation(t, store, ids, ca.keyGenID, leafCertID, now)
	transitionID := seedQueryTransition(t, store, ids, ca.authorityID, leafCertID, now)
	importBatchID := seedQueryImportBatch(t, store, ids, now)
	jobID := seedQueryJob(t, store, ids)

	authorizer := &recordingAuthorizer{}
	clock := &movableClock{now: now}
	svc, err := NewQueryService(CommonDeps{
		UnitOfWork: store,
		ReadStore:  store,
		Authorizer: authorizer,
		Clock:      clock,
		IDs:        ids,
	})
	if err != nil {
		t.Fatalf("new query service: %v", err)
	}

	return &queryFixture{
		store: store, ids: ids, authorizer: authorizer, clock: clock, svc: svc,
		authorityID: ca.authorityID, caCertID: ca.certID, caKeyGenID: ca.keyGenID,
		seriesID: seriesID, leafCertID: leafCertID,
		revocationID: revocationID, transitionID: transitionID,
		importBatchID: importBatchID, jobID: jobID, now: now,
	}
}

func (f *queryFixture) meta() contract.RequestMeta {
	return contract.RequestMeta{Principal: mustAdminPrincipal()}
}

// seedQuerySeries inserts one leaf series and its current certificate, and
// reports both ids directly -- unlike transition_test.go's
// seedTransitionLeaf, which mints its own seriesID internally and never
// returns it, so a GetSeries test would have no id to ask for.
func seedQuerySeries(t *testing.T, store *porttest.Store, ids port.IDGenerator, managementAuthorityID domain.AuthorityID, issuerCAKeyGenID domain.CAKeyGenerationID, issuerCACertID domain.CertificateID, now domain.Instant) (domain.CertificateID, domain.SeriesID) {
	t.Helper()
	ctx := context.Background()

	certID := mustID(t, ids, domain.ParseCertificateID)
	seriesID := mustID(t, ids, domain.ParseSeriesID)
	keyMaterialID := mustID(t, ids, domain.ParseKeyMaterialID)

	window, err := domain.NewValidityWindow(now.Add(domain.NewDuration(-time.Hour)), now.Add(domain.NewDuration(24*90*time.Hour)))
	if err != nil {
		t.Fatalf("leaf window: %v", err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "query-leaf.example.test"})
	if err != nil {
		t.Fatalf("leaf subject: %v", err)
	}
	san, err := domain.NewSAN(domain.SANTypeDNS, "query-leaf.example.test")
	if err != nil {
		t.Fatalf("leaf san: %v", err)
	}
	cert, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      certID,
		DER:                     []byte("query-leaf-der"),
		KeyMaterialID:           keyMaterialID,
		IssuerCAKeyGenerationID: issuerCAKeyGenID,
		Serial:                  serial(t, "b001"),
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
		Name:                  "query-leaf-series",
		Purpose:               domain.SeriesPurposeDistributed,
		ManagementAuthorityID: managementAuthorityID,
		CurrentCertificateID:  certID,
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
		t.Fatalf("seed query series: %v", err)
	}
	return certID, seriesID
}

// seedQueryRevocation inserts one revocation ledger row directly (not
// through RevocationService), with ChangeGeneration 1 -- since
// seedTransitionRoot's fresh CRLState publishes nothing (PublishedGeneration
// 0), this revocation is CRLPending by construction until a test explicitly
// publishes past it.
func seedQueryRevocation(t *testing.T, store *porttest.Store, ids port.IDGenerator, issuer domain.CAKeyGenerationID, certificateID domain.CertificateID, now domain.Instant) domain.RevocationID {
	t.Helper()
	id := mustID(t, ids, domain.ParseRevocationID)
	rev, err := domain.NewRevocation(domain.RevocationFacts{
		ID:               id,
		IssuerID:         issuer,
		Serial:           serial(t, "b001"),
		CertificateID:    certificateID,
		RevokedAt:        now,
		Reason:           domain.RevocationReasonUnspecified,
		Source:           domain.RevocationSourceManual,
		ChangeGeneration: 1,
	})
	if err != nil {
		t.Fatalf("revocation: %v", err)
	}
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Revocations().Insert(context.Background(), rev)
	}); err != nil {
		t.Fatalf("seed query revocation: %v", err)
	}
	return id
}

// seedQueryTransition inserts one in-progress transition plus a single
// impact naming leafCertID, directly through TransitionRepository rather
// than TransitionService.Create -- QueryService only ever reads these rows,
// so the write-side orchestration is not this file's concern.
func seedQueryTransition(t *testing.T, store *porttest.Store, ids port.IDGenerator, sourceAuthorityID domain.AuthorityID, leafCertID domain.CertificateID, now domain.Instant) domain.TransitionID {
	t.Helper()
	id := mustID(t, ids, domain.ParseTransitionID)
	transition, err := domain.NewTransition(domain.TransitionFacts{
		ID:                id,
		SourceAuthorityID: sourceAuthorityID,
		Mode:              domain.TransitionModeNormal,
		State:             domain.TransitionStateInProgress,
		ReportedBy:        issuanceTestAdminAccountID,
		ReportedAt:        now,
		Reason:            "scheduled rotation",
	})
	if err != nil {
		t.Fatalf("transition: %v", err)
	}
	impact, err := domain.NewTransitionImpact(domain.TransitionImpactFacts{
		TransitionID:  id,
		CertificateID: leafCertID,
	})
	if err != nil {
		t.Fatalf("transition impact: %v", err)
	}
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		if err := tx.Transitions().Insert(context.Background(), transition); err != nil {
			return err
		}
		return tx.Transitions().AddImpact(context.Background(), impact)
	}); err != nil {
		t.Fatalf("seed query transition: %v", err)
	}
	return id
}

// seedQueryImportBatch inserts one committed import batch directly.
func seedQueryImportBatch(t *testing.T, store *porttest.Store, ids port.IDGenerator, now domain.Instant) domain.ImportBatchID {
	t.Helper()
	id, err := domain.ParseImportBatchID(ids.NewUUID())
	if err != nil {
		t.Fatalf("import batch id: %v", err)
	}
	manifest, err := contract.NewPublicImportManifest([]contract.ImportManifestFileFacts{
		{FileID: "cert.pem", Kind: contract.ImportFileKindCertificate, SHA256: domain.NewFingerprint([]byte("cert.pem"))},
	})
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	result := contract.ImportResultView{
		ID:             string(id),
		State:          contract.ImportResultStateCommitted,
		CommittedAt:    &now,
		Items:          []contract.ImportItemView{{FileID: "cert.pem", Status: contract.ImportItemStatusNew}},
		CertificateIDs: nil,
		AuthorityIDs:   nil,
	}
	batch := port.ImportBatch{
		ID:          id,
		CreatedAt:   now,
		RequestedBy: issuanceTestAdminAccountID,
		Manifest:    manifest,
		State:       port.ImportBatchStateCommitted,
		CommittedAt: now,
		Result:      result,
	}
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Imports().InsertBatch(context.Background(), batch)
	}); err != nil {
		t.Fatalf("seed query import batch: %v", err)
	}
	return id
}

// seedQueryJob merges one pending job demand under a fixed dedup key.
func seedQueryJob(t *testing.T, store *porttest.Store, ids port.IDGenerator) domain.JobID {
	t.Helper()
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Jobs().UpsertDemand(context.Background(), "query-test-job", "query_test", 1, []byte(`{}`))
	}); err != nil {
		t.Fatalf("seed query job: %v", err)
	}
	var jobID domain.JobID
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		job, err := tx.Jobs().GetByDedupKey(context.Background(), "query-test-job")
		if err != nil {
			return err
		}
		jobID = job.ID
		return nil
	}); err != nil {
		t.Fatalf("read seeded job: %v", err)
	}
	return jobID
}

// publishCRLDocument locks issuer's CRLState, reserves and publishes one
// document covering coveredGeneration, with the given this/next update
// window -- letting a test control Expired/Pending precisely without
// depending on CRLService's own orchestration.
func publishCRLDocument(t *testing.T, store *porttest.Store, ids port.IDGenerator, issuer domain.CAKeyGenerationID, coveredGeneration int64, thisUpdate, nextUpdate, nextPublishAt domain.Instant) {
	t.Helper()
	docID, err := domain.ParseCRLDocumentID(ids.NewUUID())
	if err != nil {
		t.Fatalf("crl document id: %v", err)
	}
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		state, err := tx.CRLs().GetStateForUpdate(context.Background(), issuer)
		if err != nil {
			return err
		}
		// expectedVersion for SaveState below is the version actually
		// stored, captured before ReserveNext/MarkPublished each bump it in
		// memory (the same "preserve the first-read version" rule
		// applyRevocations documents in revocations.go).
		expectedVersion := state.Version()
		number, state := state.ReserveNext()
		der := []byte("crl-der-" + number.Hex())
		if err := tx.CRLs().InsertDocument(context.Background(), port.CRLDocument{
			ID:                docID,
			CAKeyGenerationID: issuer,
			NumberHex:         number,
			DERSHA256:         domain.NewFingerprint(der),
			DER:               der,
			ThisUpdate:        thisUpdate,
			NextUpdate:        nextUpdate,
			CoveredGeneration: coveredGeneration,
			Origin:            "generated",
		}); err != nil {
			return err
		}
		published, err := state.MarkPublished(docID, number, coveredGeneration, nextPublishAt)
		if err != nil {
			return err
		}
		return tx.CRLs().SaveState(context.Background(), published, expectedVersion)
	}); err != nil {
		t.Fatalf("publish crl document: %v", err)
	}
}

// auditEvent builds a minimal, valid port.AuditEvent for id/action.
func auditEvent(id, action string, at domain.Instant) port.AuditEvent {
	return port.AuditEvent{
		ID:         id,
		OccurredAt: at,
		ActorKind:  contract.AuditActorAccount,
		ActorID:    string(issuanceTestAdminAccountID),
		Action:     action,
		TargetType: "test",
		Result:     contract.AuditResultSuccess,
		Details:    contract.AuditDetails{SchemaVersion: 1},
	}
}

// ---- action-per-method wiring ---------------------------------------------

// queryMethodCase names one QueryService method to exercise, for the two
// table-driven tests below: it must succeed against queryFixture's seeded
// data under a live admin session, and it must record exactly one
// authorizer call under wantAction.
type queryMethodCase struct {
	name       string
	wantAction port.Action
	call       func(f *queryFixture) error
}

func queryMethodCases(f *queryFixture) []queryMethodCase {
	ctx := context.Background()
	return []queryMethodCase{
		{"ListAuthorities", port.ActionQueryListAuthority, func(f *queryFixture) error {
			_, err := f.svc.ListAuthorities(ctx, f.meta(), contract.AuthorityListQuery{})
			return err
		}},
		{"GetAuthority", port.ActionQueryGetAuthority, func(f *queryFixture) error {
			_, err := f.svc.GetAuthority(ctx, f.meta(), contract.AuthorityGetQuery{AuthorityID: f.authorityID})
			return err
		}},
		{"ListSeries", port.ActionQueryListSeries, func(f *queryFixture) error {
			_, err := f.svc.ListSeries(ctx, f.meta(), contract.SeriesListQuery{})
			return err
		}},
		{"GetSeries", port.ActionQueryGetSeries, func(f *queryFixture) error {
			_, err := f.svc.GetSeries(ctx, f.meta(), contract.SeriesGetQuery{SeriesID: f.seriesID})
			return err
		}},
		{"ListCertificates", port.ActionQueryListCertificate, func(f *queryFixture) error {
			_, err := f.svc.ListCertificates(ctx, f.meta(), contract.CertificateListQuery{})
			return err
		}},
		{"GetCertificate", port.ActionQueryGetCertificate, func(f *queryFixture) error {
			_, err := f.svc.GetCertificate(ctx, f.meta(), contract.CertificateGetQuery{CertificateID: f.leafCertID})
			return err
		}},
		{"ListRevocations", port.ActionQueryListRevocation, func(f *queryFixture) error {
			_, err := f.svc.ListRevocations(ctx, f.meta(), contract.RevocationListQuery{})
			return err
		}},
		{"GetRevocation", port.ActionQueryGetRevocation, func(f *queryFixture) error {
			_, err := f.svc.GetRevocation(ctx, f.meta(), contract.RevocationGetQuery{RevocationID: f.revocationID})
			return err
		}},
		{"ListTransitions", port.ActionQueryListTransition, func(f *queryFixture) error {
			_, err := f.svc.ListTransitions(ctx, f.meta(), contract.TransitionListQuery{})
			return err
		}},
		{"GetTransition", port.ActionQueryGetTransition, func(f *queryFixture) error {
			_, err := f.svc.GetTransition(ctx, f.meta(), contract.TransitionGetQuery{TransitionID: f.transitionID})
			return err
		}},
		{"ListImports", port.ActionQueryListImport, func(f *queryFixture) error {
			_, err := f.svc.ListImports(ctx, f.meta(), contract.ImportListQuery{})
			return err
		}},
		{"GetImport", port.ActionQueryGetImport, func(f *queryFixture) error {
			_, err := f.svc.GetImport(ctx, f.meta(), contract.ImportGetQuery{ImportID: string(f.importBatchID)})
			return err
		}},
		{"ListJobs", port.ActionQueryListJob, func(f *queryFixture) error {
			_, err := f.svc.ListJobs(ctx, f.meta(), contract.JobListQuery{})
			return err
		}},
		{"GetJob", port.ActionQueryGetJob, func(f *queryFixture) error {
			_, err := f.svc.GetJob(ctx, f.meta(), contract.JobGetQuery{JobID: f.jobID})
			return err
		}},
		{"ListAudit", port.ActionQueryListAudit, func(f *queryFixture) error {
			_, err := f.svc.ListAudit(ctx, f.meta(), contract.AuditListQuery{})
			return err
		}},
		{"ExportAudit", port.ActionQueryExportAudit, func(f *queryFixture) error {
			return f.svc.ExportAudit(ctx, f.meta(), contract.AuditExportQuery{Format: contract.AuditExportFormatJSON}, func(it contract.AuditEventIterator) error {
				for it.Next(ctx.Done()) {
				}
				return it.Err()
			})
		}},
		{"GetCRLStatus", port.ActionQueryGetCRLStatus, func(f *queryFixture) error {
			_, err := f.svc.GetCRLStatus(ctx, f.meta(), contract.GetCRLStatusQuery{CAKeyGenerationID: f.caKeyGenID})
			return err
		}},
		{"ReadPublicCA", port.ActionQueryReadPublicCA, func(f *queryFixture) error {
			_, err := f.svc.ReadPublicCA(ctx, f.meta(), contract.ReadPublicCAQuery{AuthorityID: f.authorityID})
			return err
		}},
	}
}

// TestQueryServiceMethodsSucceedAndUseTheirOwnAction is the §13 ruling 5
// regression: every method must succeed against the seeded fixture (proving
// the wiring through port.QueryRepository actually works end to end) and
// must authorize under EXACTLY the Action port/services.go declares for it
// -- so a List and a Get on the same noun can never collapse onto one
// shared Action.
func TestQueryServiceMethodsSucceedAndUseTheirOwnAction(t *testing.T) {
	f := newQueryFixture(t)
	seenActions := map[port.Action]string{}
	for _, tc := range queryMethodCases(f) {
		t.Run(tc.name, func(t *testing.T) {
			f.authorizer.calls = nil
			if err := tc.call(f); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if len(f.authorizer.calls) == 0 {
				t.Fatalf("%s: Authorizer.Authorize was never called", tc.name)
			}
			if got := f.authorizer.lastAction(); got != tc.wantAction {
				t.Fatalf("%s: action = %q, want %q", tc.name, got, tc.wantAction)
			}
			if other, ok := seenActions[tc.wantAction]; ok && other != tc.name {
				t.Fatalf("%s and %s share action %q -- ruling 5 requires a distinct Action per method", tc.name, other, tc.wantAction)
			}
			seenActions[tc.wantAction] = tc.name
		})
	}
	if len(seenActions) != 18 {
		t.Fatalf("want 18 distinct actions across the query surface, got %d", len(seenActions))
	}
}

// ---- requireCurrentAuth re-check, every method -----------------------------

// TestQueryServiceRequireCurrentAuthEveryMethod is the table-driven
// regression the brief calls for: it proves every one of the 18 methods
// re-validates the session inside its own transaction, not just at
// dispatch. Without requireCurrentAuth, a session revoked (epoch bump),
// disabled (account state) or expired (idle timeout) AFTER the request
// began would still succeed, since meta.Principal itself carries none of
// that live state -- it is exactly the defect authtime_test.go/
// settings_service_test.go already pin for the write side.
func TestQueryServiceRequireCurrentAuthEveryMethod(t *testing.T) {
	scenarios := []struct {
		name    string
		break_  func(t *testing.T, f *queryFixture)
		wantErr string
	}{
		{"AuthEpochSuperseded", func(t *testing.T, f *queryFixture) { bumpAccountAuthEpoch(t, f.store) }, "auth_epoch_superseded"},
		{"AccountDisabled", func(t *testing.T, f *queryFixture) { disableAccount(t, f.store) }, ""},
		{"SessionIdleExpired", func(t *testing.T, f *queryFixture) {
			touchAdminSession(t, f.store, f.now.Add(domain.NewDuration(-2*time.Hour)))
		}, ""},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			f := newQueryFixture(t)
			scenario.break_(t, f)
			for _, tc := range queryMethodCases(f) {
				t.Run(tc.name, func(t *testing.T) {
					err := tc.call(f)
					var appErr *contract.AppError
					if !errors.As(err, &appErr) {
						t.Fatalf("%s/%s: err = %v, want an AppError", scenario.name, tc.name, err)
					}
					if appErr.Kind() != contract.ErrorKindAuth {
						t.Fatalf("%s/%s: kind = %s, want auth", scenario.name, tc.name, appErr.Kind())
					}
					if scenario.wantErr != "" && appErr.Code() != scenario.wantErr {
						t.Fatalf("%s/%s: code = %q, want %q", scenario.name, tc.name, appErr.Code(), scenario.wantErr)
					}
				})
			}
		})
	}
}

// ---- paging round trip ------------------------------------------------------

// TestQueryServiceListAuthoritiesPagingRoundTrip walks ListAuthorities one
// row at a time and checks that every seeded authority is seen exactly
// once -- no duplicate, no gap -- proving the service round-trips the
// store's own cursor rather than reconstructing or reinterpreting it (rule
// 3: "커서는 저장소가 발급한 것을 그대로 왕복시킨다").
func TestQueryServiceListAuthoritiesPagingRoundTrip(t *testing.T) {
	f := newQueryFixture(t)
	ctx := context.Background()
	want := map[domain.AuthorityID]bool{f.authorityID: true}
	for i := 0; i < 4; i++ {
		id := mustID(t, f.ids, domain.ParseAuthorityID)
		a, err := domain.NewAuthority(domain.AuthorityFacts{
			ID: id, Kind: domain.AuthorityKindRoot, Name: fmt.Sprintf("extra-%d", i),
			IssuanceState: domain.IssuanceStateEnabled, KeyGenerationID: f.caKeyGenID, KeyAvailable: true,
		})
		if err != nil {
			t.Fatalf("extra authority: %v", err)
		}
		if err := f.store.Write(ctx, func(tx port.TxStores) error { return tx.PKI().InsertAuthority(ctx, a) }); err != nil {
			t.Fatalf("insert extra authority: %v", err)
		}
		want[id] = true
	}

	seen := map[domain.AuthorityID]int{}
	cursor := ""
	for step := 0; step < len(want)+2; step++ {
		page, err := f.svc.ListAuthorities(ctx, f.meta(), contract.AuthorityListQuery{Page: contract.PageRequest{Limit: 1, Cursor: cursor}})
		if err != nil {
			t.Fatalf("ListAuthorities: %v", err)
		}
		for _, a := range page.Items {
			seen[a.ID]++
		}
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}
	if len(seen) != len(want) {
		t.Fatalf("saw %d distinct authorities across pages, want %d", len(seen), len(want))
	}
	for id, count := range seen {
		if count != 1 {
			t.Fatalf("authority %s seen %d times, want exactly 1 (duplicate or overlapping page)", id, count)
		}
		if !want[id] {
			t.Fatalf("saw unexpected authority %s", id)
		}
	}
	for id := range want {
		if seen[id] != 1 {
			t.Fatalf("authority %s missing from the paged walk", id)
		}
	}
}

// ---- not-found passthrough --------------------------------------------------

func TestQueryServiceGetUnknownIDIsNotFound(t *testing.T) {
	f := newQueryFixture(t)
	ctx := context.Background()
	unknown := mustID(t, f.ids, domain.ParseAuthorityID)
	_, err := f.svc.GetAuthority(ctx, f.meta(), contract.AuthorityGetQuery{AuthorityID: unknown})
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Code() != "not_found" {
		t.Fatalf("code = %q, want %q (api-contract.md's 404 mapping)", appErr.Code(), "not_found")
	}
}

// ---- ReadPublicCA is the one anonymous-reachable method --------------------

func TestQueryServiceReadPublicCAAllowsAnonymousAndAdmin(t *testing.T) {
	f := newQueryFixture(t)
	ctx := context.Background()
	query := contract.ReadPublicCAQuery{AuthorityID: f.authorityID}

	cert, err := f.svc.ReadPublicCA(ctx, contract.RequestMeta{Principal: contract.AnonymousPrincipal()}, query)
	if err != nil {
		t.Fatalf("ReadPublicCA (anonymous): %v", err)
	}
	if cert.ID() != f.caCertID {
		t.Fatalf("anonymous ReadPublicCA returned %s, want %s", cert.ID(), f.caCertID)
	}

	cert, err = f.svc.ReadPublicCA(ctx, f.meta(), query)
	if err != nil {
		t.Fatalf("ReadPublicCA (admin): %v", err)
	}
	if cert.ID() != f.caCertID {
		t.Fatalf("admin ReadPublicCA returned %s, want %s", cert.ID(), f.caCertID)
	}
}

// TestQueryServiceOtherMethodsRejectAnonymous is the flip side: every method
// but ReadPublicCA requires an admin session (§2 "MVP Authorization은 전체
// 관리자만 허용한다").
func TestQueryServiceOtherMethodsRejectAnonymous(t *testing.T) {
	f := newQueryFixture(t)
	anon := contract.RequestMeta{Principal: contract.AnonymousPrincipal()}
	_, err := f.svc.ListAuthorities(context.Background(), anon, contract.AuthorityListQuery{})
	if err == nil {
		t.Fatal("want an error for anonymous ListAuthorities")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("err = %v, want a forbidden AppError", err)
	}
}

// ---- U14: multi-scope audit access, service layer --------------------------

// TestQueryServiceAuditVisibleToAdminAcrossEveryScopeShape proves the
// service layer's plumbing does not narrow (or, under the "always All"
// defect, widen past) what the store's own contract test already pins
// (porttest's TestQueryAuditRequiresEveryScope): a global admin's
// QueryScope resolves to All, so every stored scope shape -- single,
// multi-authority, and empty -- must come back unfiltered. Combined with
// TestPublicCAScopeSelection below (which fails under the "force All:true"
// injection for the one path that is NOT supposed to always be All), this
// is this file's coverage of that required defect.
func TestQueryServiceAuditVisibleToAdminAcrossEveryScopeShape(t *testing.T) {
	f := newQueryFixture(t)
	ctx := context.Background()
	otherAuthority := mustID(t, f.ids, domain.ParseAuthorityID)

	if err := f.store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.Audit().Append(ctx, auditEvent("evt-single", "Test.Single", f.now), []domain.AuthorityID{f.authorityID}); err != nil {
			return err
		}
		if err := tx.Audit().Append(ctx, auditEvent("evt-multi", "Test.Multi", f.now), []domain.AuthorityID{f.authorityID, otherAuthority}); err != nil {
			return err
		}
		return tx.Audit().Append(ctx, auditEvent("evt-none", "Test.None", f.now), nil)
	}); err != nil {
		t.Fatalf("seed audit events: %v", err)
	}

	page, err := f.svc.ListAudit(ctx, f.meta(), contract.AuditListQuery{Page: contract.PageRequest{Limit: 50}})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	got := map[string]bool{}
	for _, e := range page.Items {
		got[e.ID] = true
	}
	for _, id := range []string{"evt-single", "evt-multi", "evt-none"} {
		if !got[id] {
			t.Fatalf("admin ListAudit did not see %s (want All-scope to bypass the multi-scope restriction)", id)
		}
	}
}

// TestQueryServiceExportAuditUsesSameFilterAsList pins §3's "감사 export는
// QueryService가 같은 권한 필터를 적용한 iterator를 반환": List and Export
// given the identical AuditFilter must yield the identical event set.
func TestQueryServiceExportAuditUsesSameFilterAsList(t *testing.T) {
	f := newQueryFixture(t)
	ctx := context.Background()
	if err := f.store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.Audit().Append(ctx, auditEvent("evt-a", "Test.A", f.now), []domain.AuthorityID{f.authorityID}); err != nil {
			return err
		}
		return tx.Audit().Append(ctx, auditEvent("evt-b", "Test.B", f.now), []domain.AuthorityID{f.authorityID})
	}); err != nil {
		t.Fatalf("seed audit events: %v", err)
	}
	filter := contract.AuditFilter{Action: "Test.A"}

	page, err := f.svc.ListAudit(ctx, f.meta(), contract.AuditListQuery{Filter: filter, Page: contract.PageRequest{Limit: 50}})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	var listIDs []string
	for _, e := range page.Items {
		listIDs = append(listIDs, e.ID)
	}

	var exportIDs []string
	err = f.svc.ExportAudit(ctx, f.meta(), contract.AuditExportQuery{Filter: filter, Format: contract.AuditExportFormatJSON}, func(it contract.AuditEventIterator) error {
		for it.Next(ctx.Done()) {
			exportIDs = append(exportIDs, it.Event().ID)
		}
		return it.Err()
	})
	if err != nil {
		t.Fatalf("ExportAudit: %v", err)
	}

	sort.Strings(listIDs)
	sort.Strings(exportIDs)
	if len(listIDs) != 1 || listIDs[0] != "evt-a" {
		t.Fatalf("ListAudit with filter = %v, want [evt-a]", listIDs)
	}
	if fmt.Sprint(listIDs) != fmt.Sprint(exportIDs) {
		t.Fatalf("ExportAudit = %v, want the same set List returned: %v", exportIDs, listIDs)
	}
}

// ---- CRLPending / Expired flow through the store ----------------------------

// TestQueryServiceRevocationCRLPendingFlipsAfterPublish exercises CRLPending
// end to end: a freshly seeded revocation (ChangeGeneration 1 against a
// CRLState whose PublishedGeneration starts at 0) is pending, and publishing
// a document that covers generation 1 clears it -- on both List and Get.
func TestQueryServiceRevocationCRLPendingFlipsAfterPublish(t *testing.T) {
	f := newQueryFixture(t)
	ctx := context.Background()

	get := func() contract.RevocationView {
		t.Helper()
		v, err := f.svc.GetRevocation(ctx, f.meta(), contract.RevocationGetQuery{RevocationID: f.revocationID})
		if err != nil {
			t.Fatalf("GetRevocation: %v", err)
		}
		return v
	}
	list := func() contract.RevocationView {
		t.Helper()
		page, err := f.svc.ListRevocations(ctx, f.meta(), contract.RevocationListQuery{})
		if err != nil {
			t.Fatalf("ListRevocations: %v", err)
		}
		for _, r := range page.Items {
			if r.ID == f.revocationID {
				return r
			}
		}
		t.Fatalf("seeded revocation %s not found in ListRevocations", f.revocationID)
		return contract.RevocationView{}
	}

	if !get().CRLPending {
		t.Fatal("want CRLPending=true before any CRL has been published")
	}
	if !list().CRLPending {
		t.Fatal("want CRLPending=true (list) before any CRL has been published")
	}

	publishCRLDocument(t, f.store, f.ids, f.caKeyGenID, 1,
		f.now, f.now.Add(domain.NewDuration(48*time.Hour)), f.now.Add(domain.NewDuration(12*time.Hour)))

	if get().CRLPending {
		t.Fatal("want CRLPending=false after a CRL covering generation 1 was published")
	}
	if list().CRLPending {
		t.Fatal("want CRLPending=false (list) after publish")
	}
}

// TestQueryServiceCRLStatusPendingAndExpired exercises GetCRLStatus's own
// derived fields end to end, including Expired computed against a clock
// read inside the Read (movableClock lets this test move it without
// touching the fixture's seeded rows).
func TestQueryServiceCRLStatusPendingAndExpired(t *testing.T) {
	f := newQueryFixture(t)
	ctx := context.Background()
	// nextUpdate is kept inside the seeded admin session's 24h absolute
	// lifetime (auth.go's SessionState.ValidateAt), so advancing the clock
	// past it below exercises CRL expiry, not session expiry.
	nextUpdate := f.now.Add(domain.NewDuration(2 * time.Hour))
	publishCRLDocument(t, f.store, f.ids, f.caKeyGenID, 0, f.now, nextUpdate, f.now.Add(domain.NewDuration(time.Hour)))

	view, err := f.svc.GetCRLStatus(ctx, f.meta(), contract.GetCRLStatusQuery{CAKeyGenerationID: f.caKeyGenID})
	if err != nil {
		t.Fatalf("GetCRLStatus: %v", err)
	}
	if view.Number == nil || view.CoveredGeneration == nil {
		t.Fatalf("want Number/CoveredGeneration set after a publish, got %+v", view)
	}
	if view.NextUpdate == nil || !view.NextUpdate.Equal(nextUpdate) {
		t.Fatalf("NextUpdate = %v, want %v", view.NextUpdate, nextUpdate)
	}
	if view.Expired {
		t.Fatal("want Expired=false while now is before next_update")
	}

	// Move the clock past next_update: the SAME published document must now
	// report Expired=true, computed fresh inside this Read -- never from a
	// value cached at publish time. The session's own idle timeout is
	// unrelated to CRL expiry, so its last_seen_at is advanced right along
	// with the clock -- otherwise requireCurrentAuth would (correctly)
	// reject a session that really has sat idle for 48+ hours, which is not
	// what this test is exercising.
	f.clock.now = nextUpdate.Add(domain.NewDuration(time.Second))
	touchAdminSession(t, f.store, f.clock.now)
	view, err = f.svc.GetCRLStatus(ctx, f.meta(), contract.GetCRLStatusQuery{CAKeyGenerationID: f.caKeyGenID})
	if err != nil {
		t.Fatalf("GetCRLStatus after advancing clock: %v", err)
	}
	if !view.Expired {
		t.Fatal("want Expired=true once now has passed next_update")
	}
}

// ---- pure mapping-function unit tests ---------------------------------------

func TestCrlPending(t *testing.T) {
	cases := []struct {
		change, published int64
		want              bool
	}{
		{1, 0, true},
		{1, 1, false},
		{0, 1, false},
		{5, 4, true},
	}
	for _, c := range cases {
		if got := crlPending(c.change, c.published); got != c.want {
			t.Fatalf("crlPending(%d,%d) = %v, want %v", c.change, c.published, got, c.want)
		}
	}
}

func TestToCertificateViewComputesExpiredAtReadTime(t *testing.T) {
	notAfter := testNow()
	window, err := domain.NewValidityWindow(notAfter.Add(domain.NewDuration(-time.Hour)), notAfter)
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "cn"})
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	cert, err := domain.NewCertificate(domain.CertificateFacts{
		ID: "11111111-1111-4111-8111-111111111111", DER: []byte("der"),
		KeyMaterialID:           "22222222-2222-4222-8222-222222222222",
		IssuerCAKeyGenerationID: "33333333-3333-4333-8333-333333333333",
		Serial:                  serial(t, "1"), Validity: window, Subject: subject,
		Kind: domain.CertificateKindCA, KeyAlgorithm: domain.KeyAlgorithmECDSAP256,
		Origin: domain.CertificateOriginGenerated,
	})
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	qc := port.QueriedCertificate{Certificate: cert}

	before := toCertificateView(qc, notAfter.Add(domain.NewDuration(-time.Second)))
	if before.Expired {
		t.Fatal("want Expired=false one second before not_after")
	}
	atOrAfter := toCertificateView(qc, notAfter)
	if !atOrAfter.Expired {
		t.Fatal("want Expired=true at exactly not_after (project rule: now >= expires_at)")
	}
}

func TestToSeriesViewMapsCurrentKeyGeneration(t *testing.T) {
	validity, err := domain.NewCalendarValidity(1, domain.ValidityUnitYears)
	if err != nil {
		t.Fatalf("validity: %v", err)
	}
	series, err := domain.NewLeafSeries(domain.LeafSeriesFacts{
		ID: "11111111-1111-4111-8111-111111111111", Name: "s", Purpose: domain.SeriesPurposeDistributed,
		ManagementAuthorityID:  "22222222-2222-4222-8222-222222222222",
		CurrentCertificateID:   "33333333-3333-4333-8333-333333333333",
		CurrentKeyGenerationID: "44444444-4444-4444-8444-444444444444",
		Policy:                 domain.SeriesPolicy{RotateEvery: 3, CertificateValidity: validity},
	})
	if err != nil {
		t.Fatalf("series: %v", err)
	}
	keyGen, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
		ID: "44444444-4444-4444-8444-444444444444", SeriesID: series.ID(),
		KeyMaterialID: "55555555-5555-4555-8555-555555555555", GenerationNo: 2,
		RenewalCount: 4, PriorHistoryUnknown: true, Custody: domain.KeyCustodyClientHeld,
	})
	if err != nil {
		t.Fatalf("key generation: %v", err)
	}

	view := toSeriesView(port.SeriesSnapshot{Series: series, CurrentKeyGeneration: keyGen})
	if view.CurrentKeyGenerationID == nil || *view.CurrentKeyGenerationID != keyGen.ID() {
		t.Fatalf("CurrentKeyGenerationID = %v, want %s", view.CurrentKeyGenerationID, keyGen.ID())
	}
	if view.RenewalCount != 4 {
		t.Fatalf("RenewalCount = %d, want 4", view.RenewalCount)
	}
	if !view.PriorHistoryUnknown {
		t.Fatal("want PriorHistoryUnknown=true")
	}
}

func TestQueryNotFoundIsValidationKindWithNotFoundCode(t *testing.T) {
	err := queryNotFound("authority", "authority not found")
	appErr, ok := contract.AsAppError(err)
	if !ok {
		t.Fatalf("queryNotFound did not return an *AppError: %v", err)
	}
	if appErr.Kind() != contract.ErrorKindValidation {
		t.Fatalf("kind = %s, want validation", appErr.Kind())
	}
	if appErr.Code() != "not_found" {
		t.Fatalf("code = %q, want %q (api-contract.md's fixed 404 code)", appErr.Code(), "not_found")
	}
}

// ---- QueryScope construction: the required "always All:true" defect -------

// TestPublicCAScopeSelection is this file's reproduction target for the
// brief's required "QueryScope를 무조건 All: true로 만드는" defect: the only
// place this service computes anything other than the blanket admin scope
// is ReadPublicCA's anonymous branch. A mutation that collapses
// publicCAScope down to "always adminScope()" changes the VALUE this
// function returns (Public flips from true to false, All from false to
// true) even though porttest's current queryRepo.ReadPublicCA fake does not
// happen to distinguish the two for this one method (both bypass its
// visibility check) -- so this test asserts on the constructed
// port.QueryScope directly rather than on a store round-trip, which is the
// only way to make the mutation observably fail without depending on a
// property of the fake that a real store need not share.
func TestPublicCAScopeSelection(t *testing.T) {
	admin := publicCAScope(mustAdminPrincipal())
	if !admin.All {
		t.Fatal("admin principal: want All=true")
	}
	if admin.Public {
		t.Fatal("admin principal: want Public=false (All already grants everything)")
	}

	anon := publicCAScope(contract.AnonymousPrincipal())
	if anon.All {
		t.Fatal("anonymous principal: want All=false -- forcing All here would be the required defect")
	}
	if !anon.Public {
		t.Fatal("anonymous principal: want Public=true")
	}
	if len(anon.AuthorityIDs) != 0 {
		t.Fatalf("anonymous principal: want no AuthorityIDs, got %v", anon.AuthorityIDs)
	}
}

func TestAdminScopeIsAll(t *testing.T) {
	scope := adminScope()
	if !scope.All {
		t.Fatal("want adminScope().All = true")
	}
	if scope.Public {
		t.Fatal("want adminScope().Public = false")
	}
}
