package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

func TestIssuanceReissueRepositoryFailuresRollBackPreparedMutation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failAt   string
		wantCode string
	}{
		{name: "series pointer save", failAt: "save_series", wantCode: "issuance_series_save_failed"},
		{name: "leaf lineage insert", failAt: "insert_leaf_certificate_record", wantCode: "issuance_leaf_certificate_record_store_failed"},
		{name: "private delivery insert", failAt: "insert_delivery", wantCode: "issuance_delivery_store_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			source := issueReissueSource(t, f)
			snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
			beforeAuditEvents := len(f.store.AuditEvents())
			issuerID := sourceIssuerKeyID(t, f.store, source.CertificateID)
			seedCRLState(t, f.store, issuerID)
			f.svc.deps.UnitOfWork = reissueFailureUnitOfWork{inner: f.store, failAt: tc.failAt}

			_, err := f.svc.Reissue(context.Background(),
				reissueMeta(t, snapshot.Series.Version(), "78787878-7878-4787-8787-787878787878"),
				reissueCommandFor(source, contract.ReissueReasonManualRotation))
			assertSeriesFailure(t, err, contract.ErrorKindUnavailable, tc.wantCode)

			after := currentSeriesSnapshot(t, f.store, source.SeriesID)
			if after.Series.Version() != snapshot.Series.Version() || after.Series.CurrentCertificateID() != source.CertificateID {
				t.Fatalf("series mutation survived %s failure: version=%d current=%s", tc.name, after.Series.Version(), after.Series.CurrentCertificateID())
			}
			assertReissueSourceDeliveryPending(t, f.store, snapshot.CurrentKeyGeneration.ID())
			if got := len(f.store.AuditEvents()); got != beforeAuditEvents {
				t.Fatalf("audit event count after %s failure = %d, want unchanged %d", tc.name, got, beforeAuditEvents)
			}
			var revocationErr error
			if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
				certificate, err := tx.PKI().GetCertificate(context.Background(), source.CertificateID)
				if err != nil {
					return err
				}
				_, revocationErr = tx.Revocations().FindForUpdate(context.Background(), certificate.IssuerCAKeyGenerationID(), certificate.Serial())
				return nil
			}); err != nil {
				t.Fatalf("read source revocation after rollback: %v", err)
			}
			if !errors.Is(revocationErr, port.ErrNotFound) {
				t.Fatalf("source revocation after %s failure = %v, want no committed revocation", tc.name, revocationErr)
			}
			if state := crlState(t, f.store, issuerID); state.RevocationGeneration() != 0 {
				t.Fatalf("CRL generation after %s failure = %d, want unchanged 0", tc.name, state.RevocationGeneration())
			}
		})
	}
}

func TestIssuanceReissueCloseDeliveryFailuresRollBackCustodyAndSeries(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failAt   string
		wantCode string
	}{
		{name: "delivery read", failAt: "get_delivery", wantCode: "issuance_delivery_read_failed"},
		{name: "delivery state save", failAt: "save_delivery", wantCode: "issuance_delivery_save_failed"},
		{name: "private grant invalidation", failAt: "invalidate_grants", wantCode: "issuance_delivery_grants_invalidate_failed"},
		{name: "old key ciphertext deletion", failAt: "delete_secret", wantCode: "issuance_delivery_secret_delete_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			source := issueReissueSource(t, f)
			snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
			beforeAuditEvents := len(f.store.AuditEvents())
			issuerID := sourceIssuerKeyID(t, f.store, source.CertificateID)
			seedCRLState(t, f.store, issuerID)
			f.svc.deps.UnitOfWork = reissueFailureUnitOfWork{inner: f.store, failAt: tc.failAt}

			_, err := f.svc.Reissue(context.Background(),
				reissueMeta(t, snapshot.Series.Version(), "79797979-7979-4797-8797-797979797979"),
				reissueCommandFor(source, contract.ReissueReasonManualRotation))
			assertSeriesFailure(t, err, contract.ErrorKindUnavailable, tc.wantCode)

			after := currentSeriesSnapshot(t, f.store, source.SeriesID)
			if after.Series.Version() != snapshot.Series.Version() || after.Series.CurrentCertificateID() != source.CertificateID {
				t.Fatalf("series mutation survived %s failure: version=%d current=%s", tc.name, after.Series.Version(), after.Series.CurrentCertificateID())
			}
			assertReissueSourceDeliveryPending(t, f.store, snapshot.CurrentKeyGeneration.ID())
			if got := len(f.store.AuditEvents()); got != beforeAuditEvents {
				t.Fatalf("audit event count after %s failure = %d, want unchanged %d", tc.name, got, beforeAuditEvents)
			}
			if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
				_, err := tx.Secrets().GetEncrypted(context.Background(), snapshot.CurrentKeyGeneration.KeyMaterialID(), domain.SecretPurposeLeafDelivery)
				return err
			}); err != nil {
				t.Fatalf("old private key ciphertext after %s failure: %v", tc.name, err)
			}
		})
	}
}

func TestIssuanceReissuePreparationFailsClosedOnMissingOrUnreadableEvidence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reason   contract.ReissueReason
		plan     reissueEvidenceFailurePlan
		wantKind contract.ErrorKind
		wantCode string
	}{
		{name: "missing delivery for failed reason", reason: contract.ReissueReasonDeliveryFailed,
			plan: reissueEvidenceFailurePlan{deliveryErr: port.ErrNotFound}, wantKind: contract.ErrorKindConflict, wantCode: "reissue_delivery_missing"},
		{name: "missing pending delivery", reason: contract.ReissueReasonManualRotation,
			plan: reissueEvidenceFailurePlan{deliveryErr: port.ErrNotFound}, wantKind: contract.ErrorKindUnavailable, wantCode: "reissue_pending_delivery_missing"},
		{name: "delivery repository failure", reason: contract.ReissueReasonManualRotation,
			plan: reissueEvidenceFailurePlan{deliveryErr: errors.New("injected delivery lookup failure")}, wantKind: contract.ErrorKindUnavailable, wantCode: "issuance_delivery_read_failed"},
		{name: "delivery lineage missing", reason: contract.ReissueReasonManualRotation,
			plan: reissueEvidenceFailurePlan{leafRecordFailCall: 3, leafRecordErr: port.ErrNotFound}, wantKind: contract.ErrorKindUnavailable, wantCode: "reissue_delivery_lineage_missing"},
		{name: "delivery lineage repository failure", reason: contract.ReissueReasonManualRotation,
			plan: reissueEvidenceFailurePlan{leafRecordFailCall: 3, leafRecordErr: errors.New("injected delivery lineage lookup failure")}, wantKind: contract.ErrorKindUnavailable, wantCode: "issuance_delivery_lineage_read_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			source := issueReissueSource(t, f)
			snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
			f.svc.deps.ReadStore = &reissueEvidenceFailureReadStore{ReadStore: f.store, plan: tc.plan}
			meta := reissueMeta(t, snapshot.Series.Version(), "80808080-8080-4808-8808-808080808080")
			_, err := f.svc.Reissue(context.Background(), meta, reissueCommandFor(source, tc.reason))
			assertSeriesFailure(t, err, tc.wantKind, tc.wantCode)
			if f.keyEngine.generateCalls != 1 || f.signer.calls != 1 {
				t.Fatalf("key generations/signatures after rejected evidence = %d/%d, want only initial issuance", f.keyEngine.generateCalls, f.signer.calls)
			}
			after := currentSeriesSnapshot(t, f.store, source.SeriesID)
			if after.Series.Version() != snapshot.Series.Version() || after.Series.CurrentCertificateID() != source.CertificateID {
				t.Fatalf("series changed after %s: version=%d current=%s", tc.name, after.Series.Version(), after.Series.CurrentCertificateID())
			}
			assertReissueSourceDeliveryPending(t, f.store, snapshot.CurrentKeyGeneration.ID())
		})
	}
}

func TestIssuanceReissueMissingIssuerOrTransitionEvidenceFailsBeforeSigning(t *testing.T) {
	t.Run("source issuer generation missing", func(t *testing.T) {
		f := newIssuanceFixture(t)
		source := issueReissueSource(t, f)
		snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
		issuerID := sourceIssuerKeyID(t, f.store, source.CertificateID)
		f.svc.deps.ReadStore = &reissueEvidenceFailureReadStore{
			ReadStore: f.store, plan: reissueEvidenceFailurePlan{generationErrID: issuerID, generationErr: port.ErrNotFound},
		}
		_, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "81818181-8181-4818-8818-818181818181"),
			reissueCommandFor(source, contract.ReissueReasonManualRotation))
		assertSeriesFailure(t, err, contract.ErrorKindUnavailable, "issuance_source_issuer_missing")
		if f.keyEngine.generateCalls != 1 || f.signer.calls != 1 {
			t.Fatalf("key generations/signatures after missing issuer = %d/%d, want only initial issuance", f.keyEngine.generateCalls, f.signer.calls)
		}
	})

	t.Run("emergency transition missing", func(t *testing.T) {
		f := newIssuanceFixture(t)
		source := issueReissueSource(t, f)
		snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
		transitionID := mustID(t, f.ids, domain.ParseTransitionID)
		cmd := reissueCommandFor(source, contract.ReissueReasonEmergency)
		cmd.TransitionID = transitionID
		_, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "82828282-8282-4828-8828-828282828282"), cmd)
		assertSeriesFailure(t, err, contract.ErrorKindValidation, "transition_not_found")
		if f.keyEngine.generateCalls != 1 || f.signer.calls != 1 {
			t.Fatalf("key generations/signatures after missing transition = %d/%d, want only initial issuance", f.keyEngine.generateCalls, f.signer.calls)
		}
	})
}

func TestIssuanceReissueCanceledRequestDoesNotPrepareNewKey(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.svc.Reissue(ctx, reissueMeta(t, snapshot.Series.Version(), "83838383-8383-4838-8838-838383838383"),
		reissueCommandFor(source, contract.ReissueReasonManualRotation))
	assertSeriesFailure(t, err, contract.ErrorKindUnavailable, "request_canceled")
	if f.keyEngine.generateCalls != 1 || f.signer.calls != 1 {
		t.Fatalf("key generations/signatures after cancellation = %d/%d, want only initial issuance", f.keyEngine.generateCalls, f.signer.calls)
	}
	after := currentSeriesSnapshot(t, f.store, source.SeriesID)
	if after.Series.Version() != snapshot.Series.Version() || after.Series.CurrentCertificateID() != source.CertificateID {
		t.Fatalf("series changed after canceled request: version=%d current=%s", after.Series.Version(), after.Series.CurrentCertificateID())
	}
}

func TestIssuanceReissueRechecksCurrentAuthenticationBeforeCommit(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	meta := reissueMeta(t, snapshot.Series.Version(), "84848484-8484-4848-8848-848484848484")
	f.svc.deps.UnitOfWork = &reissueInvalidateSessionBeforeWrite{inner: f.store}
	_, err := f.svc.Reissue(context.Background(), meta, reissueCommandFor(source, contract.ReissueReasonManualRotation))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindAuth {
		t.Fatalf("Reissue after session invalidation before commit = %v, want auth failure", err)
	}
	if f.keyEngine.generateCalls != 2 || f.signer.calls != 2 {
		t.Fatalf("key generations/signatures = %d/%d, want one prepared replacement before commit auth check", f.keyEngine.generateCalls, f.signer.calls)
	}
	after := currentSeriesSnapshot(t, f.store, source.SeriesID)
	if after.Series.Version() != snapshot.Series.Version() || after.Series.CurrentCertificateID() != source.CertificateID {
		t.Fatalf("series changed after commit-time auth failure: version=%d current=%s", after.Series.Version(), after.Series.CurrentCertificateID())
	}
	assertReissueSourceDeliveryPending(t, f.store, snapshot.CurrentKeyGeneration.ID())
}

func TestIssuanceReissueRejectsCorruptCompromiseHistoryAfterExpiredDeliveryCleanup(t *testing.T) {
	for _, tc := range []struct {
		name      string
		includeCA bool
		wantKind  contract.ErrorKind
		wantCode  string
	}{
		{name: "no certificate history", wantKind: contract.ErrorKindUnavailable, wantCode: "issuance_compromised_source_missing"},
		{name: "CA certificate shares a leaf key", includeCA: true, wantKind: contract.ErrorKindForbidden, wantCode: "issuance_leaf_compromise_ca_key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			source := issueReissueSource(t, f)
			snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
			issuerID := sourceIssuerKeyID(t, f.store, source.CertificateID)
			seedCRLState(t, f.store, issuerID)
			if err := setReissuePendingDeliveryExpired(t, f.store, source, f.svc.deps.Clock.Now()); err != nil {
				t.Fatalf("expire pending source delivery: %v", err)
			}
			pendingDelivery := deliveryByID(t, f.store, source.Delivery.ID)
			keyHistory := []domain.Certificate(nil)
			if tc.includeCA {
				var caCertificate domain.Certificate
				if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
					authority, err := tx.PKI().GetIssuerForUpdate(context.Background(), f.authorityID)
					if err != nil {
						return err
					}
					caCertificate, err = tx.PKI().GetCertificate(context.Background(), authority.IssuanceCertificateID())
					return err
				}); err != nil {
					t.Fatalf("read CA certificate fixture: %v", err)
				}
				keyHistory = []domain.Certificate{caCertificate}
			}
			f.svc.deps.UnitOfWork = reissueFailureUnitOfWork{
				inner: f.store, keyHistoryOverride: keyHistory, overrideKeyHistory: true,
			}
			beforeAuditEvents := len(f.store.AuditEvents())
			_, err := f.svc.Reissue(context.Background(),
				reissueMeta(t, snapshot.Series.Version(), "85858585-8585-4858-8858-858585858585"),
				reissueCommandFor(source, contract.ReissueReasonKeyCompromise))
			assertSeriesFailure(t, err, tc.wantKind, tc.wantCode)
			after := currentSeriesSnapshot(t, f.store, source.SeriesID)
			if after.Series.Version() != snapshot.Series.Version() || after.Series.CurrentCertificateID() != source.CertificateID {
				t.Fatalf("series mutation survived corrupt compromise history: version=%d current=%s", after.Series.Version(), after.Series.CurrentCertificateID())
			}
			afterDelivery := deliveryByID(t, f.store, source.Delivery.ID)
			if afterDelivery.State() != domain.DeliveryStatePending || !afterDelivery.ExpiresAt().Equal(pendingDelivery.ExpiresAt()) {
				t.Fatalf("delivery state/deadline after rollback = %s/%s, want pending/%s", afterDelivery.State(), afterDelivery.ExpiresAt(), pendingDelivery.ExpiresAt())
			}
			if got := len(f.store.AuditEvents()); got != beforeAuditEvents {
				t.Fatalf("audit event count after corrupt compromise history = %d, want unchanged %d", got, beforeAuditEvents)
			}
		})
	}
}

func TestIssuanceReissueExpiresPendingDeliveryWithinRollbackBoundary(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	if err := setReissuePendingDeliveryExpired(t, f.store, source, f.svc.deps.Clock.Now()); err != nil {
		t.Fatalf("expire pending source delivery: %v", err)
	}
	beforeDelivery := deliveryByID(t, f.store, source.Delivery.ID)
	f.svc.deps.UnitOfWork = reissueFailureUnitOfWork{inner: f.store, failAt: "save_series"}
	_, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "86868686-8686-4868-8868-868686868686"),
		reissueCommandFor(source, contract.ReissueReasonManualRotation))
	assertSeriesFailure(t, err, contract.ErrorKindUnavailable, "issuance_series_save_failed")
	after := currentSeriesSnapshot(t, f.store, source.SeriesID)
	if after.Series.Version() != snapshot.Series.Version() || after.Series.CurrentCertificateID() != source.CertificateID {
		t.Fatalf("series mutation survived later save failure: version=%d current=%s", after.Series.Version(), after.Series.CurrentCertificateID())
	}
	afterDelivery := deliveryByID(t, f.store, source.Delivery.ID)
	if afterDelivery.State() != domain.DeliveryStatePending || !afterDelivery.ExpiresAt().Equal(beforeDelivery.ExpiresAt()) {
		t.Fatalf("expired pending delivery after rollback = %s/%s, want prior pending/%s", afterDelivery.State(), afterDelivery.ExpiresAt(), beforeDelivery.ExpiresAt())
	}
}

func TestIssuanceReissueCompromiseMarkFailureRollsBackDeliveryCleanup(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	f.svc.deps.UnitOfWork = reissueFailureUnitOfWork{inner: f.store, failAt: "mark_compromised"}
	_, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "87878787-8787-4878-8878-878787878787"),
		reissueCommandFor(source, contract.ReissueReasonKeyCompromise))
	assertSeriesFailure(t, err, contract.ErrorKindUnavailable, "issuance_key_compromise_mark_failed")
	assertReissueKeyNotCompromised(t, f.store, snapshot.CurrentKeyGeneration.KeyMaterialID())
	assertReissueSourceDeliveryPending(t, f.store, snapshot.CurrentKeyGeneration.ID())
	after := currentSeriesSnapshot(t, f.store, source.SeriesID)
	if after.Series.Version() != snapshot.Series.Version() || after.Series.CurrentCertificateID() != source.CertificateID {
		t.Fatalf("series mutation survived compromise mark failure: version=%d current=%s", after.Series.Version(), after.Series.CurrentCertificateID())
	}
}

func TestIssuanceReissueLeafGenerationInsertFailureRollsBackEarlierWrites(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	beforeAuditEvents := len(f.store.AuditEvents())
	f.svc.deps.UnitOfWork = reissueFailureUnitOfWork{inner: f.store, failAt: "insert_leaf_key_generation"}
	_, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "88878787-8787-4887-8878-878787878787"),
		reissueCommandFor(source, contract.ReissueReasonManualRotation))
	assertSeriesFailure(t, err, contract.ErrorKindUnavailable, "issuance_leaf_key_generation_store_failed")
	after := currentSeriesSnapshot(t, f.store, source.SeriesID)
	if after.Series.Version() != snapshot.Series.Version() || after.Series.CurrentCertificateID() != source.CertificateID {
		t.Fatalf("series mutation survived generation insert failure: version=%d current=%s", after.Series.Version(), after.Series.CurrentCertificateID())
	}
	assertReissueSourceDeliveryPending(t, f.store, snapshot.CurrentKeyGeneration.ID())
	if got := len(f.store.AuditEvents()); got != beforeAuditEvents {
		t.Fatalf("audit event count after generation insert failure = %d, want unchanged %d", got, beforeAuditEvents)
	}
}

func TestIssuanceReissueRechecksReplayAfterConcurrentCommitDuringPreparation(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	seedCRLState(t, f.store, sourceIssuerKeyID(t, f.store, source.CertificateID))
	gate := &lateReplayReadStore{
		ReadStore: f.store,
		paused:    make(chan struct{}),
		release:   make(chan struct{}),
	}
	f.svc.deps.ReadStore = gate
	meta := reissueMeta(t, snapshot.Series.Version(), "89898989-8989-4989-8989-898989898989")
	cmd := reissueCommandFor(source, contract.ReissueReasonManualRotation)
	type callResult struct {
		view contract.IssuanceView
		err  error
	}
	firstResult := make(chan callResult, 1)
	go func() {
		view, err := f.svc.Reissue(context.Background(), meta, cmd)
		firstResult <- callResult{view: view, err: err}
	}()
	t.Cleanup(gate.unpause)
	select {
	case <-gate.paused:
	case <-time.After(5 * time.Second):
		t.Fatal("first request did not pause before its preparation read")
	}

	second, err := f.svc.Reissue(context.Background(), meta, cmd)
	if err != nil {
		t.Fatalf("second same-key request: %v", err)
	}
	if second.Replayed {
		t.Fatal("second request unexpectedly replayed before either request committed")
	}
	gate.unpause()

	var first callResult
	select {
	case first = <-firstResult:
	case <-time.After(5 * time.Second):
		t.Fatal("first request did not finish after the second request committed")
	}
	if first.err != nil {
		t.Fatalf("first same-key request after concurrent commit: %v", first.err)
	}
	if !first.view.Replayed || first.view.CertificateID != second.CertificateID || first.view.SeriesID != second.SeriesID {
		t.Fatalf("late replay = %+v, second result = %+v; want same committed result flagged as replay", first.view, second)
	}
	after := currentSeriesSnapshot(t, f.store, source.SeriesID)
	if after.Series.Version() != snapshot.Series.Version().Next() || after.Series.CurrentCertificateID() != second.CertificateID {
		t.Fatalf("series after same-key race = version %d/current %s; want one commit at version %d for %s", after.Series.Version(), after.Series.CurrentCertificateID(), snapshot.Series.Version().Next(), second.CertificateID)
	}
}

func TestIssuanceReissueRecheckReturnsAuthenticationFailure(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	evidenceStore := &reissueEvidenceFailureReadStore{
		ReadStore: f.store,
		plan:      reissueEvidenceFailurePlan{deliveryErr: errors.New("injected preparation evidence failure")},
	}
	f.svc.deps.ReadStore = &invalidateSessionOnNthReadStore{ReadStore: evidenceStore, unitOfWork: f.store, nth: 3}
	_, err := f.svc.Reissue(context.Background(),
		reissueMeta(t, snapshot.Series.Version(), "90909090-9090-4909-8909-909090909090"),
		reissueCommandFor(source, contract.ReissueReasonManualRotation))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindAuth {
		t.Fatalf("Reissue after session invalidation during preparation = %v, want auth failure from replay recheck", err)
	}
	if f.keyEngine.generateCalls != 1 || f.signer.calls != 1 {
		t.Fatalf("key generations/signatures = %d/%d, want only initial issuance", f.keyEngine.generateCalls, f.signer.calls)
	}
	after := currentSeriesSnapshot(t, f.store, source.SeriesID)
	if after.Series.Version() != snapshot.Series.Version() || after.Series.CurrentCertificateID() != source.CertificateID {
		t.Fatalf("series changed after failed authentication recheck: version=%d current=%s", after.Series.Version(), after.Series.CurrentCertificateID())
	}
}

type lateReplayReadStore struct {
	port.ReadStore
	mu          sync.Mutex
	reads       int
	paused      chan struct{}
	release     chan struct{}
	pauseOnce   sync.Once
	releaseOnce sync.Once
}

type invalidateSessionOnNthReadStore struct {
	port.ReadStore
	unitOfWork port.UnitOfWork
	nth        int
	reads      int
}

func (s *invalidateSessionOnNthReadStore) Read(ctx context.Context, callback func(port.TxStores) error) error {
	s.reads++
	if s.reads == s.nth {
		if err := s.unitOfWork.Write(ctx, func(tx port.TxStores) error {
			return tx.Accounts().DeleteAllSessions(ctx, issuanceTestAdminAccountID)
		}); err != nil {
			return err
		}
	}
	return s.ReadStore.Read(ctx, callback)
}

func (s *lateReplayReadStore) Read(ctx context.Context, callback func(port.TxStores) error) error {
	s.mu.Lock()
	s.reads++
	readNo := s.reads
	s.mu.Unlock()
	if readNo == 2 {
		s.pauseOnce.Do(func() { close(s.paused) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.ReadStore.Read(ctx, callback)
}

func (s *lateReplayReadStore) unpause() {
	s.releaseOnce.Do(func() { close(s.release) })
}

func assertReissueKeyNotCompromised(t *testing.T, store port.ReadStore, id domain.KeyMaterialID) {
	t.Helper()
	var material port.KeyMaterial
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		material, err = tx.PKI().GetKeyMaterial(context.Background(), id)
		return err
	})
	if err != nil {
		t.Fatalf("read key material after rollback: %v", err)
	}
	if !material.CompromisedAt.IsZero() {
		t.Fatalf("compromise marker survived rollback at %s", material.CompromisedAt)
	}
}

func setReissuePendingDeliveryExpired(t *testing.T, store port.UnitOfWork, source contract.IssuanceView, now domain.Instant) error {
	t.Helper()
	if source.Delivery == nil {
		return errors.New("source issuance has no delivery")
	}
	return store.Write(context.Background(), func(tx port.TxStores) error {
		delivery, err := tx.Delivery().GetDeliveryForUpdate(context.Background(), source.Delivery.ID)
		if err != nil {
			return err
		}
		expired, err := domain.NewDelivery(domain.DeliveryFacts{
			ID: delivery.ID(), LeafKeyGenerationID: delivery.LeafKeyGenerationID(),
			CertificateID: delivery.CertificateID(), ExpiresAt: now.Add(domain.NewDuration(-1)),
			State: domain.DeliveryStatePending, Version: delivery.Version(),
		})
		if err != nil {
			return err
		}
		return tx.Delivery().SaveDelivery(context.Background(), expired, delivery.Version())
	})
}

type reissueFailureUnitOfWork struct {
	inner              port.UnitOfWork
	failAt             string
	keyHistoryOverride []domain.Certificate
	overrideKeyHistory bool
}

func (u reissueFailureUnitOfWork) Write(ctx context.Context, callback func(port.TxStores) error) error {
	return u.inner.Write(ctx, func(tx port.TxStores) error {
		return callback(reissueFailureTxStores{
			TxStores: tx,
			pki: reissueFailurePKIRepository{
				PKIRepository: tx.PKI(), failAt: u.failAt,
				keyHistoryOverride: u.keyHistoryOverride, overrideKeyHistory: u.overrideKeyHistory,
			},
			delivery: reissueFailureDeliveryRepository{DeliveryRepository: tx.Delivery(), failAt: u.failAt},
			secrets:  reissueFailureSecretRepository{SecretRepository: tx.Secrets(), failAt: u.failAt},
		})
	})
}

type reissueFailureTxStores struct {
	port.TxStores
	pki      port.PKIRepository
	delivery port.DeliveryRepository
	secrets  port.SecretRepository
}

func (tx reissueFailureTxStores) PKI() port.PKIRepository           { return tx.pki }
func (tx reissueFailureTxStores) Delivery() port.DeliveryRepository { return tx.delivery }
func (tx reissueFailureTxStores) Secrets() port.SecretRepository    { return tx.secrets }

type reissueFailurePKIRepository struct {
	port.PKIRepository
	failAt             string
	keyHistoryOverride []domain.Certificate
	overrideKeyHistory bool
}

func (r reissueFailurePKIRepository) SaveSeries(ctx context.Context, series domain.LeafSeries, expected domain.Version) error {
	if r.failAt == "save_series" {
		return errors.New("injected reissue series save failure")
	}
	return r.PKIRepository.SaveSeries(ctx, series, expected)
}

func (r reissueFailurePKIRepository) GetSeriesForUpdate(ctx context.Context, id domain.SeriesID) (port.SeriesSnapshot, error) {
	if r.failAt == "get_series" {
		return port.SeriesSnapshot{}, errors.New("injected reissue series read failure")
	}
	return r.PKIRepository.GetSeriesForUpdate(ctx, id)
}

func (r reissueFailurePKIRepository) MarkCompromised(ctx context.Context, id domain.KeyMaterialID, now domain.Instant) error {
	if r.failAt == "mark_compromised" {
		return errors.New("injected reissue key compromise mark failure")
	}
	return r.PKIRepository.MarkCompromised(ctx, id, now)
}

func (r reissueFailurePKIRepository) InsertLeafKeyGeneration(ctx context.Context, generation domain.LeafKeyGeneration) error {
	if r.failAt == "insert_leaf_key_generation" {
		return errors.New("injected reissue leaf key generation insert failure")
	}
	return r.PKIRepository.InsertLeafKeyGeneration(ctx, generation)
}

func (r reissueFailurePKIRepository) InsertLeafCertificateRecord(ctx context.Context, record port.LeafCertificateRecord) error {
	if r.failAt == "insert_leaf_certificate_record" {
		return errors.New("injected reissue leaf lineage insert failure")
	}
	return r.PKIRepository.InsertLeafCertificateRecord(ctx, record)
}

func (r reissueFailurePKIRepository) ListCertificatesUsingKey(ctx context.Context, id domain.KeyMaterialID) ([]domain.Certificate, error) {
	if r.overrideKeyHistory {
		return append([]domain.Certificate(nil), r.keyHistoryOverride...), nil
	}
	return r.PKIRepository.ListCertificatesUsingKey(ctx, id)
}

type reissueFailureDeliveryRepository struct {
	port.DeliveryRepository
	failAt string
}

func (r reissueFailureDeliveryRepository) InsertDelivery(ctx context.Context, delivery domain.Delivery) error {
	if r.failAt == "insert_delivery" {
		return errors.New("injected reissue delivery insert failure")
	}
	return r.DeliveryRepository.InsertDelivery(ctx, delivery)
}

func (r reissueFailureDeliveryRepository) GetDeliveryByLeafKeyGenerationForUpdate(ctx context.Context, id domain.LeafKeyGenerationID) (domain.Delivery, error) {
	if r.failAt == "get_delivery" {
		return domain.Delivery{}, errors.New("injected reissue delivery read failure")
	}
	return r.DeliveryRepository.GetDeliveryByLeafKeyGenerationForUpdate(ctx, id)
}

func (r reissueFailureDeliveryRepository) SaveDelivery(ctx context.Context, delivery domain.Delivery, expected domain.Version) error {
	if r.failAt == "save_delivery" {
		return errors.New("injected reissue delivery save failure")
	}
	return r.DeliveryRepository.SaveDelivery(ctx, delivery, expected)
}

func (r reissueFailureDeliveryRepository) InvalidatePrivateGrants(ctx context.Context, id domain.DeliveryID, now domain.Instant) error {
	if r.failAt == "invalidate_grants" {
		return errors.New("injected reissue private grant invalidation failure")
	}
	return r.DeliveryRepository.InvalidatePrivateGrants(ctx, id, now)
}

type reissueFailureSecretRepository struct {
	port.SecretRepository
	failAt string
}

func (r reissueFailureSecretRepository) Delete(ctx context.Context, keyID domain.KeyMaterialID, purpose domain.SecretPurpose) error {
	if r.failAt == "delete_secret" {
		return errors.New("injected reissue secret deletion failure")
	}
	return r.SecretRepository.Delete(ctx, keyID, purpose)
}

type reissueEvidenceFailurePlan struct {
	deliveryErr        error
	leafRecordFailCall int
	leafRecordErr      error
	generationErrID    domain.CAKeyGenerationID
	generationErr      error
}

type reissueEvidenceFailureReadStore struct {
	port.ReadStore
	plan            reissueEvidenceFailurePlan
	leafRecordCalls int
}

func (s *reissueEvidenceFailureReadStore) Read(ctx context.Context, callback func(port.TxStores) error) error {
	return s.ReadStore.Read(ctx, func(tx port.TxStores) error {
		return callback(reissueEvidenceFailureTxStores{
			TxStores: tx,
			pki:      reissueEvidenceFailurePKIRepository{PKIRepository: tx.PKI(), plan: s.plan, leafRecordCalls: &s.leafRecordCalls},
			delivery: reissueEvidenceFailureDeliveryRepository{DeliveryRepository: tx.Delivery(), plan: s.plan},
		})
	})
}

type reissueEvidenceFailureTxStores struct {
	port.TxStores
	pki      port.PKIRepository
	delivery port.DeliveryRepository
}

func (tx reissueEvidenceFailureTxStores) PKI() port.PKIRepository           { return tx.pki }
func (tx reissueEvidenceFailureTxStores) Delivery() port.DeliveryRepository { return tx.delivery }

type reissueEvidenceFailurePKIRepository struct {
	port.PKIRepository
	plan            reissueEvidenceFailurePlan
	leafRecordCalls *int
}

func (r reissueEvidenceFailurePKIRepository) GetLeafCertificateRecord(ctx context.Context, id domain.CertificateID) (port.LeafCertificateRecord, error) {
	if r.leafRecordCalls != nil {
		*r.leafRecordCalls = *r.leafRecordCalls + 1
		if *r.leafRecordCalls == r.plan.leafRecordFailCall && r.plan.leafRecordErr != nil {
			return port.LeafCertificateRecord{}, r.plan.leafRecordErr
		}
	}
	return r.PKIRepository.GetLeafCertificateRecord(ctx, id)
}

func (r reissueEvidenceFailurePKIRepository) GetCAKeyGeneration(ctx context.Context, id domain.CAKeyGenerationID) (port.CAKeyGeneration, error) {
	if id == r.plan.generationErrID && r.plan.generationErr != nil {
		return port.CAKeyGeneration{}, r.plan.generationErr
	}
	return r.PKIRepository.GetCAKeyGeneration(ctx, id)
}

type reissueEvidenceFailureDeliveryRepository struct {
	port.DeliveryRepository
	plan reissueEvidenceFailurePlan
}

func (r reissueEvidenceFailureDeliveryRepository) GetDeliveryByLeafKeyGenerationForUpdate(ctx context.Context, id domain.LeafKeyGenerationID) (domain.Delivery, error) {
	if r.plan.deliveryErr != nil {
		return domain.Delivery{}, r.plan.deliveryErr
	}
	return r.DeliveryRepository.GetDeliveryByLeafKeyGenerationForUpdate(ctx, id)
}

type reissueInvalidateSessionBeforeWrite struct {
	inner port.UnitOfWork
	done  bool
}

func (u *reissueInvalidateSessionBeforeWrite) Write(ctx context.Context, callback func(port.TxStores) error) error {
	if !u.done {
		if err := u.inner.Write(ctx, func(tx port.TxStores) error {
			return tx.Accounts().DeleteAllSessions(ctx, issuanceTestAdminAccountID)
		}); err != nil {
			return err
		}
		u.done = true
	}
	return u.inner.Write(ctx, callback)
}
