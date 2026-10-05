package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

func reissueMeta(t *testing.T, version domain.Version, key string) contract.MutationMeta {
	t.Helper()
	meta := issueMutationMeta(t, key)
	meta.ExpectedVersion = contract.WithExpectedVersion(version)
	return meta
}

func issueReissueSource(t *testing.T, f *issuanceFixture) contract.IssuanceView {
	t.Helper()
	result, err := f.svc.Issue(context.Background(), issueMutationMeta(t, issuanceTestIdempotencyKey), issueCommand(f.authorityID, "reissue-source"))
	if err != nil {
		t.Fatalf("Issue source certificate: %v", err)
	}
	return result
}

func reissueCommandFor(source contract.IssuanceView, reason contract.ReissueReason) contract.IssuanceReissueCommand {
	return contract.IssuanceReissueCommand{SeriesID: source.SeriesID, SourceCertificateID: source.CertificateID, Reason: reason}
}

func currentSeriesSnapshot(t *testing.T, store *porttest.Store, id domain.SeriesID) port.SeriesSnapshot {
	t.Helper()
	var snapshot port.SeriesSnapshot
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		snapshot, err = tx.PKI().GetSeriesForUpdate(context.Background(), id)
		return err
	}); err != nil {
		t.Fatalf("read series %s: %v", id, err)
	}
	return snapshot
}

func TestIssuanceReissueAlwaysCreatesFreshKeyAndReplaysBeforeChangedVersion(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	if err := markIssueDeliveryCompletedForTest(t, f, source); err != nil {
		t.Fatalf("complete source delivery: %v", err)
	}
	version := currentSeriesSnapshot(t, f.store, source.SeriesID).Series.Version()
	cmd := reissueCommandFor(source, contract.ReissueReasonManualRotation)
	meta := reissueMeta(t, version, "88888888-8888-4888-8888-888888888888")

	first, err := f.svc.Reissue(context.Background(), meta, cmd)
	if err != nil {
		t.Fatalf("Reissue: %v", err)
	}
	if first.CertificateID == source.CertificateID || first.KeyGenerationID == "" || !first.KeyRotated || first.RenewalCount != 0 {
		t.Fatalf("reissue = %+v, want a different certificate, fresh key and reset count", first)
	}
	if first.Delivery == nil || first.Delivery.State != domain.DeliveryStatePending {
		t.Fatalf("reissue delivery = %+v, want a pending one-shot delivery", first.Delivery)
	}
	if f.keyEngine.generateCalls != 2 {
		t.Fatalf("key generation calls = %d, want 2 (initial + mandatory fresh reissue key)", f.keyEngine.generateCalls)
	}

	// The first commit advanced the series version. A byte-for-byte retry with
	// the same request identity must replay successfully before checking that
	// now-stale If-Match value, and must identify itself for the HTTP 200 path.
	replayed, err := f.svc.Reissue(context.Background(), meta, cmd)
	if err != nil {
		t.Fatalf("Reissue replay with original expected version: %v", err)
	}
	if !replayed.Replayed || replayed.CertificateID != first.CertificateID || f.keyEngine.generateCalls != 2 {
		t.Fatalf("replay = %+v, key generations = %d; want the same result flagged as replay with no new key", replayed, f.keyEngine.generateCalls)
	}
}

func TestIssuanceReissueFailureAndExpiryCompleteRevocationAtomically(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason contract.ReissueReason
		state  domain.DeliveryState
	}{
		{name: "failed", reason: contract.ReissueReasonDeliveryFailed, state: domain.DeliveryStateFailed},
		{name: "expired", reason: contract.ReissueReasonDeliveryExpired, state: domain.DeliveryStateExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			source := issueReissueSource(t, f)
			if err := setReissueDeliveryTerminalForTest(t, f, source, tc.state); err != nil {
				t.Fatalf("set delivery state: %v", err)
			}
			snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
			issuerID := sourceIssuerKeyID(t, f.store, source.CertificateID)
			seedCRLState(t, f.store, issuerID)
			cmd := reissueCommandFor(source, tc.reason)
			result, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "99999999-9999-4999-8999-999999999999"), cmd)
			if err != nil {
				t.Fatalf("Reissue after %s delivery: %v", tc.state, err)
			}
			if result.CertificateID == source.CertificateID || !result.KeyRotated {
				t.Fatalf("Reissue result = %+v, want a replacement certificate with a fresh key", result)
			}
			assertReissueRevocation(t, f.store, source.CertificateID, domain.RevocationReasonUnspecified)
			if f.keyEngine.generateCalls != 2 {
				t.Fatalf("key generation calls = %d, want initial + replacement", f.keyEngine.generateCalls)
			}
		})
	}
}

func TestIssuanceReissueKeyCompromiseMarksAndRevokesSource(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	issuerID := sourceIssuerKeyID(t, f.store, source.CertificateID)
	seedCRLState(t, f.store, issuerID)
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.PKI().MarkCompromised(context.Background(), snapshot.CurrentKeyGeneration.KeyMaterialID(), testNow())
	}); err != nil {
		t.Fatalf("mark current key compromised: %v", err)
	}

	cmd := reissueCommandFor(source, contract.ReissueReasonKeyCompromise)
	result, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), cmd)
	if err != nil {
		t.Fatalf("Reissue after key compromise: %v", err)
	}
	if result.CertificateID == source.CertificateID || result.KeyGenerationID == snapshot.CurrentKeyGeneration.ID() || result.RenewalCount != 0 {
		t.Fatalf("reissue = %+v, want fresh key generation and reset count", result)
	}
	assertReissueRevocation(t, f.store, source.CertificateID, domain.RevocationReasonKeyCompromise)
}

func TestIssuanceReissueEmergencyRequiresMatchingOpenImpactAndUsesTargetAuthority(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	targetAuthorityID := seedIssuableIntermediate(t, f.store, f.ids, testNow())
	transitionID, err := domain.ParseTransitionID(f.ids.NewUUID())
	if err != nil {
		t.Fatalf("transition ID: %v", err)
	}
	transition, err := domain.NewTransition(domain.TransitionFacts{
		ID: transitionID, SourceAuthorityID: f.authorityID, TargetAuthorityID: targetAuthorityID,
		Mode: domain.TransitionModeEmergency, State: domain.TransitionStateInProgress,
		ReportedBy: issuanceTestAdminAccountID, ReportedAt: testNow(), Reason: "key compromise", Version: 1,
	})
	if err != nil {
		t.Fatalf("NewTransition: %v", err)
	}
	impact, err := domain.NewTransitionImpact(domain.TransitionImpactFacts{TransitionID: transitionID, CertificateID: source.CertificateID})
	if err != nil {
		t.Fatalf("NewTransitionImpact: %v", err)
	}
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		if err := tx.Transitions().Insert(context.Background(), transition); err != nil {
			return err
		}
		return tx.Transitions().AddImpact(context.Background(), impact)
	}); err != nil {
		t.Fatalf("seed emergency impact: %v", err)
	}
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	cmd := reissueCommandFor(source, contract.ReissueReasonEmergency)
	cmd.TargetAuthorityID = targetAuthorityID
	cmd.TransitionID = transitionID
	result, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), cmd)
	if err != nil {
		t.Fatalf("Reissue for emergency transition: %v", err)
	}
	if result.CertificateID == source.CertificateID || result.Delivery == nil || result.RenewalCount != 0 {
		t.Fatalf("reissue = %+v, want new target-CA cert, fresh key delivery and reset count", result)
	}
	var linked bool
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		impacts, err := tx.Transitions().ListImpacts(context.Background(), transitionID)
		if err != nil {
			return err
		}
		linked = len(impacts) == 1 && impacts[0].ReplacementCertificateID() == result.CertificateID
		return nil
	}); err != nil {
		t.Fatalf("read emergency impact: %v", err)
	}
	if !linked {
		t.Fatal("successful emergency reissue did not link its replacement certificate to the impact")
	}
}

func TestIssuanceReissueRejectsUnsupportedEvidenceWithoutSigning(t *testing.T) {
	tests := []struct {
		name   string
		reason contract.ReissueReason
	}{
		{name: "failed reason with pending delivery", reason: contract.ReissueReasonDeliveryFailed},
		{name: "expired reason with pending delivery", reason: contract.ReissueReasonDeliveryExpired},
		{name: "compromise without compromise marker", reason: contract.ReissueReasonKeyCompromise},
		{name: "emergency without transition", reason: contract.ReissueReasonEmergency},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			source := issueReissueSource(t, f)
			snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
			_, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "cccccccc-cccc-4ccc-8ccc-cccccccccccc"), reissueCommandFor(source, tc.reason))
			if err == nil {
				t.Fatal("Reissue succeeded without evidence required by its reason")
			}
			var appErr *contract.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("error = %v, want public AppError", err)
			}
			if f.signer.calls != 1 || f.keyEngine.generateCalls != 1 {
				t.Fatalf("signer calls = %d, generated keys = %d; invalid evidence must fail before preparation", f.signer.calls, f.keyEngine.generateCalls)
			}
		})
	}
}

func TestIssuanceReissueConcurrentSameRequestCommitsOnce(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	if err := markIssueDeliveryCompletedForTest(t, f, source); err != nil {
		t.Fatalf("complete source delivery: %v", err)
	}
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	meta := reissueMeta(t, snapshot.Series.Version(), "dddddddd-dddd-4ddd-8ddd-dddddddddddd")
	cmd := reissueCommandFor(source, contract.ReissueReasonManualRotation)
	start := make(chan struct{})
	results := make([]contract.IssuanceView, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = f.svc.Reissue(context.Background(), meta, cmd)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent Reissue %d: %v", i, err)
		}
	}
	if results[0].CertificateID == "" || results[0].CertificateID != results[1].CertificateID {
		t.Fatalf("concurrent results = %+v and %+v, want one certificate result", results[0], results[1])
	}
	if f.keyEngine.generateCalls != 2 {
		t.Fatalf("key generation calls = %d, want only one reissue key in addition to the initial key", f.keyEngine.generateCalls)
	}
}

func sourceIssuerKeyID(t *testing.T, store *porttest.Store, certificateID domain.CertificateID) domain.CAKeyGenerationID {
	t.Helper()
	var id domain.CAKeyGenerationID
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		cert, err := tx.PKI().GetCertificate(context.Background(), certificateID)
		if err == nil {
			id = cert.IssuerCAKeyGenerationID()
		}
		return err
	}); err != nil {
		t.Fatalf("read certificate issuer: %v", err)
	}
	return id
}

func assertReissueRevocation(t *testing.T, store *porttest.Store, certificateID domain.CertificateID, reason domain.RevocationReason) {
	t.Helper()
	var cert domain.Certificate
	var revocation domain.Revocation
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		cert, err = tx.PKI().GetCertificate(context.Background(), certificateID)
		if err != nil {
			return err
		}
		revocation, err = tx.Revocations().FindForUpdate(context.Background(), cert.IssuerCAKeyGenerationID(), cert.Serial())
		return err
	})
	if err != nil {
		t.Fatalf("read source revocation: %v", err)
	}
	if revocation.CertificateID() != certificateID || revocation.Reason() != reason {
		t.Fatalf("revocation = %#v, want certificate %s with reason %s", revocation, certificateID, reason)
	}
}

func markIssueDeliveryCompletedForTest(t *testing.T, f *issuanceFixture, issue contract.IssuanceView) error {
	t.Helper()
	if issue.Delivery == nil {
		return errors.New("source issuance has no delivery")
	}
	return f.store.Write(context.Background(), func(tx port.TxStores) error {
		snapshot, err := tx.PKI().GetSeriesForUpdate(context.Background(), issue.SeriesID)
		if err != nil {
			return err
		}
		generation := snapshot.CurrentKeyGeneration
		deliveredGeneration, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
			ID: generation.ID(), SeriesID: generation.SeriesID(), KeyMaterialID: generation.KeyMaterialID(),
			GenerationNo: generation.GenerationNo(), RenewalCount: generation.RenewalCount(),
			PriorHistoryUnknown: generation.PriorHistoryUnknown(), Custody: domain.KeyCustodyClientHeld,
		})
		if err != nil {
			return err
		}
		delivery, err := tx.Delivery().GetDeliveryForUpdate(context.Background(), issue.Delivery.ID)
		if err != nil {
			return err
		}
		consumed, err := delivery.Consume(testNow())
		if err != nil {
			return err
		}
		completed, err := consumed.Complete(testNow())
		if err != nil {
			return err
		}
		if err := tx.Delivery().SaveDelivery(context.Background(), completed, delivery.Version()); err != nil {
			return err
		}
		if err := tx.Secrets().Delete(context.Background(), generation.KeyMaterialID(), domain.SecretPurposeLeafDelivery); err != nil {
			return err
		}
		return tx.PKI().SaveLeafKeyGeneration(context.Background(), deliveredGeneration)
	})
}

func setReissueDeliveryTerminalForTest(t *testing.T, f *issuanceFixture, issue contract.IssuanceView, state domain.DeliveryState) error {
	t.Helper()
	if issue.Delivery == nil {
		return errors.New("source issuance has no delivery")
	}
	keyMaterialID := currentSeriesSnapshot(t, f.store, issue.SeriesID).CurrentKeyGeneration.KeyMaterialID()
	return f.store.Write(context.Background(), func(tx port.TxStores) error {
		delivery, err := tx.Delivery().GetDeliveryForUpdate(context.Background(), issue.Delivery.ID)
		if err != nil {
			return err
		}
		var next domain.Delivery
		switch state {
		case domain.DeliveryStateFailed:
			next, err = delivery.Fail("transfer_failed", testNow())
		case domain.DeliveryStateExpired:
			expiry := delivery.ExpiresAt().Add(domain.NewDuration(time.Second))
			next, err = delivery.Expire(expiry)
			f.svc.deps.Clock = fixedClock{now: expiry}
		default:
			return errors.New("unsupported test delivery state")
		}
		if err != nil {
			return err
		}
		if err := tx.Delivery().SaveDelivery(context.Background(), next, delivery.Version()); err != nil {
			return err
		}
		return tx.Secrets().Delete(context.Background(), keyMaterialID, domain.SecretPurposeLeafDelivery)
	})
}
