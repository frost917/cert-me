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
	f.authorizer.allow = false
	_, err = f.svc.Reissue(context.Background(), meta, cmd)
	var authErr *contract.AppError
	if !errors.As(err, &authErr) || authErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("replay after permission loss error = %v, want forbidden", err)
	}
	f.authorizer.allow = true
	changedInput := cmd
	changedInput.Reason = contract.ReissueReasonEmergency
	_, err = f.svc.Reissue(context.Background(), meta, changedInput)
	var conflict *contract.AppError
	if !errors.As(err, &conflict) || conflict.Kind() != contract.ErrorKindConflict || conflict.Code() != "idempotency_key_reused" {
		t.Fatalf("replay with changed input error = %v, want idempotency_key_reused conflict", err)
	}
}

func TestIssuanceReissueSerialCollisionResignsWithPreparedFreshKey(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	var sourceCertificate domain.Certificate
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		sourceCertificate, err = tx.PKI().GetCertificate(context.Background(), source.CertificateID)
		return err
	}); err != nil {
		t.Fatalf("read source certificate: %v", err)
	}
	// The initial Issue already consumed serial index 0. Force the first
	// reissue attempt to collide with that source certificate, then supply a
	// fresh serial for the retry.
	f.serials.serials = []string{"unused", sourceCertificate.Serial().Hex(), "3e9"}
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	seedCRLState(t, f.store, sourceIssuerKeyID(t, f.store, source.CertificateID))
	result, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "89898989-8989-4989-8989-898989898989"),
		reissueCommandFor(source, contract.ReissueReasonManualRotation))
	if err != nil {
		t.Fatalf("Reissue after serial collision: %v", err)
	}
	if f.signer.calls != 3 {
		t.Fatalf("signer calls = %d, want source signature plus collision and retry signatures", f.signer.calls)
	}
	if f.keyEngine.generateCalls != 2 {
		t.Fatalf("key generation calls = %d, want only one fresh reissue key across serial retry", f.keyEngine.generateCalls)
	}
	var reissuedCertificate domain.Certificate
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		reissuedCertificate, err = tx.PKI().GetCertificate(context.Background(), result.CertificateID)
		return err
	}); err != nil {
		t.Fatalf("read reissued certificate: %v", err)
	}
	if reissuedCertificate.Serial().Hex() != "3e9" || reissuedCertificate.KeyMaterialID() == sourceCertificate.KeyMaterialID() {
		t.Fatalf("reissued certificate serial/key = %s/%s, want 3e9 and a fresh key", reissuedCertificate.Serial().Hex(), reissuedCertificate.KeyMaterialID())
	}
}

func TestIssuanceReissueReplayRequiresCurrentAuthentication(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	if err := markIssueDeliveryCompletedForTest(t, f, source); err != nil {
		t.Fatalf("complete source delivery: %v", err)
	}
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	meta := reissueMeta(t, snapshot.Series.Version(), "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
	cmd := reissueCommandFor(source, contract.ReissueReasonManualRotation)
	if _, err := f.svc.Reissue(context.Background(), meta, cmd); err != nil {
		t.Fatalf("initial Reissue: %v", err)
	}
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Accounts().DeleteAllSessions(context.Background(), issuanceTestAdminAccountID)
	}); err != nil {
		t.Fatalf("invalidate admin session: %v", err)
	}
	_, err := f.svc.Reissue(context.Background(), meta, cmd)
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindAuth {
		t.Fatalf("replay after session invalidation error = %v, want auth failure", err)
	}
	if f.keyEngine.generateCalls != 2 {
		t.Fatalf("key generation calls = %d, want no key generation during rejected replay", f.keyEngine.generateCalls)
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

func TestIssuanceReissueManualRotationClosesPendingDeliveryAndRevokesSourceAtomically(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	issuerID := sourceIssuerKeyID(t, f.store, source.CertificateID)
	seedCRLState(t, f.store, issuerID)
	assertReissueSourceDeliveryPending(t, f.store, snapshot.CurrentKeyGeneration.ID())

	cmd := reissueCommandFor(source, contract.ReissueReasonManualRotation)
	result, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "98989898-9898-4989-8989-989898989898"), cmd)
	if err != nil {
		t.Fatalf("Reissue with a pending source delivery: %v", err)
	}
	if result.CertificateID == source.CertificateID || !result.KeyRotated {
		t.Fatalf("Reissue result = %+v, want a replacement certificate with a fresh key", result)
	}
	assertPendingReissueCleanup(t, f.store, source.CertificateID, snapshot.CurrentKeyGeneration.ID(),
		snapshot.CurrentKeyGeneration.KeyMaterialID(), issuerID)
}

func TestIssuanceReissueRejectsTransferringDeliveryBeforeSigningOrMutation(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	deliveryID := source.Delivery.ID
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		delivery, err := tx.Delivery().GetDeliveryForUpdate(context.Background(), deliveryID)
		if err != nil {
			return err
		}
		transferring, err := delivery.Consume(testNow())
		if err != nil {
			return err
		}
		if err := tx.Delivery().SaveDelivery(context.Background(), transferring, delivery.Version()); err != nil {
			return err
		}
		return tx.Secrets().Delete(context.Background(), snapshot.CurrentKeyGeneration.KeyMaterialID(), domain.SecretPurposeLeafDelivery)
	}); err != nil {
		t.Fatalf("mark source delivery as transferring: %v", err)
	}
	beforeEvents := len(f.store.AuditEvents())

	_, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "95959595-9595-4959-8959-959595959595"),
		reissueCommandFor(source, contract.ReissueReasonManualRotation))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindConflict || appErr.Code() != "reissue_delivery_in_progress" {
		t.Fatalf("Reissue with transferring delivery error = %v, want reissue_delivery_in_progress conflict", err)
	}
	if f.signer.calls != 1 || f.keyEngine.generateCalls != 1 {
		t.Fatalf("signer calls = %d, generated keys = %d; transferring delivery must reject before preparation", f.signer.calls, f.keyEngine.generateCalls)
	}
	after := currentSeriesSnapshot(t, f.store, source.SeriesID)
	if after.Series.Version() != snapshot.Series.Version() || after.Series.CurrentCertificateID() != source.CertificateID {
		t.Fatal("series changed despite rejecting a transferring source delivery")
	}
	if len(f.store.AuditEvents()) != beforeEvents {
		t.Fatalf("audit event count = %d, want unchanged %d", len(f.store.AuditEvents()), beforeEvents)
	}
	assertReissueDeliveryState(t, f.store, snapshot.CurrentKeyGeneration.ID(), domain.DeliveryStateTransferring)
}

func TestIssuanceReissueRejectsMismatchedDeliveryLineageBeforeSigningOrMutation(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	other, err := f.svc.Issue(context.Background(), issueMutationMeta(t, "94949494-9494-4949-8949-949494949494"),
		issueCommand(f.authorityID, "other-reissue-series"))
	if err != nil {
		t.Fatalf("issue unrelated certificate: %v", err)
	}
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		delivery, err := tx.Delivery().GetDeliveryByLeafKeyGenerationForUpdate(context.Background(), snapshot.CurrentKeyGeneration.ID())
		if err != nil {
			return err
		}
		mismatched, err := domain.NewDelivery(domain.DeliveryFacts{
			ID: delivery.ID(), LeafKeyGenerationID: delivery.LeafKeyGenerationID(), CertificateID: other.CertificateID,
			ExpiresAt: delivery.ExpiresAt(), State: delivery.State(), Version: delivery.Version(),
		})
		if err != nil {
			return err
		}
		return tx.Delivery().SaveDelivery(context.Background(), mismatched, delivery.Version())
	}); err != nil {
		t.Fatalf("seed mismatched delivery lineage: %v", err)
	}
	beforeEvents := len(f.store.AuditEvents())

	_, err = f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "93939393-9393-4939-8939-939393939393"),
		reissueCommandFor(source, contract.ReissueReasonManualRotation))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindUnavailable || appErr.Code() != "reissue_delivery_mismatch" {
		t.Fatalf("Reissue with mismatched delivery lineage error = %v, want reissue_delivery_mismatch unavailable", err)
	}
	if f.signer.calls != 2 || f.keyEngine.generateCalls != 2 {
		t.Fatalf("signer calls = %d, generated keys = %d; mismatched lineage must reject before reissue preparation", f.signer.calls, f.keyEngine.generateCalls)
	}
	after := currentSeriesSnapshot(t, f.store, source.SeriesID)
	if after.Series.Version() != snapshot.Series.Version() || after.Series.CurrentCertificateID() != source.CertificateID {
		t.Fatal("series changed despite rejecting mismatched delivery lineage")
	}
	if len(f.store.AuditEvents()) != beforeEvents {
		t.Fatalf("audit event count = %d, want unchanged %d", len(f.store.AuditEvents()), beforeEvents)
	}
	var sourceSecretErr error
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		_, sourceSecretErr = tx.Secrets().GetEncrypted(context.Background(), snapshot.CurrentKeyGeneration.KeyMaterialID(), domain.SecretPurposeLeafDelivery)
		return nil
	}); err != nil {
		t.Fatalf("read source key secret: %v", err)
	}
	if sourceSecretErr != nil {
		t.Fatalf("source key ciphertext error = %v, want it preserved on rejected lineage", sourceSecretErr)
	}
}

func TestIssuanceReissueKeyCompromiseMarksAndRevokesSource(t *testing.T) {
	f := newIssuanceFixture(t)
	initial := issueReissueSource(t, f)
	if err := markIssueDeliveryCompletedForTest(t, f, initial); err != nil {
		t.Fatalf("complete initial delivery: %v", err)
	}
	snapshot := currentSeriesSnapshot(t, f.store, initial.SeriesID)
	renewMeta := issueMutationMeta(t, "abababab-abab-4bab-8bab-abababababab")
	renewMeta.ExpectedVersion = contract.WithExpectedVersion(snapshot.Series.Version())
	renewed, err := f.svc.Renew(context.Background(), renewMeta, renewCommand(initial.SeriesID, initial.CertificateID))
	if err != nil {
		t.Fatalf("renew without key rotation: %v", err)
	}
	if renewed.KeyRotated || renewed.KeyGenerationID != snapshot.CurrentKeyGeneration.ID() {
		t.Fatalf("renewal = %+v, want same key generation before compromise", renewed)
	}
	current := contract.IssuanceView{SeriesID: initial.SeriesID, CertificateID: renewed.CertificateID}
	snapshot = currentSeriesSnapshot(t, f.store, initial.SeriesID)
	issuerID := sourceIssuerKeyID(t, f.store, initial.CertificateID)
	seedCRLState(t, f.store, issuerID)
	cmd := reissueCommandFor(current, contract.ReissueReasonKeyCompromise)
	result, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), cmd)
	if err != nil {
		t.Fatalf("Reissue after key compromise: %v", err)
	}
	if result.CertificateID == renewed.CertificateID || result.KeyGenerationID == snapshot.CurrentKeyGeneration.ID() || result.RenewalCount != 0 {
		t.Fatalf("reissue = %+v, want fresh key generation and reset count", result)
	}
	assertReissueRevocation(t, f.store, initial.CertificateID, domain.RevocationReasonKeyCompromise)
	assertReissueRevocation(t, f.store, renewed.CertificateID, domain.RevocationReasonKeyCompromise)
	var key port.KeyMaterial
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		key, err = tx.PKI().GetKeyMaterial(context.Background(), snapshot.CurrentKeyGeneration.KeyMaterialID())
		return err
	}); err != nil {
		t.Fatalf("read compromised key material: %v", err)
	}
	if key.CompromisedAt.IsZero() {
		t.Fatal("key_compromise reissue did not persist compromised_at")
	}
}

func TestIssuanceReissueEmergencyRequiresMatchingOpenImpactAndUsesTargetAuthority(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	targetAuthorityID := seedDistinctReissueAuthority(t, f)
	recordingAuthorizer := &recordingReissueAuthorizer{}
	f.svc.deps.Authorizer = recordingAuthorizer
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
	seedCRLState(t, f.store, sourceIssuerKeyID(t, f.store, source.CertificateID))
	assertReissueSourceDeliveryPending(t, f.store, snapshot.CurrentKeyGeneration.ID())
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
	assertPendingReissueCleanup(t, f.store, source.CertificateID, snapshot.CurrentKeyGeneration.ID(),
		snapshot.CurrentKeyGeneration.KeyMaterialID(), sourceIssuerKeyID(t, f.store, source.CertificateID))
	if !recordingAuthorizer.hasScopes(f.authorityID, targetAuthorityID) {
		t.Fatalf("authorization scopes = %#v, want both transition source and target authorities", recordingAuthorizer.scopes)
	}
}

func TestIssuanceReissueKeyCompromiseRevokesUnexpiredCertificateBeforeNotBefore(t *testing.T) {
	f := newIssuanceFixture(t)
	now := testNow().Add(domain.NewDuration(500 * time.Millisecond))
	f.svc.deps.Clock = fixedClock{now: now}
	source := issueReissueSource(t, f)

	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	var certificate domain.Certificate
	var sourceRecord port.LeafCertificateRecord
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		certificate, err = tx.PKI().GetCertificate(context.Background(), source.CertificateID)
		if err != nil {
			return err
		}
		sourceRecord, err = tx.PKI().GetLeafCertificateRecord(context.Background(), source.CertificateID)
		return err
	}); err != nil {
		t.Fatalf("read source certificate: %v", err)
	}
	if !certificate.Validity().NotBefore().After(now) || certificate.IsExpiredAt(now) {
		t.Fatalf("source validity = %+v at %s, want unexpired with a future not_before", certificate.Validity(), now)
	}
	expiredID, err := domain.ParseCertificateID(f.ids.NewUUID())
	if err != nil {
		t.Fatalf("expired certificate ID: %v", err)
	}
	expiredWindow, err := domain.NewValidityWindow(testNow().Add(domain.NewDuration(-2*time.Hour)), testNow().Add(domain.NewDuration(-time.Hour)))
	if err != nil {
		t.Fatalf("expired certificate window: %v", err)
	}
	expiredCertificate, err := domain.NewCertificate(domain.CertificateFacts{
		ID: expiredID, DER: []byte("expired-same-key-certificate"), KeyMaterialID: certificate.KeyMaterialID(),
		IssuerCAKeyGenerationID: certificate.IssuerCAKeyGenerationID(), Serial: serial(t, "e001"), Validity: expiredWindow,
		Subject: certificate.Subject(), SANs: certificate.SANs(), Kind: domain.CertificateKindLeaf, Profile: certificate.Profile(),
		KeyAlgorithm: certificate.KeyAlgorithm(), Origin: domain.CertificateOriginGenerated,
		CreatedByAccountID: certificate.CreatedByAccountID(), Version: 1,
	})
	if err != nil {
		t.Fatalf("expired certificate: %v", err)
	}
	expiredRecord := sourceRecord
	expiredRecord.CertificateID = expiredID
	expiredRecord.Operation = port.CertificateOperationRenew
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		if err := tx.PKI().InsertCertificate(context.Background(), expiredCertificate); err != nil {
			return err
		}
		return tx.PKI().InsertLeafCertificateRecord(context.Background(), expiredRecord)
	}); err != nil {
		t.Fatalf("seed expired same-key certificate: %v", err)
	}

	issuerID := sourceIssuerKeyID(t, f.store, source.CertificateID)
	seedCRLState(t, f.store, issuerID)
	cmd := reissueCommandFor(source, contract.ReissueReasonKeyCompromise)
	if _, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "97979797-9797-4979-8979-979797979797"), cmd); err != nil {
		t.Fatalf("Reissue after key compromise: %v", err)
	}
	assertReissueRevocation(t, f.store, source.CertificateID, domain.RevocationReasonKeyCompromise)
	var expiredRevocationErr error
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		_, expiredRevocationErr = tx.Revocations().FindForUpdate(context.Background(), certificate.IssuerCAKeyGenerationID(), expiredCertificate.Serial())
		return nil
	}); err != nil {
		t.Fatalf("read expired certificate revocation: %v", err)
	}
	if !errors.Is(expiredRevocationErr, port.ErrNotFound) {
		t.Fatalf("expired certificate revocation error = %v, want no revocation for an expired certificate", expiredRevocationErr)
	}
	state := crlState(t, f.store, issuerID)
	if state.RevocationGeneration() != 1 || state.RevocationGeneration() <= state.PublishedGeneration() {
		t.Fatalf("CRL state = %+v, want exactly one unpublished generation for the unexpired certificate", state)
	}
}

func TestIssuanceReissueRejectsUnsupportedEvidenceWithoutSigning(t *testing.T) {
	tests := []struct {
		name   string
		reason contract.ReissueReason
	}{
		{name: "failed reason with pending delivery", reason: contract.ReissueReasonDeliveryFailed},
		{name: "expired reason with pending delivery", reason: contract.ReissueReasonDeliveryExpired},
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

func TestIssuanceReissueCompromisedKeyRequiresCompromiseReason(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.PKI().MarkCompromised(context.Background(), snapshot.CurrentKeyGeneration.KeyMaterialID(), testNow())
	}); err != nil {
		t.Fatalf("mark current key compromised: %v", err)
	}
	_, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "12121212-1212-4212-8212-121212121212"),
		reissueCommandFor(source, contract.ReissueReasonManualRotation))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("manual reissue of a compromised key error = %v, want forbidden", err)
	}
	if f.signer.calls != 1 || f.keyEngine.generateCalls != 1 {
		t.Fatalf("signer calls = %d, generated keys = %d, want no extra preparation", f.signer.calls, f.keyEngine.generateCalls)
	}
}

func TestIssuanceReissueRequiresEmergencyTransitionModeAndTargetMatch(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	targetID := seedDistinctReissueAuthority(t, f)
	transitionID, err := domain.ParseTransitionID(f.ids.NewUUID())
	if err != nil {
		t.Fatalf("transition ID: %v", err)
	}
	transition, err := domain.NewTransition(domain.TransitionFacts{
		ID: transitionID, SourceAuthorityID: f.authorityID, TargetAuthorityID: targetID,
		Mode: domain.TransitionModeNormal, State: domain.TransitionStateInProgress,
		ReportedBy: issuanceTestAdminAccountID, ReportedAt: testNow(), Reason: "normal replacement", Version: 1,
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
		t.Fatalf("seed normal transition: %v", err)
	}
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	cmd := reissueCommandFor(source, contract.ReissueReasonEmergency)
	cmd.TransitionID = transitionID
	cmd.TargetAuthorityID = targetID
	_, err = f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "13131313-1313-4313-8313-131313131313"), cmd)
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindConflict {
		t.Fatalf("emergency request against normal transition error = %v, want conflict", err)
	}
	if f.signer.calls != 1 || f.keyEngine.generateCalls != 1 {
		t.Fatalf("signer calls = %d, generated keys = %d, want failure before preparation", f.signer.calls, f.keyEngine.generateCalls)
	}
}

func TestIssuanceReissueRequiresExistingOpenTransitionWithMatchingSourceAndTarget(t *testing.T) {
	tests := []struct {
		name        string
		state       domain.TransitionState
		missing     bool
		wrongSource bool
		wrongTarget bool
		wantCode    string
	}{
		{name: "missing transition", missing: true, wantCode: "transition_not_found"},
		{name: "closed transition", state: domain.TransitionStateClosed, wantCode: "transition_not_in_progress"},
		{name: "source mismatch", wrongSource: true, wantCode: "transition_source_mismatch"},
		{name: "target mismatch", wrongTarget: true, wantCode: "transition_target_mismatch"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			source := issueReissueSource(t, f)
			targetID := seedDistinctReissueAuthority(t, f)
			transitionID, err := domain.ParseTransitionID(f.ids.NewUUID())
			if err != nil {
				t.Fatalf("transition ID: %v", err)
			}
			transitionSourceID := f.authorityID
			transitionTargetID := targetID
			requestTargetID := targetID
			state := domain.TransitionStateInProgress
			if tc.state != "" {
				state = tc.state
			}
			if tc.wrongSource {
				transitionSourceID = targetID
				transitionTargetID = f.authorityID
				requestTargetID = f.authorityID
			}
			if tc.wrongTarget {
				requestTargetID = f.authorityID
			}
			if !tc.missing {
				transition, err := domain.NewTransition(domain.TransitionFacts{
					ID: transitionID, SourceAuthorityID: transitionSourceID, TargetAuthorityID: transitionTargetID,
					Mode: domain.TransitionModeEmergency, State: state, ReportedBy: issuanceTestAdminAccountID,
					ReportedAt: testNow(), Reason: "test transition", Version: 1,
				})
				if err != nil {
					t.Fatalf("NewTransition: %v", err)
				}
				if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
					return tx.Transitions().Insert(context.Background(), transition)
				}); err != nil {
					t.Fatalf("seed transition: %v", err)
				}
			}
			snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
			cmd := reissueCommandFor(source, contract.ReissueReasonEmergency)
			cmd.TransitionID = transitionID
			cmd.TargetAuthorityID = requestTargetID
			_, err = f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "92929292-9292-4292-8292-929292929292"), cmd)
			var appErr *contract.AppError
			if !errors.As(err, &appErr) || appErr.Code() != tc.wantCode {
				t.Fatalf("Reissue error = %v, want %s", err, tc.wantCode)
			}
			if f.signer.calls != 1 || f.keyEngine.generateCalls != 1 {
				t.Fatalf("signer calls = %d, generated keys = %d; invalid transition must reject before preparation", f.signer.calls, f.keyEngine.generateCalls)
			}
			after := currentSeriesSnapshot(t, f.store, source.SeriesID)
			if after.Series.Version() != snapshot.Series.Version() || after.Series.CurrentCertificateID() != source.CertificateID {
				t.Fatal("series changed despite rejecting an invalid emergency transition")
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
	guard := &sync.Mutex{}
	f.svc.deps.IDs = synchronizedReissueIDs{IDGenerator: f.ids, mu: guard}
	f.svc.deps.KeyEngine = synchronizedReissueKeyEngine{KeyEngine: f.keyEngine, mu: guard}
	f.svc.deps.SerialGenerator = synchronizedReissueSerials{SerialGenerator: f.serials, mu: guard}
	f.svc.deps.CertificateSigner = synchronizedReissueSigner{CertificateSigner: f.signer, mu: guard}
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
	after := currentSeriesSnapshot(t, f.store, source.SeriesID)
	if after.Series.Version() != snapshot.Series.Version().Next() || after.Series.CurrentCertificateID() != results[0].CertificateID {
		t.Fatalf("series after concurrent request = version %d/current %s, want one committed replacement from version %d", after.Series.Version(), after.Series.CurrentCertificateID(), snapshot.Series.Version())
	}
}

func TestIssuanceReissueKeyCompromiseRollsBackAllChangesWhenAuditFails(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	issuerID := sourceIssuerKeyID(t, f.store, source.CertificateID)
	seedCRLState(t, f.store, issuerID)
	assertReissueSourceDeliveryPending(t, f.store, snapshot.CurrentKeyGeneration.ID())
	beforeEvents := len(f.store.AuditEvents())
	meta := reissueMeta(t, snapshot.Series.Version(), "ffffffff-ffff-4fff-8fff-ffffffffffff")
	cmd := reissueCommandFor(source, contract.ReissueReasonKeyCompromise)
	f.svc.deps.UnitOfWork = failingReissueAuditUoW{inner: f.store}
	if _, err := f.svc.Reissue(context.Background(), meta, cmd); err == nil {
		t.Fatal("Reissue succeeded when audit persistence failed")
	}
	if len(f.store.AuditEvents()) != beforeEvents {
		t.Fatalf("audit event count = %d, want unchanged %d after rollback", len(f.store.AuditEvents()), beforeEvents)
	}
	after := currentSeriesSnapshot(t, f.store, source.SeriesID)
	if after.Series.Version() != snapshot.Series.Version() || after.Series.CurrentCertificateID() != source.CertificateID {
		t.Fatal("series pointer/version changed despite failed audit and rollback")
	}
	var key port.KeyMaterial
	var revocationErr error
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		key, err = tx.PKI().GetKeyMaterial(context.Background(), snapshot.CurrentKeyGeneration.KeyMaterialID())
		if err != nil {
			return err
		}
		certificate, err := tx.PKI().GetCertificate(context.Background(), source.CertificateID)
		if err != nil {
			return err
		}
		_, revocationErr = tx.Revocations().FindForUpdate(context.Background(), certificate.IssuerCAKeyGenerationID(), certificate.Serial())
		return nil
	}); err != nil {
		t.Fatalf("read post-rollback state: %v", err)
	}
	if !key.CompromisedAt.IsZero() {
		t.Fatal("compromised_at mutation survived the failed reissue transaction")
	}
	if !errors.Is(revocationErr, port.ErrNotFound) {
		t.Fatalf("source revocation error = %v, want no committed revocation", revocationErr)
	}
	assertReissueSourceDeliveryPending(t, f.store, snapshot.CurrentKeyGeneration.ID())
	if state := crlState(t, f.store, issuerID); state.RevocationGeneration() != 0 {
		t.Fatalf("CRL generation after audit rollback = %d, want 0", state.RevocationGeneration())
	}
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		_, err := tx.Secrets().GetEncrypted(context.Background(), snapshot.CurrentKeyGeneration.KeyMaterialID(), domain.SecretPurposeLeafDelivery)
		return err
	}); err != nil {
		t.Fatalf("old private-key ciphertext error = %v, want ciphertext restored by rollback", err)
	}
	if f.signer.calls < 2 {
		t.Fatal("test did not reach signing before injected audit failure")
	}
}

func TestIssuanceReissueRollsBackAllChangesWhenCRLStateSaveFails(t *testing.T) {
	f := newIssuanceFixture(t)
	source := issueReissueSource(t, f)
	snapshot := currentSeriesSnapshot(t, f.store, source.SeriesID)
	issuerID := sourceIssuerKeyID(t, f.store, source.CertificateID)
	seedCRLState(t, f.store, issuerID)
	assertReissueSourceDeliveryPending(t, f.store, snapshot.CurrentKeyGeneration.ID())
	beforeEvents := len(f.store.AuditEvents())
	f.svc.deps.UnitOfWork = failingReissueCRLUoW{inner: f.store}
	_, err := f.svc.Reissue(context.Background(), reissueMeta(t, snapshot.Series.Version(), "91919191-9191-4191-8191-919191919191"),
		reissueCommandFor(source, contract.ReissueReasonManualRotation))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Code() != "revocation_crl_state_save_failed" {
		t.Fatalf("Reissue error = %v, want CRL state save failure", err)
	}
	if len(f.store.AuditEvents()) != beforeEvents {
		t.Fatalf("audit event count = %d, want unchanged %d after CRL rollback", len(f.store.AuditEvents()), beforeEvents)
	}
	after := currentSeriesSnapshot(t, f.store, source.SeriesID)
	if after.Series.Version() != snapshot.Series.Version() || after.Series.CurrentCertificateID() != source.CertificateID {
		t.Fatal("series pointer/version changed despite CRL failure rollback")
	}
	assertReissueSourceDeliveryPending(t, f.store, snapshot.CurrentKeyGeneration.ID())
	if state := crlState(t, f.store, issuerID); state.RevocationGeneration() != 0 {
		t.Fatalf("CRL generation after rollback = %d, want 0", state.RevocationGeneration())
	}
	var sourceCertificate domain.Certificate
	var revocationErr error
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		sourceCertificate, err = tx.PKI().GetCertificate(context.Background(), source.CertificateID)
		if err != nil {
			return err
		}
		_, revocationErr = tx.Revocations().FindForUpdate(context.Background(), sourceCertificate.IssuerCAKeyGenerationID(), sourceCertificate.Serial())
		if _, err := tx.Secrets().GetEncrypted(context.Background(), snapshot.CurrentKeyGeneration.KeyMaterialID(), domain.SecretPurposeLeafDelivery); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("read post-rollback source state: %v", err)
	}
	if !errors.Is(revocationErr, port.ErrNotFound) {
		t.Fatalf("source revocation error = %v, want no committed revocation", revocationErr)
	}
	if f.signer.calls < 2 || f.keyEngine.generateCalls != 2 {
		t.Fatalf("signer calls = %d, generated keys = %d; injected CRL failure must occur after reissue preparation", f.signer.calls, f.keyEngine.generateCalls)
	}
}

type failingReissueAuditRepo struct{ port.AuditRepository }

func (failingReissueAuditRepo) Append(context.Context, port.AuditEvent, port.AuditScope) error {
	return errors.New("injected reissue audit failure")
}

type failingReissueAuditTxStores struct{ port.TxStores }

func (f failingReissueAuditTxStores) Audit() port.AuditRepository {
	return failingReissueAuditRepo{AuditRepository: f.TxStores.Audit()}
}

type failingReissueAuditUoW struct{ inner port.UnitOfWork }

func (u failingReissueAuditUoW) Write(ctx context.Context, fn func(port.TxStores) error) error {
	return u.inner.Write(ctx, func(tx port.TxStores) error { return fn(failingReissueAuditTxStores{TxStores: tx}) })
}

type failingReissueCRLRepo struct{ port.CRLRepository }

func (failingReissueCRLRepo) SaveState(context.Context, domain.CRLState, domain.Version) error {
	return errors.New("injected reissue CRL state save failure")
}

type failingReissueCRLTxStores struct{ port.TxStores }

func (f failingReissueCRLTxStores) CRLs() port.CRLRepository {
	return failingReissueCRLRepo{CRLRepository: f.TxStores.CRLs()}
}

type failingReissueCRLUoW struct{ inner port.UnitOfWork }

func (u failingReissueCRLUoW) Write(ctx context.Context, fn func(port.TxStores) error) error {
	return u.inner.Write(ctx, func(tx port.TxStores) error { return fn(failingReissueCRLTxStores{TxStores: tx}) })
}

type recordingReissueAuthorizer struct {
	scopes []port.AuthorizationScope
}

func (a *recordingReissueAuthorizer) Authorize(_ context.Context, _ contract.Principal, action port.Action, scope port.AuthorizationScope) error {
	if action == port.ActionIssuanceReissue {
		a.scopes = append(a.scopes, scope)
	}
	return nil
}

func (a *recordingReissueAuthorizer) hasScopes(want ...domain.AuthorityID) bool {
	for _, scope := range a.scopes {
		found := make(map[domain.AuthorityID]bool)
		for _, id := range scope.AuthorityIDs() {
			found[id] = true
		}
		allFound := true
		for _, id := range want {
			if !found[id] {
				allFound = false
				break
			}
		}
		if allFound {
			return true
		}
	}
	return false
}

type synchronizedReissueIDs struct {
	port.IDGenerator
	mu *sync.Mutex
}

func (g synchronizedReissueIDs) NewUUID() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.IDGenerator.NewUUID()
}

type synchronizedReissueKeyEngine struct {
	port.KeyEngine
	mu *sync.Mutex
}

func (e synchronizedReissueKeyEngine) Generate(ctx context.Context, spec port.KeySpec) (port.GeneratedKey, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.KeyEngine.Generate(ctx, spec)
}

type synchronizedReissueSerials struct {
	port.SerialGenerator
	mu *sync.Mutex
}

func (g synchronizedReissueSerials) NewSerial(ctx context.Context) (domain.SerialNumber, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.SerialGenerator.NewSerial(ctx)
}

type synchronizedReissueSigner struct {
	port.CertificateSigner
	mu *sync.Mutex
}

func (s synchronizedReissueSigner) Sign(ctx context.Context, request port.CertificateSigningRequest, secret domain.EncryptedSecret) (domain.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.CertificateSigner.Sign(ctx, request, secret)
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

func seedDistinctReissueAuthority(t *testing.T, f *issuanceFixture) domain.AuthorityID {
	t.Helper()
	ctx := context.Background()
	authorityID, err := domain.ParseAuthorityID(f.ids.NewUUID())
	if err != nil {
		t.Fatalf("target authority ID: %v", err)
	}
	parentID, err := domain.ParseAuthorityID(f.ids.NewUUID())
	if err != nil {
		t.Fatalf("target parent ID: %v", err)
	}
	keyGenerationID, err := domain.ParseCAKeyGenerationID(f.ids.NewUUID())
	if err != nil {
		t.Fatalf("target key generation ID: %v", err)
	}
	keyMaterialID, err := domain.ParseKeyMaterialID(f.ids.NewUUID())
	if err != nil {
		t.Fatalf("target key material ID: %v", err)
	}
	certificateID, err := domain.ParseCertificateID(f.ids.NewUUID())
	if err != nil {
		t.Fatalf("target certificate ID: %v", err)
	}
	publicKey, err := domain.NewPublicKey(domain.KeyAlgorithmECDSAP256, []byte("target public key "+string(keyMaterialID)))
	if err != nil {
		t.Fatalf("target public key: %v", err)
	}
	now := testNow()
	window, err := domain.NewValidityWindow(now.Add(domain.NewDuration(-time.Hour)), now.Add(domain.NewDuration(24*365*5*time.Hour)))
	if err != nil {
		t.Fatalf("target issuer window: %v", err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "Target Intermediate CA"})
	if err != nil {
		t.Fatalf("target issuer subject: %v", err)
	}
	certificate, err := domain.NewCertificate(domain.CertificateFacts{
		ID: certificateID, DER: []byte("target issuer DER " + string(certificateID)), KeyMaterialID: keyMaterialID,
		IssuerCAKeyGenerationID: keyGenerationID, Serial: serial(t, "91"), Validity: window,
		Subject: subject, Kind: domain.CertificateKindCA, KeyAlgorithm: domain.KeyAlgorithmECDSAP256,
		Origin: domain.CertificateOriginGenerated,
	})
	if err != nil {
		t.Fatalf("target issuer certificate: %v", err)
	}
	secret, err := domain.NewEncryptedSecret(domain.EncryptedSecretFacts{
		OwnerKeyID: keyMaterialID, Purpose: domain.SecretPurposeCASigning, FormatVersion: 1,
		EncryptionGenerationID: "gen-1", Nonce: []byte("target-nonce-0000001"), Ciphertext: []byte("target-ca-ciphertext"),
	})
	if err != nil {
		t.Fatalf("target issuer secret: %v", err)
	}
	authority, err := domain.NewAuthority(domain.AuthorityFacts{
		ID: authorityID, Kind: domain.AuthorityKindIntermediate, Name: "Target Intermediate",
		ManagementParentID: parentID, IssuanceState: domain.IssuanceStateEnabled,
		IssuanceCertificateID: certificateID, KeyGenerationID: keyGenerationID,
		KeyAvailable: true, CertificateWindow: window, Version: 1,
	})
	if err != nil {
		t.Fatalf("target authority: %v", err)
	}
	if err := f.store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{ID: keyMaterialID, PublicKey: publicKey, Origin: "generated"}); err != nil {
			return err
		}
		if err := tx.PKI().InsertKeyGeneration(ctx, port.CAKeyGeneration{
			ID: keyGenerationID, AuthorityID: authorityID, KeyMaterialID: keyMaterialID, GenerationNo: 1,
		}); err != nil {
			return err
		}
		if err := tx.PKI().InsertCertificate(ctx, certificate); err != nil {
			return err
		}
		if err := tx.PKI().InsertCACertificateRecord(ctx, port.CACertificateRecord{CertificateID: certificateID, CAKeyGenerationID: keyGenerationID}); err != nil {
			return err
		}
		if err := tx.Secrets().InsertEncrypted(ctx, secret); err != nil {
			return err
		}
		return tx.PKI().InsertAuthority(ctx, authority)
	}); err != nil {
		t.Fatalf("seed target authority: %v", err)
	}
	return authorityID
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

func assertReissueSourceDeliveryPending(t *testing.T, store *porttest.Store, generationID domain.LeafKeyGenerationID) {
	t.Helper()
	var delivery domain.Delivery
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		delivery, err = tx.Delivery().GetDeliveryByLeafKeyGenerationForUpdate(context.Background(), generationID)
		return err
	}); err != nil {
		t.Fatalf("read source delivery: %v", err)
	}
	if delivery.State() != domain.DeliveryStatePending || delivery.ExpiresAt().IsExpiredAt(testNow()) {
		t.Fatalf("source delivery = state %s, expires %s; want pending and unexpired at %s", delivery.State(), delivery.ExpiresAt(), testNow())
	}
}

func assertReissueDeliveryState(t *testing.T, store *porttest.Store, generationID domain.LeafKeyGenerationID, want domain.DeliveryState) {
	t.Helper()
	var delivery domain.Delivery
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		delivery, err = tx.Delivery().GetDeliveryByLeafKeyGenerationForUpdate(context.Background(), generationID)
		return err
	}); err != nil {
		t.Fatalf("read delivery: %v", err)
	}
	if delivery.State() != want {
		t.Fatalf("delivery state = %s, want %s", delivery.State(), want)
	}
}

func assertPendingReissueCleanup(
	t *testing.T,
	store *porttest.Store,
	certificateID domain.CertificateID,
	generationID domain.LeafKeyGenerationID,
	keyMaterialID domain.KeyMaterialID,
	issuerID domain.CAKeyGenerationID,
) {
	t.Helper()
	var revocation domain.Revocation
	var revocationErr error
	var state domain.CRLState
	var delivery domain.Delivery
	var secretErr error
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		certificate, err := tx.PKI().GetCertificate(context.Background(), certificateID)
		if err != nil {
			return err
		}
		revocation, revocationErr = tx.Revocations().FindForUpdate(context.Background(), certificate.IssuerCAKeyGenerationID(), certificate.Serial())
		state, err = tx.CRLs().GetStateForUpdate(context.Background(), issuerID)
		if err != nil {
			return err
		}
		delivery, err = tx.Delivery().GetDeliveryByLeafKeyGenerationForUpdate(context.Background(), generationID)
		if err != nil {
			return err
		}
		_, secretErr = tx.Secrets().GetEncrypted(context.Background(), keyMaterialID, domain.SecretPurposeLeafDelivery)
		return nil
	})
	if err != nil {
		t.Fatalf("read source cleanup state: %v", err)
	}
	if revocationErr != nil {
		t.Fatalf("source certificate revocation error = %v, want a committed revocation", revocationErr)
	}
	if revocation.CertificateID() != certificateID || revocation.Reason() != domain.RevocationReasonUnspecified {
		t.Fatalf("source revocation = %#v, want certificate %s with unspecified reason", revocation, certificateID)
	}
	if state.RevocationGeneration() <= state.PublishedGeneration() {
		t.Fatalf("CRL state generation = %d, published generation = %d; want dirty CRL state", state.RevocationGeneration(), state.PublishedGeneration())
	}
	if delivery.State() != domain.DeliveryStateFailed || delivery.FailureCode() != "reissued" {
		t.Fatalf("source delivery = state %s, failure code %q; want failed/reissued", delivery.State(), delivery.FailureCode())
	}
	if !errors.Is(secretErr, port.ErrNotFound) {
		t.Fatalf("old private-key ciphertext error = %v, want deleted ciphertext", secretErr)
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
			alreadyExpired, buildErr := domain.NewDelivery(domain.DeliveryFacts{
				ID: delivery.ID(), LeafKeyGenerationID: delivery.LeafKeyGenerationID(), CertificateID: delivery.CertificateID(),
				ExpiresAt: testNow().Add(domain.NewDuration(-time.Second)), State: domain.DeliveryStatePending, Version: delivery.Version(),
			})
			if buildErr != nil {
				return buildErr
			}
			if err := tx.Delivery().SaveDelivery(context.Background(), alreadyExpired, delivery.Version()); err != nil {
				return err
			}
			next, err = alreadyExpired.Expire(testNow())
			if err == nil {
				return tx.Delivery().SaveDelivery(context.Background(), next, alreadyExpired.Version())
			}
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
