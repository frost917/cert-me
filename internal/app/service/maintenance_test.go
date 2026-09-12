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
)

func newMaintenanceTestService(t *testing.T, store *porttest.Store) *MaintenanceService {
	t.Helper()
	svc, err := NewMaintenanceService(MaintenanceDeps{
		CommonDeps: CommonDeps{
			UnitOfWork: store,
			ReadStore:  store,
			Authorizer: &toggleAuthorizer{allow: true},
			Clock:      fixedClock{now: testNow()},
			IDs:        &seqIDs{},
		},
		KeyEngine:   &fakeKeyEngine{},
		RuntimeGate: &fakeRuntimeGate{},
	})
	if err != nil {
		t.Fatalf("new maintenance service: %v", err)
	}
	return svc
}

func TestMaintenanceRestoreInvalidatesAdminResetTokens(t *testing.T) {
	store := porttest.NewStore()
	seedAdminSessionForIssuance(t, store)

	resetTokenID, err := domain.ParseResetTokenID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	if err != nil {
		t.Fatalf("reset token id: %v", err)
	}
	tokenHash, err := domain.NewTokenHash(domain.NewFingerprint([]byte("restore-reset-token")))
	if err != nil {
		t.Fatalf("token hash: %v", err)
	}
	token, err := domain.IssueAdminResetToken(
		resetTokenID,
		issuanceTestAdminAccountID,
		tokenHash,
		domain.AuthEpoch(1),
		testNow(),
		domain.DefaultResetPolicy(),
	)
	if err != nil {
		t.Fatalf("reset token: %v", err)
	}
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		if err := tx.Installation().Save(context.Background(), port.Installation{
			FirstAdminID: issuanceTestAdminAccountID,
		}, 0); err != nil {
			return err
		}
		return tx.Accounts().InsertResetToken(context.Background(), token)
	}); err != nil {
		t.Fatalf("seed restore state: %v", err)
	}

	if err := newMaintenanceTestService(t, store).invalidateAllAdminSessions(context.Background()); err != nil {
		t.Fatalf("invalidate administrator state: %v", err)
	}

	var stored domain.AdminResetToken
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		stored, err = tx.Accounts().GetResetToken(context.Background(), tokenHash)
		return err
	}); err != nil {
		t.Fatalf("read reset token: %v", err)
	}
	if !stored.IsInvalidated() {
		t.Fatal("reset token is still valid after restore finalization")
	}
	if stored.InvalidatedAt() != testNow() {
		t.Fatalf("invalidated_at = %v, want %v", stored.InvalidatedAt(), testNow())
	}

	var sessionErr error
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		_, sessionErr = tx.Accounts().GetSessionForUpdate(context.Background(), issuanceTestSessionID)
		return nil
	}); err != nil {
		t.Fatalf("read invalidated session: %v", err)
	}
	if sessionErr == nil {
		t.Fatal("administrator session is still present after restore finalization")
	}
}

func TestMaintenanceExpireDeliveriesUsesDeliveryExpiredFailureCode(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(-time.Second)), domain.DeliveryStatePending)
	seedCRLStateFor(t, fx.store, fx.issuerID)

	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{
		Principal: mustInternalPrincipal(t, contract.InternalOperationDeliveryExpiry),
	}}
	outcome, err := newMaintenanceTestService(t, fx.store).ExpireDeliveries(context.Background(), meta)
	if err != nil {
		t.Fatalf("expire deliveries: %v", err)
	}
	if outcome.Failed != 1 {
		t.Fatalf("failed = %d, want 1", outcome.Failed)
	}
	delivery := storedDelivery(t, fx.store, fx.deliverID)
	if delivery.State() != domain.DeliveryStateFailed {
		t.Fatalf("state = %s, want failed", delivery.State())
	}
	if delivery.FailureCode() != deliveryExpiredFailureCode {
		t.Fatalf("failure code = %q, want %q", delivery.FailureCode(), deliveryExpiredFailureCode)
	}
	if n := countRevocations(t, fx.store, fx.issuerID, distSerial(t, "a1")); n != 1 {
		t.Fatalf("revocations = %d, want 1", n)
	}
}

func TestMaintenanceRestoreCleansUnexpiredPendingDeliveryAndAllPublicGrants(t *testing.T) {
	future := distTestNow().Add(domain.NewDuration(time.Hour))
	fx := seedPrivateFixture(t, future, domain.DeliveryStatePending)
	seedCRLStateFor(t, fx.store, fx.issuerID)

	publicGrant := distGrant(t, 2, domain.GrantPurposeLeafPublic, fx.certID, "", tokenHashFor("restore-public-token-0123456789ABCDEF"), future)
	if err := fx.store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Delivery().InsertGrant(context.Background(), publicGrant)
	}); err != nil {
		t.Fatalf("seed public grant: %v", err)
	}

	if err := newMaintenanceTestService(t, fx.store).deleteRestorePendingKeys(context.Background()); err != nil {
		t.Fatalf("restore delivery cleanup: %v", err)
	}

	delivery := storedDelivery(t, fx.store, fx.deliverID)
	if delivery.State() != domain.DeliveryStateFailed {
		t.Fatalf("state = %s, want failed", delivery.State())
	}
	if delivery.FailureCode() != restoreDeliveryFailureCode {
		t.Fatalf("failure code = %q, want %q", delivery.FailureCode(), restoreDeliveryFailureCode)
	}

	if err := fx.store.Read(context.Background(), func(tx port.TxStores) error {
		if _, err := tx.Secrets().GetEncrypted(context.Background(), fx.keyMatID, domain.SecretPurposeLeafDelivery); err == nil {
			return fmt.Errorf("leaf delivery secret still exists")
		} else if !errors.Is(err, port.ErrNotFound) {
			return err
		}
		private, err := tx.Delivery().GetGrantForUpdate(context.Background(), tokenHashFor(fx.rawToken))
		if err != nil {
			return err
		}
		if private.InvalidatedAt().IsZero() {
			return fmt.Errorf("private grant is still valid")
		}
		public, err := tx.Delivery().GetGrantForUpdate(context.Background(), publicGrant.TokenHash())
		if err != nil {
			return err
		}
		if public.InvalidatedAt().IsZero() {
			return fmt.Errorf("public grant is still valid")
		}
		return nil
	}); err != nil {
		t.Fatalf("verify restored delivery cleanup: %v", err)
	}
	if n := countRevocations(t, fx.store, fx.issuerID, distSerial(t, "a1")); n != 1 {
		t.Fatalf("revocations = %d, want 1", n)
	}
}

func TestMaintenanceFinalizeRestoreKeepsPendingCRLInDedicatedRunStore(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	seedRestoreOperationalAuthority(t, fx)
	seedCRLStateFor(t, fx.store, fx.issuerID)
	runID, err := domain.ParseJobID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("run id: %v", err)
	}
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{
		Principal: mustInternalPrincipal(t, contract.InternalOperationRestoreFinalize),
	}}
	result, err := newMaintenanceTestService(t, fx.store).FinalizeRestore(context.Background(), meta, contract.MaintenanceFinalizeRestoreCommand{
		Options: contract.MaintenanceFinalizeRestoreOptions{RunID: runID, InvalidateAllSessions: true, DeletePendingKeys: true},
	})
	if err != nil {
		t.Fatalf("finalize restore: %v", err)
	}
	if result.Completed || result.Phase != contract.MaintenancePhaseBlocked {
		t.Fatalf("result = %+v, want blocked run pending CRL publication", result)
	}
	if len(result.BlockingCAIDs) != 1 || result.BlockingCAIDs[0] != fx.managementAuthorityID {
		t.Fatalf("blocking CA ids = %v, want [%s]", result.BlockingCAIDs, fx.managementAuthorityID)
	}
	if n := jobCount(t, fx.store); n != 1 {
		t.Fatalf("jobs = %d, want only the CRL publication demand, not restore state", n)
	}
	if err := fx.store.Read(context.Background(), func(tx port.TxStores) error {
		run, err := tx.Maintenance().GetRunForUpdate(context.Background(), runID)
		if err != nil {
			return err
		}
		if run.Kind != contract.MaintenanceKindRestoreFinalize || run.Phase != contract.MaintenancePhaseBlocked {
			return fmt.Errorf("stored run = %+v", run)
		}
		if !run.CompletedAt.IsZero() {
			return fmt.Errorf("completed_at = %v, want zero while CRL is pending", run.CompletedAt)
		}
		if run.ErrorCode != "maintenance_restore_crl_pending" {
			return fmt.Errorf("error_code = %q, want maintenance_restore_crl_pending", run.ErrorCode)
		}
		requirements, err := tx.Maintenance().ListCRLRequirements(context.Background(), runID)
		if err != nil {
			return err
		}
		if len(requirements) != 1 || requirements[0].SatisfiedCRLID != "" {
			return fmt.Errorf("crl requirements = %+v, want one unsatisfied requirement", requirements)
		}
		return nil
	}); err != nil {
		t.Fatalf("verify maintenance run: %v", err)
	}
}

func TestMaintenanceFinalizeRestoreFinishesAfterRequiredCRLIsPublished(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	seedRestoreOperationalAuthority(t, fx)
	seedCRLStateFor(t, fx.store, fx.issuerID)
	runID, err := domain.ParseJobID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	if err != nil {
		t.Fatalf("run id: %v", err)
	}
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{
		Principal: mustInternalPrincipal(t, contract.InternalOperationRestoreFinalize),
	}}
	svc := newMaintenanceTestService(t, fx.store)
	first, err := svc.FinalizeRestore(context.Background(), meta, contract.MaintenanceFinalizeRestoreCommand{
		Options: contract.MaintenanceFinalizeRestoreOptions{RunID: runID, InvalidateAllSessions: true, DeletePendingKeys: true},
	})
	if err != nil {
		t.Fatalf("first restore finalize: %v", err)
	}
	if first.Completed || first.Phase != contract.MaintenancePhaseBlocked {
		t.Fatalf("first result = %+v, want blocked while CRL demand is pending", first)
	}

	publishCRLDocument(t, fx.store, &seqIDs{}, fx.issuerID, 1,
		testNow(), testNow().Add(domain.NewDuration(24*time.Hour)), testNow().Add(domain.NewDuration(12*time.Hour)))

	second, err := svc.FinalizeRestore(context.Background(), meta, contract.MaintenanceFinalizeRestoreCommand{
		Options: contract.MaintenanceFinalizeRestoreOptions{RunID: runID, InvalidateAllSessions: true, DeletePendingKeys: true},
	})
	if err != nil {
		t.Fatalf("second restore finalize: %v", err)
	}
	if !second.Completed || second.Phase != contract.MaintenancePhaseFinished {
		t.Fatalf("second result = %+v, want completed maintenance run", second)
	}
	if len(second.BlockingCAIDs) != 0 {
		t.Fatalf("blocking CA ids = %v, want none after CRL publication", second.BlockingCAIDs)
	}

	if err := fx.store.Read(context.Background(), func(tx port.TxStores) error {
		run, err := tx.Maintenance().GetRunForUpdate(context.Background(), runID)
		if err != nil {
			return err
		}
		if run.Phase != contract.MaintenancePhaseFinished || run.CompletedAt.IsZero() {
			return fmt.Errorf("stored run = %+v, want finished with completion time", run)
		}
		requirements, err := tx.Maintenance().ListCRLRequirements(context.Background(), runID)
		if err != nil {
			return err
		}
		if len(requirements) != 1 || requirements[0].SatisfiedCRLID == "" {
			return fmt.Errorf("crl requirements = %+v, want satisfied evidence", requirements)
		}
		return nil
	}); err != nil {
		t.Fatalf("verify completed restore run: %v", err)
	}
}

func seedRestoreOperationalAuthority(t *testing.T, fx distFixture) {
	t.Helper()
	ctx := context.Background()
	keyMaterialID := distKeyMaterialID(t, 901)
	publicKey, err := domain.NewPublicKey(domain.KeyAlgorithmECDSAP256, []byte("restore-operational-ca-public-key"))
	if err != nil {
		t.Fatalf("restore public key: %v", err)
	}
	authority, err := domain.NewAuthority(domain.AuthorityFacts{
		ID:                fx.managementAuthorityID,
		Kind:              domain.AuthorityKindRoot,
		Name:              "Restore operational root",
		IssuanceState:     domain.IssuanceStateStopped,
		KeyGenerationID:   fx.issuerID,
		KeyAvailable:      true,
		CertificateWindow: distValidity(t),
	})
	if err != nil {
		t.Fatalf("restore authority: %v", err)
	}
	if err := fx.store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{ID: keyMaterialID, PublicKey: publicKey, Origin: "generated"}); err != nil {
			return err
		}
		if err := tx.PKI().InsertKeyGeneration(ctx, port.CAKeyGeneration{
			ID: fx.issuerID, AuthorityID: fx.managementAuthorityID, KeyMaterialID: keyMaterialID, GenerationNo: 1,
		}); err != nil {
			return err
		}
		return tx.PKI().InsertAuthority(ctx, authority)
	}); err != nil {
		t.Fatalf("seed restore operational authority: %v", err)
	}
}
