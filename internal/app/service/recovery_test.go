package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

func recoveryService(t *testing.T, store *porttest.Store) *DistributionService {
	t.Helper()
	return newDistributionService(t, distDeps(t, store, store, okEncoder("payload"), &fakeRuntimeGate{}))
}

// TestRecoverInterruptedTransfers_FailureCodeIsInterruptedTransfer pins the
// literal §14.1 name, not just the recoveryFailureCode constant against
// itself: "감사 action/failure_code로 transfer_failed·delivery_expired·
// interrupted_transfer 원인을 구별한다." Before this fix the constant was
// "restart_recovery", which this exact literal comparison would have caught
// failing.
func TestRecoverInterruptedTransfers_FailureCodeIsInterruptedTransfer(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStateTransferring)
	seedCRLStateFor(t, fx.store, fx.issuerID)

	if _, err := recoveryService(t, fx.store).RecoverInterruptedTransfers(context.Background()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if got := storedDelivery(t, fx.store, fx.deliverID).FailureCode(); got != "interrupted_transfer" {
		t.Fatalf("failure code = %q, want %q", got, "interrupted_transfer")
	}
}

// TestRecoverInterruptedTransfers_AuditScopeIsManagementAuthority is §14.6
// applied to recovery: the revocation audit applyRevocations appends for an
// interrupted transfer must be scoped to the certificate's stored
// management authority, never empty and never the cryptographic issuer.
// Before the fix, recovery.go built its RevocationChange with no
// AuthorityID at all, so this scope was always empty.
func TestRecoverInterruptedTransfers_AuditScopeIsManagementAuthority(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStateTransferring)
	seedCRLStateFor(t, fx.store, fx.issuerID)
	capture := &auditScopeCapture{}
	wrapped := &scopeCapturingStore{inner: fx.store, capture: capture}
	svc := newDistributionService(t, distDeps(t, wrapped, wrapped, okEncoder("payload"), &fakeRuntimeGate{}))

	if _, err := svc.RecoverInterruptedTransfers(context.Background()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	assertAllScopesAreManagementAuthority(t, capture, fx.managementAuthorityID, fx.issuerID)
}

func storedDelivery(t *testing.T, store *porttest.Store, id domain.DeliveryID) domain.Delivery {
	t.Helper()
	var found domain.Delivery
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		var readErr error
		found, readErr = tx.Delivery().GetDeliveryForUpdate(context.Background(), id)
		return readErr
	}); err != nil {
		t.Fatalf("read delivery: %v", err)
	}
	return found
}

// A transfer the previous process left mid-flight is failed, and the key is
// revoked with its CRL demand and audit trail in the same commit.
func TestRecoverInterruptedTransfersFailsAndRevokesLeftoverTransferring(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStateTransferring)
	seedCRLStateFor(t, fx.store, fx.issuerID)

	outcome, err := recoveryService(t, fx.store).RecoverInterruptedTransfers(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if outcome.Failed != 1 {
		t.Fatalf("failed = %d, want 1", outcome.Failed)
	}
	delivery := storedDelivery(t, fx.store, fx.deliverID)
	if delivery.State() != domain.DeliveryStateFailed {
		t.Fatalf("state = %s, want failed", delivery.State())
	}
	if delivery.FailureCode() != recoveryFailureCode {
		t.Fatalf("failure code = %q, want %q", delivery.FailureCode(), recoveryFailureCode)
	}
	if n := countRevocations(t, fx.store, fx.issuerID, distSerial(t, "a1")); n != 1 {
		t.Fatalf("revocations = %d, want 1", n)
	}
	if n := jobCount(t, fx.store); n != 1 {
		t.Fatalf("CRL job demands = %d, want 1", n)
	}
	if len(fx.store.AuditEvents()) == 0 {
		t.Fatal("recovery recorded no audit event")
	}
}

// Stored completed state is kept: a restart never re-opens or re-fails a
// delivery that finished before the process died.
func TestRecoverInterruptedTransfersKeepsStoredCompleted(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStateTransferring)
	seedCRLStateFor(t, fx.store, fx.issuerID)
	// Finish the transfer the way a successful Deliver would have.
	if err := fx.store.Write(context.Background(), func(tx port.TxStores) error {
		delivery, err := tx.Delivery().GetDeliveryForUpdate(context.Background(), fx.deliverID)
		if err != nil {
			return err
		}
		completed, err := delivery.Complete(distTestNow())
		if err != nil {
			return err
		}
		return tx.Delivery().SaveDelivery(context.Background(), completed, delivery.Version())
	}); err != nil {
		t.Fatalf("complete delivery: %v", err)
	}

	outcome, err := recoveryService(t, fx.store).RecoverInterruptedTransfers(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if outcome.Failed != 0 {
		t.Fatalf("failed = %d, want 0", outcome.Failed)
	}
	if got := storedDelivery(t, fx.store, fx.deliverID).State(); got != domain.DeliveryStateServerCompleted {
		t.Fatalf("state = %s, want it to stay completed", got)
	}
	if n := countRevocations(t, fx.store, fx.issuerID, distSerial(t, "a1")); n != 0 {
		t.Fatalf("revocations = %d, want 0 for a completed delivery", n)
	}
	if n := jobCount(t, fx.store); n != 0 {
		t.Fatalf("CRL job demands = %d, want 0", n)
	}
}

// A delivery still pending (never consumed) is not a restart's business.
func TestRecoverInterruptedTransfersLeavesPendingAlone(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	seedCRLStateFor(t, fx.store, fx.issuerID)

	outcome, err := recoveryService(t, fx.store).RecoverInterruptedTransfers(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if outcome.Failed != 0 {
		t.Fatalf("failed = %d, want 0", outcome.Failed)
	}
	if got := storedDelivery(t, fx.store, fx.deliverID).State(); got != domain.DeliveryStatePending {
		t.Fatalf("state = %s, want it to stay pending", got)
	}
}

// A recovery that cannot commit returns its error, so the runtime never
// opens admission after a partial recovery (§12).
func TestRecoverInterruptedTransfersReportsAFailedCommit(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStateTransferring)
	// Deliberately no CRLState for the issuer, so applyRevocations fails and
	// the whole recovery commit rolls back.

	_, err := recoveryService(t, fx.store).RecoverInterruptedTransfers(context.Background())
	if err == nil {
		t.Fatal("want the unresolvable recovery to be reported")
	}
	if got := storedDelivery(t, fx.store, fx.deliverID).State(); got != domain.DeliveryStateTransferring {
		t.Fatalf("state = %s, want the failed commit to have rolled back", got)
	}
	if n := countRevocations(t, fx.store, fx.issuerID, distSerial(t, "a1")); n != 0 {
		t.Fatalf("revocations = %d, want 0 after a rolled-back recovery", n)
	}
}

// The B03 acceptance criterion stated as a race: two Delivers for the same
// one-shot grant, exactly one of which may reach a sink.
func TestDeliverConcurrentRequestsOnlyTheCommitWinnerReachesTheSink(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	seedCRLStateFor(t, fx.store, fx.issuerID)
	svc := recoveryService(t, fx.store)

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		sends  int
		errCnt int
	)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sink := &fakeSink{}
			_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
			mu.Lock()
			defer mu.Unlock()
			sends += sink.callCount()
			if err != nil {
				errCnt++
			}
		}()
	}
	wg.Wait()

	if sends != 1 {
		t.Fatalf("sink calls = %d, want exactly 1 across both racers", sends)
	}
	if errCnt != 1 {
		t.Fatalf("failed requests = %d, want exactly 1 (the commit loser)", errCnt)
	}
}

// A recovery batch whose rows all turn out to be resolved already must not
// loop forever re-reading the same rows.
func TestRecoverInterruptedTransfersTerminatesOnAnAllSkippedBatch(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStateTransferring)
	seedCRLStateFor(t, fx.store, fx.issuerID)
	svc := recoveryService(t, fx.store)
	svc.deps.ReadStore = staleTransferringReads{inner: fx.store, delivery: storedDelivery(t, fx.store, fx.deliverID)}

	// Resolve the row behind the stale listing's back.
	if err := fx.store.Write(context.Background(), func(tx port.TxStores) error {
		delivery, err := tx.Delivery().GetDeliveryForUpdate(context.Background(), fx.deliverID)
		if err != nil {
			return err
		}
		completed, err := delivery.Complete(distTestNow())
		if err != nil {
			return err
		}
		return tx.Delivery().SaveDelivery(context.Background(), completed, delivery.Version())
	}); err != nil {
		t.Fatalf("complete delivery: %v", err)
	}

	done := make(chan struct{})
	var outcome RecoveryOutcome
	var err error
	go func() {
		outcome, err = svc.RecoverInterruptedTransfers(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery did not terminate on an all-skipped batch")
	}
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if outcome.Skipped != 1 || outcome.Failed != 0 {
		t.Fatalf("outcome = %+v, want one skipped and none failed", outcome)
	}
}

// staleTransferringReads keeps reporting one delivery as transferring no
// matter what the store now holds, which is what a listing read just before
// another writer finished the row would look like.
type staleTransferringReads struct {
	inner    port.ReadStore
	delivery domain.Delivery
}

func (r staleTransferringReads) Read(ctx context.Context, fn func(port.TxStores) error) error {
	return r.inner.Read(ctx, func(tx port.TxStores) error {
		return fn(staleTransferringTx{TxStores: tx, delivery: r.delivery})
	})
}

type staleTransferringTx struct {
	port.TxStores
	delivery domain.Delivery
}

func (t staleTransferringTx) Delivery() port.DeliveryRepository {
	return staleTransferringDeliveries{DeliveryRepository: t.TxStores.Delivery(), delivery: t.delivery}
}

type staleTransferringDeliveries struct {
	port.DeliveryRepository
	delivery domain.Delivery
}

func (d staleTransferringDeliveries) ListTransferring(context.Context, int) ([]domain.Delivery, error) {
	return []domain.Delivery{d.delivery}, nil
}
