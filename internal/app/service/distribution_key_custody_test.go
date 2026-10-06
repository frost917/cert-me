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

func TestDeliverPrivateSuccessMarksLineageClientHeld(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{outcome: port.TransferOutcome{Completed: true, BytesWritten: 7, FinishedAt: distTestNow()}}
	svc := newDistributionService(t, distDeps(t, fx.store, fx.store, okEncoder("private-payload"), gate))

	summary, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if !summary.Completed || summary.DeliveryID != fx.deliverID {
		t.Fatalf("summary = %+v, want completed delivery %s", summary, fx.deliverID)
	}
	if err := fx.store.Read(context.Background(), func(tx port.TxStores) error {
		snapshot, err := tx.PKI().GetSeriesForUpdate(context.Background(), fx.seriesID)
		if err != nil {
			return err
		}
		if snapshot.CurrentKeyGeneration.Custody() != domain.KeyCustodyClientHeld {
			t.Errorf("key custody = %q, want client_held after verified delivery completion", snapshot.CurrentKeyGeneration.Custody())
		}
		delivery, err := tx.Delivery().GetDeliveryForUpdate(context.Background(), fx.deliverID)
		if err != nil {
			return err
		}
		if delivery.State() != domain.DeliveryStateServerCompleted {
			t.Errorf("delivery state = %q, want server_completed", delivery.State())
		}
		if _, err := tx.Secrets().GetEncrypted(context.Background(), fx.keyMatID, domain.SecretPurposeLeafDelivery); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("leaf delivery secret lookup error = %v, want port.ErrNotFound after consumption", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("read completed delivery lineage: %v", err)
	}
}

func TestDeliverPrivateCustodyMarkFailureRollsBackCompletionWrite(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{outcome: port.TransferOutcome{Completed: true, BytesWritten: 7, FinishedAt: distTestNow()}}
	uow := markClientHeldFailureUoW{inner: fx.store}
	svc := newDistributionService(t, distDeps(t, uow, fx.store, okEncoder("private-payload"), gate))

	_, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err == nil {
		t.Fatal("Deliver succeeded despite failure to record client-held custody")
	}
	appErr, ok := contract.AsAppError(err)
	if !ok || appErr.Kind() != contract.ErrorKindCommitUnknown || appErr.Code() != "distribution_private_postprocess_failed" {
		t.Fatalf("Deliver error = %v, want commit_unknown/distribution_private_postprocess_failed", err)
	}
	if gate.callCount() != 1 {
		t.Fatalf("FailClosed calls = %d, want 1 after outcome persistence failure", gate.callCount())
	}
	if got := deliveryState(t, fx.store, fx.deliverID); got != domain.DeliveryStateTransferring {
		t.Fatalf("delivery state after rollback = %q, want transferring", got)
	}
	if err := fx.store.Read(context.Background(), func(tx port.TxStores) error {
		snapshot, err := tx.PKI().GetSeriesForUpdate(context.Background(), fx.seriesID)
		if err != nil {
			return err
		}
		if got := snapshot.CurrentKeyGeneration.Custody(); got != domain.KeyCustodyPendingDelivery {
			t.Errorf("key custody after rollback = %q, want pending_delivery", got)
		}
		if _, err := tx.Secrets().GetEncrypted(context.Background(), fx.keyMatID, domain.SecretPurposeLeafDelivery); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("leaf delivery secret lookup error = %v, want it deleted by the consumption commit", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("read rolled-back delivery lineage: %v", err)
	}
}

func TestPrivateDeliveryWritesLockSeriesBeforeDeliveryResources(t *testing.T) {
	fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	trace := &deliveryLockTrace{}
	uow := tracedDeliveryUoW{inner: fx.store, trace: trace}
	gate := &fakeRuntimeGate{}
	sink := &fakeSink{outcome: port.TransferOutcome{Completed: true, BytesWritten: 7, FinishedAt: distTestNow()}}
	svc := newDistributionService(t, distDeps(t, uow, fx.store, okEncoder("private-payload"), gate))
	if _, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	writes := trace.snapshot()
	if len(writes) != 2 {
		t.Fatalf("write lock traces = %v, want consumption and outcome writes", writes)
	}
	for i, events := range writes {
		if len(events) == 0 || events[0] != "series" {
			t.Errorf("write %d first locked resource = %v, want series before grants or deliveries", i, events)
		}
	}
}

type markClientHeldFailureUoW struct{ inner *porttest.Store }

func (u markClientHeldFailureUoW) Write(ctx context.Context, fn func(port.TxStores) error) error {
	return u.inner.Write(ctx, func(tx port.TxStores) error {
		return fn(markClientHeldFailureTx{TxStores: tx})
	})
}

type markClientHeldFailureTx struct{ port.TxStores }

func (tx markClientHeldFailureTx) PKI() port.PKIRepository {
	return markClientHeldFailurePKI{PKIRepository: tx.TxStores.PKI()}
}

type markClientHeldFailurePKI struct{ port.PKIRepository }

func (markClientHeldFailurePKI) MarkLeafKeyGenerationClientHeld(context.Context, domain.LeafKeyGenerationID) error {
	return errors.New("forced custody mark failure")
}

type deliveryLockTrace struct {
	mu     sync.Mutex
	writes [][]string
}

func (t *deliveryLockTrace) append(events []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.writes = append(t.writes, append([]string(nil), events...))
}

func (t *deliveryLockTrace) snapshot() [][]string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([][]string, len(t.writes))
	for i := range t.writes {
		out[i] = append([]string(nil), t.writes[i]...)
	}
	return out
}

type tracedDeliveryUoW struct {
	inner *porttest.Store
	trace *deliveryLockTrace
}

func (u tracedDeliveryUoW) Write(ctx context.Context, fn func(port.TxStores) error) error {
	events := make([]string, 0, 4)
	err := u.inner.Write(ctx, func(tx port.TxStores) error {
		return fn(tracedDeliveryTx{TxStores: tx, record: func(name string) { events = append(events, name) }})
	})
	u.trace.append(events)
	return err
}

type tracedDeliveryTx struct {
	port.TxStores
	record func(string)
}

func (tx tracedDeliveryTx) PKI() port.PKIRepository {
	return tracedDeliveryPKI{PKIRepository: tx.TxStores.PKI(), record: tx.record}
}

func (tx tracedDeliveryTx) Delivery() port.DeliveryRepository {
	return tracedDeliveryRepository{DeliveryRepository: tx.TxStores.Delivery(), record: tx.record}
}

type tracedDeliveryPKI struct {
	port.PKIRepository
	record func(string)
}

func (r tracedDeliveryPKI) GetSeriesForUpdate(ctx context.Context, id domain.SeriesID) (port.SeriesSnapshot, error) {
	r.record("series")
	return r.PKIRepository.GetSeriesForUpdate(ctx, id)
}

type tracedDeliveryRepository struct {
	port.DeliveryRepository
	record func(string)
}

func (r tracedDeliveryRepository) GetGrantForUpdate(ctx context.Context, hash domain.TokenHash) (domain.DownloadGrant, error) {
	r.record("grant")
	return r.DeliveryRepository.GetGrantForUpdate(ctx, hash)
}

func (r tracedDeliveryRepository) GetDeliveryForUpdate(ctx context.Context, id domain.DeliveryID) (domain.Delivery, error) {
	r.record("delivery")
	return r.DeliveryRepository.GetDeliveryForUpdate(ctx, id)
}

func (r tracedDeliveryRepository) InvalidatePrivateGrants(ctx context.Context, id domain.DeliveryID, now domain.Instant) error {
	r.record("grant")
	return r.DeliveryRepository.InvalidatePrivateGrants(ctx, id, now)
}

var _ port.UnitOfWork = tracedDeliveryUoW{}
var _ port.UnitOfWork = markClientHeldFailureUoW{}
