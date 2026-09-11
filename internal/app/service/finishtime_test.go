package service

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

// slowSink advances the clock while "transferring", so the finish time a
// long send produces is genuinely later than the consumption that authorized
// it.
type slowSink struct {
	fakeSink
	clock   *advancingClock
	elapsed time.Duration
}

func (s *slowSink) Send(ctx context.Context, descriptor port.FileDescriptor, r io.Reader) (port.TransferOutcome, error) {
	outcome, err := s.fakeSink.Send(ctx, descriptor, r)
	s.clock.advanceTo(s.clock.Now().Add(domain.NewDuration(s.elapsed)))
	return outcome, err
}

// storedDeliveryFinishedAt reads the persisted finished_at.
func storedDeliveryFinishedAt(t *testing.T, store *porttest.Store, id domain.DeliveryID) domain.Instant {
	t.Helper()
	return storedDelivery(t, store, id).FinishedAt()
}

// §14.2: the finish time is read after Send returns, so a long transfer must
// not be recorded as having finished the instant it was consumed.
func TestDeliverFinishTimeIsObservedAfterSendNotAtConsumption(t *testing.T) {
	start := distTestNow()
	fx := seedPrivateFixture(t, start.Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	seedCRLStateFor(t, fx.store, fx.issuerID)
	clock := &advancingClock{now: start}
	sink := &slowSink{
		fakeSink: fakeSink{outcome: port.TransferOutcome{Completed: true, BytesWritten: 7, FinishedAt: start}},
		clock:    clock,
		elapsed:  90 * time.Second,
	}
	svc := newDistributionService(t, withClock(distDeps(t, fx.store, fx.store, okEncoder("payload"), &fakeRuntimeGate{}), clock))

	summary, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}

	wantFinish := start.Add(domain.NewDuration(90 * time.Second))
	if !summary.FinishedAt.Equal(wantFinish) {
		t.Fatalf("summary finished_at = %v, want the post-send observation %v", summary.FinishedAt.Time(), wantFinish.Time())
	}
	stored := storedDeliveryFinishedAt(t, fx.store, fx.deliverID)
	if !stored.Equal(wantFinish) {
		t.Fatalf("stored finished_at = %v, want %v", stored.Time(), wantFinish.Time())
	}
	if stored.Equal(start) {
		t.Fatal("finished_at was recorded as consumed_at for a 90-second transfer")
	}
	// The sink's own observation stays an observation: it reported `start`,
	// and that value must not be what got persisted or returned.
	if summary.FinishedAt.Equal(sink.outcome.FinishedAt) {
		t.Fatal("the sink's observed FinishedAt replaced the app's finish time")
	}
}

// §14.2: a failed transfer takes the same app finish-time path, and the
// derived revocation's revoked_at is that same instant.
func TestDeliverFailedTransferSharesOneFinishTime(t *testing.T) {
	start := distTestNow()
	fx := seedPrivateFixture(t, start.Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	seedCRLStateFor(t, fx.store, fx.issuerID)
	clock := &advancingClock{now: start}
	sink := &slowSink{
		fakeSink: fakeSink{err: errors.New("client aborted")},
		clock:    clock,
		elapsed:  30 * time.Second,
	}
	svc := newDistributionService(t, withClock(distDeps(t, fx.store, fx.store, okEncoder("payload"), &fakeRuntimeGate{}), clock))

	if _, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink); err == nil {
		t.Fatal("want the send failure reported")
	}

	wantFinish := start.Add(domain.NewDuration(30 * time.Second))
	if stored := storedDeliveryFinishedAt(t, fx.store, fx.deliverID); !stored.Equal(wantFinish) {
		t.Fatalf("stored finished_at = %v, want %v", stored.Time(), wantFinish.Time())
	}
	revocation := storedRevocation(t, fx.store, fx.issuerID, distSerial(t, "a1"))
	if !revocation.RevokedAt().Equal(wantFinish) {
		t.Fatalf("revocation revoked_at = %v, want the transfer's finish time %v",
			revocation.RevokedAt().Time(), wantFinish.Time())
	}
}

// A panicking Send leaves TransferOutcome empty; the app's own finish time
// still has to be recorded ("오류·panic으로 outcome이 비어 있어도 동일한 app
// 종료 시각 경로를 사용한다").
func TestDeliverPanickingSendStillRecordsAnAppFinishTime(t *testing.T) {
	start := distTestNow()
	fx := seedPrivateFixture(t, start.Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	seedCRLStateFor(t, fx.store, fx.issuerID)
	clock := &advancingClock{now: start}
	sink := &panickingAdvancingSink{clock: clock, elapsed: 5 * time.Second}
	svc := newDistributionService(t, withClock(distDeps(t, fx.store, fx.store, okEncoder("payload"), &fakeRuntimeGate{}), clock))

	if _, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink); err == nil {
		t.Fatal("want the panic reported as a failure")
	}

	wantFinish := start.Add(domain.NewDuration(5 * time.Second))
	if stored := storedDeliveryFinishedAt(t, fx.store, fx.deliverID); !stored.Equal(wantFinish) {
		t.Fatalf("stored finished_at = %v, want %v", stored.Time(), wantFinish.Time())
	}
}

// panickingAdvancingSink advances the clock and then panics, the panic
// equivalent of slowSink.
type panickingAdvancingSink struct {
	fakeSink
	clock   *advancingClock
	elapsed time.Duration
}

func (s *panickingAdvancingSink) Send(_ context.Context, _ port.FileDescriptor, _ io.Reader) (port.TransferOutcome, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	s.clock.advanceTo(s.clock.Now().Add(domain.NewDuration(s.elapsed)))
	panic("sink exploded")
}

// §14.2: a system clock that steps backwards between the two reads must not
// produce a finished_at earlier than consumed_at.
func TestDeliverFinishTimeNeverPrecedesConsumption(t *testing.T) {
	start := distTestNow()
	fx := seedPrivateFixture(t, start.Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
	seedCRLStateFor(t, fx.store, fx.issuerID)
	clock := &advancingClock{now: start}
	sink := &slowSink{
		fakeSink: fakeSink{outcome: port.TransferOutcome{Completed: true, BytesWritten: 7}},
		clock:    clock,
		// The clock goes BACKWARDS while the transfer is in flight.
		elapsed: -10 * time.Minute,
	}
	svc := newDistributionService(t, withClock(distDeps(t, fx.store, fx.store, okEncoder("payload"), &fakeRuntimeGate{}), clock))

	summary, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink)
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}

	consumedAt := start
	if summary.FinishedAt.Before(consumedAt) {
		t.Fatalf("summary finished_at %v precedes consumed_at %v", summary.FinishedAt.Time(), consumedAt.Time())
	}
	if stored := storedDeliveryFinishedAt(t, fx.store, fx.deliverID); stored.Before(consumedAt) {
		t.Fatalf("stored finished_at %v precedes consumed_at %v", stored.Time(), consumedAt.Time())
	}
}

// §14.2: a transfer that was legitimately consumed is not retroactively
// failed just because the delivery deadline passed while it was in flight.
func TestDeliverSuccessIsNotRetroactivelyFailedByAPassedDeadline(t *testing.T) {
	start := distTestNow()
	fx := seedPrivateFixture(t, start.Add(domain.NewDuration(time.Minute)), domain.DeliveryStatePending)
	seedCRLStateFor(t, fx.store, fx.issuerID)
	clock := &advancingClock{now: start}
	sink := &slowSink{
		fakeSink: fakeSink{outcome: port.TransferOutcome{Completed: true, BytesWritten: 7}},
		clock:    clock,
		// Finishes well past the delivery deadline the consumption checked.
		elapsed: 10 * time.Minute,
	}
	svc := newDistributionService(t, withClock(distDeps(t, fx.store, fx.store, okEncoder("payload"), &fakeRuntimeGate{}), clock))

	if _, err := svc.Deliver(context.Background(), distMeta(), distCmd(t, fx.rawToken), sink); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	if got := storedDelivery(t, fx.store, fx.deliverID).State(); got != domain.DeliveryStateServerCompleted {
		t.Fatalf("state = %s, want server_completed -- the deadline governs consumption, not the transfer", got)
	}
	if n := countRevocations(t, fx.store, fx.issuerID, distSerial(t, "a1")); n != 0 {
		t.Fatalf("revocations = %d, want 0 for a successful transfer", n)
	}
}
