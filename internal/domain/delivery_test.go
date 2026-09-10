package domain

import (
	"errors"
	"testing"
	"time"
)

func mkDeliveryID(t *testing.T) DeliveryID {
	t.Helper()
	id, err := ParseDeliveryID("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatalf("parse delivery id: %v", err)
	}
	return id
}

func mkLeafKeyGenID(t *testing.T) LeafKeyGenerationID {
	t.Helper()
	id, err := ParseLeafKeyGenerationID("22222222-2222-4222-8222-222222222222")
	if err != nil {
		t.Fatalf("parse leaf key gen id: %v", err)
	}
	return id
}

func mkCertID(t *testing.T) CertificateID {
	t.Helper()
	id, err := ParseCertificateID("33333333-3333-4333-8333-333333333333")
	if err != nil {
		t.Fatalf("parse certificate id: %v", err)
	}
	return id
}

func mkGrantID(t *testing.T, suffix byte) GrantID {
	t.Helper()
	raw := "44444444-4444-4444-8444-44444444444" + string(suffix)
	id, err := ParseGrantID(raw)
	if err != nil {
		t.Fatalf("parse grant id: %v", err)
	}
	return id
}

func mkDeliveryIDN(t *testing.T) DeliveryID { return mkDeliveryID(t) }

func t0() Instant                                { return NewInstant(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) }
func plus(base Instant, d time.Duration) Instant { return base.Add(NewDuration(d)) }

func newPendingDelivery(t *testing.T) Delivery {
	t.Helper()
	d, err := NewDelivery(DeliveryFacts{
		ID:                  mkDeliveryID(t),
		LeafKeyGenerationID: mkLeafKeyGenID(t),
		CertificateID:       mkCertID(t),
		ExpiresAt:           plus(t0(), 3*time.Hour),
		State:               DeliveryStatePending,
	})
	if err != nil {
		t.Fatalf("new delivery: %v", err)
	}
	return d
}

func TestDelivery_ConsumeCompleteHappyPath(t *testing.T) {
	d := newPendingDelivery(t)
	now := plus(t0(), time.Minute)

	transferring, err := d.Consume(now)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if transferring.State() != DeliveryStateTransferring {
		t.Fatalf("expected transferring, got %s", transferring.State())
	}
	if transferring.Version() != d.Version().Next() {
		t.Fatalf("expected version bump")
	}

	completed, err := transferring.Complete(plus(now, time.Second))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if completed.State() != DeliveryStateServerCompleted {
		t.Fatalf("expected server_completed, got %s", completed.State())
	}
}

// U07/U08 & B01: terminal delivery states never restore to pending.
func TestDelivery_TerminalStatesNeverRestoreToPending(t *testing.T) {
	terminalStates := []DeliveryState{DeliveryStateServerCompleted, DeliveryStateFailed, DeliveryStateExpired}
	for _, st := range terminalStates {
		st := st
		t.Run(string(st), func(t *testing.T) {
			d, err := NewDelivery(DeliveryFacts{
				ID:                  mkDeliveryID(t),
				LeafKeyGenerationID: mkLeafKeyGenID(t),
				CertificateID:       mkCertID(t),
				ExpiresAt:           plus(t0(), 3*time.Hour),
				State:               st,
			})
			if err != nil {
				t.Fatalf("new delivery: %v", err)
			}
			now := plus(t0(), time.Minute)
			if err := d.CanConsume(now); err == nil {
				t.Fatalf("expected CanConsume to reject terminal state %s", st)
			}
			if _, err := d.Consume(now); err == nil {
				t.Fatalf("expected Consume to reject terminal state %s", st)
			}
			// failed/expired are terminal even for Fail; server_completed
			// alone accepts a later admin-reported storage failure
			// (certificate-lifecycle.md table row "공개 인증서 다운로드
			// 실패" vs. private-key storage failure after transfer), which
			// is covered separately in TestDelivery_FailFromServerCompletedIsAllowed.
			if st == DeliveryStateServerCompleted {
				return
			}
			if _, err := d.Fail("client_reported_failure", now); !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("expected ErrInvalidTransition failing an already-terminal delivery, got %v", err)
			}
		})
	}
}

// planning.md: expired delivery is rejected regardless of whether the
// cleanup job has run yet (state is still "pending" in storage).
func TestDelivery_ExpiredRejectedRegardlessOfCleanup(t *testing.T) {
	d := newPendingDelivery(t)
	afterDeadline := plus(d.ExpiresAt(), time.Second)

	if err := d.CanConsume(afterDeadline); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
	if _, err := d.Consume(afterDeadline); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired on consume, got %v", err)
	}

	// The cleanup job can still explicitly expire it.
	expired, err := d.Expire(afterDeadline)
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if expired.State() != DeliveryStateExpired {
		t.Fatalf("expected expired state, got %s", expired.State())
	}

	// And a not-yet-expired pending delivery cannot be force-expired early.
	notYet := plus(t0(), time.Minute)
	if _, err := d.Expire(notYet); err == nil {
		t.Fatalf("expected Expire to refuse an unexpired delivery")
	}
}

func TestDelivery_FailFromServerCompletedIsAllowed(t *testing.T) {
	d := newPendingDelivery(t)
	now := plus(t0(), time.Minute)
	transferring, err := d.Consume(now)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	completed, err := transferring.Complete(plus(now, time.Second))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	failed, err := completed.Fail("client_reported_failure", plus(now, time.Hour))
	if err != nil {
		t.Fatalf("expected admin-reported failure after server_completed to be allowed: %v", err)
	}
	if failed.State() != DeliveryStateFailed {
		t.Fatalf("expected failed state, got %s", failed.State())
	}
}

func mkTokenHash(t *testing.T, b byte) TokenHash {
	t.Helper()
	data := make([]byte, 32)
	data[0] = b
	h, err := NewTokenHash(NewFingerprint(data))
	if err != nil {
		t.Fatalf("new token hash: %v", err)
	}
	return h
}

func newPublicGrant(t *testing.T, expiresAt Instant) DownloadGrant {
	t.Helper()
	g, err := NewDownloadGrant(DownloadGrantFacts{
		ID:            mkGrantID(t, '1'),
		TokenHash:     mkTokenHash(t, 1),
		Purpose:       GrantPurposeLeafPublic,
		CertificateID: mkCertID(t),
		ExpiresAt:     expiresAt,
	})
	if err != nil {
		t.Fatalf("new public grant: %v", err)
	}
	return g
}

func newPrivateGrant(t *testing.T, deliveryID DeliveryID, expiresAt Instant) DownloadGrant {
	t.Helper()
	g, err := NewDownloadGrant(DownloadGrantFacts{
		ID:            mkGrantID(t, '2'),
		TokenHash:     mkTokenHash(t, 2),
		Purpose:       GrantPurposeLeafPrivate,
		CertificateID: mkCertID(t),
		DeliveryID:    deliveryID,
		ExpiresAt:     expiresAt,
	})
	if err != nil {
		t.Fatalf("new private grant: %v", err)
	}
	return g
}

// certificate-lifecycle.md: private grants require a delivery id, public
// grants must not carry one.
func TestNewDownloadGrant_PurposeDeliveryBinding(t *testing.T) {
	if _, err := NewDownloadGrant(DownloadGrantFacts{
		ID: mkGrantID(t, '3'), TokenHash: mkTokenHash(t, 3), Purpose: GrantPurposeLeafPrivate,
		CertificateID: mkCertID(t), ExpiresAt: plus(t0(), time.Hour),
	}); err == nil {
		t.Fatalf("expected error: private grant without delivery id")
	}
	if _, err := NewDownloadGrant(DownloadGrantFacts{
		ID: mkGrantID(t, '4'), TokenHash: mkTokenHash(t, 4), Purpose: GrantPurposeLeafPublic,
		CertificateID: mkCertID(t), DeliveryID: mkDeliveryID(t), ExpiresAt: plus(t0(), time.Hour),
	}); err == nil {
		t.Fatalf("expected error: public grant carrying a delivery id")
	}
}

// U07: link replacement invalidates the old link, and the old link is
// rejected afterward.
func TestDownloadGrant_ReplacementInvalidatesOldLink(t *testing.T) {
	now := plus(t0(), time.Minute)
	old := newPublicGrant(t, plus(t0(), 10*time.Minute))

	invalidated, err := old.Invalidate(now)
	if err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	if err := invalidated.Validate(GrantPurposeLeafPublic, mkCertID(t), "", plus(now, time.Second)); !errors.Is(err, ErrAlreadyConsumed) {
		t.Fatalf("expected replaced link to be rejected, got %v", err)
	}

	// Idempotent: invalidating again is a no-op, not an error.
	twice, err := invalidated.Invalidate(plus(now, time.Second))
	if err != nil {
		t.Fatalf("expected idempotent invalidate, got %v", err)
	}
	if twice.InvalidatedAt() != invalidated.InvalidatedAt() {
		t.Fatalf("expected invalidated_at to stay put on repeat invalidate")
	}
}

// A consumed grant is a spent one-shot permission: invalidate must refuse
// to touch it (nothing can "undo" a used download), and consuming twice
// must fail regardless of process restarts (storage-level unconsumable).
func TestDownloadGrant_ConsumedNeverRestored(t *testing.T) {
	now := plus(t0(), time.Minute)
	g := newPublicGrant(t, plus(t0(), 10*time.Minute))

	consumed, err := g.Consume(now)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if _, err := consumed.Consume(plus(now, time.Second)); !errors.Is(err, ErrAlreadyConsumed) {
		t.Fatalf("expected second consume to fail, got %v", err)
	}
	if _, err := consumed.Invalidate(plus(now, time.Second)); !errors.Is(err, ErrAlreadyConsumed) {
		t.Fatalf("expected invalidate of a consumed grant to fail, got %v", err)
	}
}

func TestDownloadGrant_ExpiredRejected(t *testing.T) {
	g := newPublicGrant(t, plus(t0(), 10*time.Minute))
	after := plus(t0(), 11*time.Minute)
	if err := g.Validate(GrantPurposeLeafPublic, mkCertID(t), "", after); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestDownloadGrant_PrivateGrantBindsDelivery(t *testing.T) {
	deliveryID := mkDeliveryID(t)
	g := newPrivateGrant(t, deliveryID, plus(t0(), 3*time.Hour))
	now := plus(t0(), time.Minute)

	otherDelivery, err := ParseDeliveryID("55555555-5555-4555-8555-555555555555")
	if err != nil {
		t.Fatalf("parse other delivery id: %v", err)
	}
	if err := g.Validate(GrantPurposeLeafPrivate, mkCertID(t), otherDelivery, now); !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("expected delivery mismatch to be rejected, got %v", err)
	}
	if err := g.Validate(GrantPurposeLeafPrivate, mkCertID(t), deliveryID, now); err != nil {
		t.Fatalf("expected matching delivery to validate, got %v", err)
	}
}

// Config changes to the receipt/link windows must not retroactively move an
// existing grant's expiry: this is enforced simply by ExpiresAt being fixed
// at construction and never mutated by any method other than none existing.
func TestDownloadGrant_ExpiryNeverMutatedByLifecycleMethods(t *testing.T) {
	g := newPublicGrant(t, plus(t0(), 10*time.Minute))
	now := plus(t0(), time.Minute)
	consumed, err := g.Consume(now)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if consumed.ExpiresAt() != g.ExpiresAt() {
		t.Fatalf("expiry must not change on consume")
	}
}
