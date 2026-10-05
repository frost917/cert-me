package porttest

import (
	"context"
	"errors"
	"testing"
	"time"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

func TestDeliveryRepositoryGetDeliveryByLeafKeyGenerationForUpdate(t *testing.T) {
	store := NewStore()
	ctx := context.Background()
	deliveryID := domain.DeliveryID("11111111-1111-4111-8111-111111111111")
	leafGenerationID := domain.LeafKeyGenerationID("22222222-2222-4222-8222-222222222222")
	certificateID := domain.CertificateID("33333333-3333-4333-8333-333333333333")
	expiresAt := domain.NewInstant(time.Date(2026, 10, 5, 4, 0, 0, 0, time.UTC))
	delivery, err := domain.NewDelivery(domain.DeliveryFacts{
		ID: deliveryID, LeafKeyGenerationID: leafGenerationID, CertificateID: certificateID,
		ExpiresAt: expiresAt, State: domain.DeliveryStatePending, Version: 1,
	})
	if err != nil {
		t.Fatalf("NewDelivery: %v", err)
	}
	if err := store.Write(ctx, func(tx port.TxStores) error { return tx.Delivery().InsertDelivery(ctx, delivery) }); err != nil {
		t.Fatalf("InsertDelivery: %v", err)
	}

	err = store.Read(ctx, func(tx port.TxStores) error {
		got, err := tx.Delivery().GetDeliveryByLeafKeyGenerationForUpdate(ctx, leafGenerationID)
		if err != nil {
			return err
		}
		if got.ID() != deliveryID || got.CertificateID() != certificateID || got.State() != domain.DeliveryStatePending {
			t.Fatalf("delivery = %#v, want the pending row for generation %s", got, leafGenerationID)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("GetDeliveryByLeafKeyGenerationForUpdate: %v", err)
	}

	err = store.Read(ctx, func(tx port.TxStores) error {
		_, err := tx.Delivery().GetDeliveryByLeafKeyGenerationForUpdate(ctx, domain.LeafKeyGenerationID("44444444-4444-4444-8444-444444444444"))
		return err
	})
	if !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("unknown generation error = %v, want port.ErrNotFound", err)
	}
}
