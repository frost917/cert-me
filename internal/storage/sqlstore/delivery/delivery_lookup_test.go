package delivery

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"cert-me/internal/app/port"
	"cert-me/internal/config"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/dialect"

	_ "modernc.org/sqlite"
)

func TestDeliveryRepositoryGetDeliveryByLeafKeyGenerationForUpdate(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE key_deliveries (
		id TEXT PRIMARY KEY, leaf_key_generation_id TEXT NOT NULL UNIQUE,
		certificate_id TEXT NOT NULL, expires_at INTEGER NOT NULL, state TEXT NOT NULL,
		consumed_at INTEGER NULL, finished_at INTEGER NULL, failure_code TEXT NULL, version INTEGER NOT NULL
	)`)
	if err != nil {
		t.Fatalf("create fixture table: %v", err)
	}
	now := time.Date(2026, 10, 5, 4, 0, 0, 0, time.UTC)
	want := domain.DeliveryID("11111111-1111-4111-8111-111111111111")
	leafGenerationID := domain.LeafKeyGenerationID("22222222-2222-4222-8222-222222222222")
	certificateID := domain.CertificateID("33333333-3333-4333-8333-333333333333")
	_, err = db.Exec(`INSERT INTO key_deliveries (
		id, leaf_key_generation_id, certificate_id, expires_at, state, consumed_at, finished_at, failure_code, version
	) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, 1)`, string(want), string(leafGenerationID), string(certificateID), now.UnixMicro(), string(domain.DeliveryStatePending))
	if err != nil {
		t.Fatalf("insert fixture delivery: %v", err)
	}
	d, err := dialect.New(config.SQLite)
	if err != nil {
		t.Fatalf("sqlite dialect: %v", err)
	}
	repo, err := NewDeliveryRepository(db, d)
	if err != nil {
		t.Fatalf("NewDeliveryRepository: %v", err)
	}

	got, err := repo.GetDeliveryByLeafKeyGenerationForUpdate(context.Background(), leafGenerationID)
	if err != nil {
		t.Fatalf("GetDeliveryByLeafKeyGenerationForUpdate: %v", err)
	}
	if got.ID() != want || got.LeafKeyGenerationID() != leafGenerationID || got.CertificateID() != certificateID ||
		got.State() != domain.DeliveryStatePending || !got.ExpiresAt().Equal(domain.NewInstant(now)) {
		t.Fatalf("delivery = %#v, does not match the row selected by leaf key generation", got)
	}

	if _, err := repo.GetDeliveryByLeafKeyGenerationForUpdate(context.Background(), domain.LeafKeyGenerationID("44444444-4444-4444-8444-444444444444")); !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("unknown generation error = %v, want port.ErrNotFound", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repo.GetDeliveryByLeafKeyGenerationForUpdate(canceled, leafGenerationID); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lookup error = %v, want context.Canceled", err)
	}
}
