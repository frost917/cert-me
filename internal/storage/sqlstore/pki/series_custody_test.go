package pki

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"cert-me/internal/app/port"
	"cert-me/internal/config"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/dialect"

	_ "modernc.org/sqlite"
)

func TestMarkLeafKeyGenerationClientHeldRequiresCompletedDelivery(t *testing.T) {
	tests := []struct {
		name              string
		deliveryState     domain.DeliveryState
		custody           domain.KeyCustody
		withSecret        bool
		matchingKey       bool
		matchingLineage   bool
		withoutGeneration bool
		wantError         bool
		wantNotFound      bool
		wantCustody       domain.KeyCustody
	}{
		{name: "completed delivery moves pending generation to client held", deliveryState: domain.DeliveryStateServerCompleted, matchingKey: true, matchingLineage: true, wantCustody: domain.KeyCustodyClientHeld},
		{name: "pending delivery does not move custody", deliveryState: domain.DeliveryStatePending, matchingKey: true, matchingLineage: true, wantError: true, wantCustody: domain.KeyCustodyPendingDelivery},
		{name: "completed delivery with retained private secret does not move custody", deliveryState: domain.DeliveryStateServerCompleted, withSecret: true, matchingKey: true, matchingLineage: true, wantError: true, wantCustody: domain.KeyCustodyPendingDelivery},
		{name: "completed delivery for a different key does not move custody", deliveryState: domain.DeliveryStateServerCompleted, matchingLineage: true, wantError: true, wantCustody: domain.KeyCustodyPendingDelivery},
		{name: "completed delivery for different generation lineage does not move custody", deliveryState: domain.DeliveryStateServerCompleted, matchingKey: true, wantError: true, wantCustody: domain.KeyCustodyPendingDelivery},
		{name: "internal custody cannot be changed", deliveryState: domain.DeliveryStateServerCompleted, custody: domain.KeyCustodyInternal, matchingKey: true, matchingLineage: true, wantError: true, wantCustody: domain.KeyCustodyInternal},
		{name: "client held is idempotent while completion proof remains", deliveryState: domain.DeliveryStateServerCompleted, custody: domain.KeyCustodyClientHeld, matchingKey: true, matchingLineage: true, wantCustody: domain.KeyCustodyClientHeld},
		{name: "client held without completion proof is refused", deliveryState: domain.DeliveryStatePending, custody: domain.KeyCustodyClientHeld, matchingKey: true, matchingLineage: true, wantError: true, wantCustody: domain.KeyCustodyClientHeld},
		{name: "missing generation is reported", deliveryState: domain.DeliveryStateServerCompleted, matchingKey: true, matchingLineage: true, withoutGeneration: true, wantError: true, wantNotFound: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
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
			for _, statement := range []string{
				`CREATE TABLE leaf_key_generations (id TEXT PRIMARY KEY, series_id TEXT NOT NULL, key_material_id TEXT NOT NULL, custody TEXT NOT NULL)`,
				`CREATE TABLE key_deliveries (id TEXT PRIMARY KEY, leaf_key_generation_id TEXT NOT NULL, certificate_id TEXT NOT NULL, state TEXT NOT NULL)`,
				`CREATE TABLE leaf_certificates (certificate_id TEXT PRIMARY KEY, series_id TEXT NOT NULL, leaf_key_generation_id TEXT NOT NULL)`,
				`CREATE TABLE certificates (id TEXT PRIMARY KEY, key_material_id TEXT NOT NULL)`,
				`CREATE TABLE private_key_secrets (key_material_id TEXT NOT NULL, purpose TEXT NOT NULL)`,
			} {
				if _, err := db.ExecContext(ctx, statement); err != nil {
					t.Fatalf("create fixture table: %v", err)
				}
			}

			const (
				generationID  = "11111111-1111-4111-8111-111111111111"
				seriesID      = "22222222-2222-4222-8222-222222222222"
				keyID         = "33333333-3333-4333-8333-333333333333"
				certificateID = "44444444-4444-4444-8444-444444444444"
				deliveryID    = "55555555-5555-4555-8555-555555555555"
			)
			custody := tt.custody
			if custody == "" {
				custody = domain.KeyCustodyPendingDelivery
			}
			if !tt.withoutGeneration {
				if _, err := db.ExecContext(ctx, `INSERT INTO leaf_key_generations (id, series_id, key_material_id, custody) VALUES (?, ?, ?, ?)`,
					generationID, seriesID, keyID, custody); err != nil {
					t.Fatalf("insert generation: %v", err)
				}
			}
			lineageGenerationID := "77777777-7777-4777-8777-777777777777"
			if tt.matchingLineage {
				lineageGenerationID = generationID
			}
			if _, err := db.ExecContext(ctx, `INSERT INTO leaf_certificates (certificate_id, series_id, leaf_key_generation_id) VALUES (?, ?, ?)`,
				certificateID, seriesID, lineageGenerationID); err != nil {
				t.Fatalf("insert leaf certificate lineage: %v", err)
			}
			certificateKeyID := "66666666-6666-4666-8666-666666666666"
			if tt.matchingKey {
				certificateKeyID = keyID
			}
			if _, err := db.ExecContext(ctx, `INSERT INTO certificates (id, key_material_id) VALUES (?, ?)`, certificateID, certificateKeyID); err != nil {
				t.Fatalf("insert certificate: %v", err)
			}
			if _, err := db.ExecContext(ctx, `INSERT INTO key_deliveries (id, leaf_key_generation_id, certificate_id, state) VALUES (?, ?, ?, ?)`,
				deliveryID, generationID, certificateID, tt.deliveryState); err != nil {
				t.Fatalf("insert delivery: %v", err)
			}
			if tt.withSecret {
				if _, err := db.ExecContext(ctx, `INSERT INTO private_key_secrets (key_material_id, purpose) VALUES (?, ?)`,
					keyID, domain.SecretPurposeLeafDelivery); err != nil {
					t.Fatalf("insert retained private secret: %v", err)
				}
			}
			d, err := dialect.New(config.SQLite)
			if err != nil {
				t.Fatalf("sqlite dialect: %v", err)
			}
			repo := New(db, d)
			parsedGenerationID, err := domain.ParseLeafKeyGenerationID(generationID)
			if err != nil {
				t.Fatalf("parse generation id: %v", err)
			}
			err = repo.MarkLeafKeyGenerationClientHeld(ctx, parsedGenerationID)
			if tt.wantError && err == nil {
				t.Fatal("MarkLeafKeyGenerationClientHeld succeeded without valid completed-delivery proof")
			}
			if !tt.wantError && err != nil {
				t.Fatalf("MarkLeafKeyGenerationClientHeld: %v", err)
			}
			if tt.wantNotFound && !errors.Is(err, port.ErrNotFound) {
				t.Fatalf("MarkLeafKeyGenerationClientHeld error = %v, want port.ErrNotFound", err)
			}
			if !tt.withoutGeneration {
				var storedCustody string
				if err := db.QueryRowContext(ctx, `SELECT custody FROM leaf_key_generations WHERE id = ?`, generationID).Scan(&storedCustody); err != nil {
					t.Fatalf("read custody: %v", err)
				}
				if storedCustody != string(tt.wantCustody) {
					t.Fatalf("custody = %q, want %q", storedCustody, tt.wantCustody)
				}
			}
		})
	}
}
