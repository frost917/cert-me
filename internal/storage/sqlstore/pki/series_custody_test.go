package pki

import (
	"context"
	"database/sql"
	"testing"

	"cert-me/internal/config"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/dialect"

	_ "modernc.org/sqlite"
)

func TestMarkLeafKeyGenerationClientHeldRequiresCompletedDelivery(t *testing.T) {
	tests := []struct {
		name          string
		deliveryState domain.DeliveryState
		withSecret    bool
		wantError     bool
	}{
		{name: "completed delivery moves pending generation to client held", deliveryState: domain.DeliveryStateServerCompleted},
		{name: "pending delivery does not move custody", deliveryState: domain.DeliveryStatePending, wantError: true},
		{name: "completed delivery with retained private secret does not move custody", deliveryState: domain.DeliveryStateServerCompleted, withSecret: true, wantError: true},
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
			if _, err := db.ExecContext(ctx, `INSERT INTO leaf_key_generations (id, series_id, key_material_id, custody) VALUES (?, ?, ?, ?)`,
				generationID, seriesID, keyID, domain.KeyCustodyPendingDelivery); err != nil {
				t.Fatalf("insert generation: %v", err)
			}
			if _, err := db.ExecContext(ctx, `INSERT INTO leaf_certificates (certificate_id, series_id, leaf_key_generation_id) VALUES (?, ?, ?)`,
				certificateID, seriesID, generationID); err != nil {
				t.Fatalf("insert leaf certificate lineage: %v", err)
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
			var custody string
			if err := db.QueryRowContext(ctx, `SELECT custody FROM leaf_key_generations WHERE id = ?`, generationID).Scan(&custody); err != nil {
				t.Fatalf("read custody: %v", err)
			}
			wantCustody := string(domain.KeyCustodyPendingDelivery)
			if !tt.wantError {
				wantCustody = string(domain.KeyCustodyClientHeld)
			}
			if custody != wantCustody {
				t.Fatalf("custody = %q, want %q", custody, wantCustody)
			}
		})
	}
}
