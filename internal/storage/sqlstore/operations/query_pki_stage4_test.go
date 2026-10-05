package operations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/config"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/dialect"

	_ "modernc.org/sqlite"
)

func TestQueryRepositoryStage4ProjectionsReadPersistedRows(t *testing.T) {
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
		`CREATE TABLE authorities (id TEXT, created_at INTEGER NOT NULL, kind TEXT, name TEXT, management_parent_id TEXT, issuance_state TEXT, issuance_certificate_id TEXT, archived_at INTEGER, version INTEGER)`,
		`CREATE TABLE ca_key_generations (id TEXT, authority_id TEXT, key_material_id TEXT, generation_no INTEGER, key_destroyed_at INTEGER)`,
		`CREATE TABLE certificates (id TEXT, created_at INTEGER NOT NULL, der_sha256 TEXT, der BLOB, key_material_id TEXT, issuer_ca_key_generation_id TEXT, serial_hex TEXT, not_before INTEGER, not_after INTEGER, subject_json TEXT, extensions_json TEXT, origin TEXT, created_by TEXT)`,
		`CREATE TABLE ca_certificates (certificate_id TEXT, ca_key_generation_id TEXT)`,
		`CREATE TABLE ca_takeovers (ca_key_generation_id TEXT, state TEXT)`,
		`CREATE TABLE ca_transitions (source_authority_id TEXT, mode TEXT, state TEXT)`,
		`CREATE TABLE leaf_series (id TEXT, created_at INTEGER NOT NULL, name TEXT, purpose TEXT, management_authority_id TEXT, current_certificate_id TEXT, current_key_generation_id TEXT, validity_policy_json TEXT, version INTEGER, archived_at INTEGER)`,
		`CREATE TABLE leaf_key_generations (id TEXT, series_id TEXT, key_material_id TEXT, generation_no INTEGER, renewal_count INTEGER, prior_history_unknown BOOLEAN, custody TEXT)`,
		`CREATE TABLE leaf_certificates (certificate_id TEXT, series_id TEXT, leaf_key_generation_id TEXT, issuer_ca_certificate_id TEXT, previous_certificate_id TEXT, operation TEXT, renewal_count_at_issue INTEGER, policy_snapshot_json TEXT)`,
		`CREATE TABLE key_deliveries (id TEXT, leaf_key_generation_id TEXT, certificate_id TEXT, expires_at INTEGER, state TEXT, consumed_at INTEGER, finished_at INTEGER, failure_code TEXT, version INTEGER)`,
		`CREATE TABLE key_materials (id TEXT, algorithm TEXT)`,
		`CREATE TABLE certificate_sans (certificate_id TEXT, position INTEGER, type TEXT, normalized_value TEXT, normalized_value_hash TEXT)`,
		`CREATE TABLE revocations (issuer_ca_key_generation_id TEXT, serial_hex TEXT)`,
		`CREATE TABLE transition_impacts (certificate_id TEXT)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("create query fixture table: %v", err)
		}
	}

	const (
		authorityID = "11111111-1111-4111-8111-111111111111"
		caKeyGenID  = "22222222-2222-4222-8222-222222222222"
		keyID       = "33333333-3333-4333-8333-333333333333"
		seriesID    = "44444444-4444-4444-8444-444444444444"
		leafGenID   = "55555555-5555-4555-8555-555555555555"
		certID      = "66666666-6666-4666-8666-666666666666"
		deliveryID  = "77777777-7777-4777-8777-777777777777"
	)
	const authorityCreatedAt int64 = 1_700_000_000_000_001
	const seriesCreatedAt int64 = 1_700_000_000_000_002
	const seriesArchivedAt int64 = 1_700_000_000_000_003
	const certificateCreatedAt int64 = 1_700_000_000_000_004
	const deliveryExpiresAt int64 = 1_900_000_000_000_000
	der := []byte("stage4-query-certificate-der")
	derHash := sha256.Sum256(der)
	sanValue := "query.stage4.example"
	sanHash := sha256.Sum256([]byte(sanValue))

	for _, insert := range []struct {
		query string
		args  []any
	}{
		{
			query: `INSERT INTO authorities (id, created_at, kind, name, management_parent_id, issuance_state, issuance_certificate_id, archived_at, version) VALUES (?, ?, 'root', 'query-root', NULL, 'inventory', NULL, NULL, 1)`,
			args:  []any{authorityID, authorityCreatedAt},
		},
		{
			query: `INSERT INTO ca_key_generations (id, authority_id, key_material_id, generation_no, key_destroyed_at) VALUES (?, ?, ?, 1, NULL)`,
			args:  []any{caKeyGenID, authorityID, keyID},
		},
		{
			query: `INSERT INTO key_materials (id, algorithm) VALUES (?, 'ecdsa_p256')`,
			args:  []any{keyID},
		},
		{
			query: `INSERT INTO leaf_series (id, created_at, name, purpose, management_authority_id, current_certificate_id, current_key_generation_id, validity_policy_json, version, archived_at) VALUES (?, ?, 'query-leaf', 'distributed', ?, ?, ?, '{"schema_version":1,"rotate_every":3,"validity":{"value":1,"unit":"years"}}', 1, ?)`,
			args:  []any{seriesID, seriesCreatedAt, authorityID, certID, leafGenID, seriesArchivedAt},
		},
		{
			query: `INSERT INTO leaf_key_generations (id, series_id, key_material_id, generation_no, renewal_count, prior_history_unknown, custody) VALUES (?, ?, ?, 1, 0, 0, 'pending_delivery')`,
			args:  []any{leafGenID, seriesID, keyID},
		},
		{
			query: `INSERT INTO certificates (id, created_at, der_sha256, der, key_material_id, issuer_ca_key_generation_id, serial_hex, not_before, not_after, subject_json, extensions_json, origin, created_by) VALUES (?, ?, ?, ?, ?, ?, 'b001', 1000, 9999999999999, '{"common_name":"query.stage4.example","organization":"","organizational_unit":"","country":""}', '{"schema_version":1,"kind":"leaf","profile":"server_tls"}', 'generated', NULL)`,
			args:  []any{certID, certificateCreatedAt, hex.EncodeToString(derHash[:]), der, keyID, caKeyGenID},
		},
		{
			query: `INSERT INTO leaf_certificates (certificate_id, series_id, leaf_key_generation_id, issuer_ca_certificate_id, previous_certificate_id, operation, renewal_count_at_issue, policy_snapshot_json) VALUES (?, ?, ?, ?, NULL, 'initial', 0, '{}')`,
			args:  []any{certID, seriesID, leafGenID, certID},
		},
		{
			query: `INSERT INTO certificate_sans (certificate_id, position, type, normalized_value, normalized_value_hash) VALUES (?, 0, 'dns', ?, ?)`,
			args:  []any{certID, sanValue, hex.EncodeToString(sanHash[:])},
		},
		{
			query: `INSERT INTO key_deliveries (id, leaf_key_generation_id, certificate_id, expires_at, state, consumed_at, finished_at, failure_code, version) VALUES (?, ?, ?, ?, 'pending', NULL, NULL, NULL, 1)`,
			args:  []any{deliveryID, leafGenID, certID, deliveryExpiresAt},
		},
	} {
		if _, err := db.ExecContext(ctx, insert.query, insert.args...); err != nil {
			t.Fatalf("insert query fixture: %v", err)
		}
	}

	d, err := dialect.New(config.SQLite)
	if err != nil {
		t.Fatalf("sqlite dialect: %v", err)
	}
	repo := &QueryRepository{executor: db, dialect: d}
	scope := port.QueryScope{All: true}

	t.Run("authority list and get retain stored created_at", func(t *testing.T) {
		page, err := repo.ListAuthorities(ctx, contract.AuthorityListQuery{Page: contract.PageRequest{Limit: 10}}, scope)
		if err != nil {
			t.Fatalf("ListAuthorities: %v", err)
		}
		if len(page.Items) != 1 || page.Items[0].Authority.ID() != domain.AuthorityID(authorityID) {
			t.Fatalf("authority list = %#v, want fixture authority", page.Items)
		}
		if got := page.Items[0].CreatedAt; !got.Equal(domain.InstantFromUnixMicro(authorityCreatedAt)) {
			t.Errorf("listed authority created_at = %s, want persisted %d", got, authorityCreatedAt)
		}
		item, err := repo.GetAuthority(ctx, domain.AuthorityID(authorityID), scope)
		if err != nil {
			t.Fatalf("GetAuthority: %v", err)
		}
		if got := item.CreatedAt; !got.Equal(domain.InstantFromUnixMicro(authorityCreatedAt)) {
			t.Errorf("authority created_at = %s, want persisted %d", got, authorityCreatedAt)
		}
	})

	t.Run("series list and get retain timestamps and current delivery", func(t *testing.T) {
		page, err := repo.ListSeries(ctx, contract.SeriesListQuery{Page: contract.PageRequest{Limit: 10}}, scope)
		if err != nil {
			t.Fatalf("ListSeries: %v", err)
		}
		if len(page.Items) != 1 {
			t.Fatalf("ListSeries returned %d rows, want one", len(page.Items))
		}
		assertStage4SeriesSnapshot(t, page.Items[0], seriesCreatedAt, seriesArchivedAt, deliveryID)
		item, err := repo.GetSeries(ctx, domain.SeriesID(seriesID), scope)
		if err != nil {
			t.Fatalf("GetSeries: %v", err)
		}
		assertStage4SeriesSnapshot(t, item, seriesCreatedAt, seriesArchivedAt, deliveryID)
	})

	t.Run("certificate list and get retain stored created_at", func(t *testing.T) {
		page, err := repo.ListCertificates(ctx, contract.CertificateListQuery{Page: contract.PageRequest{Limit: 10}}, scope)
		if err != nil {
			t.Fatalf("ListCertificates: %v", err)
		}
		if len(page.Items) != 1 || page.Items[0].Certificate.ID() != domain.CertificateID(certID) {
			t.Fatalf("certificate list = %#v, want fixture certificate", page.Items)
		}
		if got := page.Items[0].CreatedAt; !got.Equal(domain.InstantFromUnixMicro(certificateCreatedAt)) {
			t.Errorf("listed certificate created_at = %s, want persisted %d", got, certificateCreatedAt)
		}
		item, err := repo.GetCertificate(ctx, domain.CertificateID(certID), scope)
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		if got := item.CreatedAt; !got.Equal(domain.InstantFromUnixMicro(certificateCreatedAt)) {
			t.Errorf("certificate created_at = %s, want persisted %d", got, certificateCreatedAt)
		}
	})
}

func assertStage4SeriesSnapshot(t *testing.T, snapshot port.SeriesSnapshot, createdAt, archivedAt int64, deliveryID string) {
	t.Helper()
	if snapshot.Series.ID() != "44444444-4444-4444-8444-444444444444" {
		t.Errorf("series ID = %q, want fixture series", snapshot.Series.ID())
	}
	if !snapshot.CreatedAt.Equal(domain.InstantFromUnixMicro(createdAt)) {
		t.Errorf("series created_at = %s, want persisted %d", snapshot.CreatedAt, createdAt)
	}
	if !snapshot.Series.ArchivedAt().Equal(domain.InstantFromUnixMicro(archivedAt)) {
		t.Errorf("series archived_at = %s, want persisted %d", snapshot.Series.ArchivedAt(), archivedAt)
	}
	if snapshot.Delivery == nil || snapshot.Delivery.ID() != domain.DeliveryID(deliveryID) || snapshot.Delivery.State() != domain.DeliveryStatePending {
		t.Errorf("series delivery = %#v, want pending delivery %q", snapshot.Delivery, deliveryID)
	}
}
