// Package pki implements the SQL-backed PKIRepository. All methods use the
// executor supplied by the current unit of work; this package never opens or
// finishes a transaction of its own.
package pki

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

// Repository is a PKIRepository bound to one transaction-scoped executor.
type Repository struct {
	exec    core.SQLExecutor
	dialect dialect.Dialect
}

// New binds a repository to exec and d. The caller owns transaction lifetime.
func New(exec core.SQLExecutor, d dialect.Dialect) *Repository {
	return &Repository{exec: exec, dialect: d}
}

var _ port.PKIRepository = (*Repository)(nil)

func (r *Repository) lockSuffix() string {
	return r.dialect.RowLockClause()
}

// databaseNowMicros returns a dialect-native Unix-microsecond expression for
// schema timestamps not present on the domain value (created_at/updated_at).
// Keeping this in SQL avoids silently writing a zero or a fabricated epoch.
func (r *Repository) databaseNowMicros() string {
	switch string(r.dialect.Kind()) {
	case "postgres":
		return "CAST(EXTRACT(EPOCH FROM clock_timestamp()) * 1000000 AS BIGINT)"
	case "mysql", "mariadb":
		return "CAST(UNIX_TIMESTAMP(CURRENT_TIMESTAMP(6)) * 1000000 AS SIGNED)"
	default: // SQLite
		return "CAST((julianday('now') - 2440587.5) * 86400000000 AS INTEGER)"
	}
}

func (r *Repository) builder() *dialect.Builder { return r.dialect.NewBuilder() }

func (r *Repository) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return r.exec.QueryRowContext(ctx, query, args...)
}

func missing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return port.ErrNotFound
	}
	return err
}

// mapWriteError normalizes unique-key conflicts without tying this package to
// any particular driver's concrete error type. Other constraint failures are
// preserved so callers can distinguish invalid relations from duplicates.
func mapWriteError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		code := state.SQLState()
		if code == "23505" {
			return fmt.Errorf("%s: %w", operation, port.ErrDuplicate)
		}
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unique constraint") || strings.Contains(message, "duplicate entry") || strings.Contains(message, "duplicate key") || strings.Contains(message, "unique violation") {
		return fmt.Errorf("%s: %w", operation, port.ErrDuplicate)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func rowsAffected(result sql.Result, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableInstant(value domain.Instant) any {
	if value.IsZero() {
		return nil
	}
	return value.UnixMicro()
}

func instantFromNullable(value sql.NullInt64) domain.Instant {
	if !value.Valid {
		return domain.Instant{}
	}
	return domain.InstantFromUnixMicro(value.Int64)
}

func validateNullableTimestamp(field string, value sql.NullInt64) error {
	if value.Valid && value.Int64 == 0 {
		return fmt.Errorf("pki: %s contains the reserved zero timestamp", field)
	}
	return nil
}

func instantFromInt64(value int64) domain.Instant { return domain.InstantFromUnixMicro(value) }

func decodeJSONStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func parseAuthorityID(raw string) (domain.AuthorityID, error) {
	v, err := domain.ParseAuthorityID(raw)
	if err != nil {
		return "", fmt.Errorf("invalid authority id in database: %w", err)
	}
	return v, nil
}
func parseCAKeyGenerationID(raw string) (domain.CAKeyGenerationID, error) {
	v, err := domain.ParseCAKeyGenerationID(raw)
	if err != nil {
		return "", fmt.Errorf("invalid CA key generation id in database: %w", err)
	}
	return v, nil
}
func parseCertificateID(raw string) (domain.CertificateID, error) {
	v, err := domain.ParseCertificateID(raw)
	if err != nil {
		return "", fmt.Errorf("invalid certificate id in database: %w", err)
	}
	return v, nil
}
func parseSeriesID(raw string) (domain.SeriesID, error) {
	v, err := domain.ParseSeriesID(raw)
	if err != nil {
		return "", fmt.Errorf("invalid series id in database: %w", err)
	}
	return v, nil
}
func parseLeafKeyGenerationID(raw string) (domain.LeafKeyGenerationID, error) {
	v, err := domain.ParseLeafKeyGenerationID(raw)
	if err != nil {
		return "", fmt.Errorf("invalid leaf key generation id in database: %w", err)
	}
	return v, nil
}
func parseKeyMaterialID(raw string) (domain.KeyMaterialID, error) {
	v, err := domain.ParseKeyMaterialID(raw)
	if err != nil {
		return "", fmt.Errorf("invalid key material id in database: %w", err)
	}
	return v, nil
}

func (r *Repository) rowExists(ctx context.Context, table, idColumn, id string) (bool, error) {
	b := r.builder()
	p := b.Add(id)
	var count int
	err := r.queryRow(ctx, "SELECT COUNT(*) FROM "+table+" WHERE "+idColumn+" = "+p, b.Args()...).Scan(&count)
	if err != nil {
		return false, err
	}
	return count != 0, nil
}

func (r *Repository) optimisticUpdateMiss(ctx context.Context, table, id string, expected domain.Version) error {
	b := r.builder()
	p := b.Add(id)
	var version int64
	if err := r.queryRow(ctx, "SELECT version FROM "+table+" WHERE id = "+p, b.Args()...).Scan(&version); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return port.ErrNotFound
		}
		return err
	}
	if domain.Version(version) == expected {
		return nil
	}
	return port.ErrVersionConflict
}
