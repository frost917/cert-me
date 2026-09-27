package delivery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

// DeliveryRepository stores delivery and grant state on the caller's SQL
// transaction.
type DeliveryRepository struct {
	executor core.SQLExecutor
	dialect  dialect.Dialect
}

// NewDeliveryRepository binds the repository to the caller's executor and SQL dialect.
func NewDeliveryRepository(executor core.SQLExecutor, d dialect.Dialect) (*DeliveryRepository, error) {
	if err := validate(executor, d); err != nil {
		return nil, err
	}
	return &DeliveryRepository{executor: executor, dialect: d}, nil
}

func (r *DeliveryRepository) GetDeliveryForUpdate(ctx context.Context, id domain.DeliveryID) (domain.Delivery, error) {
	if err := checkContext(ctx); err != nil {
		return domain.Delivery{}, err
	}
	b := r.dialect.NewBuilder()
	query := "SELECT id, leaf_key_generation_id, certificate_id, expires_at, state, consumed_at, finished_at, failure_code, version FROM key_deliveries WHERE id = " + b.Add(string(id)) + r.dialect.RowLockClause()
	delivery, err := scanDelivery(r.executor.QueryRowContext(ctx, query, b.Args()...))
	if err != nil {
		return domain.Delivery{}, fmt.Errorf("sqlstore delivery: get for update: %w", notFound(err))
	}
	return delivery, nil
}

func (r *DeliveryRepository) InsertDelivery(ctx context.Context, delivery domain.Delivery) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	now := databaseNowMicros()
	b := r.dialect.NewBuilder()
	query := "INSERT INTO key_deliveries (id, created_at, updated_at, version, leaf_key_generation_id, certificate_id, expires_at, state, consumed_at, finished_at, failure_code) VALUES (" +
		b.Add(string(delivery.ID())) + ", " + b.Add(now) + ", " + b.Add(now) + ", " + b.Add(int64(delivery.Version())) + ", " +
		b.Add(string(delivery.LeafKeyGenerationID())) + ", " + b.Add(string(delivery.CertificateID())) + ", " + b.Add(delivery.ExpiresAt().UnixMicro()) + ", " +
		b.Add(string(delivery.State())) + ", " + nullableInstant(delivery.ConsumedAt(), b) + ", " + nullableInstant(delivery.FinishedAt(), b) + ", " + nullableString(delivery.FailureCode(), b) + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return duplicateOrWrap("sqlstore delivery: insert delivery", err)
	}
	return nil
}

func (r *DeliveryRepository) SaveDelivery(ctx context.Context, delivery domain.Delivery, expectedVersion domain.Version) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "UPDATE key_deliveries SET updated_at = " + b.Add(databaseNowMicros()) + ", version = " + b.Add(int64(delivery.Version())) +
		", leaf_key_generation_id = " + b.Add(string(delivery.LeafKeyGenerationID())) + ", certificate_id = " + b.Add(string(delivery.CertificateID())) +
		", expires_at = " + b.Add(delivery.ExpiresAt().UnixMicro()) + ", state = " + b.Add(string(delivery.State())) +
		", consumed_at = " + nullableInstant(delivery.ConsumedAt(), b) + ", finished_at = " + nullableInstant(delivery.FinishedAt(), b) +
		", failure_code = " + nullableString(delivery.FailureCode(), b) + " WHERE id = " + b.Add(string(delivery.ID())) + " AND version = " + b.Add(int64(expectedVersion))
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return fmt.Errorf("sqlstore delivery: save delivery: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlstore delivery: inspect save result: %w", err)
	}
	if affected > 0 {
		return nil
	}
	var storedVersion int64
	lookup := r.dialect.NewBuilder()
	lookupQuery := "SELECT version FROM key_deliveries WHERE id = " + lookup.Add(string(delivery.ID()))
	if err := r.executor.QueryRowContext(ctx, lookupQuery, lookup.Args()...).Scan(&storedVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return port.ErrNotFound
		}
		return fmt.Errorf("sqlstore delivery: inspect delivery version: %w", err)
	}
	if storedVersion != int64(expectedVersion) {
		return port.ErrVersionConflict
	}
	// Some drivers report zero rows for a no-op UPDATE. The row still matched
	// expectedVersion, so this is a successful idempotent save.
	return nil
}

func (r *DeliveryRepository) ListExpired(ctx context.Context, now domain.Instant, limit int) ([]domain.Delivery, error) {
	return r.list(ctx, "state = 'pending' AND expires_at <= ", now.UnixMicro(), limit, true)
}

func (r *DeliveryRepository) ListPending(ctx context.Context, limit int) ([]domain.Delivery, error) {
	return r.list(ctx, "state = 'pending'", nil, limit, false)
}

func (r *DeliveryRepository) ListTransferring(ctx context.Context, limit int) ([]domain.Delivery, error) {
	return r.list(ctx, "state = 'transferring'", nil, limit, false)
}

func (r *DeliveryRepository) list(ctx context.Context, predicate string, value any, limit int, hasValue bool) ([]domain.Delivery, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	b := r.dialect.NewBuilder()
	query := "SELECT id, leaf_key_generation_id, certificate_id, expires_at, state, consumed_at, finished_at, failure_code, version FROM key_deliveries WHERE " + predicate
	if hasValue {
		query += b.Add(value)
	}
	query += " ORDER BY id"
	if limit > 0 {
		query += " LIMIT " + b.Add(limit)
	}
	rows, err := r.executor.QueryContext(ctx, query, b.Args()...)
	if err != nil {
		return nil, fmt.Errorf("sqlstore delivery: list deliveries: %w", err)
	}
	defer rows.Close()
	out := make([]domain.Delivery, 0)
	for rows.Next() {
		row, err := scanDelivery(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlstore delivery: scan delivery: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore delivery: list deliveries: %w", err)
	}
	return out, nil
}

func scanDelivery(row interface{ Scan(...any) error }) (domain.Delivery, error) {
	var id, leafKeyGenerationID, certificateID, state string
	var expiresAt, version int64
	var consumedAt, finishedAt sql.NullInt64
	var failureCode sql.NullString
	if err := row.Scan(&id, &leafKeyGenerationID, &certificateID, &expiresAt, &state, &consumedAt, &finishedAt, &failureCode, &version); err != nil {
		return domain.Delivery{}, err
	}
	deliveryID, err := domain.ParseDeliveryID(id)
	if err != nil {
		return domain.Delivery{}, err
	}
	leafID, err := domain.ParseLeafKeyGenerationID(leafKeyGenerationID)
	if err != nil {
		return domain.Delivery{}, err
	}
	certID, err := domain.ParseCertificateID(certificateID)
	if err != nil {
		return domain.Delivery{}, err
	}
	parsedVersion, err := parseVersion(version)
	if err != nil {
		return domain.Delivery{}, err
	}
	var consumed, finished domain.Instant
	if consumedAt.Valid {
		consumed = domain.InstantFromUnixMicro(consumedAt.Int64)
	}
	if finishedAt.Valid {
		finished = domain.InstantFromUnixMicro(finishedAt.Int64)
	}
	failure := ""
	if failureCode.Valid {
		failure = failureCode.String
	}
	return domain.NewDelivery(domain.DeliveryFacts{
		ID:                  deliveryID,
		LeafKeyGenerationID: leafID,
		CertificateID:       certID,
		ExpiresAt:           domain.InstantFromUnixMicro(expiresAt),
		State:               domain.DeliveryState(state),
		ConsumedAt:          consumed,
		FinishedAt:          finished,
		FailureCode:         failure,
		Version:             parsedVersion,
	})
}

func nullableInstant(value domain.Instant, b *dialect.Builder) string {
	if value.IsZero() {
		return "NULL"
	}
	return b.Add(value.UnixMicro())
}

func nullableString(value string, b *dialect.Builder) string {
	if value == "" {
		return "NULL"
	}
	return b.Add(value)
}
