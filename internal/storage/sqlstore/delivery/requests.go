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

// RequestRepository stores successful idempotency results on the caller's
// transaction executor.
type RequestRepository struct {
	executor core.SQLExecutor
	dialect  dialect.Dialect
}

// NewRequestRepository binds the repository to the caller's executor and SQL dialect.
func NewRequestRepository(executor core.SQLExecutor, d dialect.Dialect) (*RequestRepository, error) {
	if err := validate(executor, d); err != nil {
		return nil, err
	}
	return &RequestRepository{executor: executor, dialect: d}, nil
}

var _ port.RequestRepository = (*RequestRepository)(nil)

func (r *RequestRepository) Find(ctx context.Context, key port.OperationRequestKey) (port.OperationRequestResult, error) {
	if err := checkContext(ctx); err != nil {
		return port.OperationRequestResult{}, err
	}
	b := r.dialect.NewBuilder()
	query := "SELECT input_hash, result_certificate_id, result_json FROM operation_requests WHERE actor_key = " + b.Add(key.ActorKey) +
		" AND operation = " + b.Add(key.Operation) + " AND request_id = " + b.Add(key.RequestID) + " AND state = 'succeeded'"
	var inputHash string
	var certificateID sql.NullString
	var result []byte
	if err := r.executor.QueryRowContext(ctx, query, b.Args()...).Scan(&inputHash, &certificateID, &result); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return port.OperationRequestResult{}, port.ErrNotFound
		}
		return port.OperationRequestResult{}, fmt.Errorf("sqlstore request: find result: %w", err)
	}
	if result == nil {
		return port.OperationRequestResult{}, errors.New("sqlstore request: succeeded request has a NULL result_json")
	}
	var parsedCertificateID domain.CertificateID
	if certificateID.Valid {
		parsed, err := domain.ParseCertificateID(certificateID.String)
		if err != nil {
			return port.OperationRequestResult{}, fmt.Errorf("sqlstore request: invalid result certificate id: %w", err)
		}
		parsedCertificateID = parsed
	}
	return port.OperationRequestResult{
		InputHash:           inputHash,
		ResultCertificateID: parsedCertificateID,
		ResultJSON:          append([]byte(nil), result...),
	}, nil
}

func (r *RequestRepository) InsertResult(ctx context.Context, key port.OperationRequestKey, inputHash string, publicResult []byte) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	id, err := newUUID()
	if err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "INSERT INTO operation_requests (id, created_at, actor_key, operation, request_id, input_hash, state, result_certificate_id, result_json) VALUES (" +
		b.Add(id) + ", " + b.Add(databaseNowMicros()) + ", " + b.Add(key.ActorKey) + ", " + b.Add(key.Operation) + ", " +
		b.Add(key.RequestID) + ", " + b.Add(inputHash) + ", 'succeeded', NULL, " + b.Add(string(publicResult)) + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return duplicateOrWrap("sqlstore request: insert result", err)
	}
	return nil
}
