// Package operations implements SQL-backed job, maintenance, TLS, audit and
// query repositories. Every value is bound to the caller's transaction-scoped
// executor; methods in this package never begin or finish a transaction.
package operations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"cert-me/internal/app/port"
	"cert-me/internal/config"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

// Repositories groups operations repositories sharing one transaction-bound
// executor. Keep this value within the callback that supplied executor.
type Repositories struct {
	Jobs        *JobRepository
	Maintenance *MaintenanceRepository
	TLS         *TLSRepository
	Audit       *AuditRepository
	Queries     *QueryRepository
}

// New validates executor and dialect once and binds each repository to them.
func New(executor core.SQLExecutor, d dialect.Dialect) (*Repositories, error) {
	if executor == nil || isNil(executor) {
		return nil, errors.New("sqlstore operations: SQL executor is required")
	}
	validated, err := dialect.New(d.Kind())
	if err != nil {
		return nil, fmt.Errorf("sqlstore operations: %w", err)
	}
	return &Repositories{
		Jobs:        &JobRepository{executor: executor, dialect: validated},
		Maintenance: &MaintenanceRepository{executor: executor, dialect: validated},
		TLS:         &TLSRepository{executor: executor, dialect: validated},
		Audit:       &AuditRepository{executor: executor, dialect: validated},
		Queries:     &QueryRepository{executor: executor, dialect: validated},
	}, nil
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

type repositoryError struct {
	op  string
	err error
}

func (e *repositoryError) Error() string { return "sqlstore operations: " + e.op }
func (e *repositoryError) Unwrap() error { return e.err }
func failed(op string, err error) error {
	if err == nil {
		return nil
	}
	return &repositoryError{op: op, err: err}
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("sqlstore operations: context is required")
	}
	if err := ctx.Err(); err != nil {
		return failed("operation canceled", err)
	}
	return nil
}

func missing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return port.ErrNotFound
	}
	return err
}

func duplicate(err error) bool {
	if err == nil {
		return false
	}
	var state interface{ SQLState() string }
	if errors.As(err, &state) && state.SQLState() == "23505" {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{"unique constraint", "unique violation", "duplicate entry", "duplicate key", "is not unique"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func duplicateOrFailed(op string, err error) error {
	if duplicate(err) {
		return failed(op, port.ErrDuplicate)
	}
	return failed(op, err)
}

func databaseNowMicros(d dialect.Dialect) string {
	switch d.Kind() {
	case config.Postgres:
		return "CAST(EXTRACT(EPOCH FROM clock_timestamp()) * 1000000 AS BIGINT)"
	case config.MySQL, config.MariaDB:
		return "CAST(UNIX_TIMESTAMP(CURRENT_TIMESTAMP(6)) * 1000000 AS SIGNED)"
	default:
		return "CAST((julianday('now') - 2440587.5) * 86400000000 AS INTEGER)"
	}
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func nullableTime(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}
func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte(nil), value...)
}

type rowScanner interface{ Scan(...any) error }

func rowsAffected(result sql.Result, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (r *JobRepository) builder() *dialect.Builder         { return r.dialect.NewBuilder() }
func (r *MaintenanceRepository) builder() *dialect.Builder { return r.dialect.NewBuilder() }
func (r *TLSRepository) builder() *dialect.Builder         { return r.dialect.NewBuilder() }
func (r *AuditRepository) builder() *dialect.Builder       { return r.dialect.NewBuilder() }
func (r *QueryRepository) builder() *dialect.Builder       { return r.dialect.NewBuilder() }

func (r *JobRepository) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return r.executor.QueryRowContext(ctx, query, args...)
}
func (r *MaintenanceRepository) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return r.executor.QueryRowContext(ctx, query, args...)
}
func (r *TLSRepository) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return r.executor.QueryRowContext(ctx, query, args...)
}
func (r *AuditRepository) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return r.executor.QueryRowContext(ctx, query, args...)
}
func (r *QueryRepository) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return r.executor.QueryRowContext(ctx, query, args...)
}
