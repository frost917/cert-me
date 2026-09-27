// Package workflow implements SQL-backed import/takeover and CA-transition
// repositories. Repositories are bound to the current unit-of-work executor;
// they never begin, commit, or roll back transactions themselves.
package workflow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"cert-me/internal/app/port"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

// Repositories groups workflow repositories sharing one executor. Keep this
// value within the transaction callback that supplied executor.
type Repositories struct {
	Imports     *ImportRepository
	Transitions *TransitionRepository
}

// New binds both repositories to executor and validates the dialect once.
func New(executor core.SQLExecutor, d dialect.Dialect) (*Repositories, error) {
	validated, err := validate(executor, d)
	if err != nil {
		return nil, err
	}
	return &Repositories{
		Imports:     &ImportRepository{executor: executor, dialect: validated},
		Transitions: &TransitionRepository{executor: executor, dialect: validated},
	}, nil
}

func validate(executor core.SQLExecutor, d dialect.Dialect) (dialect.Dialect, error) {
	if executor == nil || isNil(executor) {
		return dialect.Dialect{}, errors.New("sqlstore workflow: SQL executor is required")
	}
	validated, err := dialect.New(d.Kind())
	if err != nil {
		return dialect.Dialect{}, fmt.Errorf("sqlstore workflow: %w", err)
	}
	return validated, nil
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

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("sqlstore workflow: context is required")
	}
	return ctx.Err()
}

func nowUnixMicro() int64 { return time.Now().UTC().UnixMicro() }

func optionalString(value string, b *dialect.Builder) string {
	if value == "" {
		return "NULL"
	}
	return b.Add(value)
}

func optionalInstant(value interface {
	UnixMicro() int64
	IsZero() bool
}, b *dialect.Builder) string {
	if value.IsZero() {
		return "NULL"
	}
	return b.Add(value.UnixMicro())
}

func missing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return port.ErrNotFound
	}
	return err
}

func isDuplicate(err error) bool {
	if err == nil {
		return false
	}
	var state interface{ SQLState() string }
	if errors.As(err, &state) && state.SQLState() == "23505" {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{
		"unique constraint failed", "unique violation", "duplicate entry", "duplicate key", "is not unique",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func insertError(operation string, err error) error {
	if isDuplicate(err) {
		return fmt.Errorf("sqlstore workflow: %s: %w", operation, port.ErrDuplicate)
	}
	return fmt.Errorf("sqlstore workflow: %s: %w", operation, err)
}

func rowsAffected(result sql.Result, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

type rowScanner interface {
	Scan(...any) error
}
