// Package delivery implements SQL-backed download, operation-request, and
// encrypted-secret repositories. All operations use the transaction-bound
// executor supplied by sqlstore/core; repositories never create a transaction.
package delivery

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

func validate(executor core.SQLExecutor, d dialect.Dialect) error {
	if executor == nil || isNilInterface(executor) {
		return errors.New("sqlstore delivery: executor is required")
	}
	if _, err := dialect.New(d.Kind()); err != nil {
		return fmt.Errorf("sqlstore delivery: %w", err)
	}
	return nil
}

func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("sqlstore delivery: context is required")
	}
	return ctx.Err()
}

func databaseNowMicros() int64 { return time.Now().UTC().UnixMicro() }

func newUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("sqlstore delivery: generate row id: %w", err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	var out [36]byte
	// Fill through a compact hex string to keep UUID formatting explicit.
	compact := hex.EncodeToString(raw[:])
	j := 0
	for i := range out {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			out[i] = '-'
			continue
		}
		out[i] = compact[j]
		j++
	}
	return string(out[:]), nil
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return port.ErrNotFound
	}
	return err
}

// isDuplicate recognizes the constraint signals exposed by the database
// drivers without taking a dependency on a particular driver package.
func isDuplicate(err error) bool {
	if err == nil {
		return false
	}
	var sqlStater interface{ SQLState() string }
	if errors.As(err, &sqlStater) && sqlStater.SQLState() == "23505" {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{"unique constraint failed", "unique violation", "duplicate entry", "duplicate key", "is not unique"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func duplicateOrWrap(operation string, err error) error {
	if isDuplicate(err) {
		return fmt.Errorf("%s: %w", operation, port.ErrDuplicate)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func parseVersion(value int64) (domain.Version, error) {
	v, err := domain.ParseVersion(value)
	if err != nil {
		return 0, fmt.Errorf("sqlstore delivery: invalid stored version: %w", err)
	}
	return v, nil
}
