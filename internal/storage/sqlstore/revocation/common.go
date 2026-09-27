// Package revocation implements SQL-backed revocation and CRL repositories.
// Repository methods use only the caller's transaction-scoped executor.
package revocation

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"cert-me/internal/app/port"
	"cert-me/internal/config"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

func validate(executor core.SQLExecutor, d dialect.Dialect) (dialect.Dialect, error) {
	if executor == nil || isNil(executor) {
		return dialect.Dialect{}, errors.New("sqlstore revocation: SQL executor is required")
	}
	validated, err := dialect.New(d.Kind())
	if err != nil {
		return dialect.Dialect{}, fmt.Errorf("sqlstore revocation: %w", err)
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
		return errors.New("sqlstore revocation: context is required")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("sqlstore revocation: operation canceled: %w", err)
	}
	return nil
}

func failed(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("sqlstore revocation: %s: %w", operation, err)
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
	var sqlStater interface{ SQLState() string }
	if errors.As(err, &sqlStater) {
		if sqlStater.SQLState() == "23505" {
			return true
		}
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{"unique constraint", "unique violation", "duplicate entry", "duplicate key", "is not unique"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func duplicateOrFailed(operation string, err error) error {
	if isDuplicate(err) {
		return failed(operation, port.ErrDuplicate)
	}
	return failed(operation, err)
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

func optionalString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func optionalInstant(value domain.Instant) any {
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

func instantFromInt64(value int64) domain.Instant {
	return domain.InstantFromUnixMicro(value)
}

func uuid() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate row id: %w", err)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

func revocationReasonToDB(reason domain.RevocationReason) (string, error) {
	switch reason {
	case domain.RevocationReasonUnspecified:
		return "unspecified", nil
	case domain.RevocationReasonKeyCompromise:
		return "keyCompromise", nil
	case domain.RevocationReasonCACompromise:
		return "caCompromise", nil
	case domain.RevocationReasonAffiliationChanged:
		return "affiliationChanged", nil
	case domain.RevocationReasonSuperseded:
		return "superseded", nil
	case domain.RevocationReasonCessationOfOperation:
		return "cessationOfOperation", nil
	case domain.RevocationReasonPrivilegeWithdrawn:
		return "privilegeWithdrawn", nil
	case domain.RevocationReasonAACompromise:
		return "aACompromise", nil
	default:
		return "", fmt.Errorf("unsupported revocation reason %q", reason)
	}
}

func revocationReasonFromDB(raw string) (domain.RevocationReason, error) {
	switch raw {
	case "unspecified":
		return domain.RevocationReasonUnspecified, nil
	case "keyCompromise":
		return domain.RevocationReasonKeyCompromise, nil
	case "caCompromise":
		return domain.RevocationReasonCACompromise, nil
	case "affiliationChanged":
		return domain.RevocationReasonAffiliationChanged, nil
	case "superseded":
		return domain.RevocationReasonSuperseded, nil
	case "cessationOfOperation":
		return domain.RevocationReasonCessationOfOperation, nil
	case "privilegeWithdrawn":
		return domain.RevocationReasonPrivilegeWithdrawn, nil
	case "aACompromise":
		return domain.RevocationReasonAACompromise, nil
	default:
		return "", fmt.Errorf("unknown revocation reason in database %q", raw)
	}
}

func parseCAKeyGenerationID(raw string) (domain.CAKeyGenerationID, error) {
	id, err := domain.ParseCAKeyGenerationID(raw)
	if err != nil {
		return "", fmt.Errorf("invalid CA key generation id in database: %w", err)
	}
	return id, nil
}

func parseCertificateID(raw string) (domain.CertificateID, error) {
	id, err := domain.ParseCertificateID(raw)
	if err != nil {
		return "", fmt.Errorf("invalid certificate id in database: %w", err)
	}
	return id, nil
}

func parseRevocationID(raw string) (domain.RevocationID, error) {
	id, err := domain.ParseRevocationID(raw)
	if err != nil {
		return "", fmt.Errorf("invalid revocation id in database: %w", err)
	}
	return id, nil
}

func parseCRLDocumentID(raw string) (domain.CRLDocumentID, error) {
	id, err := domain.ParseCRLDocumentID(raw)
	if err != nil {
		return "", fmt.Errorf("invalid CRL document id in database: %w", err)
	}
	return id, nil
}

func parseCRLNumber(raw string) (domain.CRLNumber, error) {
	number, err := domain.ParseCRLNumber(raw)
	if err != nil {
		return domain.CRLNumber{}, fmt.Errorf("invalid CRL number in database: %w", err)
	}
	return number, nil
}

func crlNumberForStorage(number domain.CRLNumber) string {
	if number.Hex() == "" {
		return "0"
	}
	return number.Hex()
}
