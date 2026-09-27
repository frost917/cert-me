package delivery

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
)

func TestScanGrantDerivesSupportedVersionFromTerminalFields(t *testing.T) {
	issued, err := scanGrant(grantScanRow{values: []any{
		"00000000-0000-4000-8000-000000000001",
		strings.Repeat("a", 64),
		"leaf_public",
		"00000000-0000-4000-8000-000000000002",
		nil,
		int64(1800000000000000),
		nil,
		nil,
		"00000000-0000-4000-8000-000000000003",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if issued.Version() != 1 {
		t.Fatalf("issued grant version = %d, want 1", issued.Version())
	}

	consumed, err := scanGrant(grantScanRow{values: []any{
		"00000000-0000-4000-8000-000000000001",
		strings.Repeat("a", 64),
		"leaf_public",
		"00000000-0000-4000-8000-000000000002",
		nil,
		int64(1800000000000000),
		int64(1800000000000001),
		nil,
		"00000000-0000-4000-8000-000000000003",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if consumed.Version() != 2 {
		t.Fatalf("consumed grant version = %d, want 2", consumed.Version())
	}
}

func TestScanGrantRejectsBothTerminalFields(t *testing.T) {
	_, err := scanGrant(grantScanRow{values: []any{
		"00000000-0000-4000-8000-000000000001",
		strings.Repeat("a", 64),
		"leaf_public",
		"00000000-0000-4000-8000-000000000002",
		nil,
		int64(1800000000000000),
		int64(1800000000000001),
		int64(1800000000000002),
		"00000000-0000-4000-8000-000000000003",
	}})
	if err == nil || !strings.Contains(err.Error(), "both consumed and invalidated") {
		t.Fatalf("scanGrant error = %v, want incompatible terminal-state error", err)
	}
}

type grantScanRow struct{ values []any }

func (r grantScanRow) Scan(destinations ...any) error {
	if len(destinations) != len(r.values) {
		return errors.New("scan field count mismatch")
	}
	for i, destination := range destinations {
		switch target := destination.(type) {
		case *string:
			value, ok := r.values[i].(string)
			if !ok {
				return errors.New("invalid string test value")
			}
			*target = value
		case *sql.NullString:
			if r.values[i] == nil {
				*target = sql.NullString{}
			} else {
				value, ok := r.values[i].(string)
				if !ok {
					return errors.New("invalid nullable string test value")
				}
				*target = sql.NullString{String: value, Valid: true}
			}
		case *int64:
			value, ok := r.values[i].(int64)
			if !ok {
				return errors.New("invalid integer test value")
			}
			*target = value
		case *sql.NullInt64:
			if r.values[i] == nil {
				*target = sql.NullInt64{}
			} else {
				value, ok := r.values[i].(int64)
				if !ok {
					return errors.New("invalid nullable integer test value")
				}
				*target = sql.NullInt64{Int64: value, Valid: true}
			}
		default:
			return errors.New("unsupported scan target")
		}
	}
	return nil
}
