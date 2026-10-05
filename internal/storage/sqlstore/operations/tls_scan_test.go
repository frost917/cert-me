package operations

import (
	"context"
	"database/sql"
	"testing"

	"cert-me/internal/domain"

	_ "modernc.org/sqlite"
)

func TestTLSChangeScanNullablePreviousVersion(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, previous := range []any{nil, "11111111-1111-4111-8111-111111111111"} {
		name := "initial"
		want := domain.TLSVersionID("")
		if previous != nil {
			name, want = "replacement", domain.TLSVersionID(previous.(string))
		}
		t.Run(name, func(t *testing.T) {
			row := db.QueryRowContext(context.Background(), "SELECT ?, ?, ?, ?, ?", previous, "22222222-2222-4222-8222-222222222222", "applied", nil, 1)
			change, err := scanTLSChange(row)
			if err != nil {
				t.Fatalf("read persisted TLS change: %v", err)
			}
			if change.PreviousVersionID() != want || change.Phase() != domain.TLSChangePhaseApplied {
				t.Fatal("TLS change lost its nullable previous pointer or applied phase")
			}
		})
	}
}
