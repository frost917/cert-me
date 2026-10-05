package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"cert-me/internal/config"
	"cert-me/internal/secret"
	"cert-me/internal/storage/connection"
)

// TestExternalCatalogDiagnostic is a focused integration diagnostic for the
// catalog reader. It uses the disposable runtime databases configured by the
// stage verification harness and reports the exact failed catalog query.
func TestExternalCatalogDiagnostic(t *testing.T) {
	for _, kind := range []config.DatabaseKind{config.Postgres, config.MySQL, config.MariaDB} {
		t.Run(string(kind), func(t *testing.T) {
			prefix := "CERTME_RUNTIME_TEST_" + strings.ToUpper(string(kind)) + "_"
			fields := []string{"HOST", "PORT", "DATABASE", "USERNAME", "PASSWORD"}
			values := make(map[string]string, len(fields))
			for _, field := range fields {
				value, ok := os.LookupEnv(prefix + field)
				if !ok || value == "" {
					t.Skip("disposable external database is not configured")
				}
				values[field] = value
			}
			port, err := strconv.ParseUint(values["PORT"], 10, 16)
			if err != nil || port == 0 {
				t.Fatal("diagnostic database port is invalid")
			}
			password := secret.FromString(values["PASSWORD"])
			defer password.Close()
			database := config.Database{
				Kind: kind, Host: values["HOST"], Port: uint16(port),
				DatabaseName: values["DATABASE"], Username: values["USERNAME"], Password: password,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			handle, err := connection.Open(ctx, database, connection.Options{})
			if err != nil {
				t.Fatalf("open disposable database failed: %s", sanitizeDiagnosticError(err, values))
			}
			defer handle.Close()

			recorder := &catalogQueryRecorder{queryer: handle.ReadDB()}
			actual, err := readCatalog(ctx, recorder, kind)
			if err != nil {
				t.Fatalf("catalog query failed; query=%q cause=%s", recorder.lastQuery, sanitizeDiagnosticError(err, values))
			}
			plan, err := loadPlan(kind)
			if err != nil {
				t.Fatalf("load migration plan: %v", err)
			}
			inspection, err := inspectWithPlan(ctx, handle.WriterConn(), kind, plan)
			if err != nil {
				t.Fatalf("inspect disposable schema failed: %s", sanitizeDiagnosticError(err, values))
			}
			if inspection.status.State == StateIncompatible {
				t.Logf("migration state=%s actual_tables=%v unknown=%v", inspection.status.State, sortedTableNames(actual), actual.unknown)
				for name, expected := range plan.full[0].tables {
					observed, exists := actual.tables[name]
					if !exists || !sameTable(observed, expected, kind) {
						t.Logf("initial catalog mismatch table=%s exists=%t actual=%#v expected=%#v", name, exists, observed, expected)
					}
				}
				t.Fatal("server-reported migration catalog must match a recognized schema prefix")
			}
		})
	}
}

func sortedTableNames(value schema) []string {
	names := make([]string, 0, len(value.tables))
	for name := range value.tables {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type catalogQueryRecorder struct {
	queryer interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	}
	lastQuery string
}

func (r *catalogQueryRecorder) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	r.lastQuery = query
	return r.queryer.QueryContext(ctx, query, args...)
}

func sanitizeDiagnosticError(err error, values map[string]string) string {
	message := err.Error()
	for _, field := range []string{"PASSWORD", "USERNAME", "HOST", "DATABASE"} {
		value := values[field]
		if value != "" {
			message = strings.ReplaceAll(message, value, "[redacted]")
		}
	}
	for _, scheme := range []string{"postgres://", "mysql://", "mariadb://"} {
		for {
			start := strings.Index(message, scheme)
			if start < 0 {
				break
			}
			end := strings.IndexAny(message[start:], " \t\r\n\"'")
			if end < 0 {
				end = len(message) - start
			}
			message = message[:start] + fmt.Sprint("[redacted connection string]") + message[start+end:]
		}
	}
	return message
}
