package runtime

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"cert-me/internal/config"
	"cert-me/internal/secret"
)

// TestExternalRuntimeOpenDiagnostic exposes the sanitized startup cause when
// an external disposable database fails before the HTTPS lifecycle test starts.
func TestExternalRuntimeOpenDiagnostic(t *testing.T) {
	for _, kind := range []config.DatabaseKind{config.SQLite, config.Postgres, config.MySQL, config.MariaDB} {
		t.Run(string(kind), func(t *testing.T) {
			databaseSpec, ok := runtimeIntegrationDatabaseForKind(t, kind)
			if !ok {
				t.Skip("disposable runtime database is not configured")
			}
			database := databaseSpec.config(t)
			if database.Password != nil {
				defer database.Password.Close()
			}
			storageKey := secret.New(bytes.Repeat([]byte{0x5a}, 32))
			defer storageKey.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			app, err := Open(ctx, Options{
				Database: database, StorageKey: storageKey, ListenAddress: "127.0.0.1:0",
			})
			if err != nil {
				t.Fatalf("Open failed: %s", sanitizeRuntimeDiagnosticError(err.Error(), databaseSpec.envPrefix))
			}
			if err := closeRuntimeIntegrationApp(app); err != nil {
				t.Fatalf("close Open result: %s", sanitizeRuntimeDiagnosticError(err.Error(), databaseSpec.envPrefix))
			}
		})
	}
}

func sanitizeRuntimeDiagnosticError(message, prefix string) string {
	for _, field := range []string{"HOST", "PORT", "DATABASE", "USERNAME", "PASSWORD"} {
		value := os.Getenv(prefix + field)
		if value != "" {
			message = strings.ReplaceAll(message, value, "[redacted]")
		}
	}
	return message
}
