package connection

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"cert-me/internal/config"
	"cert-me/internal/secret"
)

func TestOpenSQLiteMemoryPinsWriterAndSetsPragmas(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.Database{Kind: config.SQLite, SQLitePath: ":memory:"}, Options{CreateIfMissing: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	writer := db.WriterConn()
	if writer == nil {
		t.Fatal("writer connection is nil")
	}
	if _, err := writer.ExecContext(ctx, "CREATE TEMP TABLE writer_pin (value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ExecContext(ctx, "INSERT INTO writer_pin (value) VALUES ('pinned')"); err != nil {
		t.Fatal(err)
	}
	var value string
	if err := writer.QueryRowContext(ctx, "SELECT value FROM writer_pin").Scan(&value); err != nil {
		t.Fatalf("writer temporary table was lost: %v", err)
	}
	if value != "pinned" {
		t.Fatalf("writer temporary table value = %q, want pinned", value)
	}
	if _, err := writer.ExecContext(ctx, "CREATE TABLE shared_data (value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ExecContext(ctx, "INSERT INTO shared_data (value) VALUES ('shared')"); err != nil {
		t.Fatal(err)
	}

	checkPragmas := func(queryer interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	}) {
		t.Helper()
		var foreignKeys, busyTimeout int
		if err := queryer.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
			t.Fatal(err)
		}
		if err := queryer.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
			t.Fatal(err)
		}
		if foreignKeys != 1 || busyTimeout != sqliteBusyMS {
			t.Fatalf("SQLite pragmas = foreign_keys:%d busy_timeout:%d, want 1:%d", foreignKeys, busyTimeout, sqliteBusyMS)
		}
	}
	checkPragmas(writer)

	reader := db.ReadDB()
	if reader == nil {
		t.Fatal("read pool is nil")
	}
	var sharedValue string
	if err := reader.QueryRowContext(ctx, "SELECT value FROM shared_data").Scan(&sharedValue); err != nil {
		t.Fatalf("read pool could not see writer data: %v", err)
	}
	if sharedValue != "shared" {
		t.Fatalf("read pool value = %q, want shared", sharedValue)
	}
	reader.SetMaxOpenConns(2)
	first, err := reader.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := reader.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	checkPragmas(first)
	checkPragmas(second)

	if err := db.CheckWriter(ctx); err != nil {
		t.Fatalf("CheckWriter() error = %v", err)
	}
}

func TestOpenSQLiteCreationMode(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "new.db")
	settings := config.Database{Kind: config.SQLite, SQLitePath: path}

	if db, err := Open(ctx, settings, Options{}); err == nil {
		_ = db.Close()
		t.Fatal("Open without CreateIfMissing succeeded for a missing file")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-creating Open left file state err = %v, want not exist", err)
	}

	db, err := Open(ctx, settings, Options{CreateIfMissing: true})
	if err != nil {
		t.Fatalf("creating Open failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("created SQLite file stat = %v, %v", info, err)
	}

	db, err = Open(ctx, settings, Options{})
	if err != nil {
		t.Fatalf("non-creating Open failed for existing file: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestSQLiteWriterBeginsImmediateTransaction(t *testing.T) {
	ctx := context.Background()
	settings := config.Database{Kind: config.SQLite, SQLitePath: filepath.Join(t.TempDir(), "writer-lock.db")}
	db, err := Open(ctx, settings, Options{CreateIfMissing: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.WriterConn().ExecContext(ctx, "CREATE TABLE write_lock_test (value INTEGER)"); err != nil {
		t.Fatal(err)
	}

	transaction, err := db.WriterConn().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("writer BeginTx() error = %v", err)
	}
	defer transaction.Rollback()

	observer, err := db.ReadDB().Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	if _, err := observer.ExecContext(ctx, "PRAGMA busy_timeout=0"); err != nil {
		t.Fatal(err)
	}
	if _, err := observer.ExecContext(ctx, "BEGIN IMMEDIATE"); err == nil {
		t.Fatal("second connection acquired a write reservation before the writer's transaction ended")
	}
}

func TestPostgresConfigRequiresVerifiedTLSAndIgnoresAmbientSettings(t *testing.T) {
	serviceFile := filepath.Join(t.TempDir(), "pg_service.conf")
	if err := os.WriteFile(serviceFile, []byte("[ambient]\nhost=redirect.invalid\nport=1\nsslmode=disable\noptions='-c search_path=ambient'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	passFile := filepath.Join(t.TempDir(), "pgpass")
	if err := os.WriteFile(passFile, []byte("*:*:*:cert-me:ambient-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PGSERVICE", "ambient")
	t.Setenv("PGSERVICEFILE", serviceFile)
	t.Setenv("PGPASSFILE", passFile)
	t.Setenv("PGHOST", "ambient.invalid")
	t.Setenv("PGPORT", "1")
	t.Setenv("PGDATABASE", "ambient-db")
	t.Setenv("PGUSER", "ambient-user")
	t.Setenv("PGPASSWORD", "ambient-password")
	t.Setenv("PGSSLMODE", "disable")
	t.Setenv("PGSSLROOTCERT", filepath.Join(t.TempDir(), "ambient-root.crt"))
	t.Setenv("PGSSLCERT", filepath.Join(t.TempDir(), "ambient-client.crt"))
	t.Setenv("PGSSLKEY", filepath.Join(t.TempDir(), "ambient-client.key"))
	t.Setenv("PGCONNECT_TIMEOUT", "not-a-duration")
	t.Setenv("PGTARGETSESSIONATTRS", "invalid")

	password := secret.FromString("validated-password")
	defer password.Close()
	settings := config.Database{
		Kind:         config.Postgres,
		Host:         "db.example.test",
		Port:         5432,
		DatabaseName: "certificates",
		Username:     "cert-me",
		Password:     password,
	}
	connConfig, err := postgresConnConfig(settings)
	if err != nil {
		t.Fatal(err)
	}
	if connConfig.Host != settings.Host || connConfig.Port != settings.Port || connConfig.Database != settings.DatabaseName || connConfig.User != settings.Username || connConfig.Password != "validated-password" {
		t.Fatalf("PostgreSQL config inherited ambient settings: host=%q port=%d database=%q user=%q", connConfig.Host, connConfig.Port, connConfig.Database, connConfig.User)
	}
	if connConfig.TLSConfig == nil {
		t.Fatal("PostgreSQL TLS configuration is nil")
	}
	if connConfig.TLSConfig.ServerName != settings.Host || connConfig.TLSConfig.InsecureSkipVerify || connConfig.TLSConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("PostgreSQL TLS configuration is not verified for %q: %#v", settings.Host, connConfig.TLSConfig)
	}
	if len(connConfig.Fallbacks) != 0 {
		t.Fatalf("PostgreSQL config has %d fallback(s), want none", len(connConfig.Fallbacks))
	}
	if len(connConfig.RuntimeParams) != 0 {
		t.Fatalf("PostgreSQL config inherited runtime parameters: %v", connConfig.RuntimeParams)
	}

	settings.Password.Close()
	settings.Password = nil
	connConfig, err = postgresConnConfig(settings)
	if err != nil {
		t.Fatal(err)
	}
	if connConfig.Password != "" {
		t.Fatal("PostgreSQL config inherited a password from the ambient environment or passfile")
	}
}

func TestCloseIsIdempotentAndCheckWriterFailsAfterClose(t *testing.T) {
	db, err := Open(context.Background(), config.Database{Kind: config.SQLite, SQLitePath: ":memory:"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if err := db.CheckWriter(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("CheckWriter() after Close error = %v, want ErrClosed", err)
	}
	if db.ReadDB() != nil || db.WriterConn() != nil {
		t.Fatal("database handles should be nil after Close")
	}
}
