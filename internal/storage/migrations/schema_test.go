package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManifest(t *testing.T) {
	raw, err := Files.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		SchemaVersion int               `json:"schema_version"`
		Files         map[string]string `json:"files"`
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != 7 || len(manifest.Files) != 32 {
		t.Fatal("unexpected migration set")
	}
	for path, want := range manifest.Files {
		data, err := Files.ReadFile(strings.TrimPrefix(path, "internal/storage/migrations/"))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != want {
			t.Errorf("checksum mismatch: %s", path)
		}
	}
}

// External DSNs must point to dedicated EMPTY disposable databases. This test
// creates tables and fixtures; it deliberately fails if a schema already exists.
func TestSchema(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql", "mariadb"} {
		t.Run(dialect, func(t *testing.T) {
			driver, dsn := dialect, os.Getenv("CERTME_TEST_"+strings.ToUpper(dialect)+"_DSN")
			if dialect == "sqlite" {
				dsn = filepath.Join(t.TempDir(), "schema.db") + "?_pragma=foreign_keys(1)"
			}
			if dialect == "postgres" {
				driver = "pgx"
			}
			if dialect == "mariadb" {
				driver = "mysql"
			}
			if dsn == "" {
				t.Skip("dedicated empty DB DSN not supplied")
			}
			db, err := sql.Open(driver, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			if err = db.PingContext(ctx); err != nil {
				t.Fatal(err)
			}
			entries, err := Files.ReadDir(dialect)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				data, err := Files.ReadFile(dialect + "/" + entry.Name())
				if err != nil {
					t.Fatal(err)
				}
				// Initial SQL has no procedure bodies or semicolons inside literals.
				// The production runner needs a reviewed statement manifest.
				for _, statement := range strings.Split(string(data), ";") {
					if strings.TrimSpace(statement) == "" {
						continue
					}
					if _, err = db.ExecContext(ctx, statement); err != nil {
						t.Fatalf("%s: %v", entry.Name(), err)
					}
				}
			}
			bind := func(query string) string {
				if dialect != "postgres" {
					return query
				}
				n := 0
				for strings.Contains(query, "?") {
					n++
					query = strings.Replace(query, "?", fmt.Sprintf("$%d", n), 1)
				}
				return query
			}
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := db.ExecContext(ctx, bind(q), args...); err != nil {
					t.Fatal(err)
				}
			}
			reject := func(q string, args ...any) {
				t.Helper()
				if _, err := db.ExecContext(ctx, bind(q), args...); err == nil {
					t.Fatal("constraint accepted invalid write:", q)
				}
			}
			id := "00000000-0000-4000-8000-000000000001"
			second := "00000000-0000-4000-8000-000000000002"
			accountSQL := "INSERT INTO accounts (id,created_at,updated_at,version,login_name,normalized_login_name,password_hash,state,auth_epoch,is_global_admin) VALUES (?,1,1,0,?,?,?,'active',0,?)"
			exec(accountSQL, id, "Admin", "admin", "test-placeholder", true)
			reject(accountSQL, second, "ADMIN", "admin", "test-placeholder", true)
			reject("UPDATE accounts SET state='unknown' WHERE id=?", id)
			reject("UPDATE accounts SET version=-1 WHERE id=?", id)
			exec("INSERT INTO sessions (id,created_at,token_hash,account_id,auth_epoch,last_seen_at,absolute_expires_at,csrf_secret_hash) VALUES (?,1,?,?,0,1,100,?)", id, strings.Repeat("a", 64), id, strings.Repeat("b", 64))
			reject("DELETE FROM accounts WHERE id=?", id)
			reject("UPDATE sessions SET account_id=?", second)
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.ExecContext(ctx, bind("UPDATE accounts SET auth_epoch=1 WHERE id=?"), id); err != nil {
				t.Fatal(err)
			}
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			var epoch int
			if err = db.QueryRowContext(ctx, bind("SELECT auth_epoch FROM accounts WHERE id=?"), id).Scan(&epoch); err != nil || epoch != 0 {
				t.Fatalf("rollback: epoch=%d err=%v", epoch, err)
			}
			testPKIConstraints(t, exec, reject)
			if dialect == "sqlite" {
				var sqliteVersion string
				if err := db.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&sqliteVersion); err != nil {
					t.Fatal(err)
				}
				t.Log("SQLite", sqliteVersion)
				var violations int
				if err = db.QueryRowContext(ctx, "SELECT count(*) FROM pragma_foreign_key_check").Scan(&violations); err != nil || violations != 0 {
					t.Fatalf("foreign keys: %d, %v", violations, err)
				}
			}
		})
	}
}
