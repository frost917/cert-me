package migrate

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"cert-me/internal/config"
	"cert-me/internal/storage/connection"
	"cert-me/internal/storage/executionlock"
)

func TestStatusDoesNotCreateMissingSQLiteDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	runner, err := NewRunner(config.Database{Kind: config.SQLite, SQLitePath: path})
	if err != nil {
		t.Fatal(err)
	}
	status, err := runner.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StateEmpty {
		t.Fatalf("got state %q, want empty", status.State)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("status created or changed the SQLite path: stat error %v", err)
	}
}

func TestResumeDoesNotBootstrapEmptySQLiteDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	runner, err := NewRunner(config.Database{Kind: config.SQLite, SQLitePath: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Resume(context.Background()); !errors.Is(err, ErrMigrateRequired) {
		t.Fatalf("Resume error = %v, want ErrMigrateRequired", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resume created a SQLite file: stat error %v", err)
	}
}

func TestMigrateIsIdempotentAndResumeIsNoOpOnCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema.db")
	runner, err := NewRunner(config.Database{Kind: config.SQLite, SQLitePath: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	status, err := runner.Status(context.Background())
	if err != nil {
		t.Fatalf("Status after migrate: %v", err)
	}
	if status.State != StateCurrent || status.CurrentVersion != targetVersion {
		t.Fatalf("after migrate got state=%q version=%d", status.State, status.CurrentVersion)
	}
	if err := runner.Migrate(context.Background()); err != nil {
		t.Fatalf("idempotent Migrate: %v", err)
	}
	if err := runner.Resume(context.Background()); err != nil {
		t.Fatalf("Resume on current schema: %v", err)
	}
}

func TestResumeDoesNotApplyNormalPendingVersion(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "pending.db")
	database := config.Database{Kind: config.SQLite, SQLitePath: path}
	runner, err := NewRunner(database)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := connection.Open(ctx, database, connection.Options{CreateIfMissing: true})
	if err != nil {
		t.Fatal(err)
	}
	lock, err := executionlock.Acquire(ctx, database, handle.WriterConn())
	if err != nil {
		_ = handle.Close()
		t.Fatal(err)
	}
	plan, err := loadPlan(config.SQLite)
	if err == nil {
		err = bootstrap(ctx, handle.WriterConn(), lock, runner, plan)
	}
	if err != nil {
		_ = lock.Release(ctx)
		_ = handle.Close()
		t.Fatalf("prepare journal with a normal pending version: %v", err)
	}
	if err := lock.Release(ctx); err != nil {
		_ = handle.Close()
		t.Fatalf("release setup lock: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runner.Resume(ctx); !errors.Is(err, ErrMigrateRequired) {
		t.Fatalf("Resume error = %v, want ErrMigrateRequired", err)
	}
	status, err := runner.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StateUpgradeRequired || status.CurrentVersion != 0 {
		t.Fatalf("Resume changed pending schema: state=%q version=%d", status.State, status.CurrentVersion)
	}
}

func TestAuditScopeBackfillIsExplicitAndUnclassifiableRowsBlockVersionNine(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit-scope.db")
	database := config.Database{Kind: config.SQLite, SQLitePath: path}
	runner, err := NewRunner(database)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := connection.Open(ctx, database, connection.Options{CreateIfMissing: true})
	if err != nil {
		t.Fatal(err)
	}
	lock, err := executionlock.Acquire(ctx, database, handle.WriterConn())
	if err != nil {
		_ = handle.Close()
		t.Fatal(err)
	}
	plan, err := loadPlan(config.SQLite)
	if err == nil {
		err = bootstrap(ctx, handle.WriterConn(), lock, runner, plan)
	}
	if err == nil {
		for version := 1; version <= 7; version++ {
			if err = applyVersion(ctx, handle.WriterConn(), lock, runner, plan, version, false, 0); err != nil {
				break
			}
		}
	}
	if err == nil {
		_, err = handle.WriterConn().ExecContext(ctx, `INSERT INTO authorities
			(id,created_at,updated_at,version,kind,name,issuance_state)
			VALUES (?,?,?,?,?,?,?)`, "00000000-0000-4000-8000-000000000101", 1, 1, 0, "root", "test-root", "inventory")
	}
	if err == nil {
		_, err = handle.WriterConn().ExecContext(ctx, `INSERT INTO audit_events
			(id,created_at,occurred_at,actor_kind,action,target_type,result,details_json)
			VALUES (?,?,?,?,?,?,?,?)`, "00000000-0000-4000-8000-000000000201", 1, 1, "system", "settings.update", "installation", "success", `{"schema_version":1}`)
	}
	if err == nil {
		_, err = handle.WriterConn().ExecContext(ctx, `INSERT INTO audit_events
			(id,created_at,occurred_at,actor_kind,action,target_type,result,details_json)
			VALUES (?,?,?,?,?,?,?,?)`, "00000000-0000-4000-8000-000000000202", 1, 1, "system", "authority.archive", "authority", "success", `{"schema_version":1}`)
	}
	if err == nil {
		_, err = handle.WriterConn().ExecContext(ctx, `INSERT INTO audit_events
			(id,created_at,occurred_at,actor_kind,action,target_type,result,details_json)
			VALUES (?,?,?,?,?,?,?,?)`, "00000000-0000-4000-8000-000000000203", 1, 1, "system", "authority.archive", "authority", "success", `{"schema_version":1}`)
	}
	if err == nil {
		_, err = handle.WriterConn().ExecContext(ctx, `INSERT INTO audit_event_scopes (event_id,authority_id) VALUES (?,?)`,
			"00000000-0000-4000-8000-000000000203", "00000000-0000-4000-8000-000000000101")
	}
	if err == nil {
		err = applyVersion(ctx, handle.WriterConn(), lock, runner, plan, 8, false, 0)
	}
	if err != nil {
		_ = lock.Release(ctx)
		_ = handle.Close()
		t.Fatalf("prepare and apply audit scope backfill: %v", err)
	}
	rows, err := handle.WriterConn().QueryContext(ctx, `SELECT id, scope_kind FROM audit_events ORDER BY id`)
	if err != nil {
		_ = lock.Release(ctx)
		_ = handle.Close()
		t.Fatal(err)
	}
	got := make(map[string]string)
	for rows.Next() {
		var id string
		var scopeKind sql.NullString
		if err := rows.Scan(&id, &scopeKind); err != nil {
			rows.Close()
			_ = lock.Release(ctx)
			_ = handle.Close()
			t.Fatal(err)
		}
		if scopeKind.Valid {
			got[id] = scopeKind.String
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		_ = lock.Release(ctx)
		_ = handle.Close()
		t.Fatal(err)
	}
	rows.Close()
	if got["00000000-0000-4000-8000-000000000201"] != "installation" ||
		got["00000000-0000-4000-8000-000000000203"] != "authorities" {
		_ = lock.Release(ctx)
		_ = handle.Close()
		t.Fatalf("backfill classifications = %#v", got)
	}
	if _, classified := got["00000000-0000-4000-8000-000000000202"]; classified {
		_ = lock.Release(ctx)
		_ = handle.Close()
		t.Fatal("unscoped non-global event was defaulted to a scope")
	}
	if err := applyDataHandler(ctx, handle.WriterConn(), config.SQLite, auditScopeBackfillHandlerID); err != nil {
		_ = lock.Release(ctx)
		_ = handle.Close()
		t.Fatalf("idempotent backfill retry: %v", err)
	}
	if err := applyVersion(ctx, handle.WriterConn(), lock, runner, plan, 9, false, 0); !errors.Is(err, ErrUnavailable) {
		_ = lock.Release(ctx)
		_ = handle.Close()
		t.Fatalf("version 9 error = %v, want a blocked migration", err)
	}
	if err := lock.Release(ctx); err != nil {
		_ = handle.Close()
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	status, err := runner.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StateResumeRequired || status.IncompleteVersion == nil || *status.IncompleteVersion != 9 {
		t.Fatalf("after unclassifiable row state=%q incomplete=%v", status.State, status.IncompleteVersion)
	}
}
