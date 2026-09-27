package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"cert-me/internal/app/port"
	"cert-me/internal/config"
	"cert-me/internal/storage/connection"
)

func openTestStore(t *testing.T) (*connection.DB, *Store, *SQLExecutor) {
	t.Helper()
	ctx := context.Background()
	db, err := connection.Open(ctx, config.Database{
		Kind:       config.SQLite,
		SQLitePath: filepath.Join(t.TempDir(), "core.db"),
	}, connection.Options{CreateIfMissing: true})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})

	var current SQLExecutor
	store, err := New(db, config.SQLite, func(executor SQLExecutor) (port.TxStores, error) {
		current = executor
		return testStores{}, nil
	})
	if err != nil {
		t.Fatalf("construct store: %v", err)
	}
	return db, store, &current
}

type testStores struct{}

func (testStores) Accounts() port.AccountRepository          { return nil }
func (testStores) Installation() port.InstallationRepository { return nil }
func (testStores) PKI() port.PKIRepository                   { return nil }
func (testStores) Delivery() port.DeliveryRepository         { return nil }
func (testStores) Revocations() port.RevocationRepository    { return nil }
func (testStores) CRLs() port.CRLRepository                  { return nil }
func (testStores) Transitions() port.TransitionRepository    { return nil }
func (testStores) TLS() port.TLSRepository                   { return nil }
func (testStores) Requests() port.RequestRepository          { return nil }
func (testStores) Secrets() port.SecretRepository            { return nil }
func (testStores) Jobs() port.JobRepository                  { return nil }
func (testStores) Maintenance() port.MaintenanceRepository   { return nil }
func (testStores) Audit() port.AuditRepository               { return nil }
func (testStores) Imports() port.ImportRepository            { return nil }
func (testStores) Queries() port.QueryRepository             { return nil }

func execWriter(t *testing.T, db *connection.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.WriterConn().ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("execute writer query: %v", err)
	}
}

func countRows(t *testing.T, db *connection.DB, table string) int {
	t.Helper()
	var count int
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s", table)
	if err := db.ReadDB().QueryRowContext(context.Background(), query).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return count
}

func TestWriteRollsBackCallbackError(t *testing.T) {
	db, store, executor := openTestStore(t)
	execWriter(t, db, "CREATE TABLE records (id INTEGER PRIMARY KEY)")
	wantErr := errors.New("stop write")

	err := store.Write(context.Background(), func(port.TxStores) error {
		if _, err := (*executor).ExecContext(context.Background(), "INSERT INTO records(id) VALUES (1)"); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Write() error = %v, want callback error", err)
	}
	if got := countRows(t, db, "records"); got != 0 {
		t.Fatalf("rows after rollback = %d, want 0", got)
	}
}

func TestWriteRollsBackThenRepanics(t *testing.T) {
	db, store, executor := openTestStore(t)
	execWriter(t, db, "CREATE TABLE records (id INTEGER PRIMARY KEY)")
	panicValue := "callback panic"

	func() {
		defer func() {
			if got := recover(); got != panicValue {
				t.Fatalf("recovered panic = %#v, want %#v", got, panicValue)
			}
		}()
		_ = store.Write(context.Background(), func(port.TxStores) error {
			if _, err := (*executor).ExecContext(context.Background(), "INSERT INTO records(id) VALUES (1)"); err != nil {
				return err
			}
			panic(panicValue)
		})
	}()

	if got := countRows(t, db, "records"); got != 0 {
		t.Fatalf("rows after panic rollback = %d, want 0", got)
	}
}

func TestWriteCommitErrorIsUnknownAndDoesNotRetry(t *testing.T) {
	db, store, executor := openTestStore(t)
	execWriter(t, db, "CREATE TABLE parents (id INTEGER PRIMARY KEY)")
	execWriter(t, db, "CREATE TABLE children (parent_id INTEGER, FOREIGN KEY(parent_id) REFERENCES parents(id) DEFERRABLE INITIALLY DEFERRED)")
	callbackCalls := 0

	err := store.Write(context.Background(), func(port.TxStores) error {
		callbackCalls++
		_, err := (*executor).ExecContext(context.Background(), "INSERT INTO children(parent_id) VALUES (99)")
		return err
	})
	if !errors.Is(err, port.ErrCommitUnknown) {
		t.Fatalf("Write() error = %v, want ErrCommitUnknown", err)
	}
	if callbackCalls != 1 {
		t.Fatalf("callback calls = %d, want 1", callbackCalls)
	}
}

func TestReadUsesOneTransactionSnapshot(t *testing.T) {
	db, store, executor := openTestStore(t)
	if _, err := db.WriterConn().ExecContext(context.Background(), "PRAGMA journal_mode=WAL"); err != nil {
		t.Fatalf("enable WAL: %v", err)
	}
	execWriter(t, db, "CREATE TABLE records (id INTEGER PRIMARY KEY, value INTEGER NOT NULL)")
	execWriter(t, db, "INSERT INTO records(id, value) VALUES (1, 10)")

	err := store.Read(context.Background(), func(port.TxStores) error {
		var before int
		if err := (*executor).QueryRowContext(context.Background(), "SELECT value FROM records WHERE id = 1").Scan(&before); err != nil {
			return err
		}
		if before != 10 {
			return fmt.Errorf("initial value = %d, want 10", before)
		}

		if _, err := db.WriterConn().ExecContext(context.Background(), "UPDATE records SET value = 20 WHERE id = 1"); err != nil {
			return fmt.Errorf("update during read snapshot: %w", err)
		}
		var after int
		if err := (*executor).QueryRowContext(context.Background(), "SELECT value FROM records WHERE id = 1").Scan(&after); err != nil {
			return err
		}
		if after != 10 {
			return fmt.Errorf("value in read snapshot = %d, want 10", after)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Read(): %v", err)
	}
	var committed int
	if err := db.ReadDB().QueryRowContext(context.Background(), "SELECT value FROM records WHERE id = 1").Scan(&committed); err != nil {
		t.Fatalf("read committed value: %v", err)
	}
	if committed != 20 {
		t.Fatalf("committed value = %d, want 20", committed)
	}
}

func TestTransactionIsolationOptions(t *testing.T) {
	for _, kind := range []config.DatabaseKind{config.Postgres, config.MySQL, config.MariaDB} {
		store := &Store{kind: kind}
		writeOptions := store.writeTxOptions()
		if writeOptions == nil || writeOptions.Isolation != sql.LevelReadCommitted {
			t.Fatalf("%s write options = %#v, want READ COMMITTED", kind, writeOptions)
		}
		readOptions := store.readTxOptions()
		if readOptions == nil || readOptions.Isolation != sql.LevelRepeatableRead {
			t.Fatalf("%s read options = %#v, want REPEATABLE READ", kind, readOptions)
		}
	}

	sqlite := &Store{kind: config.SQLite}
	if got := sqlite.writeTxOptions(); got != nil {
		t.Fatalf("SQLite write options = %#v, want driver default", got)
	}
	if got := sqlite.readTxOptions(); got != nil {
		t.Fatalf("SQLite read options = %#v, want driver default", got)
	}
}
