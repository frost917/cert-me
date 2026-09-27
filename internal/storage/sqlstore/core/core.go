// Package core implements the SQL transaction boundary shared by SQL-backed
// repositories. Repository factories receive an executor bound to the single
// transaction opened for the service operation.
package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"cert-me/internal/app/port"
	"cert-me/internal/config"
	"cert-me/internal/storage/connection"
)

// SQLExecutor is the subset of database/sql used by SQL repositories. Both
// *sql.Tx and the transaction-bound test executor implement this interface.
type SQLExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Factory builds the repository set bound to the supplied executor. The
// executor belongs to the transaction opened by Store and must not be retained
// after the callback returns.
type Factory func(SQLExecutor) (port.TxStores, error)

// Store owns the transaction boundary for SQL-backed ports. It serializes
// writes because every write uses the connection package's single pinned
// writer connection.
type Store struct {
	db      *connection.DB
	kind    config.DatabaseKind
	factory Factory
	writeMu sync.Mutex
}

// New creates a transaction boundary over db. The factory must construct all
// repositories from the executor it receives so their operations participate
// in the same transaction.
func New(db *connection.DB, kind config.DatabaseKind, factory Factory) (*Store, error) {
	if db == nil {
		return nil, errors.New("sqlstore: connection database is required")
	}
	if factory == nil {
		return nil, errors.New("sqlstore: transaction repository factory is required")
	}
	switch kind {
	case config.SQLite, config.Postgres, config.MySQL, config.MariaDB:
	default:
		return nil, fmt.Errorf("sqlstore: unsupported database kind %q", kind)
	}
	if db.WriterConn() == nil || db.ReadDB() == nil {
		return nil, errors.New("sqlstore: connection database is closed")
	}
	return &Store{db: db, kind: kind, factory: factory}, nil
}

// Write opens one transaction on the pinned writer connection. The callback
// is invoked at most once. Callback errors and panics roll back; a panic is
// allowed to continue after the rollback attempt.
func (s *Store) Write(ctx context.Context, callback func(port.TxStores) error) error {
	if callback == nil {
		return errors.New("sqlstore: write callback is required")
	}
	if ctx == nil {
		return errors.New("sqlstore: write context is required")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	writer := s.db.WriterConn()
	if writer == nil {
		return errors.New("sqlstore: connection database is closed")
	}
	tx, err := writer.BeginTx(ctx, s.writeTxOptions())
	if err != nil {
		return fmt.Errorf("sqlstore: begin write transaction: %w", err)
	}
	return s.run(tx, callback, true)
}

// Read runs the callback in a transaction on the read pool, giving all reads
// through the supplied repositories one transaction-scoped view of the data.
func (s *Store) Read(ctx context.Context, callback func(port.TxStores) error) error {
	if callback == nil {
		return errors.New("sqlstore: read callback is required")
	}
	if ctx == nil {
		return errors.New("sqlstore: read context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	readDB := s.db.ReadDB()
	if readDB == nil {
		return errors.New("sqlstore: connection database is closed")
	}
	tx, err := readDB.BeginTx(ctx, s.readTxOptions())
	if err != nil {
		return fmt.Errorf("sqlstore: begin read transaction: %w", err)
	}
	return s.run(tx, callback, false)
}

func (s *Store) writeTxOptions() *sql.TxOptions {
	// modernc SQLite starts a deferred transaction unless the connection's DSN
	// opts into _txlock=immediate. The connection package sets that option for
	// the writer only; pass no isolation override here because database/sql's
	// SQLite driver does not implement isolation-level selection.
	if s.kind == config.SQLite {
		return nil
	}
	return &sql.TxOptions{Isolation: sql.LevelReadCommitted}
}

func (s *Store) readTxOptions() *sql.TxOptions {
	// A transaction-wide view requires REPEATABLE READ on PostgreSQL and MySQL
	// compatible databases. READ COMMITTED may choose a fresh snapshot for each
	// statement. SQLite's deferred transaction holds its snapshot after the
	// first read, so leave its isolation at the driver's default.
	if s.kind == config.SQLite {
		return nil
	}
	return &sql.TxOptions{Isolation: sql.LevelRepeatableRead}
}

func (s *Store) run(tx *sql.Tx, callback func(port.TxStores) error, write bool) error {
	finished := false
	defer func() {
		if !finished {
			finished = true
			_ = safeRollback(tx)
		}
	}()

	stores, err := s.factory(tx)
	if err != nil {
		finished = true
		if rollbackErr := safeRollback(tx); rollbackErr != nil {
			return errors.Join(fmt.Errorf("sqlstore: construct transaction repositories: %w", err), fmt.Errorf("sqlstore: rollback transaction: %w", rollbackErr))
		}
		return fmt.Errorf("sqlstore: construct transaction repositories: %w", err)
	}
	if stores == nil {
		finished = true
		_ = safeRollback(tx)
		return errors.New("sqlstore: repository factory returned nil stores")
	}
	if err := callback(stores); err != nil {
		// Mark the transaction finished before rollback, so even an unexpected
		// panic from the driver cannot cause the deferred path to roll it back a
		// second time.
		finished = true
		if rollbackErr := safeRollback(tx); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("sqlstore: rollback transaction: %w", rollbackErr))
		}
		return err
	}

	// Commit consumes the transaction even when it reports an error. Do not
	// follow a failed commit with Rollback: its outcome is already uncertain.
	finished = true
	if err := tx.Commit(); err != nil {
		commitErr := fmt.Errorf("sqlstore: commit transaction: %w", err)
		if write {
			return errors.Join(port.ErrCommitUnknown, commitErr)
		}
		return commitErr
	}
	return nil
}

func safeRollback(tx *sql.Tx) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("driver panicked while rolling back: %v", recovered)
		}
	}()
	return tx.Rollback()
}

var (
	_ port.UnitOfWork = (*Store)(nil)
	_ port.ReadStore  = (*Store)(nil)
)
