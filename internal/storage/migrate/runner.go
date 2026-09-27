// Package migrate applies and verifies the embedded database schema under the
// execution lock held by the pinned writer connection.
package migrate

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"cert-me/internal/config"
	"cert-me/internal/storage/connection"
	"cert-me/internal/storage/executionlock"
)

const (
	outputSchemaVersion   = 1
	defaultStepTimeout    = 120 * time.Second
	defaultConnectTimeout = 10 * time.Second
)

type State string

const (
	StateEmpty           State = "empty"
	StateCurrent         State = "current"
	StateUpgradeRequired State = "upgrade_required"
	StateResumeRequired  State = "resume_required"
	StateBusy            State = "busy"
	StateIncompatible    State = "incompatible"
	StateUnavailable     State = "unavailable"
)

var (
	ErrBusy            = errors.New("migration busy")
	ErrIncompatible    = errors.New("migration incompatible")
	ErrUnavailable     = errors.New("migration unavailable")
	ErrResumeRequired  = errors.New("migration resume required")
	ErrMigrateRequired = errors.New("migration required")
	ErrInvalidConfig   = errors.New("invalid migration configuration")
	ErrCommitUnknown   = errors.New("migration commit outcome unknown")
)

// MigrationError carries a stable, secret-free code. Driver details are
// intentionally omitted from the exported error chain.
type MigrationError struct {
	Code string
	Kind State
}

func (e *MigrationError) Error() string {
	if e == nil {
		return ""
	}
	return e.Code
}

func (e *MigrationError) Is(target error) bool {
	if e == nil {
		return false
	}
	switch target {
	case ErrBusy:
		return e.Kind == StateBusy
	case ErrIncompatible:
		return e.Kind == StateIncompatible
	case ErrUnavailable, ErrCommitUnknown:
		return e.Kind == StateUnavailable
	case ErrResumeRequired:
		return e.Kind == StateResumeRequired
	case ErrMigrateRequired:
		return e.Kind == StateUpgradeRequired
	case ErrInvalidConfig:
		return e.Kind == "invalid"
	default:
		return false
	}
}

func migrationError(kind State, code string, cause error) error {
	_ = cause
	return &MigrationError{Code: code, Kind: kind}
}

type Status struct {
	SchemaVersion      int    `json:"schema_version"`
	DatabaseKind       string `json:"database_kind"`
	State              State  `json:"state"`
	CurrentVersion     int    `json:"current_version"`
	TargetVersion      int    `json:"target_version"`
	IncompleteVersion  *int   `json:"incomplete_version,omitempty"`
	LastVerifiedStep   int    `json:"last_verified_step"`
	SnapshotConsistent bool   `json:"snapshot_consistent"`
	NextCommand        string `json:"next_command,omitempty"`
}

func newStatus(kind config.DatabaseKind, state State) Status {
	status := Status{
		SchemaVersion: outputSchemaVersion, DatabaseKind: string(kind), State: state,
		TargetVersion: targetVersion, SnapshotConsistent: state != StateUnavailable && state != StateBusy,
	}
	switch state {
	case StateEmpty, StateUpgradeRequired:
		status.NextCommand = "cert-me db migrate"
	case StateResumeRequired:
		status.NextCommand = "cert-me db resume"
	}
	return status
}

type Option func(*Runner) error

func WithStepTimeout(timeout time.Duration) Option {
	return func(r *Runner) error {
		if timeout < time.Second || timeout > time.Hour {
			return migrationError(State("invalid"), "migration_step_timeout_invalid", ErrInvalidConfig)
		}
		r.stepTimeout = timeout
		return nil
	}
}

func WithConnectionTimeout(timeout time.Duration) Option {
	return func(r *Runner) error {
		if timeout <= 0 || timeout > time.Hour {
			return migrationError(State("invalid"), "migration_connection_timeout_invalid", ErrInvalidConfig)
		}
		r.connectionTimeout = timeout
		return nil
	}
}

type Runner struct {
	database          config.Database
	stepTimeout       time.Duration
	connectionTimeout time.Duration
	mu                sync.Mutex
}

func NewRunner(database config.Database, options ...Option) (*Runner, error) {
	if _, err := directoryFor(database.Kind); err != nil {
		return nil, migrationError(State("invalid"), "migration_database_kind_invalid", ErrInvalidConfig)
	}
	if database.Kind == config.SQLite && (strings.TrimSpace(database.SQLitePath) == "" || database.SQLitePath == ":memory:" || strings.ContainsAny(database.SQLitePath, "?#")) {
		return nil, migrationError(State("invalid"), "migration_database_path_invalid", ErrInvalidConfig)
	}
	runner := &Runner{database: database, stepTimeout: defaultStepTimeout, connectionTimeout: defaultConnectTimeout}
	for _, option := range options {
		if option != nil {
			if err := option(runner); err != nil {
				return nil, err
			}
		}
	}
	return runner, nil
}

// Close lets callers own a Runner with the same lifecycle as other storage
// components. Operations use short-lived connections, so there is no retained
// resource to release.
func (*Runner) Close() error { return nil }

// Status inspects a consistent catalog/journal snapshot without creating a
// missing SQLite database file or changing any database rows.
func (r *Runner) Status(ctx context.Context) (Status, error) {
	if r == nil {
		return Status{}, migrationError(StateUnavailable, "migration_runner_nil", ErrUnavailable)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return newStatus(r.database.Kind, StateUnavailable), migrationError(StateUnavailable, "migration_context_canceled", err)
	}
	if r.database.Kind == config.SQLite {
		state, err := inspectSQLiteFile(r.database.SQLitePath)
		if err != nil {
			return newStatus(r.database.Kind, StateUnavailable), migrationError(StateUnavailable, "migration_status_unavailable", err)
		}
		if state == sqliteFileMissing || state == sqliteFileEmpty {
			return newStatus(r.database.Kind, StateEmpty), nil
		}
	}
	status := newStatus(r.database.Kind, StateUnavailable)
	err := r.withLockedConnection(ctx, false, func(handle dbHandle, lock *executionlock.Lock) error {
		if err := lock.Check(ctx); err != nil {
			return classifyLockError(err)
		}
		observed, err := inspect(ctx, handle.WriterConn(), r.database.Kind)
		if err != nil {
			return err
		}
		status = observed
		if err := lock.Check(ctx); err != nil {
			return classifyLockError(err)
		}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrBusy):
			status = newStatus(r.database.Kind, StateBusy)
		case errors.Is(err, ErrIncompatible):
			status = newStatus(r.database.Kind, StateIncompatible)
		default:
			status = newStatus(r.database.Kind, StateUnavailable)
		}
		return status, err
	}
	return status, nil
}

// Migrate installs an empty database or applies a normal pending suffix. It
// never takes over an applying/failed migration.
func (r *Runner) Migrate(ctx context.Context) error {
	if r == nil {
		return migrationError(StateUnavailable, "migration_runner_nil", ErrUnavailable)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mutate(nonNilContext(ctx), false)
}

// Resume verifies the journal and physical schema of an incomplete version,
// repairs only a single unrecorded successful DDL step, then applies the
// remaining normal suffix.
func (r *Runner) Resume(ctx context.Context) error {
	if r == nil {
		return migrationError(StateUnavailable, "migration_runner_nil", ErrUnavailable)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mutate(nonNilContext(ctx), true)
}

func (r *Runner) mutate(ctx context.Context, resume bool) error {
	if err := ctx.Err(); err != nil {
		return migrationError(StateUnavailable, "migration_context_canceled", err)
	}
	if resume && r.database.Kind == config.SQLite {
		state, err := inspectSQLiteFile(r.database.SQLitePath)
		if err != nil {
			return migrationError(StateUnavailable, "migration_status_unavailable", err)
		}
		if state == sqliteFileMissing || state == sqliteFileEmpty {
			return migrationError(StateUpgradeRequired, "migration_required", ErrMigrateRequired)
		}
	}
	create := !resume
	return r.withLockedConnection(ctx, create, func(handle dbHandle, lock *executionlock.Lock) error {
		if err := lock.Check(ctx); err != nil {
			return classifyLockError(err)
		}
		plan, err := loadPlan(r.database.Kind)
		if err != nil {
			return migrationError(StateUnavailable, "migration_plan_invalid", err)
		}
		state, err := inspectWithPlan(ctx, handle.WriterConn(), r.database.Kind, plan)
		if err != nil {
			return err
		}
		switch state.status.State {
		case StateIncompatible:
			return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
		case StateCurrent:
			return nil
		case StateEmpty:
			if resume {
				return migrationError(StateUpgradeRequired, "migration_required", ErrMigrateRequired)
			}
			if err := bootstrap(ctx, handle.WriterConn(), lock, r, plan); err != nil {
				return err
			}
			state, err = inspectWithPlan(ctx, handle.WriterConn(), r.database.Kind, plan)
			if err != nil {
				return err
			}
		case StateResumeRequired:
			if !resume {
				return migrationError(StateResumeRequired, "migration_resume_required", ErrResumeRequired)
			}
			if err := resumeIncomplete(ctx, handle.WriterConn(), lock, r, plan, state); err != nil {
				return err
			}
			state, err = inspectWithPlan(ctx, handle.WriterConn(), r.database.Kind, plan)
			if err != nil {
				return err
			}
		case StateUpgradeRequired:
			if resume {
				return migrationError(StateUpgradeRequired, "migration_required", ErrMigrateRequired)
			}
		default:
			return migrationError(StateUnavailable, "migration_status_unavailable", ErrUnavailable)
		}
		if state.status.State == StateIncompatible {
			return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
		}
		if state.status.State == StateResumeRequired {
			return migrationError(StateResumeRequired, "migration_resume_required", ErrResumeRequired)
		}
		if state.status.State != StateUpgradeRequired {
			if state.status.State == StateCurrent {
				return nil
			}
			return migrationError(StateUnavailable, "migration_status_unavailable", ErrUnavailable)
		}
		for version := state.status.CurrentVersion + 1; version <= targetVersion; version++ {
			if err := lock.Check(ctx); err != nil {
				return classifyLockError(err)
			}
			if err := applyVersion(ctx, handle.WriterConn(), lock, r, plan, version, false, 0); err != nil {
				return err
			}
		}
		return nil
	})
}

type dbHandle interface {
	WriterConn() *sql.Conn
	ReadDB() *sql.DB
	Close() error
}

func (r *Runner) withLockedConnection(ctx context.Context, createIfMissing bool, callback func(dbHandle, *executionlock.Lock) error) error {
	connectCtx, cancel := context.WithTimeout(ctx, r.connectionTimeout)
	defer cancel()
	handle, err := connection.Open(connectCtx, r.database, connection.Options{CreateIfMissing: createIfMissing})
	if err != nil {
		return classifyConnectionError(err)
	}
	defer handle.Close()
	lock, err := executionlock.Acquire(connectCtx, r.database, handle.WriterConn())
	if err != nil {
		return classifyLockError(err)
	}
	released := false
	var releaseErr error
	release := func() error {
		if released {
			return releaseErr
		}
		released = true
		releaseCtx, releaseCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer releaseCancel()
		releaseErr = lock.Release(releaseCtx)
		return releaseErr
	}
	defer func() { _ = release() }()
	operationErr := callback(handle, lock)
	releaseErr = release()
	if operationErr != nil {
		return operationErr
	}
	if releaseErr != nil {
		return migrationError(StateUnavailable, "migration_lock_release_failed", releaseErr)
	}
	return nil
}

type sqliteFileCondition uint8

const (
	sqliteFilePresent sqliteFileCondition = iota
	sqliteFileMissing
	sqliteFileEmpty
)

func inspectSQLiteFile(path string) (sqliteFileCondition, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return sqliteFileMissing, nil
	}
	if err != nil {
		return sqliteFilePresent, err
	}
	if info.IsDir() {
		return sqliteFilePresent, errors.New("database path is a directory")
	}
	if info.Size() == 0 {
		return sqliteFileEmpty, nil
	}
	return sqliteFilePresent, nil
}

func classifyConnectionError(err error) error {
	if err == nil {
		return nil
	}
	return migrationError(StateUnavailable, "migration_connection_unavailable", err)
}

func classifyLockError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, executionlock.ErrAlreadyHeld) {
		return migrationError(StateBusy, "migration_busy", ErrBusy)
	}
	return migrationError(StateUnavailable, "migration_lock_unavailable", err)
}

func classifySQLFailure(err error, code string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return migrationError(StateUnavailable, code, err)
	}
	return migrationError(StateUnavailable, code, err)
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func intPointer(value int) *int { return &value }
