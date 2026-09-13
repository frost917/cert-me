// Package migrations provides the schema-only migration runner used by the
// storage adapter. The command-line adapter owns argument parsing and output.
package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	outputSchemaVersion = 1
	targetVersion       = 7
	defaultStepTimeout  = 120 * time.Second
	defaultConnTimeout  = 10 * time.Second
)

// State is the stable classification returned by Status.
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

// Sentinel errors are safe for callers to inspect without exposing a driver
// error, SQL statement, path, or DSN.
var (
	ErrBusy            = errors.New("migration busy")
	ErrIncompatible    = errors.New("migration incompatible")
	ErrUnavailable     = errors.New("migration unavailable")
	ErrResumeRequired  = errors.New("migration resume required")
	ErrMigrateRequired = errors.New("migration required")
	ErrInvalidConfig   = errors.New("invalid migration configuration")
	errLockBusy        = errors.New("migration lock busy")
	errCommitUncertain = errors.New("migration commit outcome is unknown")
)

// MigrationError is the normalized error surface of the runner. Cause is
// intentionally private; errors.Is remains useful without leaking SQL text.
type MigrationError struct {
	Code  string
	Kind  string
	cause error
}

func (e *MigrationError) Error() string {
	if e == nil {
		return ""
	}
	return e.Code
}

func (e *MigrationError) Unwrap() error { return e.cause }

func (e *MigrationError) Is(target error) bool {
	if e == nil {
		return false
	}
	switch target {
	case ErrBusy:
		return e.Kind == string(StateBusy)
	case ErrIncompatible:
		return e.Kind == string(StateIncompatible)
	case ErrUnavailable:
		return e.Kind == string(StateUnavailable)
	case ErrResumeRequired:
		return e.Kind == string(StateResumeRequired)
	case ErrMigrateRequired:
		return e.Kind == string(StateUpgradeRequired)
	case ErrInvalidConfig:
		return e.Kind == "invalid"
	default:
		return false
	}
}

func migrationError(kind State, code string, cause error) error {
	return &MigrationError{Code: code, Kind: string(kind), cause: cause}
}

func invalidError(code string, cause error) error {
	return &MigrationError{Code: code, Kind: "invalid", cause: cause}
}

// Status is the schema inspection result. IncompleteVersion is nil when all
// journal rows are complete.
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

func defaultStatus(state State) Status {
	return Status{
		SchemaVersion:      outputSchemaVersion,
		DatabaseKind:       "sqlite",
		State:              state,
		TargetVersion:      targetVersion,
		SnapshotConsistent: true,
	}
}

// Config controls a SQLite runner. Path is the only required field.
type Config struct {
	Path              string
	StepTimeout       time.Duration
	ConnectionTimeout time.Duration
}

// Option customizes a Runner. Options only affect local execution policy and
// do not change the migration plan or schema contract.
type Option func(*Runner) error

func WithStepTimeout(timeout time.Duration) Option {
	return func(r *Runner) error {
		if timeout < time.Second || timeout > time.Hour {
			return invalidError("migration_step_timeout_invalid", ErrInvalidConfig)
		}
		r.stepTimeout = timeout
		return nil
	}
}

func WithConnectionTimeout(timeout time.Duration) Option {
	return func(r *Runner) error {
		if timeout <= 0 {
			return invalidError("migration_connection_timeout_invalid", ErrInvalidConfig)
		}
		r.connectionTimeout = timeout
		return nil
	}
}

// Runner applies the embedded SQLite migration plan. Connections are opened
// for each operation so a writer cannot outlive the execution lock.
type Runner struct {
	path              string
	stepTimeout       time.Duration
	connectionTimeout time.Duration
	mu                sync.Mutex
}

// NewSQLiteRunner constructs a runner for a local SQLite file. It does not
// create the database or lock file.
func NewSQLiteRunner(path string, options ...Option) (*Runner, error) {
	canonical, err := canonicalSQLitePath(path)
	if err != nil {
		return nil, err
	}
	r := &Runner{
		path:              canonical,
		stepTimeout:       defaultStepTimeout,
		connectionTimeout: defaultConnTimeout,
	}
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// NewSQLite is a concise alias for NewSQLiteRunner.
func NewSQLite(path string, options ...Option) (*Runner, error) {
	return NewSQLiteRunner(path, options...)
}

// NewRunner constructs the SQLite runner from Config. Other database kinds
// are deliberately not accepted by this B05 unit.
func NewRunner(config Config) (*Runner, error) {
	options := make([]Option, 0, 2)
	if config.StepTimeout != 0 {
		options = append(options, WithStepTimeout(config.StepTimeout))
	}
	if config.ConnectionTimeout != 0 {
		options = append(options, WithConnectionTimeout(config.ConnectionTimeout))
	}
	return NewSQLiteRunner(config.Path, options...)
}

// Close is present so the runner can be owned by a runtime. Operations use
// short-lived connections, so there is no persistent resource to close.
func (*Runner) Close() error { return nil }

// Status inspects the database without creating a missing SQLite file or any
// journal/business rows.
func (r *Runner) Status(ctx context.Context) (Status, error) {
	if r == nil {
		return defaultStatus(StateUnavailable), migrationError(StateUnavailable, "migration_runner_nil", ErrUnavailable)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx = nonNilContext(ctx)

	info, err := os.Stat(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return defaultStatus(StateEmpty), nil
	}
	if err != nil {
		return defaultStatus(StateUnavailable), migrationError(StateUnavailable, "migration_status_unavailable", ErrUnavailable)
	}
	if info.IsDir() || info.Size() == 0 {
		if info.IsDir() {
			return defaultStatus(StateUnavailable), migrationError(StateUnavailable, "migration_status_unavailable", ErrUnavailable)
		}
		// Opening an empty file through SQLite may initialize it. Treat it as an
		// empty database for status purposes while preserving the file bytes.
		return defaultStatus(StateEmpty), nil
	}

	lock, err := acquireFileLock(r.lockPath(), true)
	if err != nil {
		if errors.Is(err, errLockBusy) {
			return defaultStatus(StateBusy), migrationError(StateBusy, "migration_busy", ErrBusy)
		}
		return defaultStatus(StateUnavailable), migrationError(StateUnavailable, "migration_lock_unavailable", ErrUnavailable)
	}
	defer func() { _ = lock.release() }()

	db, conn, err := r.open(ctx, true)
	if err != nil {
		return defaultStatus(StateUnavailable), err
	}
	defer closeSQLite(db, conn)
	return r.inspect(ctx, conn)
}

// Migrate installs an empty database or applies only normal pending versions.
// It refuses to take over an applying/failed version; callers must use Resume.
func (r *Runner) Migrate(ctx context.Context) error {
	if r == nil {
		return migrationError(StateUnavailable, "migration_runner_nil", ErrUnavailable)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mutate(ctx, false)
}

// Resume verifies an incomplete SQLite version against its actual catalog and
// safely replays or completes it before applying subsequent pending versions.
func (r *Runner) Resume(ctx context.Context) error {
	if r == nil {
		return migrationError(StateUnavailable, "migration_runner_nil", ErrUnavailable)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mutate(ctx, true)
}

// Convenience functions keep the package usable by adapters that do not need
// to retain a Runner value.
func MigrateSQLite(ctx context.Context, path string) error {
	r, err := NewSQLiteRunner(path)
	if err != nil {
		return err
	}
	return r.Migrate(ctx)
}

func ResumeSQLite(ctx context.Context, path string) error {
	r, err := NewSQLiteRunner(path)
	if err != nil {
		return err
	}
	return r.Resume(ctx)
}

func StatusSQLite(ctx context.Context, path string) (Status, error) {
	r, err := NewSQLiteRunner(path)
	if err != nil {
		return defaultStatus(StateUnavailable), err
	}
	return r.Status(ctx)
}

func (r *Runner) mutate(ctx context.Context, resume bool) error {
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return migrationError(StateUnavailable, "migration_context_canceled", ErrUnavailable)
	}
	lock, err := acquireFileLock(r.lockPath(), true)
	if err != nil {
		if errors.Is(err, errLockBusy) {
			return migrationError(StateBusy, "migration_busy", ErrBusy)
		}
		return migrationError(StateUnavailable, "migration_lock_unavailable", ErrUnavailable)
	}
	defer func() { _ = lock.release() }()

	db, conn, err := r.open(ctx, false)
	if err != nil {
		return err
	}
	defer closeSQLite(db, conn)

	if _, err := loadMigrationPlan(); err != nil {
		return migrationError(StateUnavailable, "migration_plan_unavailable", ErrUnavailable)
	}

	status, err := r.inspect(ctx, conn)
	if err != nil {
		return err
	}
	if status.State == StateEmpty {
		if err := r.bootstrap(ctx, conn); err != nil {
			return err
		}
		status, err = r.inspect(ctx, conn)
		if err != nil {
			return err
		}
	}
	if status.State == StateIncompatible {
		return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
	}
	if status.State == StateCurrent {
		return nil
	}
	if status.State == StateResumeRequired {
		if !resume {
			return migrationError(StateResumeRequired, "migration_resume_required", ErrResumeRequired)
		}
		if err := r.resumeIncomplete(ctx, conn); err != nil {
			return err
		}
		status, err = r.inspect(ctx, conn)
		if err != nil {
			return err
		}
	}
	if status.State == StateUpgradeRequired {
		if status.CurrentVersion >= targetVersion {
			return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
		}
		for version := status.CurrentVersion + 1; version <= targetVersion; version++ {
			if err := r.applyVersion(ctx, conn, version, false); err != nil {
				return err
			}
		}
		return nil
	}
	if status.State == StateResumeRequired {
		return migrationError(StateResumeRequired, "migration_resume_required", ErrResumeRequired)
	}
	if status.State == StateUnavailable || status.State == StateBusy {
		return migrationError(StateUnavailable, "migration_unavailable", ErrUnavailable)
	}
	return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
}

func (r *Runner) lockPath() string { return r.path + ".lock" }

func canonicalSQLitePath(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" || raw == ":memory:" || strings.ContainsAny(raw, "?#") {
		return "", invalidError("migration_database_path_invalid", ErrInvalidConfig)
	}
	abs, err := filepath.Abs(filepath.Clean(raw))
	if err != nil {
		return "", invalidError("migration_database_path_invalid", ErrInvalidConfig)
	}
	info, statErr := os.Stat(abs)
	if statErr == nil {
		if info.IsDir() {
			return "", invalidError("migration_database_path_invalid", ErrInvalidConfig)
		}
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return "", invalidError("migration_database_path_invalid", ErrInvalidConfig)
		}
		return filepath.Clean(real), nil
	}
	if !errors.Is(statErr, os.ErrNotExist) {
		return "", invalidError("migration_database_path_invalid", ErrInvalidConfig)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", invalidError("migration_database_path_invalid", ErrInvalidConfig)
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}

type sqliteHandle struct {
	db   *sql.DB
	conn *sql.Conn
}

func (r *Runner) open(ctx context.Context, readOnly bool) (*sql.DB, *sql.Conn, error) {
	connCtx, cancel := context.WithTimeout(nonNilContext(ctx), r.connectionTimeout)
	defer cancel()
	mode := "rwc"
	if readOnly {
		mode = "ro"
	}
	dsn := "file:" + filepath.ToSlash(r.path) + "?mode=" + mode + "&_pragma=busy_timeout(0)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, nil, migrationError(StateUnavailable, "migration_connection_unavailable", ErrUnavailable)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(connCtx); err != nil {
		_ = db.Close()
		return nil, nil, migrationError(StateUnavailable, "migration_connection_unavailable", ErrUnavailable)
	}
	conn, err := db.Conn(connCtx)
	if err != nil {
		_ = db.Close()
		return nil, nil, migrationError(StateUnavailable, "migration_connection_unavailable", ErrUnavailable)
	}
	if _, err := conn.ExecContext(connCtx, "PRAGMA foreign_keys = ON"); err != nil {
		_ = conn.Close()
		_ = db.Close()
		return nil, nil, migrationError(StateUnavailable, "migration_connection_unavailable", ErrUnavailable)
	}
	var foreignKeys int
	if err := conn.QueryRowContext(connCtx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		_ = conn.Close()
		_ = db.Close()
		return nil, nil, migrationError(StateUnavailable, "migration_foreign_keys_unavailable", ErrUnavailable)
	}
	return db, conn, nil
}

func closeSQLite(db *sql.DB, conn *sql.Conn) {
	if conn != nil {
		_ = conn.Close()
	}
	if db != nil {
		_ = db.Close()
	}
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

type journalEntry struct {
	version     int
	name        string
	checksum    string
	state       string
	startedAt   int64
	completedAt sql.NullInt64
	lastStep    int
	errorCode   sql.NullString
}

type inspection struct {
	status          Status
	incomplete      *journalEntry
	incompleteAfter bool
}

func (r *Runner) inspect(ctx context.Context, conn *sql.Conn) (Status, error) {
	cat, err := loadMigrationPlan()
	if err != nil {
		return defaultStatus(StateUnavailable), migrationError(StateUnavailable, "migration_plan_unavailable", ErrUnavailable)
	}
	return r.inspectWithCatalog(ctx, conn, cat)
}

func (r *Runner) inspectWithCatalog(ctx context.Context, conn *sql.Conn, cat *migrationPlan) (Status, error) {
	status := defaultStatus(StateUnavailable)
	actual, err := readCatalog(ctx, conn)
	if err != nil {
		return status, migrationError(StateUnavailable, "migration_catalog_unavailable", ErrUnavailable)
	}
	if !hasObject(actual, "table", "schema_migrations") {
		if len(actual.objects) == 0 {
			return defaultStatus(StateEmpty), nil
		}
		status.State = StateIncompatible
		status.SnapshotConsistent = true
		return status, nil
	}
	if objectType(actual, "schema_migrations") != "table" || !catalogMatches(actual, cat.full[0]) {
		status.State = StateIncompatible
		return status, nil
	}

	entries, err := readJournal(ctx, conn)
	if err != nil {
		return status, migrationError(StateUnavailable, "migration_journal_unavailable", ErrUnavailable)
	}
	if len(entries) == 0 {
		zero := 0
		status.State = StateResumeRequired
		status.IncompleteVersion = &zero
		status.NextCommand = "cert-me db resume"
		return status, nil
	}

	byVersion := make(map[int]journalEntry, len(entries))
	for _, entry := range entries {
		if entry.version < 0 || entry.version > targetVersion {
			status.State = StateIncompatible
			return status, nil
		}
		if _, duplicate := byVersion[entry.version]; duplicate {
			status.State = StateIncompatible
			return status, nil
		}
		byVersion[entry.version] = entry
		file, ok := cat.file(entry.version)
		if !ok || entry.name != file.name || entry.checksum != file.checksum || entry.lastStep < 0 || entry.lastStep > len(file.steps) {
			status.State = StateIncompatible
			return status, nil
		}
		if entry.state != "applying" && entry.state != "applied" && entry.state != "failed" {
			status.State = StateIncompatible
			return status, nil
		}
		if entry.state == "applied" && (!entry.completedAt.Valid || entry.errorCode.Valid) {
			status.State = StateIncompatible
			return status, nil
		}
		if entry.state != "applied" && entry.completedAt.Valid {
			status.State = StateIncompatible
			return status, nil
		}
	}
	zeroEntry, ok := byVersion[0]
	if !ok || zeroEntry.state != "applied" || zeroEntry.lastStep != len(cat.fileMust(0).steps) {
		status.State = StateIncompatible
		return status, nil
	}
	for version := 0; version <= targetVersion; version++ {
		if _, ok := byVersion[version]; !ok {
			// A missing version is a normal pending suffix only when no later
			// journal row exists.
			for later := version + 1; later <= targetVersion; later++ {
				if _, exists := byVersion[later]; exists {
					status.State = StateIncompatible
					return status, nil
				}
			}
			status.CurrentVersion = version - 1
			if status.CurrentVersion < 0 {
				status.CurrentVersion = 0
			}
			if !catalogMatches(actual, cat.full[status.CurrentVersion]) || !foreignKeyCheckOK(ctx, conn) {
				status.State = StateIncompatible
				return status, nil
			}
			status.State = StateUpgradeRequired
			status.NextCommand = "cert-me db migrate"
			return status, nil
		}
		entry := byVersion[version]
		if entry.state != "applied" {
			if version == 0 {
				status.State = StateIncompatible
				return status, nil
			}
			status.CurrentVersion = version - 1
			status.IncompleteVersion = intPointer(version)
			before := cat.full[version-1]
			after := cat.full[version]
			beforeMatch := catalogMatches(actual, before)
			afterMatch := catalogMatches(actual, after)
			if !beforeMatch && !afterMatch {
				status.State = StateIncompatible
				return status, nil
			}
			status.LastVerifiedStep = entry.lastStep
			if afterMatch {
				status.LastVerifiedStep = len(cat.fileMust(version).steps)
			}
			status.State = StateResumeRequired
			status.NextCommand = "cert-me db resume"
			status.SnapshotConsistent = foreignKeyCheckOK(ctx, conn)
			if !status.SnapshotConsistent {
				status.State = StateIncompatible
			}
			return status, nil
		}
		status.CurrentVersion = version
		status.LastVerifiedStep = len(cat.fileMust(version).steps)
	}
	if !catalogMatches(actual, cat.full[targetVersion]) || !foreignKeyCheckOK(ctx, conn) {
		status.State = StateIncompatible
		return status, nil
	}
	status.State = StateCurrent
	status.NextCommand = ""
	return status, nil
}

func intPointer(value int) *int { return &value }

func objectType(cat schemaCatalog, name string) string {
	for key, object := range cat.objects {
		if key.name == name {
			return object.typ
		}
	}
	return ""
}

func hasObject(cat schemaCatalog, typ, name string) bool {
	for key, object := range cat.objects {
		if key.typ == typ && key.name == name {
			return object.typ == typ
		}
	}
	return false
}

func readJournal(ctx context.Context, conn queryer) ([]journalEntry, error) {
	rows, err := conn.QueryContext(ctx, `
		SELECT version, name, checksum, state, started_at, completed_at,
		       last_step, error_code
		FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []journalEntry
	for rows.Next() {
		var entry journalEntry
		if err := rows.Scan(&entry.version, &entry.name, &entry.checksum, &entry.state, &entry.startedAt, &entry.completedAt, &entry.lastStep, &entry.errorCode); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (r *Runner) bootstrap(ctx context.Context, conn *sql.Conn) error {
	cat, err := loadMigrationPlan()
	if err != nil {
		return migrationError(StateUnavailable, "migration_plan_unavailable", ErrUnavailable)
	}
	actual, err := readCatalog(ctx, conn)
	if err != nil {
		return migrationError(StateUnavailable, "migration_catalog_unavailable", ErrUnavailable)
	}
	if len(actual.objects) != 0 && !catalogMatches(actual, cat.full[0]) {
		return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
	}
	if !hasObject(actual, "table", "schema_migrations") {
		file := cat.fileMust(0)
		if err := beginImmediate(ctx, conn); err != nil {
			return classifyDBError(err)
		}
		committed := false
		defer func() {
			if !committed {
				_ = rollback(ctx, conn)
			}
		}()
		for index, step := range file.steps {
			if err := r.execStep(ctx, conn, step.sql); err != nil {
				_ = rollback(ctx, conn)
				return err
			}
			if actual, err = readCatalog(ctx, conn); err != nil {
				_ = rollback(ctx, conn)
				return migrationError(StateUnavailable, "migration_catalog_unavailable", ErrUnavailable)
			} else if !catalogMatches(actual, cat.step[0][index]) {
				_ = rollback(ctx, conn)
				return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
			}
		}
		if err := commit(ctx, conn); err != nil {
			return classifyCommitError(err)
		}
		committed = true
	}
	actual, err = readCatalog(ctx, conn)
	if err != nil || !catalogMatches(actual, cat.full[0]) {
		return migrationError(StateUnavailable, "migration_catalog_unavailable", ErrUnavailable)
	}
	// 000 is a special bootstrap: CREATE and row insertion are separate
	// commits so a stop between them is resumable without replaying CREATE.
	entries, err := readJournal(ctx, conn)
	if err != nil {
		return migrationError(StateUnavailable, "migration_journal_unavailable", ErrUnavailable)
	}
	if len(entries) == 0 {
		file := cat.fileMust(0)
		if err := beginImmediate(ctx, conn); err != nil {
			return classifyDBError(err)
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO schema_migrations
			(version,name,checksum,state,started_at,completed_at,last_step,error_code)
			VALUES (?,?,?,?,?,?,?,NULL)`, 0, file.name, file.checksum, "applied", r.nowUnixMicro(), r.nowUnixMicro(), len(file.steps))
		if err != nil {
			_ = rollback(ctx, conn)
			return classifyDBError(err)
		}
		if err := commit(ctx, conn); err != nil {
			return classifyCommitError(err)
		}
	}
	return nil
}

func (r *Runner) nowUnixMicro() int64 { return time.Now().UTC().UnixMicro() }

func (r *Runner) resumeIncomplete(ctx context.Context, conn *sql.Conn) error {
	status, err := r.inspect(ctx, conn)
	if err != nil {
		return err
	}
	if status.State != StateResumeRequired || status.IncompleteVersion == nil {
		return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
	}
	version := *status.IncompleteVersion
	if version == 0 {
		return r.bootstrap(ctx, conn)
	}
	cat, err := loadMigrationPlan()
	if err != nil {
		return migrationError(StateUnavailable, "migration_plan_unavailable", ErrUnavailable)
	}
	actual, err := readCatalog(ctx, conn)
	if err != nil {
		return migrationError(StateUnavailable, "migration_catalog_unavailable", ErrUnavailable)
	}
	if catalogMatches(actual, cat.full[version]) {
		if err := r.promoteAndMarkApplied(ctx, conn, version, len(cat.fileMust(version).steps)); err != nil {
			return err
		}
		return nil
	}
	if !catalogMatches(actual, cat.full[version-1]) {
		return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
	}
	if err := r.promoteFailed(ctx, conn, version); err != nil {
		return err
	}
	return r.applyVersion(ctx, conn, version, true)
}

func (r *Runner) promoteFailed(ctx context.Context, conn *sql.Conn, version int) error {
	status, err := r.inspect(ctx, conn)
	if err != nil {
		return err
	}
	if status.IncompleteVersion == nil || *status.IncompleteVersion != version {
		return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
	}
	// Applying is already safe to resume. Failed is moved to applying in its
	// own commit so a crash does not make a DDL attempt look applied.
	cat, err := loadMigrationPlan()
	if err != nil {
		return migrationError(StateUnavailable, "migration_plan_unavailable", ErrUnavailable)
	}
	entries, err := readJournal(ctx, conn)
	if err != nil {
		return migrationError(StateUnavailable, "migration_journal_unavailable", ErrUnavailable)
	}
	entry := findJournal(entries, version)
	if entry == nil || entry.state != "failed" {
		return nil
	}
	if err := beginImmediate(ctx, conn); err != nil {
		return classifyDBError(err)
	}
	_, execErr := conn.ExecContext(ctx, `UPDATE schema_migrations SET state='applying', completed_at=NULL, error_code=NULL WHERE version=? AND state='failed'`, version)
	if execErr != nil {
		_ = rollback(ctx, conn)
		return classifyDBError(execErr)
	}
	if err := commit(ctx, conn); err != nil {
		return classifyCommitError(err)
	}
	_ = cat
	return nil
}

func findJournal(entries []journalEntry, version int) *journalEntry {
	for index := range entries {
		if entries[index].version == version {
			return &entries[index]
		}
	}
	return nil
}

func (r *Runner) promoteAndMarkApplied(ctx context.Context, conn *sql.Conn, version, lastStep int) error {
	if err := r.promoteFailed(ctx, conn, version); err != nil {
		return err
	}
	if err := beginImmediate(ctx, conn); err != nil {
		return classifyDBError(err)
	}
	_, err := conn.ExecContext(ctx, `UPDATE schema_migrations
		SET state='applied', completed_at=?, last_step=?, error_code=NULL
		WHERE version=? AND state='applying'`, r.nowUnixMicro(), lastStep, version)
	if err != nil {
		_ = rollback(ctx, conn)
		return classifyDBError(err)
	}
	if err := commit(ctx, conn); err != nil {
		return classifyCommitError(err)
	}
	return nil
}

func (r *Runner) applyVersion(ctx context.Context, conn *sql.Conn, version int, existing bool) error {
	cat, err := loadMigrationPlan()
	if err != nil {
		return migrationError(StateUnavailable, "migration_plan_unavailable", ErrUnavailable)
	}
	file := cat.fileMust(version)
	if !existing {
		if err := r.insertApplying(ctx, conn, file); err != nil {
			return err
		}
	}
	if err := beginImmediate(ctx, conn); err != nil {
		return classifyDBError(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = rollback(ctx, conn)
		}
	}()
	for index, step := range file.steps {
		if err := r.execStep(ctx, conn, step.sql); err != nil {
			_ = rollback(ctx, conn)
			if isContextFailure(err) || errors.Is(err, errLockBusy) {
				return err
			}
			_ = r.markFailed(ctx, conn, version, "migration_step_failed")
			return err
		}
		actual, err := readCatalog(ctx, conn)
		if err != nil {
			_ = rollback(ctx, conn)
			return migrationError(StateUnavailable, "migration_catalog_unavailable", ErrUnavailable)
		}
		if !catalogMatches(actual, cat.step[version][index]) {
			_ = rollback(ctx, conn)
			return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
		}
		if _, err := conn.ExecContext(ctx, `UPDATE schema_migrations SET last_step=? WHERE version=? AND state='applying'`, index+1, version); err != nil {
			_ = rollback(ctx, conn)
			return classifyDBError(err)
		}
	}
	actual, err := readCatalog(ctx, conn)
	if err != nil || !catalogMatches(actual, cat.full[version]) || !foreignKeyCheckOK(ctx, conn) {
		_ = rollback(ctx, conn)
		return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
	}
	if _, err := conn.ExecContext(ctx, `UPDATE schema_migrations
		SET state='applied', completed_at=?, last_step=?, error_code=NULL
		WHERE version=? AND state='applying'`, r.nowUnixMicro(), len(file.steps), version); err != nil {
		_ = rollback(ctx, conn)
		return classifyDBError(err)
	}
	if err := commit(ctx, conn); err != nil {
		return classifyCommitError(err)
	}
	committed = true
	return nil
}

func (r *Runner) insertApplying(ctx context.Context, conn *sql.Conn, file migrationFile) error {
	if err := beginImmediate(ctx, conn); err != nil {
		return classifyDBError(err)
	}
	_, err := conn.ExecContext(ctx, `INSERT INTO schema_migrations
		(version,name,checksum,state,started_at,completed_at,last_step,error_code)
		VALUES (?,?,?,?,?,NULL,0,NULL)`, file.version, file.name, file.checksum, "applying", r.nowUnixMicro())
	if err != nil {
		_ = rollback(ctx, conn)
		return classifyDBError(err)
	}
	if err := commit(ctx, conn); err != nil {
		return classifyCommitError(err)
	}
	return nil
}

func (r *Runner) markFailed(ctx context.Context, conn *sql.Conn, version int, code string) error {
	if err := beginImmediate(ctx, conn); err != nil {
		return err
	}
	_, err := conn.ExecContext(ctx, `UPDATE schema_migrations SET state='failed', completed_at=NULL, error_code=? WHERE version=? AND state='applying'`, code, version)
	if err != nil {
		_ = rollback(ctx, conn)
		return err
	}
	return commit(ctx, conn)
}

func (r *Runner) execStep(ctx context.Context, conn *sql.Conn, statement string) error {
	stepCtx, cancel := context.WithTimeout(nonNilContext(ctx), r.stepTimeout)
	defer cancel()
	_, err := conn.ExecContext(stepCtx, statement)
	if err == nil {
		return nil
	}
	if isSQLiteBusy(err) {
		return migrationError(StateBusy, "migration_busy", ErrBusy)
	}
	if isContextFailure(err) {
		return migrationError(StateUnavailable, "migration_step_unavailable", ErrUnavailable)
	}
	return migrationError(StateUnavailable, "migration_step_failed", ErrUnavailable)
}

func isContextFailure(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(errString(err)), "interrupted")
}

func classifyDBError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errLockBusy) || isSQLiteBusy(err) {
		return migrationError(StateBusy, "migration_busy", ErrBusy)
	}
	if isContextFailure(err) {
		return migrationError(StateUnavailable, "migration_unavailable", ErrUnavailable)
	}
	return migrationError(StateUnavailable, "migration_unavailable", ErrUnavailable)
}

func classifyCommitError(err error) error {
	if err == nil {
		return nil
	}
	// A lost commit response is intentionally not treated as rollback. The
	// next explicit status/resume must inspect the journal and catalog.
	if errors.Is(err, errCommitUncertain) || isContextFailure(err) {
		return migrationError(StateUnavailable, "migration_commit_unknown", ErrUnavailable)
	}
	return classifyDBError(err)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func isSQLiteBusy(err error) bool {
	message := strings.ToLower(errString(err))
	return strings.Contains(message, "database is locked") || strings.Contains(message, "database is busy") || strings.Contains(message, "sqlite_busy") || strings.Contains(message, "sqlite_locked")
}

func beginImmediate(ctx context.Context, conn execer) error {
	_, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE")
	return err
}

func commit(ctx context.Context, conn execer) error {
	_, err := conn.ExecContext(ctx, "COMMIT")
	return err
}

func rollback(ctx context.Context, conn execer) error {
	_, err := conn.ExecContext(ctx, "ROLLBACK")
	return err
}

type execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// --- reviewed statement manifest and SQLite catalog -----------------------

type reviewedStatement struct {
	id       string
	order    int
	start    int
	end      int
	sql      string
	checksum string
}

type migrationFile struct {
	version  int
	name     string
	path     string
	checksum string
	data     []byte
	steps    []reviewedStatement
}

type migrationPlan struct {
	files []migrationFile
	full  []schemaCatalog
	step  [][]schemaCatalog
}

var catalogCache struct {
	once sync.Once
	cat  *migrationPlan
	err  error
}

func loadMigrationPlan() (*migrationPlan, error) {
	catalogCache.once.Do(func() {
		catalogCache.cat, catalogCache.err = buildMigrationCatalog()
	})
	return catalogCache.cat, catalogCache.err
}

func (c *migrationPlan) file(version int) (migrationFile, bool) {
	if c == nil || version < 0 || version >= len(c.files) {
		return migrationFile{}, false
	}
	return c.files[version], true
}

func (c *migrationPlan) fileMust(version int) migrationFile {
	return c.files[version]
}

func buildMigrationCatalog() (*migrationPlan, error) {
	var manifest struct {
		SchemaVersion int               `json:"schema_version"`
		Files         map[string]string `json:"files"`
	}
	raw, err := Files.ReadFile("manifest.json")
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &manifest); err != nil || manifest.SchemaVersion != targetVersion {
		return nil, fmt.Errorf("invalid migration manifest")
	}
	cat := &migrationPlan{files: make([]migrationFile, targetVersion+1), step: make([][]schemaCatalog, targetVersion+1)}
	for version := 0; version <= targetVersion; version++ {
		prefix := fmt.Sprintf("internal/storage/migrations/sqlite/%03d_", version)
		var path string
		for candidate := range manifest.Files {
			if strings.HasPrefix(candidate, prefix) && strings.HasSuffix(candidate, ".sql") {
				if path != "" {
					return nil, fmt.Errorf("duplicate sqlite migration")
				}
				path = candidate
			}
		}
		if path == "" {
			return nil, fmt.Errorf("missing sqlite migration")
		}
		relative := strings.TrimPrefix(path, "internal/storage/migrations/")
		data, err := Files.ReadFile(relative)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		checksum := hex.EncodeToString(sum[:])
		if checksum != manifest.Files[path] {
			return nil, fmt.Errorf("migration checksum mismatch")
		}
		steps, err := reviewedStatements(data, version)
		if err != nil || len(steps) == 0 {
			return nil, fmt.Errorf("invalid migration statements")
		}
		cat.files[version] = migrationFile{
			version:  version,
			name:     strings.TrimSuffix(filepath.Base(relative), ".sql"),
			path:     relative,
			checksum: checksum,
			data:     append([]byte(nil), data...),
			steps:    steps,
		}
	}

	db, err := sql.Open("sqlite", "file:certme_migration_catalog?mode=memory&cache=private")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		return nil, err
	}
	for version := 0; version <= targetVersion; version++ {
		file := cat.files[version]
		cat.step[version] = make([]schemaCatalog, len(file.steps))
		for index, step := range file.steps {
			if _, err := db.ExecContext(ctx, step.sql); err != nil {
				return nil, err
			}
			snapshot, err := readCatalog(ctx, db)
			if err != nil {
				return nil, err
			}
			cat.step[version][index] = snapshot
		}
		cat.full = append(cat.full, cat.step[version][len(cat.step[version])-1])
	}
	return cat, nil
}

// reviewedStatements is a lexical scanner, not strings.Split(';'). It keeps
// semicolons inside literals/quoted identifiers and rejects unterminated SQL.
func reviewedStatements(data []byte, version int) ([]reviewedStatement, error) {
	const (
		scanNormal = iota
		scanSingle
		scanDouble
		scanBacktick
		scanBracket
		scanLineComment
		scanBlockComment
	)
	state := scanNormal
	start := 0
	hasSQL := false
	var statements []reviewedStatement
	for index := 0; index < len(data); index++ {
		ch := data[index]
		switch state {
		case scanNormal:
			switch {
			case ch == '-' && index+1 < len(data) && data[index+1] == '-':
				state = scanLineComment
				index++
			case ch == '/' && index+1 < len(data) && data[index+1] == '*':
				state = scanBlockComment
				index++
			case ch == '\'':
				hasSQL = true
				state = scanSingle
			case ch == '"':
				hasSQL = true
				state = scanDouble
			case ch == '`':
				hasSQL = true
				state = scanBacktick
			case ch == '[':
				hasSQL = true
				state = scanBracket
			case ch == ';':
				if hasSQL {
					statement := strings.TrimSpace(string(data[start:index]))
					statements = append(statements, makeReviewedStatement(statement, start, index, version, len(statements)+1))
				}
				start = index + 1
				hasSQL = false
			default:
				if ch > ' ' {
					hasSQL = true
				}
			}
		case scanSingle:
			if ch == '\'' {
				if index+1 < len(data) && data[index+1] == '\'' {
					index++
				} else {
					state = scanNormal
				}
			}
		case scanDouble:
			if ch == '"' {
				if index+1 < len(data) && data[index+1] == '"' {
					index++
				} else {
					state = scanNormal
				}
			}
		case scanBacktick:
			if ch == '`' {
				if index+1 < len(data) && data[index+1] == '`' {
					index++
				} else {
					state = scanNormal
				}
			}
		case scanBracket:
			if ch == ']' {
				state = scanNormal
			}
		case scanLineComment:
			if ch == '\n' || ch == '\r' {
				state = scanNormal
			}
		case scanBlockComment:
			if ch == '*' && index+1 < len(data) && data[index+1] == '/' {
				state = scanNormal
				index++
			}
		}
	}
	if state == scanSingle || state == scanDouble || state == scanBacktick || state == scanBracket || state == scanBlockComment {
		return nil, fmt.Errorf("unterminated SQL")
	}
	if hasSQL {
		statement := strings.TrimSpace(string(data[start:]))
		statements = append(statements, makeReviewedStatement(statement, start, len(data), version, len(statements)+1))
	}
	return statements, nil
}

func makeReviewedStatement(statement string, start, end, version, order int) reviewedStatement {
	sum := sha256.Sum256([]byte(statement))
	return reviewedStatement{
		id:       fmt.Sprintf("%03d.%03d", version, order),
		order:    order,
		start:    start,
		end:      end,
		sql:      statement,
		checksum: hex.EncodeToString(sum[:]),
	}
}

type schemaObjectKey struct {
	typ  string
	name string
}

type schemaObject struct {
	typ    string
	name   string
	table  string
	sql    string
	unique bool
}

type schemaCatalog struct {
	objects map[schemaObjectKey]schemaObject
}

func readCatalog(ctx context.Context, query queryer) (schemaCatalog, error) {
	rows, err := query.QueryContext(ctx, `
		SELECT type, name, tbl_name, COALESCE(sql, '')
		FROM sqlite_master
		WHERE name NOT LIKE 'sqlite_%'
		ORDER BY type, name`)
	if err != nil {
		return schemaCatalog{}, err
	}
	defer rows.Close()
	cat := schemaCatalog{objects: make(map[schemaObjectKey]schemaObject)}
	for rows.Next() {
		var object schemaObject
		if err := rows.Scan(&object.typ, &object.name, &object.table, &object.sql); err != nil {
			return schemaCatalog{}, err
		}
		object.sql = normalizeSchemaSQL(object.sql)
		if object.typ == "index" {
			unique, err := indexIsUnique(ctx, query, object.table, object.name)
			if err != nil {
				return schemaCatalog{}, err
			}
			object.unique = unique
		}
		cat.objects[schemaObjectKey{typ: object.typ, name: object.name}] = object
	}
	if err := rows.Err(); err != nil {
		return schemaCatalog{}, err
	}
	return cat, nil
}

func indexIsUnique(ctx context.Context, query queryer, table, index string) (bool, error) {
	rows, err := query.QueryContext(ctx, `PRAGMA index_list("`+strings.ReplaceAll(table, `"`, `""`)+`")`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var name string
		var unique int
		var origin string
		var partial int
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			return false, err
		}
		if name == index {
			return unique != 0, nil
		}
	}
	return false, rows.Err()
}

func normalizeSchemaSQL(sqlText string) string {
	return strings.Join(strings.Fields(sqlText), " ")
}

func catalogMatches(actual, expected schemaCatalog) bool {
	if expected.objects == nil {
		return false
	}
	for key, want := range expected.objects {
		got, ok := actual.objects[key]
		if !ok || got.typ != want.typ || got.table != want.table || got.sql != want.sql || (key.typ == "index" && got.unique != want.unique) {
			return false
		}
	}
	for key, got := range actual.objects {
		if _, expected := expected.objects[key]; expected {
			continue
		}
		// Additional non-unique helper indexes are explicitly tolerated by
		// the contract; all other unknown schema objects are not adopted.
		if key.typ == "index" && !got.unique {
			continue
		}
		return false
	}
	return true
}

func foreignKeyCheckOK(ctx context.Context, query queryer) bool {
	rows, err := query.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return false
	}
	defer rows.Close()
	return !rows.Next() && rows.Err() == nil
}
