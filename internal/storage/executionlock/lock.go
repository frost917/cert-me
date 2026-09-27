// Package executionlock provides process-wide exclusive locks for storage
// maintenance and other operations that must not overlap.
package executionlock

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cert-me/internal/config"
)

var (
	// ErrInvalidConfiguration reports an incomplete database configuration or
	// an invalid execution-lock argument.
	ErrInvalidConfiguration = errors.New("executionlock: invalid configuration")
	// ErrUnsupportedDatabase reports a database kind this package does not know.
	ErrUnsupportedDatabase = errors.New("executionlock: unsupported database kind")
	// ErrAlreadyHeld reports that another process or session holds the lock.
	ErrAlreadyHeld = errors.New("executionlock: lock is already held")
	// ErrOwnershipLost reports that the lock is no longer held by this session.
	ErrOwnershipLost = errors.New("executionlock: lock ownership was lost")
	// ErrReleased reports use of a lock after Release.
	ErrReleased = errors.New("executionlock: lock is released")
	// ErrOperation reports an operation failure without exposing a path, DSN,
	// credential, or driver error text.
	ErrOperation = errors.New("executionlock: operation failed")
)

const (
	mysqlLockPrefix = "cert-me:"
	mysqlHashBytes = (64 - len(mysqlLockPrefix)) / 2
	releaseTimeout = 5 * time.Second

	pgLockClass  int32 = 0x43455254 // "CERT"
	pgLockObject int32 = 0x4d453035 // "ME05"
)

// Lock is an acquired execution lock. For PostgreSQL and MySQL/MariaDB it
// stays bound to the writer connection supplied to Acquire.
type Lock struct {
	mu       sync.Mutex
	kind     config.DatabaseKind
	writer   *sql.Conn
	file     *os.File
	name     string
	released bool
}

// Acquire takes the execution lock for database. It never obtains another
// database connection. SQLite uses a persistent sibling lock file; external
// databases use session-scoped locks on writer.
func Acquire(ctx context.Context, database config.Database, writer *sql.Conn) (*Lock, error) {
	if ctx == nil || ctx.Err() != nil {
		if ctx != nil {
			return nil, ctx.Err()
		}
		return nil, ErrInvalidConfiguration
	}

	switch database.Kind {
	case config.SQLite:
		if database.SQLitePath == "" {
			return nil, ErrInvalidConfiguration
		}
		return acquireSQLite(ctx, database.SQLitePath)
	case config.Postgres:
		if writer == nil {
			return nil, ErrInvalidConfiguration
		}
		var alreadyHeld bool
		if err := writer.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_locks
				WHERE locktype = 'advisory'
				  AND pid = pg_backend_pid()
				  AND classid = $1::oid
				  AND objid = $2::oid
				  AND objsubid = 2
				  AND granted
			)`, pgLockClass, pgLockObject).Scan(&alreadyHeld); err != nil {
			return nil, operationError(ctx)
		}
		if alreadyHeld {
			return nil, ErrAlreadyHeld
		}
		var acquired bool
		if err := writer.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1, $2)", pgLockClass, pgLockObject).Scan(&acquired); err != nil {
			return nil, operationError(ctx)
		}
		if !acquired {
			return nil, ErrAlreadyHeld
		}
		return &Lock{kind: database.Kind, writer: writer}, nil
	case config.MySQL, config.MariaDB:
		if writer == nil {
			return nil, ErrInvalidConfiguration
		}
		var currentDatabase sql.NullString
		var lowerCaseTableNames sql.NullInt64
		if err := writer.QueryRowContext(ctx, "SELECT DATABASE(), @@lower_case_table_names").Scan(&currentDatabase, &lowerCaseTableNames); err != nil {
			return nil, operationError(ctx)
		}
		if !currentDatabase.Valid || currentDatabase.String == "" {
			return nil, ErrInvalidConfiguration
		}
		if !lowerCaseTableNames.Valid || lowerCaseTableNames.Int64 < 0 || lowerCaseTableNames.Int64 > 2 {
			return nil, ErrOperation
		}
		name := mysqlLockName(currentDatabase.String, lowerCaseTableNames.Int64)
		var alreadyHeld sql.NullBool
		if err := writer.QueryRowContext(ctx, "SELECT IS_USED_LOCK(?) = CONNECTION_ID()", name).Scan(&alreadyHeld); err != nil {
			return nil, operationError(ctx)
		}
		if alreadyHeld.Valid && alreadyHeld.Bool {
			return nil, ErrAlreadyHeld
		}
		var acquired sql.NullInt64
		if err := writer.QueryRowContext(ctx, "SELECT GET_LOCK(?, 0)", name).Scan(&acquired); err != nil {
			return nil, operationError(ctx)
		}
		if !acquired.Valid {
			return nil, ErrOperation
		}
		if acquired.Int64 != 1 {
			return nil, ErrAlreadyHeld
		}
		return &Lock{kind: database.Kind, writer: writer, name: name}, nil
	default:
		return nil, ErrUnsupportedDatabase
	}
}

// Check verifies that the lock is still owned by the current process or
// database session. It must be called before continuing work after a possible
// writer-connection interruption.
func (lock *Lock) Check(ctx context.Context) error {
	if lock == nil || ctx == nil {
		return ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.released {
		return ErrReleased
	}

	switch lock.kind {
	case config.SQLite:
		if lock.file == nil {
			return ErrOwnershipLost
		}
		if _, err := lock.file.Stat(); err != nil {
			return ErrOwnershipLost
		}
		return nil
	case config.Postgres:
		var held bool
		err := lock.writer.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_locks
				WHERE locktype = 'advisory'
				  AND pid = pg_backend_pid()
				  AND classid = $1::oid
				  AND objid = $2::oid
				  AND objsubid = 2
				  AND granted
			)`, pgLockClass, pgLockObject).Scan(&held)
		if err != nil {
			return operationError(ctx)
		}
		if !held {
			return ErrOwnershipLost
		}
		return nil
	case config.MySQL, config.MariaDB:
		var held sql.NullBool
		if err := lock.writer.QueryRowContext(ctx, "SELECT IS_USED_LOCK(?) = CONNECTION_ID()", lock.name).Scan(&held); err != nil {
			return operationError(ctx)
		}
		if !held.Valid || !held.Bool {
			return ErrOwnershipLost
		}
		return nil
	default:
		return ErrUnsupportedDatabase
	}
}

// Release relinquishes the lock. Database locks are released on the exact
// writer session that acquired them. The SQLite lock file is intentionally
// retained after closing its descriptor.
func (lock *Lock) Release(ctx context.Context) error {
	if lock == nil || ctx == nil {
		return ErrInvalidConfiguration
	}

	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.released {
		return nil
	}

	var err error
	switch lock.kind {
	case config.SQLite:
		if lock.file == nil {
			err = ErrOwnershipLost
			break
		}
		if unlockErr := unlockFile(lock.file); unlockErr != nil {
			err = ErrOperation
		}
		if closeErr := lock.file.Close(); closeErr != nil && err == nil {
			err = ErrOperation
		}
		lock.file = nil
	case config.Postgres:
		var released bool
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
		defer cancel()
		if queryErr := lock.writer.QueryRowContext(releaseCtx, "SELECT pg_advisory_unlock($1, $2)", pgLockClass, pgLockObject).Scan(&released); queryErr != nil {
			err = operationError(releaseCtx)
		} else if !released {
			err = ErrOwnershipLost
		}
	case config.MySQL, config.MariaDB:
		var released sql.NullInt64
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
		defer cancel()
		if queryErr := lock.writer.QueryRowContext(releaseCtx, "SELECT RELEASE_LOCK(?)", lock.name).Scan(&released); queryErr != nil {
			err = operationError(releaseCtx)
		} else if !released.Valid || released.Int64 != 1 {
			err = ErrOwnershipLost
		}
	default:
		err = ErrUnsupportedDatabase
	}

	// A failed or ambiguous release cannot safely be retried: another lock
	// acquisition on this session could otherwise have its count decremented.
	lock.released = true
	return err
}

func acquireSQLite(ctx context.Context, databasePath string) (*Lock, error) {
	canonicalPath, err := canonicalSQLitePath(databasePath)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	file, err := openLockFile(canonicalPath + ".lock")
	if err != nil {
		return nil, ErrOperation
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return nil, ErrOperation
	}
	acquired, err := tryExclusiveFileLock(file)
	if err != nil {
		_ = file.Close()
		return nil, ErrOperation
	}
	if !acquired {
		_ = file.Close()
		return nil, ErrAlreadyHeld
	}
	if err := ctx.Err(); err != nil {
		_ = unlockFile(file)
		_ = file.Close()
		return nil, err
	}
	return &Lock{kind: config.SQLite, file: file}, nil
}

func canonicalSQLitePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", ErrInvalidConfiguration
	}
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", ErrInvalidConfiguration
	}

	// Resolve each existing prefix so a not-yet-created database still maps to
	// the same lock path through symlinked parent directories. Also resolve a
	// dangling final symlink before appending any missing path components.
	current := filepath.Clean(absolute)
	var missing []string
	linkCount := 0
	for {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			for _, part := range missing {
				resolved = filepath.Join(resolved, part)
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(resolveErr, fs.ErrNotExist) {
			return "", ErrInvalidConfiguration
		}

		info, lstatErr := os.Lstat(current)
		if lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
			linkCount++
			if linkCount > 255 {
				return "", ErrInvalidConfiguration
			}
			target, readErr := os.Readlink(current)
			if readErr != nil {
				return "", ErrInvalidConfiguration
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(current), target)
			}
			current = filepath.Clean(target)
			continue
		}
		if lstatErr != nil && !errors.Is(lstatErr, fs.ErrNotExist) {
			return "", ErrInvalidConfiguration
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", ErrInvalidConfiguration
		}
		missing = append([]string{filepath.Base(current)}, missing...)
		current = parent
	}
}

func mysqlLockName(serverDatabase string, lowerCaseTableNames int64) string {
	// The name comes from SELECT DATABASE(), not from a potentially aliased
	// DSN/configuration name. Respect the server's identifier case semantics:
	// modes 1 and 2 fold names, while mode 0 preserves case-sensitive names.
	normalized := serverDatabase
	if lowerCaseTableNames == 1 || lowerCaseTableNames == 2 {
		normalized = strings.ToLower(normalized)
	}
	digest := sha256.Sum256([]byte(normalized))
	return mysqlLockPrefix + hex.EncodeToString(digest[:mysqlHashBytes])
}

func operationError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrOperation
}
