// Package connection opens the read pool and the pinned writer connection used
// by storage operations.
package connection

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"cert-me/internal/config"
	"cert-me/internal/secret"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

const (
	readPoolMaxOpen = 8
	sqliteBusyMS    = 5000
)

var ErrClosed = errors.New("connection: closed")

// Options controls local database file creation. It applies to SQLite; the
// PostgreSQL, MySQL, and MariaDB databases must already exist.
type Options struct {
	CreateIfMissing bool
}

// DB owns a read pool plus a separately pinned writer connection. The writer
// pool exists only to create and retain the pinned connection.
type DB struct {
	mu         sync.RWMutex
	closed     bool
	read       *sql.DB
	writerPool *sql.DB
	writer     *sql.Conn
}

// Open opens the database described by db. SQLite uses a read/write-only mode
// unless CreateIfMissing is set. External database TLS always verifies the
// server certificate.
func Open(ctx context.Context, db config.Database, options Options) (*DB, error) {
	read, writerPool, err := openPools(db, options)
	if err != nil {
		return nil, err
	}
	cleanup := func() {
		_ = writerPool.Close()
		_ = read.Close()
	}

	writerPool.SetMaxOpenConns(1)
	writerPool.SetMaxIdleConns(1)
	read.SetMaxOpenConns(readPoolMaxOpen)
	read.SetMaxIdleConns(readPoolMaxOpen)

	writer, err := writerPool.Conn(ctx)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("connection: acquire writer: %w", err)
	}
	if err = writer.PingContext(ctx); err != nil {
		_ = writer.Close()
		cleanup()
		return nil, fmt.Errorf("connection: check writer: %w", err)
	}
	if err = read.PingContext(ctx); err != nil {
		_ = writer.Close()
		cleanup()
		return nil, fmt.Errorf("connection: check read pool: %w", err)
	}

	return &DB{read: read, writerPool: writerPool, writer: writer}, nil
}

// ReadDB returns the read pool, or nil after Close.
func (db *DB) ReadDB() *sql.DB {
	if db == nil {
		return nil
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	if db.closed {
		return nil
	}
	return db.read
}

// WriterConn returns the pinned writer connection, or nil after Close.
func (db *DB) WriterConn() *sql.Conn {
	if db == nil {
		return nil
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	if db.closed {
		return nil
	}
	return db.writer
}

// CheckWriter checks the health of the pinned writer. It does not reconnect a
// failed writer because doing so would lose any session-scoped ownership state.
func (db *DB) CheckWriter(ctx context.Context) error {
	if db == nil {
		return ErrClosed
	}
	db.mu.RLock()
	if db.closed || db.writer == nil {
		db.mu.RUnlock()
		return ErrClosed
	}
	writer := db.writer
	db.mu.RUnlock()
	if err := writer.PingContext(ctx); err != nil {
		return fmt.Errorf("connection: pinned writer health check failed: %w", err)
	}
	return nil
}

// Close releases the pinned connection and both pools. It is safe to call
// repeatedly.
func (db *DB) Close() error {
	if db == nil {
		return nil
	}
	db.mu.Lock()
	if db.closed {
		db.mu.Unlock()
		return nil
	}
	db.closed = true
	writer, writerPool, read := db.writer, db.writerPool, db.read
	db.writer, db.writerPool, db.read = nil, nil, nil
	db.mu.Unlock()

	var closeErr error
	if writer != nil {
		closeErr = errors.Join(closeErr, writer.Close())
	}
	if writerPool != nil {
		closeErr = errors.Join(closeErr, writerPool.Close())
	}
	if read != nil {
		closeErr = errors.Join(closeErr, read.Close())
	}
	return closeErr
}

func openPools(db config.Database, options Options) (*sql.DB, *sql.DB, error) {
	switch db.Kind {
	case config.SQLite:
		readDSN, writerDSN, err := sqliteDSNs(db.SQLitePath, options.CreateIfMissing)
		if err != nil {
			return nil, nil, err
		}
		return openPair("sqlite", readDSN, writerDSN)
	case config.Postgres:
		return openPostgresPair(db)
	case config.MySQL, config.MariaDB:
		return openMySQLPair(db)
	default:
		return nil, nil, fmt.Errorf("connection: unsupported database kind %q", db.Kind)
	}
}

func openPair(driver, readDSN, writerDSN string) (*sql.DB, *sql.DB, error) {
	read, err := sql.Open(driver, readDSN)
	if err != nil {
		return nil, nil, fmt.Errorf("connection: open read pool: %w", err)
	}
	writer, err := sql.Open(driver, writerDSN)
	if err != nil {
		_ = read.Close()
		return nil, nil, fmt.Errorf("connection: open writer pool: %w", err)
	}
	return read, writer, nil
}

func sqliteDSNs(path string, createIfMissing bool) (string, string, error) {
	memoryName := ""
	if path == ":memory:" {
		var nameBytes [16]byte
		if _, err := rand.Read(nameBytes[:]); err != nil {
			return "", "", fmt.Errorf("connection: create SQLite memory database name: %w", err)
		}
		memoryName = "cert-me-" + hex.EncodeToString(nameBytes[:])
	}
	read, err := sqliteDSN(path, createIfMissing, false, memoryName)
	if err != nil {
		return "", "", err
	}
	writer, err := sqliteDSN(path, createIfMissing, true, memoryName)
	if err != nil {
		return "", "", err
	}
	return read, writer, nil
}

func sqliteDSN(path string, createIfMissing, writer bool, memoryName string) (string, error) {
	if path == "" {
		return "", errors.New("connection: SQLite path is required")
	}

	query := url.Values{}
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", sqliteBusyMS))

	if path == ":memory:" {
		if memoryName == "" {
			return "", errors.New("connection: SQLite memory database name is required")
		}
		query.Set("mode", "memory")
		query.Set("cache", "shared")
		if writer {
			query.Set("_txlock", "immediate")
		}
		return "file:" + memoryName + "?" + query.Encode(), nil
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("connection: resolve SQLite path: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(absolute); resolveErr == nil {
		absolute = resolved
	} else if !errors.Is(resolveErr, os.ErrNotExist) {
		return "", fmt.Errorf("connection: resolve SQLite path: %w", resolveErr)
	}

	mode := "rw"
	if createIfMissing {
		mode = "rwc"
	}
	query.Set("mode", mode)
	if writer {
		query.Set("_txlock", "immediate")
	}
	uri := url.URL{Scheme: "file", Path: absolute, RawQuery: query.Encode()}
	return uri.String(), nil
}

func openPostgresPair(db config.Database) (*sql.DB, *sql.DB, error) {
	if db.Host == "" || db.DatabaseName == "" || db.Port == 0 {
		return nil, nil, errors.New("connection: PostgreSQL host, port, and database are required")
	}
	config, err := postgresConnConfig(db)
	if err != nil {
		return nil, nil, fmt.Errorf("connection: initialize PostgreSQL driver: %w", err)
	}
	read, writer := stdlib.OpenDB(*config), stdlib.OpenDB(*config)
	return read, writer, nil
}

func postgresConnConfig(db config.Database) (*pgx.ConnConfig, error) {
	password, err := passwordString(db.Password)
	if err != nil {
		return nil, fmt.Errorf("connection: read PostgreSQL password: %w", err)
	}
	parsePassword := password
	if parsePassword == "" {
		// Supplying a non-empty value while parsing prevents pgx from consulting
		// an ambient .pgpass/PGPASSFILE. The validated empty password is restored
		// immediately afterward.
		parsePassword = "cert-me-empty-password"
	}
	query := url.Values{}
	query.Set("sslmode", "verify-full")
	query.Set("sslrootcert", "system")
	query.Set("sslcert", "")
	query.Set("sslkey", "")
	query.Set("sslpassword", "")
	query.Set("sslsni", "1")
	query.Set("sslnegotiation", "postgres")
	query.Set("connect_timeout", "0")
	query.Set("target_session_attrs", "any")
	query.Set("channel_binding", "prefer")
	query.Set("require_auth", "")
	query.Set("min_protocol_version", "3.0")
	query.Set("max_protocol_version", "3.0")
	query.Set("default_query_exec_mode", "cache_statement")
	query.Set("statement_cache_capacity", "512")
	query.Set("description_cache_capacity", "512")
	query.Set("krbsrvname", "")
	query.Set("krbspn", "")
	query.Set("options", "")
	query.Set("application_name", "")
	databasePath := "/" + db.DatabaseName
	connURL := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(db.Username, parsePassword),
		Host:     net.JoinHostPort(db.Host, fmt.Sprint(db.Port)),
		Path:     databasePath,
		RawPath:  "/" + url.PathEscape(db.DatabaseName),
		RawQuery: query.Encode(),
	}
	connConfig, err := pgx.ParseConfig(connURL.String())
	if err != nil {
		// pgx only best-effort redacts credentials from parse errors.
		return nil, errors.New("connection: invalid PostgreSQL connection settings")
	}

	// Set the validated inputs directly as well. Service-file options and
	// environment values may be present while pgx parses the URL.
	connConfig.Host = db.Host
	connConfig.Port = db.Port
	connConfig.Database = db.DatabaseName
	connConfig.User = db.Username
	connConfig.Password = password
	connConfig.TLSConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         db.Host,
		InsecureSkipVerify: false,
	}
	connConfig.Fallbacks = nil
	connConfig.RuntimeParams = nil
	connConfig.ConnectTimeout = 0
	connConfig.KerberosSrvName = ""
	connConfig.KerberosSpn = ""
	connConfig.SSLNegotiation = "postgres"
	connConfig.ChannelBinding = "prefer"
	connConfig.RequireAuth = ""
	connConfig.MinProtocolVersion = "3.0"
	connConfig.MaxProtocolVersion = "3.0"
	connConfig.ValidateConnect = nil
	connConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
	connConfig.StatementCacheCapacity = 512
	connConfig.DescriptionCacheCapacity = 512
	return connConfig, nil
}

func openMySQLPair(db config.Database) (*sql.DB, *sql.DB, error) {
	if db.Host == "" || db.DatabaseName == "" || db.Port == 0 {
		return nil, nil, errors.New("connection: MySQL/MariaDB host, port, and database are required")
	}
	password, err := passwordString(db.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("connection: read MySQL/MariaDB password: %w", err)
	}
	config := mysql.NewConfig()
	config.User = db.Username
	config.Passwd = password
	config.Net = "tcp"
	config.Addr = net.JoinHostPort(db.Host, fmt.Sprint(db.Port))
	config.DBName = db.DatabaseName
	config.TLSConfig = "true"
	readConnector, err := mysql.NewConnector(config)
	if err != nil {
		return nil, nil, fmt.Errorf("connection: configure MySQL/MariaDB read pool: %w", err)
	}
	writerConnector, err := mysql.NewConnector(config)
	if err != nil {
		return nil, nil, fmt.Errorf("connection: configure MySQL/MariaDB writer pool: %w", err)
	}
	return sql.OpenDB(readConnector), sql.OpenDB(writerConnector), nil
}

func passwordString(password *secret.Input) (string, error) {
	if password == nil {
		return "", nil
	}
	var value string
	err := password.Use(func(bytes []byte) error {
		value = string(bytes)
		return nil
	})
	return value, err
}
