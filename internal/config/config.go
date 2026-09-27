// Package config loads and validates database connection settings and the
// optional storage encryption key from the process environment.
package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"cert-me/internal/secret"
)

const (
	envDBConfigFile = "CERT_ME_DB_CONFIG_FILE"
	envDBKind       = "CERT_ME_DB_KIND"
	envDBPath       = "CERT_ME_DB_PATH"
	envDBHost       = "CERT_ME_DB_HOST"
	envDBPort       = "CERT_ME_DB_PORT"
	envDBName       = "CERT_ME_DB_NAME"
	envDBUser       = "CERT_ME_DB_USER"
	envDBPassword   = "CERT_ME_DB_PASSWORD"

	envStorageKey     = "CERT_ME_ENCRYPTION_KEY"
	envStorageKeyFile = "CERT_ME_ENCRYPTION_KEY_FILE"

	dbConfigFileLimit = 64 * 1024
	storageKeyFileMax = 46 // 44 Base64 characters plus a final CRLF.
)

// ErrInvalidConfig identifies a configuration error. Error details contain
// only fixed field names and reasons, never the value that failed validation.
var ErrInvalidConfig = errors.New("config: invalid configuration")

// ErrNotSerializable is returned when a configuration is marshaled. Use
// explicit output types instead of serializing connection settings.
var ErrNotSerializable = errors.New("config: refusing to serialize configuration")

// DatabaseKind identifies one of the supported database engines.
type DatabaseKind string

const (
	SQLite  DatabaseKind = "sqlite"
	Postgres DatabaseKind = "postgres"
	MySQL    DatabaseKind = "mysql"
	MariaDB  DatabaseKind = "mariadb"
)

// Config contains the resolved database connection and an optional storage
// encryption key. StorageKey is optional so schema-only database commands do
// not need access to key material. The returned secret inputs are owned by
// Config and should be closed when the configuration is no longer needed.
type Config struct {
	Database   Database
	StorageKey *secret.Input
}

// Database contains the validated connection parameters for one database.
// Password is nil when no password source was configured. It is never stored
// as a plain string and its textual forms are redacted by secret.Input.
type Database struct {
	Kind         DatabaseKind
	SQLitePath   string
	Host         string
	Port         uint16
	DatabaseName string
	Username     string
	Password     *secret.Input
}

// Lookup reads one environment variable and reports whether it was present.
// Presence is distinct from an empty value, which matters when detecting
// duplicate sources.
type Lookup func(name string) (value string, present bool)

// Load reads the process environment.
func Load() (Config, error) {
	return LoadFrom(os.LookupEnv)
}

// LoadFrom resolves settings using lookup. Database connection settings may
// come from either individual CERT_ME_DB_* variables or CERT_ME_DB_CONFIG_FILE
// (a JSON file), but not both. The storage key may independently come from
// CERT_ME_ENCRYPTION_KEY or CERT_ME_ENCRYPTION_KEY_FILE, but not both.
func LoadFrom(lookup Lookup) (Config, error) {
	if lookup == nil {
		return Config{}, configError("environment", "lookup function is required")
	}

	database, err := loadDatabase(lookup)
	if err != nil {
		return Config{}, err
	}

	storageKey, err := loadStorageKey(lookup)
	if err != nil {
		if database.Password != nil {
			_ = database.Password.Close()
		}
		return Config{}, err
	}

	return Config{Database: database, StorageKey: storageKey}, nil
}

// RequireStorageKey verifies that a loaded configuration has a valid
// 32-byte storage encryption key. Use this for server startup and key
// maintenance paths; schema-only database commands should not call it.
func RequireStorageKey(cfg Config) error {
	if cfg.StorageKey == nil || cfg.StorageKey.Len() != 32 {
		return configError(envStorageKey, "must provide a Base64-encoded 32-byte key")
	}
	return nil
}

// Close releases the secret buffers owned by cfg. It is safe to call more
// than once.
func (cfg *Config) Close() {
	if cfg == nil {
		return
	}
	secret.CloseAll(cfg.StorageKey, cfg.Database.Password)
	cfg.StorageKey = nil
	cfg.Database.Password = nil
}

// String, GoString, Format, and LogValue keep complete configurations safe to
// print even if future fields are added.
func (Config) String() string   { return "<config: redacted>" }
func (Config) GoString() string { return "<config: redacted>" }
func (Config) MarshalJSON() ([]byte, error) { return nil, ErrNotSerializable }
func (Config) MarshalText() ([]byte, error) { return nil, ErrNotSerializable }
func (Config) Format(state fmt.State, verb rune) {
	if verb == 'q' {
		_, _ = io.WriteString(state, `"<config: redacted>"`)
		return
	}
	_, _ = io.WriteString(state, "<config: redacted>")
}
func (Config) LogValue() slog.Value { return slog.StringValue("<config: redacted>") }

func (Database) String() string   { return "<database: redacted>" }
func (Database) GoString() string { return "<database: redacted>" }
func (Database) MarshalJSON() ([]byte, error) { return nil, ErrNotSerializable }
func (Database) MarshalText() ([]byte, error) { return nil, ErrNotSerializable }
func (Database) Format(state fmt.State, verb rune) {
	if verb == 'q' {
		_, _ = io.WriteString(state, `"<database: redacted>"`)
		return
	}
	_, _ = io.WriteString(state, "<database: redacted>")
}
func (Database) LogValue() slog.Value { return slog.StringValue("<database: redacted>") }

type configErrorValue struct {
	field   string
	problem string
}

func (e *configErrorValue) Error() string {
	return "config: " + e.field + ": " + e.problem
}

func (e *configErrorValue) Is(target error) bool { return target == ErrInvalidConfig }

func configError(field, problem string) error {
	return &configErrorValue{field: field, problem: problem}
}

func loadDatabase(lookup Lookup) (Database, error) {
	filePath, fileConfigured := lookup(envDBConfigFile)
	inlineNames := []string{envDBKind, envDBPath, envDBHost, envDBPort, envDBName, envDBUser, envDBPassword}
	inlineConfigured := false
	for _, name := range inlineNames {
		if _, present := lookup(name); present {
			inlineConfigured = true
		}
	}

	if fileConfigured {
		if inlineConfigured {
			return Database{}, configError(envDBConfigFile, "cannot be combined with individual database settings")
		}
		if filePath == "" {
			return Database{}, configError(envDBConfigFile, "must name a connection settings file")
		}
		return loadDatabaseFile(filePath)
	}

	return loadDatabaseEnvironment(lookup)
}

func loadDatabaseEnvironment(lookup Lookup) (Database, error) {
	var db Database

	kind, present := lookup(envDBKind)
	if !present || kind == "" {
		return db, configError(envDBKind, "must be set")
	}
	db.Kind = DatabaseKind(kind)

	path, hasPath := lookup(envDBPath)
	host, hasHost := lookup(envDBHost)
	port, hasPort := lookup(envDBPort)
	name, hasName := lookup(envDBName)
	username, hasUsername := lookup(envDBUser)
	password, hasPassword := lookup(envDBPassword)

	db.SQLitePath = path
	db.Host = host
	db.DatabaseName = name
	db.Username = username

	switch db.Kind {
	case SQLite:
		if !hasPath || isBlank(path) {
			return db, configError(envDBPath, "must be set for sqlite")
		}
		if hasHost || hasPort || hasName || hasUsername || hasPassword {
			return Database{}, configError(envDBKind, "sqlite cannot include external database settings")
		}
	case Postgres, MySQL, MariaDB:
		if hasPath {
			return Database{}, configError(envDBPath, "is only valid for sqlite")
		}
		if isBlank(host) {
			return Database{}, configError(envDBHost, "must be set for an external database")
		}
		if isBlank(name) {
			return Database{}, configError(envDBName, "must be set for an external database")
		}
		if isBlank(username) {
			return Database{}, configError(envDBUser, "must be set for an external database")
		}
		if hasPort {
			parsed, err := strconv.ParseUint(port, 10, 16)
			if err != nil || parsed == 0 {
				return Database{}, configError(envDBPort, "must be an integer between 1 and 65535")
			}
			db.Port = uint16(parsed)
		} else {
			db.Port = defaultPort(db.Kind)
		}
	default:
		return Database{}, configError(envDBKind, "must be sqlite, postgres, mysql, or mariadb")
	}
	if hasPassword {
		db.Password = secret.FromString(password)
	}

	return db, nil
}

func loadDatabaseFile(path string) (Database, error) {
	raw, err := readFileLimited(path, dbConfigFileLimit)
	if err != nil {
		return Database{}, configError(envDBConfigFile, "could not read connection settings file")
	}
	defer zero(raw)

	values, err := decodeDatabaseJSON(raw)
	if err != nil {
		return Database{}, configError(envDBConfigFile, "must contain one valid connection settings object")
	}

	var db Database
	kind, ok := values["kind"]
	if !ok || kind.stringValue == "" {
		return db, configError("database.kind", "must be set")
	}
	db.Kind = DatabaseKind(kind.stringValue)

	pathValue, hasPath := values["path"]
	host, hasHost := values["host"]
	port, hasPort := values["port"]
	name, hasName := values["database"]
	username, hasUsername := values["username"]
	password, hasPassword := values["password"]

	db.SQLitePath = pathValue.stringValue
	db.Host = host.stringValue
	db.DatabaseName = name.stringValue
	db.Username = username.stringValue

	switch db.Kind {
	case SQLite:
		if !hasPath || isBlank(db.SQLitePath) {
			return db, configError("database.path", "must be set for sqlite")
		}
		if hasHost || hasPort || hasName || hasUsername || hasPassword {
			return Database{}, configError("database.kind", "sqlite cannot include external database settings")
		}
	case Postgres, MySQL, MariaDB:
		if hasPath {
			return Database{}, configError("database.path", "is only valid for sqlite")
		}
		if !hasHost || isBlank(db.Host) {
			return Database{}, configError("database.host", "must be set for an external database")
		}
		if !hasName || isBlank(db.DatabaseName) {
			return Database{}, configError("database.database", "must be set for an external database")
		}
		if !hasUsername || isBlank(db.Username) {
			return Database{}, configError("database.username", "must be set for an external database")
		}
		if hasPort {
			if port.portValue == 0 {
				return Database{}, configError("database.port", "must be between 1 and 65535")
			}
			db.Port = port.portValue
		} else {
			db.Port = defaultPort(db.Kind)
		}
	default:
		return Database{}, configError("database.kind", "must be sqlite, postgres, mysql, or mariadb")
	}
	if hasPassword {
		db.Password = secret.FromString(password.stringValue)
	}
	return db, nil
}

type databaseJSONValue struct {
	stringValue string
	portValue   uint16
}

func decodeDatabaseJSON(raw []byte) (map[string]databaseJSONValue, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid object")
	}

	values := make(map[string]databaseJSONValue)
	for dec.More() {
		token, err = dec.Token()
		if err != nil {
			return nil, errors.New("invalid field")
		}
		field, ok := token.(string)
		if !ok || !knownDatabaseJSONField(field) {
			return nil, errors.New("unknown field")
		}
		if _, duplicate := values[field]; duplicate {
			return nil, errors.New("duplicate field")
		}

		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, errors.New("invalid value")
		}
		if field == "port" {
			var parsed uint16
			if err := json.Unmarshal(value, &parsed); err != nil {
				return nil, errors.New("invalid port")
			}
			values[field] = databaseJSONValue{portValue: parsed}
			continue
		}
		var parsed string
		if len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &parsed) != nil {
			return nil, errors.New("invalid string")
		}
		values[field] = databaseJSONValue{stringValue: parsed}
	}

	if token, err = dec.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("invalid object end")
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return values, nil
}

func knownDatabaseJSONField(field string) bool {
	switch field {
	case "kind", "path", "host", "port", "database", "username", "password":
		return true
	default:
		return false
	}
}

func loadStorageKey(lookup Lookup) (*secret.Input, error) {
	encoded, keyPresent := lookup(envStorageKey)
	path, filePresent := lookup(envStorageKeyFile)
	if keyPresent && filePresent {
		return nil, configError(envStorageKeyFile, "cannot be combined with the environment key")
	}
	if !keyPresent && !filePresent {
		return nil, nil
	}
	if keyPresent {
		decoded, err := decodeStorageKey([]byte(encoded))
		if err != nil {
			return nil, configError(envStorageKey, "must be Base64-encoded 32-byte key material")
		}
		return secret.New(decoded), nil
	}
	if path == "" {
		return nil, configError(envStorageKeyFile, "must name a key file")
	}

	raw, err := readFileLimited(path, storageKeyFileMax)
	if err != nil {
		return nil, configError(envStorageKeyFile, "could not read key file")
	}
	defer zero(raw)
	if len(raw) > 0 && raw[len(raw)-1] == '\n' {
		raw = raw[:len(raw)-1]
		if len(raw) > 0 && raw[len(raw)-1] == '\r' {
			raw = raw[:len(raw)-1]
		}
	}
	decoded, err := decodeStorageKey(raw)
	if err != nil {
		return nil, configError(envStorageKeyFile, "must contain Base64-encoded 32-byte key material")
	}
	return secret.New(decoded), nil
}

func decodeStorageKey(encoded []byte) ([]byte, error) {
	// 32 bytes encode to exactly 44 Base64 characters with standard padding.
	// Check the alphabet ourselves because encoding/base64 intentionally ignores
	// CR and LF characters while decoding.
	if len(encoded) != base64.StdEncoding.EncodedLen(32) {
		return nil, errors.New("invalid length")
	}
	for _, b := range encoded {
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '+' || b == '/' || b == '=' {
			continue
		}
		return nil, errors.New("invalid encoding")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(string(encoded))
	if err != nil || len(decoded) != 32 {
		zero(decoded)
		return nil, errors.New("invalid key material")
	}
	return decoded, nil
}

func defaultPort(kind DatabaseKind) uint16 {
	if kind == Postgres {
		return 5432
	}
	return 3306
}

func isBlank(value string) bool { return strings.TrimSpace(value) == "" }

func readFileLimited(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	contents, err := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if err != nil {
		zero(contents)
		return nil, err
	}
	if len(contents) > limit {
		zero(contents)
		return nil, errors.New("file exceeds configured limit")
	}
	return contents, nil
}

func zero(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

var (
	_ fmt.Formatter  = Config{}
	_ fmt.Stringer   = Config{}
	_ slog.LogValuer = Config{}
	_ fmt.Formatter  = Database{}
	_ fmt.Stringer   = Database{}
	_ slog.LogValuer = Database{}
)
