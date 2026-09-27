package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectsDuplicateAndMalformedSources(t *testing.T) {
	validKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	t.Run("storage key env and file", func(t *testing.T) {
		values := sqliteEnvironment()
		values[envStorageKey] = validKey
		values[envStorageKeyFile] = filepath.Join(t.TempDir(), "key")

		_, err := LoadFrom(mapLookup(values))
		assertInvalidConfig(t, err)
		assertDoesNotLeak(t, err.Error(), validKey)
	})

	t.Run("database env and file", func(t *testing.T) {
		values := sqliteEnvironment()
		values[envDBConfigFile] = filepath.Join(t.TempDir(), "database.json")
		values[envDBPassword] = "db-password-must-not-appear"

		_, err := LoadFrom(mapLookup(values))
		assertInvalidConfig(t, err)
		assertDoesNotLeak(t, err.Error(), values[envDBPassword], values[envDBConfigFile])
	})

	t.Run("duplicate JSON property", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "database.json")
		contents := `{"kind":"sqlite","path":"db.sqlite","password":"private-value","password":"other-value"}`
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}

		_, err := LoadFrom(mapLookup(map[string]string{envDBConfigFile: path}))
		assertInvalidConfig(t, err)
		assertDoesNotLeak(t, err.Error(), "private-value", "other-value", path)
	})

	t.Run("malformed JSON", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "database.json")
		contents := `{"kind":"sqlite","path":"private-path",`
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}

		_, err := LoadFrom(mapLookup(map[string]string{envDBConfigFile: path}))
		assertInvalidConfig(t, err)
		assertDoesNotLeak(t, err.Error(), "private-path", path)
	})
}

func TestRejectsStorageKeyWithWrongDecodedLength(t *testing.T) {
	material := bytes.Repeat([]byte("k"), 31)
	encoded := base64.StdEncoding.EncodeToString(material)
	values := sqliteEnvironment()
	values[envStorageKey] = encoded

	_, err := LoadFrom(mapLookup(values))
	assertInvalidConfig(t, err)
	assertDoesNotLeak(t, err.Error(), encoded, string(material))
}

func TestStorageKeyIsOptionalUntilRequiredAndAllOutputIsRedacted(t *testing.T) {
	values := map[string]string{
		envDBKind:     string(Postgres),
		envDBHost:     "db.internal",
		envDBName:     "certificates",
		envDBUser:     "cert-me",
		envDBPassword: "db-password-very-secret",
	}
	cfg, err := LoadFrom(mapLookup(values))
	if err != nil {
		t.Fatalf("LoadFrom without storage key: %v", err)
	}
	defer cfg.Close()
	if cfg.StorageKey != nil {
		t.Fatal("StorageKey is set without a configured key source")
	}
	if err := RequireStorageKey(cfg); err == nil {
		t.Fatal("RequireStorageKey succeeded without a key")
	}

	plaintext := "storage-key-plaintext-must-not-appear"
	material := []byte("01234567890123456789012345678901")
	encoded := base64.StdEncoding.EncodeToString(material)
	values[envStorageKey] = encoded
	values[envDBPassword] = plaintext
	cfgWithKey, err := LoadFrom(mapLookup(values))
	if err != nil {
		t.Fatalf("LoadFrom with valid key: %v", err)
	}
	defer cfgWithKey.Close()
	if err := RequireStorageKey(cfgWithKey); err != nil {
		t.Fatalf("RequireStorageKey: %v", err)
	}

	renderings := []string{
		fmt.Sprintf("%v", cfgWithKey),
		fmt.Sprintf("%+v", cfgWithKey),
		fmt.Sprintf("%#v", cfgWithKey),
		fmt.Sprintf("%q", cfgWithKey),
		fmt.Sprintf("%v", cfgWithKey.Database),
		fmt.Sprintf("%#v", cfgWithKey.Database.Password),
	}
	var logBuffer bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuffer, nil)).Info("loaded config", "config", cfgWithKey)
	renderings = append(renderings, logBuffer.String())
	if _, err := json.Marshal(cfgWithKey); err == nil {
		t.Fatal("JSON marshaling a config containing secret inputs succeeded")
	} else {
		renderings = append(renderings, err.Error())
	}
	for _, rendered := range renderings {
		assertDoesNotLeak(t, rendered, plaintext, string(material), encoded, values[envDBPassword])
	}
}

func TestLoadsDatabaseSettingsFileAndDefaultsPort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database.json")
	contents := `{"kind":"postgres","host":"db.internal","database":"certificates","username":"cert-me","password":"file-password"}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFrom(mapLookup(map[string]string{envDBConfigFile: path}))
	if err != nil {
		t.Fatalf("LoadFrom database file: %v", err)
	}
	defer cfg.Close()
	if cfg.Database.Kind != Postgres || cfg.Database.Port != 5432 {
		t.Fatalf("database = %#v, want postgres with default port 5432", cfg.Database)
	}
	if cfg.Database.Password == nil || cfg.Database.Password.String() != "<redacted>" {
		t.Fatal("database password is missing or not redacted")
	}
}

func TestStorageKeyFileAllowsOnlyOneTrailingNewline(t *testing.T) {
	material := bytes.Repeat([]byte{0x7c}, 32)
	encoded := base64.StdEncoding.EncodeToString(material)
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFrom(mapLookup(map[string]string{
		envDBKind:           string(SQLite),
		envDBPath:           "./cert-me.db",
		envStorageKeyFile:   path,
	}))
	if err != nil {
		t.Fatalf("LoadFrom newline-terminated key file: %v", err)
	}
	defer cfg.Close()
	if err := RequireStorageKey(cfg); err != nil {
		t.Fatalf("RequireStorageKey: %v", err)
	}

	if err := os.WriteFile(path, []byte(encoded+"\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadFrom(mapLookup(map[string]string{
		envDBKind:         string(SQLite),
		envDBPath:         "./cert-me.db",
		envStorageKeyFile: path,
	}))
	assertInvalidConfig(t, err)
	assertDoesNotLeak(t, err.Error(), encoded, path)
}

func sqliteEnvironment() map[string]string {
	return map[string]string{
		envDBKind: string(SQLite),
		envDBPath: "./cert-me.db",
	}
}

func mapLookup(values map[string]string) Lookup {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func assertInvalidConfig(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected invalid configuration error")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want ErrInvalidConfig", err)
	}
}

func assertDoesNotLeak(t *testing.T, rendered string, values ...string) {
	t.Helper()
	for _, value := range values {
		if value != "" && strings.Contains(rendered, value) {
			t.Errorf("rendered output leaked %q: %s", value, rendered)
		}
	}
}
