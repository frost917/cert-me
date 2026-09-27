//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package executionlock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cert-me/internal/config"
)

func TestSQLiteLockUsesCanonicalPersistentSiblingFile(t *testing.T) {
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0700); err != nil {
		t.Fatal("could not create test directory")
	}
	aliasDirectory := filepath.Join(root, "alias")
	if err := os.Symlink(realDirectory, aliasDirectory); err != nil {
		t.Fatal("could not create test symlink")
	}

	databasePath := filepath.Join(realDirectory, "cert-me.db")
	aliasPath := filepath.Join(aliasDirectory, "cert-me.db")
	lock, err := Acquire(context.Background(), config.Database{Kind: config.SQLite, SQLitePath: databasePath}, nil)
	if err != nil {
		t.Fatalf("Acquire returned an error: %v", err)
	}
	if _, err := Acquire(context.Background(), config.Database{Kind: config.SQLite, SQLitePath: aliasPath}, nil); !errors.Is(err, ErrAlreadyHeld) {
		t.Fatalf("Acquire through symlink = %v, want ErrAlreadyHeld", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := lock.Release(canceled); err != nil {
		t.Fatalf("Release with a canceled context returned an error: %v", err)
	}

	lockFilePath := databasePath + ".lock"
	info, err := os.Stat(lockFilePath)
	if err != nil {
		t.Fatalf("persistent lock file is missing: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("lock file mode = %04o, want 0600", got)
	}

	second, err := Acquire(context.Background(), config.Database{Kind: config.SQLite, SQLitePath: aliasPath}, nil)
	if err != nil {
		t.Fatalf("Acquire after release returned an error: %v", err)
	}
	if err := second.Release(context.Background()); err != nil {
		t.Fatalf("second Release returned an error: %v", err)
	}
}

func TestSQLiteLockRejectsSymlinkLockFile(t *testing.T) {
	root := t.TempDir()
	databasePath := filepath.Join(root, "cert-me.db")
	target := filepath.Join(root, "unrelated")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal("could not create test target")
	}
	if err := os.Symlink(target, databasePath+".lock"); err != nil {
		t.Fatal("could not create lock symlink")
	}

	_, err := Acquire(context.Background(), config.Database{Kind: config.SQLite, SQLitePath: databasePath}, nil)
	if !errors.Is(err, ErrOperation) {
		t.Fatalf("Acquire with symlink lock file = %v, want ErrOperation", err)
	}
	if err != nil && strings.Contains(err.Error(), root) {
		t.Fatal("lock error exposed a filesystem path")
	}
}
