package executionlock

import (
	"strings"
	"testing"
)

func TestMySQLLockNameIsBounded(t *testing.T) {
	name := mysqlLockName("CertStore", 0)
	if len(name) > 64 {
		t.Fatalf("lock name length = %d, want at most 64", len(name))
	}
	if !strings.HasPrefix(name, mysqlLockPrefix) {
		t.Fatalf("lock name does not have the fixed prefix")
	}
}

func TestMySQLLockNameFollowsServerCaseMode(t *testing.T) {
	for _, mode := range []int64{0, 1, 2} {
		t.Run(string(rune('0'+mode)), func(t *testing.T) {
			upper := mysqlLockName("Foo", mode)
			lower := mysqlLockName("foo", mode)
			if mode == 0 && upper == lower {
				t.Fatal("case-sensitive mode produced a colliding lock name")
			}
			if mode != 0 && upper != lower {
				t.Fatal("case-insensitive mode did not fold database-name case")
			}
		})
	}
}
