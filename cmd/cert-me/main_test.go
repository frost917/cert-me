package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"cert-me/internal/config"
	"cert-me/internal/storage/migrate"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantOp     dbOperation
		wantJSON   bool
		wantStep   time.Duration
		wantValid  bool
	}{
		{name: "status defaults", args: []string{"db", "status"}, wantOp: dbStatus, wantValid: true},
		{name: "status json", args: []string{"db", "status", "--json"}, wantOp: dbStatus, wantJSON: true, wantValid: true},
		{name: "migrate flags", args: []string{"db", "migrate", "--step-timeout", "1m", "--json"}, wantOp: dbMigrate, wantJSON: true, wantStep: time.Minute, wantValid: true},
		{name: "resume equals timeout", args: []string{"db", "resume", "--step-timeout=1h"}, wantOp: dbResume, wantStep: time.Hour, wantValid: true},
		{name: "missing command", args: []string{"db"}},
		{name: "unknown command", args: []string{"db", "rollback"}},
		{name: "unknown option", args: []string{"db", "migrate", "--password", "secret"}},
		{name: "positional argument", args: []string{"db", "status", "postgres://secret"}},
		{name: "step timeout rejected on status", args: []string{"db", "status", "--step-timeout", "1s"}},
		{name: "timeout below minimum", args: []string{"db", "migrate", "--step-timeout=999ms"}},
		{name: "timeout above maximum", args: []string{"db", "resume", "--step-timeout=1h1s"}},
		{name: "duplicate json", args: []string{"db", "status", "--json", "--json"}},
		{name: "duplicate timeout", args: []string{"db", "migrate", "--step-timeout=1s", "--step-timeout=2s"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseArgs(tt.args)
			if tt.wantValid {
				if err != nil {
					t.Fatalf("parseArgs() error = %v", err)
				}
				if got.operation != tt.wantOp || got.json != tt.wantJSON || got.stepTimeout != tt.wantStep {
					t.Fatalf("parseArgs() = %#v", got)
				}
				return
			}
			if err == nil {
				t.Fatal("parseArgs() accepted invalid arguments")
			}
		})
	}
}

func TestRunDoesNotEchoRejectedArgument(t *testing.T) {
	const secretArg = "postgres://admin:do-not-print@example.test/db"
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"db", "status", secretArg}, config.Lookup(func(string) (string, bool) {
		return "", false
	}), &stdout, &stderr)
	if code != inputExitCode {
		t.Fatalf("run() code = %d, want %d", code, inputExitCode)
	}
	if strings.Contains(stderr.String(), secretArg) || strings.Contains(stdout.String(), secretArg) {
		t.Fatal("rejected argument was echoed")
	}
}

func TestStatusExitCode(t *testing.T) {
	tests := []struct {
		state migrate.State
		want  int
	}{
		{state: migrate.StateEmpty, want: 0},
		{state: migrate.StateCurrent, want: 0},
		{state: migrate.StateUpgradeRequired, want: 0},
		{state: migrate.StateResumeRequired, want: 0},
		{state: migrate.StateBusy, want: busyExitCode},
		{state: migrate.StateIncompatible, want: incompatibleExitCode},
		{state: migrate.StateUnavailable, want: executionExitCode},
	}
	for _, tt := range tests {
		if got := exitCodeForStatus(migrate.Status{State: tt.state}); got != tt.want {
			t.Errorf("exitCodeForStatus(%q) = %d, want %d", tt.state, got, tt.want)
		}
	}
}

func TestErrorExitCode(t *testing.T) {
	tests := []struct {
		err  error
		want int
	}{
		{err: config.ErrInvalidConfig, want: inputExitCode},
		{err: migrate.ErrInvalidConfig, want: inputExitCode},
		{err: migrate.ErrMigrateRequired, want: inputExitCode},
		{err: migrate.ErrBusy, want: busyExitCode},
		{err: migrate.ErrIncompatible, want: incompatibleExitCode},
		{err: migrate.ErrUnavailable, want: executionExitCode},
		{err: migrate.ErrCommitUnknown, want: executionExitCode},
		{err: migrate.ErrResumeRequired, want: executionExitCode},
	}
	for _, tt := range tests {
		if got := exitCodeForError(tt.err); got != tt.want {
			t.Errorf("exitCodeForError(%v) = %d, want %d", tt.err, got, tt.want)
		}
	}
}

func TestWriteJSONUsesStableStatusSchema(t *testing.T) {
	incomplete := 3
	status := migrate.Status{
		SchemaVersion: 1, DatabaseKind: "mysql", State: migrate.StateResumeRequired,
		CurrentVersion: 2, TargetVersion: 7, IncompleteVersion: &incomplete,
		LastVerifiedStep: 4, SnapshotConsistent: true, NextCommand: "cert-me db resume",
	}
	var output bytes.Buffer
	if err := writeJSON(&output, status); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	want := []string{
		"schema_version", "database_kind", "state", "current_version", "target_version",
		"incomplete_version", "last_verified_step", "snapshot_consistent", "next_command",
	}
	if len(fields) != len(want) {
		t.Fatalf("JSON has %d fields, want %d: %s", len(fields), len(want), output.String())
	}
	for _, key := range want {
		if _, ok := fields[key]; !ok {
			t.Errorf("JSON is missing %q", key)
		}
	}
}
