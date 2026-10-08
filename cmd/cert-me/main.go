package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cert-me/internal/config"
	appruntime "cert-me/internal/runtime"
	"cert-me/internal/storage/migrate"
)

const (
	inputExitCode        = 2
	busyExitCode         = 3
	incompatibleExitCode = 4
	executionExitCode    = 5
	minStepTimeout       = time.Second
	maxStepTimeout       = time.Hour
	statusSchemaVersion  = 1
)

type dbOperation uint8

const (
	dbStatus dbOperation = iota
	dbMigrate
	dbResume
)

type commandOptions struct {
	operation   dbOperation
	json        bool
	stepTimeout time.Duration
	hasTimeout  bool
}

// main is intentionally a thin wrapper so argument handling and output can be
// exercised without a process environment or a live database.
func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "serve" {
		os.Exit(runServe(context.Background(), args[1:], os.LookupEnv, os.Stdout, os.Stderr))
	}
	os.Exit(run(context.Background(), args, os.LookupEnv, os.Stdout, os.Stderr))
}

func runServe(ctx context.Context, args []string, lookup config.Lookup, stdout, stderr io.Writer) int {
	serveCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	listenAddress, err := parseListenAddress(args)
	if err != nil {
		writeServeInputError(stderr)
		return inputExitCode
	}

	cfg, err := config.LoadFrom(lookup)
	if err != nil {
		writeServeInputError(stderr)
		return inputExitCode
	}
	defer cfg.Close()
	if err := config.RequireStorageKey(cfg); err != nil {
		writeServeInputError(stderr)
		return inputExitCode
	}
	trustedProxyCIDRs, err := config.LoadTrustedProxyCIDRs(lookup)
	if err != nil {
		writeServeInputError(stderr)
		return inputExitCode
	}

	app, err := appruntime.Open(serveCtx, appruntime.Options{
		Database:          cfg.Database,
		StorageKey:        cfg.StorageKey,
		TrustedProxyCIDRs: trustedProxyCIDRs,
		ListenAddress:     listenAddress,
		Logger: slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
	})
	if err != nil {
		if serveCtx.Err() != nil {
			return 0
		}
		writeServeFailure(stderr)
		return executionExitCode
	}
	if fingerprint := app.BootstrapFingerprint(); fingerprint != "" {
		if _, err := fmt.Fprintf(stdout, "Bootstrap HTTPS leaf SHA-256: %s\n", fingerprint); err != nil {
			if closeErr := app.Close(context.Background()); closeErr != nil {
				writeServeFailure(stderr)
				return executionExitCode
			}
			writeServeFailure(stderr)
			return executionExitCode
		}
	}

	serveErr := app.ListenAndServe(serveCtx)
	closeErr := app.Close(context.Background())
	if serveErr != nil || closeErr != nil {
		writeServeFailure(stderr)
		return executionExitCode
	}
	return 0
}

func parseListenAddress(args []string) (string, error) {
	const defaultAddress = ":8443"
	address := defaultAddress
	seen := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		var value string
		switch {
		case arg == "--listen":
			if i+1 >= len(args) {
				return "", errors.New("missing listener address")
			}
			i++
			value = args[i]
		case strings.HasPrefix(arg, "--listen="):
			value = strings.TrimPrefix(arg, "--listen=")
		default:
			return "", errors.New("unknown serve option")
		}
		if seen || value == "" || strings.TrimSpace(value) != value {
			return "", errors.New("invalid listener address")
		}
		seen = true
		address = value
	}
	return address, nil
}

func writeServeInputError(dst io.Writer) {
	if dst != nil {
		_, _ = io.WriteString(dst, "invalid serve command or configuration\n")
	}
}

func writeServeFailure(dst io.Writer) {
	if dst != nil {
		_, _ = io.WriteString(dst, "HTTPS service could not start or stop cleanly\n")
	}
}

// run implements the schema-only database commands. It does not load or
// require the storage encryption key; config.LoadFrom leaves it optional.
func run(ctx context.Context, args []string, lookup config.Lookup, stdout, stderr io.Writer) int {
	options, err := parseArgs(args)
	if err != nil {
		writeInputError(stderr)
		return inputExitCode
	}

	cfg, err := config.LoadFrom(lookup)
	if err != nil {
		writeFailure(stderr, inputExitCode)
		return inputExitCode
	}
	defer cfg.Close()

	runnerOptions := make([]migrate.Option, 0, 1)
	if options.hasTimeout {
		runnerOptions = append(runnerOptions, migrate.WithStepTimeout(options.stepTimeout))
	}
	runner, err := migrate.NewRunner(cfg.Database, runnerOptions...)
	if err != nil {
		if runner != nil {
			_ = runner.Close()
		}
		code := exitCodeForError(err)
		writeFailure(stderr, code)
		return code
	}
	if runner == nil {
		writeFailure(stderr, executionExitCode)
		return executionExitCode
	}
	closed := false
	defer func() {
		if !closed {
			_ = runner.Close()
		}
	}()

	var status migrate.Status
	var operationErr error
	switch options.operation {
	case dbStatus:
		status, operationErr = runner.Status(ctx)
	case dbMigrate:
		operationErr = runner.Migrate(ctx)
		var statusErr error
		status, statusErr = runner.Status(ctx)
		if operationErr == nil {
			operationErr = statusErr
		}
	case dbResume:
		operationErr = runner.Resume(ctx)
		var statusErr error
		status, statusErr = runner.Status(ctx)
		if operationErr == nil {
			operationErr = statusErr
		}
	}
	closeErr := runner.Close()
	closed = true
	if operationErr == nil {
		operationErr = closeErr
	}

	code := exitCodeForStatus(status)
	if operationErr != nil {
		code = exitCodeForError(operationErr)
	}
	if !hasStatus(status) {
		if operationErr == nil {
			operationErr = migrate.ErrUnavailable
		}
		code = exitCodeForError(operationErr)
		writeFailure(stderr, code)
		return code
	}
	if options.json {
		if err := writeJSON(stdout, status); err != nil {
			writeFailure(stderr, executionExitCode)
			return executionExitCode
		}
	} else {
		if err := writeHumanStatus(stdout, status); err != nil {
			writeFailure(stderr, executionExitCode)
			return executionExitCode
		}
	}
	if operationErr != nil && !errors.Is(operationErr, migrate.ErrMigrateRequired) &&
		!errors.Is(operationErr, migrate.ErrResumeRequired) && exitCodeForStatus(status) != code {
		writeFailure(stderr, code)
	}
	return code
}

func parseArgs(args []string) (commandOptions, error) {
	if len(args) < 2 || args[0] != "db" {
		return commandOptions{}, errors.New("invalid command")
	}
	options := commandOptions{}
	switch args[1] {
	case "status":
		options.operation = dbStatus
	case "migrate":
		options.operation = dbMigrate
	case "resume":
		options.operation = dbResume
	default:
		return commandOptions{}, errors.New("invalid command")
	}

	seenJSON, seenTimeout := false, false
	for i := 2; i < len(args); i++ {
		arg := args[i]
		if arg == "--json" {
			if seenJSON {
				return commandOptions{}, errors.New("duplicate option")
			}
			seenJSON = true
			options.json = true
			continue
		}

		var rawTimeout string
		switch {
		case arg == "--step-timeout":
			if i+1 >= len(args) {
				return commandOptions{}, errors.New("missing option value")
			}
			i++
			rawTimeout = args[i]
		case strings.HasPrefix(arg, "--step-timeout="):
			rawTimeout = strings.TrimPrefix(arg, "--step-timeout=")
		default:
			return commandOptions{}, errors.New("unknown option")
		}
		if options.operation == dbStatus || seenTimeout || rawTimeout == "" {
			return commandOptions{}, errors.New("invalid option")
		}
		timeout, err := time.ParseDuration(rawTimeout)
		if err != nil || timeout < minStepTimeout || timeout > maxStepTimeout {
			return commandOptions{}, errors.New("invalid option value")
		}
		seenTimeout = true
		options.hasTimeout = true
		options.stepTimeout = timeout
	}
	return options, nil
}

func exitCodeForStatus(status migrate.Status) int {
	switch status.State {
	case migrate.StateBusy:
		return busyExitCode
	case migrate.StateIncompatible:
		return incompatibleExitCode
	case migrate.StateUnavailable:
		return executionExitCode
	default:
		return 0
	}
}

func exitCodeForError(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, config.ErrInvalidConfig), errors.Is(err, migrate.ErrInvalidConfig), errors.Is(err, migrate.ErrMigrateRequired):
		return inputExitCode
	case errors.Is(err, migrate.ErrBusy):
		return busyExitCode
	case errors.Is(err, migrate.ErrIncompatible):
		return incompatibleExitCode
	default:
		return executionExitCode
	}
}

func hasStatus(status migrate.Status) bool {
	return status.SchemaVersion == statusSchemaVersion
}

func writeJSON(dst io.Writer, status migrate.Status) error {
	type stableStatus struct {
		SchemaVersion      int           `json:"schema_version"`
		DatabaseKind       string        `json:"database_kind"`
		State              migrate.State `json:"state"`
		CurrentVersion     int           `json:"current_version"`
		TargetVersion      int           `json:"target_version"`
		IncompleteVersion  *int          `json:"incomplete_version"`
		LastVerifiedStep   int           `json:"last_verified_step"`
		SnapshotConsistent bool          `json:"snapshot_consistent"`
		NextCommand        string        `json:"next_command"`
	}
	encoder := json.NewEncoder(dst)
	return encoder.Encode(stableStatus{
		SchemaVersion: status.SchemaVersion, DatabaseKind: status.DatabaseKind, State: status.State,
		CurrentVersion: status.CurrentVersion, TargetVersion: status.TargetVersion,
		IncompleteVersion: status.IncompleteVersion, LastVerifiedStep: status.LastVerifiedStep,
		SnapshotConsistent: status.SnapshotConsistent, NextCommand: status.NextCommand,
	})
}

func writeHumanStatus(dst io.Writer, status migrate.Status) error {
	incomplete := "none"
	if status.IncompleteVersion != nil {
		incomplete = fmt.Sprint(*status.IncompleteVersion)
	}
	_, err := fmt.Fprintf(dst,
		"schema_version: %d\ndatabase_kind: %s\nstate: %s\ncurrent_version: %d\ntarget_version: %d\nincomplete_version: %s\nlast_verified_step: %d\nsnapshot_consistent: %t\nnext_command: %s\n",
		status.SchemaVersion,
		status.DatabaseKind,
		status.State,
		status.CurrentVersion,
		status.TargetVersion,
		incomplete,
		status.LastVerifiedStep,
		status.SnapshotConsistent,
		status.NextCommand,
	)
	return err
}

func writeInputError(dst io.Writer) {
	writeFailure(dst, inputExitCode)
}

func writeFailure(dst io.Writer, code int) {
	if dst == nil {
		return
	}
	switch code {
	case inputExitCode:
		_, _ = io.WriteString(dst, "invalid database command or configuration\n")
	case busyExitCode:
		_, _ = io.WriteString(dst, "database is busy\n")
	case incompatibleExitCode:
		_, _ = io.WriteString(dst, "database schema is incompatible\n")
	default:
		_, _ = io.WriteString(dst, "database command failed\n")
	}
}
