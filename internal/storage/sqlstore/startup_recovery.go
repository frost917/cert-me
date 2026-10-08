package sqlstore

import (
	"context"
	"errors"
	"fmt"

	"cert-me/internal/config"
	"cert-me/internal/storage/connection"
	"cert-me/internal/storage/executionlock"
	"cert-me/internal/storage/sqlstore/dialect"
)

var ErrOperationalRecoveryRequired = errors.New("sqlstore: operational recovery required")

// EnsureNoIncompleteMaintenance blocks server startup while a durable
// maintenance operation or restore CRL requirement remains unresolved. The
// caller must hold the execution lock for the lifetime of startup checks.
func EnsureNoIncompleteMaintenance(ctx context.Context, db *connection.DB, kind config.DatabaseKind, lock *executionlock.Lock) error {
	if ctx == nil || db == nil || lock == nil {
		return errors.New("sqlstore: startup recovery check requires context, database, and execution lock")
	}
	reader := db.ReadDB()
	if reader == nil {
		return connection.ErrClosed
	}
	d, err := dialect.New(kind)
	if err != nil {
		return fmt.Errorf("sqlstore: startup recovery dialect: %w", err)
	}
	if err := lock.Check(ctx); err != nil {
		return fmt.Errorf("sqlstore: startup recovery lock check: %w", err)
	}

	b := d.NewBuilder()
	unfinishedPhase := b.Add("finished")
	restoreKind := b.Add("restore_finalize")
	query := "SELECT EXISTS (SELECT 1 FROM maintenance_runs WHERE phase <> " + unfinishedPhase + " OR completed_at IS NULL)" +
		" OR EXISTS (SELECT 1 FROM maintenance_crl_requirements AS requirements JOIN maintenance_runs AS runs" +
		" ON runs.id = requirements.maintenance_run_id WHERE runs.kind = " + restoreKind +
		" AND requirements.satisfied_crl_id IS NULL)"
	var blocked bool
	if err := reader.QueryRowContext(ctx, query, b.Args()...).Scan(&blocked); err != nil {
		return fmt.Errorf("sqlstore: inspect incomplete maintenance state: %w", err)
	}
	if err := lock.Check(ctx); err != nil {
		return fmt.Errorf("sqlstore: startup recovery lock check: %w", err)
	}
	if blocked {
		return ErrOperationalRecoveryRequired
	}
	return nil
}
