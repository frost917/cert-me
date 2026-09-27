package migrate

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"cert-me/internal/config"
	"cert-me/internal/storage/executionlock"
)

type sqlExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func bootstrap(ctx context.Context, conn *sql.Conn, lock *executionlock.Lock, runner *Runner, plan *migrationPlan) error {
	if err := lock.Check(ctx); err != nil {
		return classifyLockError(err)
	}
	actual, err := readCatalog(ctx, conn, runner.database.Kind)
	if err != nil {
		return catalogFailure(err)
	}
	if len(actual.tables) != 0 || len(actual.indexes) != 0 || len(actual.unknown) != 0 {
		return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
	}
	file := plan.files[0]
	if runner.database.Kind == config.MySQL || runner.database.Kind == config.MariaDB {
		stepCtx, cancel := context.WithTimeout(ctx, runner.stepTimeout)
		_, err = conn.ExecContext(stepCtx, file.steps[0].sql)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return migrationError(StateUnavailable, "migration_step_unavailable", ctx.Err())
			}
			return migrationError(StateUnavailable, "migration_bootstrap_failed", err)
		}
	} else {
		tx, beginErr := conn.BeginTx(ctx, nil)
		if beginErr != nil {
			return migrationError(StateUnavailable, "migration_transaction_unavailable", beginErr)
		}
		stepCtx, cancel := context.WithTimeout(ctx, runner.stepTimeout)
		_, execErr := tx.ExecContext(stepCtx, file.steps[0].sql)
		cancel()
		if execErr != nil {
			_ = tx.Rollback()
			return classifyStepError(execErr)
		}
		inside, readErr := readCatalog(ctx, tx, runner.database.Kind)
		if readErr != nil || !catalogMatches(inside, file.steps[0].after, runner.database.Kind) {
			_ = tx.Rollback()
			if readErr != nil {
				return catalogFailure(readErr)
			}
			return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
		}
		if err := tx.Commit(); err != nil {
			return classifyCommitError(err)
		}
	}
	if err := lock.Check(ctx); err != nil {
		return classifyLockError(err)
	}
	actual, err = readCatalog(ctx, conn, runner.database.Kind)
	if err != nil {
		return catalogFailure(err)
	}
	if !catalogMatches(actual, plan.full[0], runner.database.Kind) {
		return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
	}
	if err := insertApplied(ctx, conn, runner.database.Kind, file, len(file.steps), nowUnixMicro()); err != nil {
		return err
	}
	return nil
}

func resumeIncomplete(ctx context.Context, conn *sql.Conn, lock *executionlock.Lock, runner *Runner, plan *migrationPlan, state inspection) error {
	if state.status.State != StateResumeRequired || state.status.IncompleteVersion == nil || state.incomplete == nil {
		return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
	}
	version := *state.status.IncompleteVersion
	if version == 0 {
		if state.incomplete.state != "unrecorded" || !catalogMatches(state.actual, plan.full[0], runner.database.Kind) {
			return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
		}
		file := plan.files[0]
		return insertApplied(ctx, conn, runner.database.Kind, file, len(file.steps), nowUnixMicro())
	}
	if err := lock.Check(ctx); err != nil {
		return classifyLockError(err)
	}
	entry := *state.incomplete
	if entry.state == "failed" {
		if err := promoteApplying(ctx, conn, runner.database.Kind, version); err != nil {
			return err
		}
		entry.state = "applying"
	}
	file := plan.files[version]
	if catalogMatches(state.actual, plan.full[version], runner.database.Kind) {
		if handlerStep, ok := dataHandlerStep(file); ok && state.status.LastVerifiedStep < handlerStep.order {
			if runner.database.Kind != config.MySQL && runner.database.Kind != config.MariaDB {
				return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
			}
			return applyVersion(ctx, conn, lock, runner, plan, version, true, state.status.LastVerifiedStep)
		}
		if state.status.LastVerifiedStep > entry.lastStep {
			if err := updateLastStep(ctx, conn, runner.database.Kind, version, state.status.LastVerifiedStep); err != nil {
				return err
			}
		}
		return markApplied(ctx, conn, runner.database.Kind, version, len(file.steps), nowUnixMicro())
	}
	fromStep := 0
	if runner.database.Kind == config.MySQL || runner.database.Kind == config.MariaDB {
		fromStep = state.status.LastVerifiedStep
		if fromStep < entry.lastStep || fromStep > len(file.steps) {
			return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
		}
		if fromStep > entry.lastStep {
			if err := updateLastStep(ctx, conn, runner.database.Kind, version, fromStep); err != nil {
				return err
			}
		}
	}
	return applyVersion(ctx, conn, lock, runner, plan, version, true, fromStep)
}

func applyVersion(ctx context.Context, conn *sql.Conn, lock *executionlock.Lock, runner *Runner, plan *migrationPlan, version int, existing bool, fromStep int) error {
	if err := lock.Check(ctx); err != nil {
		return classifyLockError(err)
	}
	if version < 1 || version > targetVersion {
		return migrationError(StateIncompatible, "migration_version_invalid", ErrIncompatible)
	}
	file := plan.files[version]
	if version == auditScopeRequiredVersion {
		ready, err := dataHandlerSatisfied(ctx, conn, runner.database.Kind, auditScopeBackfillHandlerID)
		if err != nil {
			return migrationError(StateUnavailable, "migration_handler_unavailable", err)
		}
		if !ready {
			return migrationError(StateIncompatible, "migration_audit_scope_inconsistent", ErrIncompatible)
		}
	}
	if fromStep < 0 || fromStep > len(file.steps) {
		return migrationError(StateIncompatible, "migration_step_invalid", ErrIncompatible)
	}
	if !existing {
		if err := insertApplying(ctx, conn, runner.database.Kind, file, nowUnixMicro()); err != nil {
			return err
		}
	}
	if err := lock.Check(ctx); err != nil {
		return classifyLockError(err)
	}
	if runner.database.Kind == config.MySQL || runner.database.Kind == config.MariaDB {
		return applyNonTransactional(ctx, conn, lock, runner, plan, file, fromStep)
	}
	return applyTransactional(ctx, conn, lock, runner, plan, file)
}

func applyTransactional(ctx context.Context, conn *sql.Conn, lock *executionlock.Lock, runner *Runner, plan *migrationPlan, file migrationFile) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return migrationError(StateUnavailable, "migration_transaction_unavailable", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	for _, step := range file.steps {
		before, readErr := readCatalog(ctx, tx, runner.database.Kind)
		if readErr != nil {
			return catalogFailure(readErr)
		}
		if !catalogMatches(before, step.before, runner.database.Kind) {
			return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
		}
		if step.handler != "" {
			stepCtx, cancel := context.WithTimeout(ctx, runner.stepTimeout)
			handlerErr := applyDataHandler(stepCtx, tx, runner.database.Kind, step.handler)
			cancel()
			if handlerErr != nil {
				return handlerErr
			}
		} else {
			stepCtx, cancel := context.WithTimeout(ctx, runner.stepTimeout)
			_, execErr := tx.ExecContext(stepCtx, step.sql)
			cancel()
			if execErr != nil {
				_ = tx.Rollback()
				if !isContextFailure(execErr) {
					if lockErr := lock.Check(ctx); lockErr != nil {
						return classifyLockError(lockErr)
					}
					if failErr := markFailed(ctx, conn, runner.database.Kind, file.version, "migration_step_failed"); failErr != nil {
						return failErr
					}
				}
				return classifyStepError(execErr)
			}
		}
		after, readErr := readCatalog(ctx, tx, runner.database.Kind)
		if readErr != nil {
			return catalogFailure(readErr)
		}
		if !catalogMatches(after, step.after, runner.database.Kind) {
			return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
		}
		if step.handler != "" {
			satisfied, err := dataHandlerSatisfied(ctx, tx, runner.database.Kind, step.handler)
			if err != nil {
				return migrationError(StateUnavailable, "migration_handler_unavailable", err)
			}
			if !satisfied {
				return migrationError(StateIncompatible, "migration_handler_postcondition_failed", ErrIncompatible)
			}
		}
		if err := updateLastStepOn(ctx, tx, runner.database.Kind, file.version, step.order); err != nil {
			return err
		}
	}
	final, err := readCatalog(ctx, tx, runner.database.Kind)
	if err != nil {
		return catalogFailure(err)
	}
	if !catalogMatches(final, plan.full[file.version], runner.database.Kind) {
		return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
	}
	ok, err := foreignKeyCheckOK(ctx, tx, runner.database.Kind)
	if err != nil {
		return migrationError(StateUnavailable, "migration_integrity_check_unavailable", err)
	}
	if !ok {
		return migrationError(StateIncompatible, "migration_integrity_check_failed", ErrIncompatible)
	}
	if err := markAppliedOn(ctx, tx, runner.database.Kind, file.version, len(file.steps), nowUnixMicro()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return classifyCommitError(err)
	}
	committed = true
	if err := lock.Check(ctx); err != nil {
		return classifyLockError(err)
	}
	return nil
}

func applyNonTransactional(ctx context.Context, conn *sql.Conn, lock *executionlock.Lock, runner *Runner, plan *migrationPlan, file migrationFile, fromStep int) error {
	for index := fromStep; index < len(file.steps); index++ {
		step := file.steps[index]
		if err := lock.Check(ctx); err != nil {
			return classifyLockError(err)
		}
		before, err := readCatalog(ctx, conn, runner.database.Kind)
		if err != nil {
			return catalogFailure(err)
		}
		if !catalogMatches(before, step.before, runner.database.Kind) {
			return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
		}
		stepCtx, cancel := context.WithTimeout(ctx, runner.stepTimeout)
		if step.handler != "" {
			tx, beginErr := conn.BeginTx(stepCtx, nil)
			if beginErr != nil {
				cancel()
				return migrationError(StateUnavailable, "migration_handler_transaction_unavailable", beginErr)
			}
			handlerErr := applyDataHandler(stepCtx, tx, runner.database.Kind, step.handler)
			if handlerErr == nil {
				var satisfied bool
				satisfied, handlerErr = dataHandlerSatisfied(stepCtx, tx, runner.database.Kind, step.handler)
				if handlerErr == nil && !satisfied {
					handlerErr = migrationError(StateIncompatible, "migration_handler_postcondition_failed", ErrIncompatible)
				}
			}
			if handlerErr != nil {
				_ = tx.Rollback()
				cancel()
				return handlerErr
			}
			if err := tx.Commit(); err != nil {
				cancel()
				return classifyCommitError(err)
			}
			cancel()
			if err := lock.Check(ctx); err != nil {
				return classifyLockError(err)
			}
			if err := updateLastStep(ctx, conn, runner.database.Kind, file.version, step.order); err != nil {
				return err
			}
			continue
		}
		_, execErr := conn.ExecContext(stepCtx, step.sql)
		cancel()
		if execErr != nil {
			if err := lock.Check(ctx); err != nil {
				return classifyLockError(err)
			}
			after, readErr := readCatalog(ctx, conn, runner.database.Kind)
			if readErr != nil {
				return catalogFailure(readErr)
			}
			if catalogMatches(after, step.after, runner.database.Kind) {
				if err := updateLastStep(ctx, conn, runner.database.Kind, file.version, step.order); err != nil {
					return err
				}
				continue
			}
			if !catalogMatches(after, step.before, runner.database.Kind) {
				return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
			}
			if !isContextFailure(execErr) {
				if err := markFailed(ctx, conn, runner.database.Kind, file.version, "migration_step_failed"); err != nil {
					return err
				}
			}
			return classifyStepError(execErr)
		}
		after, err := readCatalog(ctx, conn, runner.database.Kind)
		if err != nil {
			return catalogFailure(err)
		}
		if !catalogMatches(after, step.after, runner.database.Kind) {
			return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
		}
		if err := updateLastStep(ctx, conn, runner.database.Kind, file.version, step.order); err != nil {
			return err
		}
	}
	final, err := readCatalog(ctx, conn, runner.database.Kind)
	if err != nil {
		return catalogFailure(err)
	}
	if !catalogMatches(final, plan.full[file.version], runner.database.Kind) {
		return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
	}
	if err := lock.Check(ctx); err != nil {
		return classifyLockError(err)
	}
	if err := markApplied(ctx, conn, runner.database.Kind, file.version, len(file.steps), nowUnixMicro()); err != nil {
		return err
	}
	return nil
}

func insertApplying(ctx context.Context, conn *sql.Conn, kind config.DatabaseKind, file migrationFile, now int64) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return migrationError(StateUnavailable, "migration_journal_unavailable", err)
	}
	query := `INSERT INTO schema_migrations
		(version,name,checksum,state,started_at,completed_at,last_step,error_code)
		VALUES (` + placeholders(kind, 5) + `,NULL,0,NULL)`
	if _, err = tx.ExecContext(ctx, query, file.version, file.name, file.checksum, "applying", now); err != nil {
		_ = tx.Rollback()
		return migrationError(StateUnavailable, "migration_journal_unavailable", err)
	}
	if err := tx.Commit(); err != nil {
		return classifyCommitError(err)
	}
	return nil
}

func insertApplied(ctx context.Context, conn *sql.Conn, kind config.DatabaseKind, file migrationFile, lastStep int, now int64) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return migrationError(StateUnavailable, "migration_journal_unavailable", err)
	}
	query := `INSERT INTO schema_migrations
		(version,name,checksum,state,started_at,completed_at,last_step,error_code)
		VALUES (` + placeholders(kind, 7) + `,NULL)`
	if _, err = tx.ExecContext(ctx, query, file.version, file.name, file.checksum, "applied", now, now, lastStep); err != nil {
		_ = tx.Rollback()
		return migrationError(StateUnavailable, "migration_journal_unavailable", err)
	}
	if err := tx.Commit(); err != nil {
		return classifyCommitError(err)
	}
	return nil
}

func updateLastStep(ctx context.Context, conn *sql.Conn, kind config.DatabaseKind, version, step int) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return migrationError(StateUnavailable, "migration_journal_unavailable", err)
	}
	if err := updateLastStepOn(ctx, tx, kind, version, step); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return classifyCommitError(err)
	}
	return nil
}

func updateLastStepOn(ctx context.Context, exec sqlExecer, kind config.DatabaseKind, version, step int) error {
	query := `UPDATE schema_migrations SET last_step=` + placeholder(kind, 1) +
		` WHERE version=` + placeholder(kind, 2) + ` AND state='applying'`
	result, err := exec.ExecContext(ctx, query, step, version)
	if err != nil {
		return migrationError(StateUnavailable, "migration_journal_unavailable", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return migrationError(StateIncompatible, "migration_journal_conflict", ErrIncompatible)
	}
	return nil
}

func markApplied(ctx context.Context, conn *sql.Conn, kind config.DatabaseKind, version, lastStep int, completed int64) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return migrationError(StateUnavailable, "migration_journal_unavailable", err)
	}
	if err := markAppliedOn(ctx, tx, kind, version, lastStep, completed); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return classifyCommitError(err)
	}
	return nil
}

func markAppliedOn(ctx context.Context, exec sqlExecer, kind config.DatabaseKind, version, lastStep int, completed int64) error {
	query := `UPDATE schema_migrations SET state='applied', completed_at=` + placeholder(kind, 1) +
		`, last_step=` + placeholder(kind, 2) + `, error_code=NULL WHERE version=` + placeholder(kind, 3) + ` AND state='applying'`
	result, err := exec.ExecContext(ctx, query, completed, lastStep, version)
	if err != nil {
		return migrationError(StateUnavailable, "migration_journal_unavailable", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return migrationError(StateIncompatible, "migration_journal_conflict", ErrIncompatible)
	}
	return nil
}

func markFailed(ctx context.Context, conn *sql.Conn, kind config.DatabaseKind, version int, code string) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return migrationError(StateUnavailable, "migration_journal_unavailable", err)
	}
	query := `UPDATE schema_migrations SET state='failed', completed_at=NULL, error_code=` + placeholder(kind, 1) +
		` WHERE version=` + placeholder(kind, 2) + ` AND state='applying'`
	result, err := tx.ExecContext(ctx, query, code, version)
	if err != nil {
		_ = tx.Rollback()
		return migrationError(StateUnavailable, "migration_journal_unavailable", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		_ = tx.Rollback()
		return migrationError(StateIncompatible, "migration_journal_conflict", ErrIncompatible)
	}
	if err := tx.Commit(); err != nil {
		return classifyCommitError(err)
	}
	return nil
}

func promoteApplying(ctx context.Context, conn *sql.Conn, kind config.DatabaseKind, version int) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return migrationError(StateUnavailable, "migration_journal_unavailable", err)
	}
	query := `UPDATE schema_migrations SET state='applying', completed_at=NULL, error_code=NULL WHERE version=` +
		placeholder(kind, 1) + ` AND state='failed'`
	result, err := tx.ExecContext(ctx, query, version)
	if err != nil {
		_ = tx.Rollback()
		return migrationError(StateUnavailable, "migration_journal_unavailable", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		_ = tx.Rollback()
		return migrationError(StateIncompatible, "migration_journal_conflict", ErrIncompatible)
	}
	if err := tx.Commit(); err != nil {
		return classifyCommitError(err)
	}
	return nil
}

func placeholders(kind config.DatabaseKind, count int) string {
	values := make([]string, count)
	for index := range values {
		values[index] = placeholder(kind, index+1)
	}
	return strings.Join(values, ",")
}

func placeholder(kind config.DatabaseKind, index int) string {
	if kind == config.Postgres {
		return "$" + strconv.Itoa(index)
	}
	return "?"
}

func classifyStepError(err error) error {
	if err == nil {
		return nil
	}
	if isContextFailure(err) {
		return migrationError(StateUnavailable, "migration_step_unavailable", err)
	}
	return migrationError(StateUnavailable, "migration_step_failed", err)
}

func classifyCommitError(err error) error {
	if err == nil {
		return nil
	}
	return migrationError(StateUnavailable, "migration_commit_unknown", errors.Join(ErrCommitUnknown, err))
}

func isContextFailure(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func nowUnixMicro() int64 { return time.Now().UTC().UnixMicro() }
