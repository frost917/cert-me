package migrate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"

	"cert-me/internal/config"
)

// This ID is part of the reviewed version-008 step plan. Change its semantics
// only in a new migration version with a new handler ID.
const auditScopeBackfillHandlerID = "audit_scope_kind_backfill_v1"

var globalAuditActions = []string{
	"identity.login",
	"identity.logout",
	"identity.begin_reset",
	"identity.complete_reset",
	"setup.create_admin",
	"setup.complete",
	"settings.update",
	"maintenance.rotate",
	"maintenance.finalize_restore",
	"tls.upload_candidate",
	"tls.reload",
	"tls.activate",
	"tls.activate.rejected",
	"tls.activate.rolled_back",
	"tls.reconcile",
}

type handlerDB interface {
	catalogQueryer
	sqlExecer
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func applyDataHandler(ctx context.Context, db handlerDB, kind config.DatabaseKind, handler string) error {
	switch handler {
	case auditScopeBackfillHandlerID:
		return applyAuditScopeBackfill(ctx, db, kind)
	default:
		return migrationError(StateIncompatible, "migration_handler_unknown", ErrIncompatible)
	}
}

func dataHandlerSatisfied(ctx context.Context, db handlerDB, kind config.DatabaseKind, handler string) (bool, error) {
	switch handler {
	case auditScopeBackfillHandlerID:
		return auditScopeBackfillSatisfied(ctx, db, kind)
	default:
		return false, migrationError(StateIncompatible, "migration_handler_unknown", ErrIncompatible)
	}
}

func applyAuditScopeBackfill(ctx context.Context, db handlerDB, kind config.DatabaseKind) error {
	invalid, err := auditScopeClassificationInvalid(ctx, db, kind)
	if err != nil {
		return migrationError(StateUnavailable, "migration_handler_unavailable", err)
	}
	if invalid {
		return migrationError(StateIncompatible, "migration_audit_scope_inconsistent", ErrIncompatible)
	}
	globalPredicate := "action IN (" + placeholders(kind, len(globalAuditActions)) + ")"
	authoritiesQuery := `UPDATE audit_events SET scope_kind='authorities'
		WHERE scope_kind IS NULL AND ` + `NOT (` + globalPredicate + `)
		AND EXISTS (SELECT 1 FROM audit_event_scopes s WHERE s.event_id=audit_events.id)`
	if _, err := db.ExecContext(ctx, authoritiesQuery, actionArgs()...); err != nil {
		return migrationError(StateUnavailable, "migration_handler_failed", err)
	}
	installationQuery := `UPDATE audit_events SET scope_kind='installation'
		WHERE scope_kind IS NULL AND ` + globalPredicate + `
		AND NOT EXISTS (SELECT 1 FROM audit_event_scopes s WHERE s.event_id=audit_events.id)`
	if _, err := db.ExecContext(ctx, installationQuery, actionArgs()...); err != nil {
		return migrationError(StateUnavailable, "migration_handler_failed", err)
	}
	satisfied, err := auditScopeBackfillSatisfied(ctx, db, kind)
	if err != nil {
		return migrationError(StateUnavailable, "migration_handler_unavailable", err)
	}
	if !satisfied {
		return migrationError(StateIncompatible, "migration_audit_scope_inconsistent", ErrIncompatible)
	}
	return nil
}

func auditScopeClassificationInvalid(ctx context.Context, db handlerDB, kind config.DatabaseKind) (bool, error) {
	globalPredicate := "e.action IN (" + placeholders(kind, len(globalAuditActions)) + ")"
	hasScopes := "EXISTS (SELECT 1 FROM audit_event_scopes s WHERE s.event_id=e.id)"
	query := `SELECT EXISTS (
		SELECT 1 FROM audit_events e WHERE
		(e.scope_kind IS NOT NULL AND e.scope_kind NOT IN ('installation','authorities'))
		OR (e.scope_kind='installation' AND (` + hasScopes + ` OR NOT (` + globalPredicate + `)))
		OR (e.scope_kind='authorities' AND NOT ` + hasScopes + `)
		OR (` + hasScopes + ` AND ` + globalPredicate + `)
	)`
	var invalid bool
	args := repeatedActionArgs(kind, 2)
	if err := db.QueryRowContext(ctx, query, args...).Scan(&invalid); err != nil {
		return false, err
	}
	return invalid, nil
}

func auditScopeBackfillSatisfied(ctx context.Context, db handlerDB, kind config.DatabaseKind) (bool, error) {
	invalid, err := auditScopeClassificationInvalid(ctx, db, kind)
	if err != nil || invalid {
		return false, err
	}
	globalPredicate := "e.action IN (" + placeholders(kind, len(globalAuditActions)) + ")"
	hasScopes := "EXISTS (SELECT 1 FROM audit_event_scopes s WHERE s.event_id=e.id)"
	query := `SELECT NOT EXISTS (
		SELECT 1 FROM audit_events e WHERE
		(` + hasScopes + ` AND NOT (` + globalPredicate + `) AND e.scope_kind IS NULL)
		OR (NOT ` + hasScopes + ` AND ` + globalPredicate + ` AND e.scope_kind IS NULL)
	)`
	var satisfied bool
	if err := db.QueryRowContext(ctx, query, repeatedActionArgs(kind, 2)...).Scan(&satisfied); err != nil {
		return false, err
	}
	return satisfied, nil
}

func actionArgs() []any {
	args := make([]any, len(globalAuditActions))
	for i, action := range globalAuditActions {
		args[i] = action
	}
	return args
}

func repeatedActionArgs(kind config.DatabaseKind, repetitions int) []any {
	args := actionArgs()
	if kind != config.Postgres {
		for i := 1; i < repetitions; i++ {
			args = append(args, actionArgs()...)
		}
	}
	return args
}

func handlerStepChecksum(handler string) string {
	sum := sha256.Sum256([]byte("handler:" + handler))
	return hex.EncodeToString(sum[:])
}
