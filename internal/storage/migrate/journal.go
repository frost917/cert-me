package migrate

import (
	"context"
	"database/sql"
	"errors"
	"sort"

	"cert-me/internal/config"
)

type journalEntry struct {
	version     int
	name        string
	checksum    string
	state       string
	startedAt   int64
	completedAt sql.NullInt64
	lastStep    int
	errorCode   sql.NullString
}

type inspection struct {
	status     Status
	incomplete *journalEntry
	actual     schema
}

func inspect(ctx context.Context, conn handlerDB, kind config.DatabaseKind) (Status, error) {
	plan, err := loadPlan(kind)
	if err != nil {
		return newStatus(kind, StateUnavailable), migrationError(StateUnavailable, "migration_plan_invalid", err)
	}
	state, err := inspectWithPlan(ctx, conn, kind, plan)
	return state.status, err
}

func inspectWithPlan(ctx context.Context, conn handlerDB, kind config.DatabaseKind, plan *migrationPlan) (inspection, error) {
	result := inspection{status: newStatus(kind, StateUnavailable)}
	actual, err := readCatalog(ctx, conn, kind)
	if err != nil {
		if errors.Is(err, ErrCatalogUnrecognized) {
			result.status = newStatus(kind, StateIncompatible)
			return result, nil
		}
		return result, migrationError(StateUnavailable, "migration_catalog_unavailable", err)
	}
	result.actual = actual
	journal, hasJournal := actual.tables["schema_migrations"]
	if !hasJournal {
		if len(actual.tables) == 0 && len(actual.indexes) == 0 && len(actual.unknown) == 0 {
			result.status = newStatus(kind, StateEmpty)
			return result, nil
		}
		result.status = newStatus(kind, StateIncompatible)
		return result, nil
	}
	expectedJournal := plan.full[0].tables["schema_migrations"]
	if !sameTable(journal, expectedJournal, kind) {
		result.status = newStatus(kind, StateIncompatible)
		return result, nil
	}
	entries, err := readJournal(ctx, conn)
	if err != nil {
		return result, migrationError(StateUnavailable, "migration_journal_unavailable", err)
	}
	if len(entries) == 0 {
		if !catalogMatches(actual, plan.full[0], kind) {
			result.status = newStatus(kind, StateIncompatible)
			return result, nil
		}
		result.status = newStatus(kind, StateResumeRequired)
		zero := 0
		result.status.IncompleteVersion = &zero
		result.status.LastVerifiedStep = 0
		result.incomplete = &journalEntry{version: 0, name: plan.files[0].name, checksum: plan.files[0].checksum, state: "unrecorded"}
		return result, nil
	}

	byVersion := make(map[int]journalEntry, len(entries))
	for _, entry := range entries {
		if entry.version < 0 || entry.version > targetVersion || entry.lastStep < 0 {
			result.status = newStatus(kind, StateIncompatible)
			return result, nil
		}
		if _, duplicate := byVersion[entry.version]; duplicate {
			result.status = newStatus(kind, StateIncompatible)
			return result, nil
		}
		file := plan.files[entry.version]
		if entry.name != file.name || entry.checksum != file.checksum || entry.lastStep > len(file.steps) || !validEntryState(entry) {
			result.status = newStatus(kind, StateIncompatible)
			return result, nil
		}
		byVersion[entry.version] = entry
	}
	if zero, ok := byVersion[0]; !ok || zero.state != "applied" || zero.lastStep != len(plan.files[0].steps) {
		result.status = newStatus(kind, StateIncompatible)
		return result, nil
	}
	for version := range byVersion {
		if version > targetVersion {
			result.status = newStatus(kind, StateIncompatible)
			return result, nil
		}
	}

	for version := 0; version <= targetVersion; version++ {
		entry, exists := byVersion[version]
		if !exists {
			for later := version + 1; later <= targetVersion; later++ {
				if _, ok := byVersion[later]; ok {
					result.status = newStatus(kind, StateIncompatible)
					return result, nil
				}
			}
			current := version - 1
			if current < 0 {
				current = 0
			}
			if version == auditScopeRequiredVersion {
				ready, err := dataHandlerSatisfied(ctx, conn, kind, auditScopeBackfillHandlerID)
				if err != nil {
					return result, migrationError(StateUnavailable, "migration_handler_unavailable", err)
				}
				if !ready {
					result.status = newStatus(kind, StateIncompatible)
					return result, nil
				}
			}
			if !catalogMatches(actual, plan.full[current], kind) {
				result.status = newStatus(kind, StateIncompatible)
				return result, nil
			}
			ok, checkErr := foreignKeyCheckOK(ctx, conn, kind)
			if checkErr != nil {
				return result, migrationError(StateUnavailable, "migration_integrity_check_unavailable", checkErr)
			}
			if !ok {
				result.status = newStatus(kind, StateIncompatible)
				return result, nil
			}
			result.status = newStatus(kind, StateUpgradeRequired)
			result.status.CurrentVersion = current
			result.status.LastVerifiedStep = len(plan.files[current].steps)
			result.status.NextCommand = "cert-me db migrate"
			return result, nil
		}
		if entry.state == "applied" {
			if entry.lastStep != len(plan.files[version].steps) {
				result.status = newStatus(kind, StateIncompatible)
				return result, nil
			}
			result.status.CurrentVersion = version
			result.status.LastVerifiedStep = entry.lastStep
			continue
		}
		if version == 0 || result.incomplete != nil {
			result.status = newStatus(kind, StateIncompatible)
			return result, nil
		}
		if version == auditScopeRequiredVersion {
			ready, err := dataHandlerSatisfied(ctx, conn, kind, auditScopeBackfillHandlerID)
			if err != nil {
				return result, migrationError(StateUnavailable, "migration_handler_unavailable", err)
			}
			if !ready {
				result.status = newStatus(kind, StateIncompatible)
				return result, nil
			}
		}
		for later := version + 1; later <= targetVersion; later++ {
			if _, ok := byVersion[later]; ok {
				result.status = newStatus(kind, StateIncompatible)
				return result, nil
			}
		}
		previous := version - 1
		lastVerifiedStep := 0
		if catalogMatches(actual, plan.full[version], kind) {
			lastVerifiedStep = len(plan.files[version].steps)
			if handlerStep, ok := dataHandlerStep(plan.files[version]); ok {
				satisfied, handlerErr := dataHandlerSatisfied(ctx, conn, kind, handlerStep.handler)
				if handlerErr != nil {
					return result, migrationError(StateUnavailable, "migration_handler_unavailable", handlerErr)
				}
				if !satisfied {
					invalid, invalidErr := auditScopeClassificationInvalid(ctx, conn, kind)
					if invalidErr != nil {
						return result, migrationError(StateUnavailable, "migration_handler_unavailable", invalidErr)
					}
					if invalid {
						result.status = newStatus(kind, StateIncompatible)
						return result, nil
					}
					if entry.lastStep >= handlerStep.order || (kind != config.MySQL && kind != config.MariaDB) {
						result.status = newStatus(kind, StateIncompatible)
						return result, nil
					}
					lastVerifiedStep = handlerStep.order - 1
				}
			}
		} else if kind == config.MySQL || kind == config.MariaDB {
			if entry.lastStep == 0 && catalogMatches(actual, plan.full[previous], kind) {
				lastVerifiedStep = 0
			} else if entry.lastStep > 0 && catalogMatches(actual, plan.files[version].steps[entry.lastStep-1].after, kind) {
				lastVerifiedStep = entry.lastStep
			} else if entry.lastStep < len(plan.files[version].steps) && catalogMatches(actual, plan.files[version].steps[entry.lastStep].after, kind) {
				// For non-transactional DDL, accept exactly one unrecorded step.
				lastVerifiedStep = entry.lastStep + 1
			} else {
				result.status = newStatus(kind, StateIncompatible)
				return result, nil
			}
		} else if catalogMatches(actual, plan.full[previous], kind) {
			// PostgreSQL and SQLite roll DDL back with the version transaction.
			lastVerifiedStep = 0
		} else {
			result.status = newStatus(kind, StateIncompatible)
			return result, nil
		}
		ok, checkErr := foreignKeyCheckOK(ctx, conn, kind)
		if checkErr != nil {
			return result, migrationError(StateUnavailable, "migration_integrity_check_unavailable", checkErr)
		}
		if !ok {
			result.status = newStatus(kind, StateIncompatible)
			return result, nil
		}
		result.status = newStatus(kind, StateResumeRequired)
		result.status.CurrentVersion = previous
		result.status.LastVerifiedStep = lastVerifiedStep
		result.status.IncompleteVersion = intPointer(version)
		result.status.NextCommand = "cert-me db resume"
		result.incomplete = entryPointer(entry)
		return result, nil
	}

	if !catalogMatches(actual, plan.full[targetVersion], kind) {
		result.status = newStatus(kind, StateIncompatible)
		return result, nil
	}
	ok, checkErr := foreignKeyCheckOK(ctx, conn, kind)
	if checkErr != nil {
		return result, migrationError(StateUnavailable, "migration_integrity_check_unavailable", checkErr)
	}
	if !ok {
		result.status = newStatus(kind, StateIncompatible)
		return result, nil
	}
	ready, err := dataHandlerSatisfied(ctx, conn, kind, auditScopeBackfillHandlerID)
	if err != nil {
		return result, migrationError(StateUnavailable, "migration_handler_unavailable", err)
	}
	if !ready {
		result.status = newStatus(kind, StateIncompatible)
		return result, nil
	}
	result.status = newStatus(kind, StateCurrent)
	result.status.CurrentVersion = targetVersion
	result.status.LastVerifiedStep = len(plan.files[targetVersion].steps)
	return result, nil
}

func dataHandlerStep(file migrationFile) (reviewedStep, bool) {
	for _, step := range file.steps {
		if step.handler != "" {
			return step, true
		}
	}
	return reviewedStep{}, false
}

func readJournal(ctx context.Context, conn catalogQueryer) ([]journalEntry, error) {
	rows, err := conn.QueryContext(ctx, `SELECT version, name, checksum, state, started_at,
		completed_at, last_step, error_code FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []journalEntry
	for rows.Next() {
		var entry journalEntry
		var version, lastStep int64
		if err := rows.Scan(&version, &entry.name, &entry.checksum, &entry.state, &entry.startedAt,
			&entry.completedAt, &lastStep, &entry.errorCode); err != nil {
			return nil, err
		}
		if version < -1<<31 || version > 1<<31-1 || lastStep < -1<<31 || lastStep > 1<<31-1 {
			return nil, errors.New("journal integer is outside supported range")
		}
		entry.version, entry.lastStep = int(version), int(lastStep)
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].version < entries[j].version })
	return entries, nil
}

func validEntryState(entry journalEntry) bool {
	if entry.name == "" || entry.startedAt <= 0 {
		return false
	}
	switch entry.state {
	case "applied":
		return entry.completedAt.Valid && entry.completedAt.Int64 >= entry.startedAt && !entry.errorCode.Valid
	case "applying":
		return !entry.completedAt.Valid && !entry.errorCode.Valid
	case "failed":
		return !entry.completedAt.Valid && entry.errorCode.Valid && entry.errorCode.String != ""
	default:
		return false
	}
}

func entryPointer(entry journalEntry) *journalEntry { return &entry }
