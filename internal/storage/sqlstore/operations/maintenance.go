package operations

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

// MaintenanceRepository persists maintenance history and CRL blocking
// evidence in the caller's transaction.
type MaintenanceRepository struct {
	executor core.SQLExecutor
	dialect  dialect.Dialect
}

var _ port.MaintenanceRepository = (*MaintenanceRepository)(nil)

func (r *MaintenanceRepository) GetRunForUpdate(ctx context.Context, id domain.JobID) (port.MaintenanceRun, error) {
	if err := checkContext(ctx); err != nil {
		return port.MaintenanceRun{}, err
	}
	if _, err := domain.ParseJobID(string(id)); err != nil {
		return port.MaintenanceRun{}, failed("validate maintenance run id", err)
	}
	b := r.builder()
	query := "SELECT id, created_at, updated_at, version, kind, phase, details_json, started_at, completed_at, error_code FROM maintenance_runs WHERE id = " + b.Add(string(id)) + r.dialect.RowLockClause()
	run, err := scanMaintenanceRun(r.queryRow(ctx, query, b.Args()...))
	if err != nil {
		return port.MaintenanceRun{}, failed("read maintenance run for update", err)
	}
	return run, nil
}

func (r *MaintenanceRepository) InsertRun(ctx context.Context, run port.MaintenanceRun) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateMaintenanceRun(run); err != nil {
		return failed("validate maintenance run", err)
	}
	details := run.DetailsJSON
	if len(details) == 0 {
		details = []byte("null")
	}
	b := r.builder()
	query := "INSERT INTO maintenance_runs (id, created_at, updated_at, version, kind, phase, details_json, started_at, completed_at, error_code) VALUES (" +
		b.Add(string(run.ID)) + "," + b.Add(run.CreatedAt.UnixMicro()) + "," + b.Add(run.UpdatedAt.UnixMicro()) + "," + b.Add(run.Version.Int64()) + "," +
		b.Add(string(run.Kind)) + "," + b.Add(string(run.Phase)) + "," + b.Add(string(details)) + "," + b.Add(run.StartedAt.UnixMicro()) + "," +
		b.Add(nullableTime(run.CompletedAt.UnixMicro())) + "," + b.Add(nullable(run.ErrorCode)) + ")"
	_, err := r.executor.ExecContext(ctx, query, b.Args()...)
	return duplicateOrFailed("insert maintenance run", err)
}

func (r *MaintenanceRepository) SaveRun(ctx context.Context, run port.MaintenanceRun, expectedVersion domain.Version) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateMaintenanceRun(run); err != nil {
		return failed("validate maintenance run", err)
	}
	if expectedVersion < 0 {
		return failed("validate expected maintenance run version", domain.ErrInvalidValue)
	}
	details := run.DetailsJSON
	if len(details) == 0 {
		details = []byte("null")
	}
	b := r.builder()
	query := "UPDATE maintenance_runs SET updated_at = " + b.Add(run.UpdatedAt.UnixMicro()) + ", version = " + b.Add(run.Version.Int64()) +
		", kind = " + b.Add(string(run.Kind)) + ", phase = " + b.Add(string(run.Phase)) + ", details_json = " + b.Add(string(details)) +
		", started_at = " + b.Add(run.StartedAt.UnixMicro()) + ", completed_at = " + b.Add(nullableTime(run.CompletedAt.UnixMicro())) +
		", error_code = " + b.Add(nullable(run.ErrorCode)) + " WHERE id = " + b.Add(string(run.ID)) + " AND version = " + b.Add(expectedVersion.Int64())
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return duplicateOrFailed("save maintenance run", err)
	}
	n, err := rowsAffected(result, nil)
	if err != nil {
		return failed("save maintenance run rows affected", err)
	}
	if n > 0 {
		return nil
	}
	return r.resolveVersionMiss(ctx, run.ID, expectedVersion)
}

func (r *MaintenanceRepository) UpsertCRLRequirement(ctx context.Context, requirement port.MaintenanceCRLRequirement) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if _, err := domain.ParseJobID(string(requirement.MaintenanceRunID)); err != nil {
		return failed("validate maintenance requirement run id", err)
	}
	if _, err := domain.ParseCAKeyGenerationID(string(requirement.CAKeyGenerationID)); err != nil {
		return failed("validate maintenance requirement CA id", err)
	}
	if requirement.MinimumGeneration < 0 || requirement.MinimumNumber.IsZero() {
		return failed("validate maintenance requirement minimum", domain.ErrInvalidValue)
	}
	if requirement.SatisfiedCRLID != "" {
		if _, err := domain.ParseCRLDocumentID(string(requirement.SatisfiedCRLID)); err != nil {
			return failed("validate maintenance requirement CRL id", err)
		}
	}
	b := r.builder()
	var runExists bool
	if err := r.queryRow(ctx, "SELECT EXISTS (SELECT 1 FROM maintenance_runs WHERE id = "+b.Add(string(requirement.MaintenanceRunID))+")", b.Args()...).Scan(&runExists); err != nil {
		return failed("check maintenance run for CRL requirement", err)
	}
	if !runExists {
		return port.ErrNotFound
	}
	// Replacing the row rather than blindly retaining satisfied_crl_id is
	// essential: newer minimums invalidate evidence for the old requirement.
	b = r.builder()
	query := "UPDATE maintenance_crl_requirements SET minimum_generation = " + b.Add(requirement.MinimumGeneration) +
		", minimum_number_hex = " + b.Add(requirement.MinimumNumber.Hex()) + ", satisfied_crl_id = " + b.Add(nullable(string(requirement.SatisfiedCRLID))) +
		" WHERE maintenance_run_id = " + b.Add(string(requirement.MaintenanceRunID)) + " AND ca_key_generation_id = " + b.Add(string(requirement.CAKeyGenerationID))
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return duplicateOrFailed("update maintenance CRL requirement", err)
	}
	n, err := rowsAffected(result, nil)
	if err != nil {
		return failed("update maintenance CRL requirement rows affected", err)
	}
	if n > 0 {
		return nil
	}
	b = r.builder()
	var exists bool
	if err := r.queryRow(ctx, "SELECT EXISTS (SELECT 1 FROM maintenance_crl_requirements WHERE maintenance_run_id = "+b.Add(string(requirement.MaintenanceRunID))+" AND ca_key_generation_id = "+b.Add(string(requirement.CAKeyGenerationID))+")", b.Args()...).Scan(&exists); err != nil {
		return failed("check maintenance CRL requirement", err)
	}
	if exists {
		// Some drivers report zero rows for a matched no-op update.
		return nil
	}
	b = r.builder()
	query = "INSERT INTO maintenance_crl_requirements (maintenance_run_id, ca_key_generation_id, minimum_generation, minimum_number_hex, satisfied_crl_id) VALUES (" +
		b.Add(string(requirement.MaintenanceRunID)) + "," + b.Add(string(requirement.CAKeyGenerationID)) + "," + b.Add(requirement.MinimumGeneration) + "," +
		b.Add(requirement.MinimumNumber.Hex()) + "," + b.Add(nullable(string(requirement.SatisfiedCRLID))) + ")"
	_, err = r.executor.ExecContext(ctx, query, b.Args()...)
	return duplicateOrFailed("insert maintenance CRL requirement", err)
}

func (r *MaintenanceRepository) ListCRLRequirements(ctx context.Context, runID domain.JobID) ([]port.MaintenanceCRLRequirement, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if _, err := domain.ParseJobID(string(runID)); err != nil {
		return nil, failed("validate maintenance run id", err)
	}
	b := r.builder()
	var exists bool
	if err := r.queryRow(ctx, "SELECT EXISTS (SELECT 1 FROM maintenance_runs WHERE id = "+b.Add(string(runID))+")", b.Args()...).Scan(&exists); err != nil {
		return nil, failed("check maintenance run", err)
	}
	if !exists {
		return nil, port.ErrNotFound
	}
	b = r.builder()
	rows, err := r.executor.QueryContext(ctx, "SELECT maintenance_run_id, ca_key_generation_id, minimum_generation, minimum_number_hex, satisfied_crl_id FROM maintenance_crl_requirements WHERE maintenance_run_id = "+b.Add(string(runID))+" ORDER BY ca_key_generation_id", b.Args()...)
	if err != nil {
		return nil, failed("list maintenance CRL requirements", err)
	}
	defer rows.Close()
	out := make([]port.MaintenanceCRLRequirement, 0)
	for rows.Next() {
		var rawRun, rawCA, minimumHex string
		var generation int64
		var satisfied sql.NullString
		if err := rows.Scan(&rawRun, &rawCA, &generation, &minimumHex, &satisfied); err != nil {
			return nil, failed("decode maintenance CRL requirement", err)
		}
		parsedRun, err := domain.ParseJobID(rawRun)
		if err != nil {
			return nil, failed("decode maintenance CRL requirement", err)
		}
		parsedCA, err := domain.ParseCAKeyGenerationID(rawCA)
		if err != nil {
			return nil, failed("decode maintenance CRL requirement", err)
		}
		number, err := domain.ParseCRLNumber(minimumHex)
		if err != nil {
			return nil, failed("decode maintenance CRL requirement", err)
		}
		req := port.MaintenanceCRLRequirement{MaintenanceRunID: parsedRun, CAKeyGenerationID: parsedCA, MinimumGeneration: generation, MinimumNumber: number}
		if satisfied.Valid {
			req.SatisfiedCRLID, err = domain.ParseCRLDocumentID(satisfied.String)
			if err != nil {
				return nil, failed("decode maintenance CRL requirement", err)
			}
		}
		if generation < 0 || number.IsZero() {
			return nil, failed("decode maintenance CRL requirement", fmt.Errorf("invalid CRL minimum"))
		}
		out = append(out, req)
	}
	if err := rows.Err(); err != nil {
		return nil, failed("iterate maintenance CRL requirements", err)
	}
	return out, nil
}

func (r *MaintenanceRepository) resolveVersionMiss(ctx context.Context, id domain.JobID, expected domain.Version) error {
	b := r.builder()
	var current int64
	if err := r.queryRow(ctx, "SELECT version FROM maintenance_runs WHERE id = "+b.Add(string(id)), b.Args()...).Scan(&current); err != nil {
		return missing(err)
	}
	if domain.Version(current) != expected {
		return port.ErrVersionConflict
	}
	return nil
}

func validateMaintenanceRun(run port.MaintenanceRun) error {
	if _, err := domain.ParseJobID(string(run.ID)); err != nil {
		return err
	}
	if run.CreatedAt.IsZero() || run.UpdatedAt.IsZero() || run.StartedAt.IsZero() || run.Version < 0 {
		return domain.ErrInvalidValue
	}
	if err := run.Kind.Validate(); err != nil {
		return err
	}
	switch run.Phase {
	case contract.MaintenancePhaseStarted, contract.MaintenancePhaseBlocked, contract.MaintenancePhaseFinished:
	default:
		return domain.ErrInvalidValue
	}
	if len(run.ErrorCode) > 64 {
		return domain.ErrInvalidValue
	}
	if len(run.DetailsJSON) > 0 && !json.Valid(run.DetailsJSON) {
		return fmt.Errorf("maintenance details are not valid JSON")
	}
	return nil
}

func scanMaintenanceRun(row rowScanner) (port.MaintenanceRun, error) {
	var rawID, kind, phase, details string
	var created, updated, version, started int64
	var completed sql.NullInt64
	var errorCode sql.NullString
	if err := row.Scan(&rawID, &created, &updated, &version, &kind, &phase, &details, &started, &completed, &errorCode); err != nil {
		return port.MaintenanceRun{}, missing(err)
	}
	id, err := domain.ParseJobID(rawID)
	if err != nil {
		return port.MaintenanceRun{}, fmt.Errorf("invalid maintenance run id in database: %w", err)
	}
	run := port.MaintenanceRun{ID: id, CreatedAt: domain.InstantFromUnixMicro(created), UpdatedAt: domain.InstantFromUnixMicro(updated), Version: domain.Version(version), Kind: contract.MaintenanceKind(kind), Phase: contract.MaintenancePhase(phase), DetailsJSON: []byte(details), StartedAt: domain.InstantFromUnixMicro(started)}
	if completed.Valid {
		run.CompletedAt = domain.InstantFromUnixMicro(completed.Int64)
	}
	if errorCode.Valid {
		run.ErrorCode = errorCode.String
	}
	if err := validateMaintenanceRun(run); err != nil {
		return port.MaintenanceRun{}, err
	}
	return run, nil
}
