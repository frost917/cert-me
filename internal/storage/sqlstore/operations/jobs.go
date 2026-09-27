package operations

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

// JobRepository is bound to one UnitOfWork executor.
type JobRepository struct {
	executor coreExecutor
	dialect  sqlDialect
}

// The aliases keep the implementation declarations in this file readable;
// their concrete types are the shared SQL executor and dialect.
type coreExecutor = core.SQLExecutor
type sqlDialect = dialect.Dialect

var _ port.JobRepository = (*JobRepository)(nil)

func (r *JobRepository) UpsertDemand(ctx context.Context, dedupKey, kind string, payloadVersion int, payload []byte) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if dedupKey == "" || len(dedupKey) > 128 || kind == "" || len(kind) > 32 || payloadVersion < 0 {
		return failed("validate job demand", domain.ErrInvalidValue)
	}
	// The transaction caller serializes SQLite writes; the unique dedup key
	// serializes the first insertion for all other dialects. Existing rows are
	// locked before applying the merge, so running leases are never stolen.
	b := r.builder()
	query := "SELECT id, created_at, updated_at, version, kind, dedup_key, payload_version, payload_json, state, available_at, lease_until, attempt_count, last_error_code FROM jobs WHERE dedup_key = " + b.Add(dedupKey) + r.dialect.RowLockClause()
	job, err := scanJob(r.queryRow(ctx, query, b.Args()...))
	if err == nil {
		job.Kind = kind
		job.PayloadVersion = payloadVersion
		job.Payload = cloneBytes(payload)
		if job.State == contract.JobStateSucceeded || job.State == contract.JobStateFailed {
			job.State = contract.JobStatePending
			job.LeaseUntil = domain.Instant{}
			job.AvailableAt = domain.Instant{}
			job.AttemptCount = 0
			job.LastErrorCode = ""
		}
		job.Version = job.Version.Next()
		return r.save(ctx, job, job.Version-1)
	}
	if err != port.ErrNotFound {
		return failed("read job demand", err)
	}
	id, err := newUUID()
	if err != nil {
		return failed("generate job id", err)
	}
	b = r.builder()
	query = "INSERT INTO jobs (id, created_at, updated_at, version, kind, dedup_key, payload_version, payload_json, state, available_at, lease_until, attempt_count, last_error_code) VALUES (" +
		b.Add(id) + "," + databaseNowMicros(r.dialect) + "," + databaseNowMicros(r.dialect) + "," + b.Add(int64(0)) + "," +
		b.Add(kind) + "," + b.Add(dedupKey) + "," + b.Add(payloadVersion) + "," + b.Add(string(payload)) + "," +
		b.Add(string(contract.JobStatePending)) + "," + b.Add(int64(0)) + ",NULL," + b.Add(int64(0)) + ",NULL)"
	_, err = r.executor.ExecContext(ctx, query, b.Args()...)
	return duplicateOrFailed("insert job demand", err)
}

func (r *JobRepository) GetByDedupKey(ctx context.Context, dedupKey string) (port.Job, error) {
	if err := checkContext(ctx); err != nil {
		return port.Job{}, err
	}
	b := r.builder()
	query := "SELECT id, created_at, updated_at, version, kind, dedup_key, payload_version, payload_json, state, available_at, lease_until, attempt_count, last_error_code FROM jobs WHERE dedup_key = " + b.Add(dedupKey)
	job, err := scanJob(r.queryRow(ctx, query, b.Args()...))
	if err != nil {
		return port.Job{}, failed("read job by dedup key", err)
	}
	return job, nil
}

func (r *JobRepository) ClaimDue(ctx context.Context, now, leaseUntil domain.Instant, limit int) ([]port.Job, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if now.IsZero() || leaseUntil.IsZero() || limit <= 0 {
		return nil, failed("validate job claim", domain.ErrInvalidValue)
	}
	b := r.builder()
	query := "SELECT id, created_at, updated_at, version, kind, dedup_key, payload_version, payload_json, state, available_at, lease_until, attempt_count, last_error_code FROM jobs WHERE (state = 'pending' AND available_at <= " + b.Add(now.UnixMicro()) + ") OR (state = 'running' AND lease_until IS NOT NULL AND lease_until <= " + b.Add(now.UnixMicro()) + ") ORDER BY available_at, id LIMIT " + b.Add(limit) + r.dialect.RowLockClause()
	rows, err := r.executor.QueryContext(ctx, query, b.Args()...)
	if err != nil {
		return nil, failed("select due jobs", err)
	}
	due := make([]port.Job, 0, limit)
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			_ = rows.Close()
			return nil, failed("decode due job", err)
		}
		due = append(due, job)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, failed("iterate due jobs", err)
	}
	if err := rows.Close(); err != nil {
		return nil, failed("close due jobs", err)
	}
	claimed := make([]port.Job, 0, len(due))
	for _, job := range due {
		job.State = contract.JobStateRunning
		job.LeaseUntil = leaseUntil
		job.AttemptCount++
		job.Version = job.Version.Next()
		if err := r.save(ctx, job, job.Version-1); err != nil {
			return nil, failed("claim due job", err)
		}
		claimed = append(claimed, cloneJob(job))
	}
	return claimed, nil
}

func (r *JobRepository) Save(ctx context.Context, job port.Job, expectedVersion domain.Version) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	return r.save(ctx, job, expectedVersion)
}

func (r *JobRepository) save(ctx context.Context, job port.Job, expectedVersion domain.Version) error {
	if _, err := domain.ParseJobID(string(job.ID)); err != nil {
		return failed("validate job id", err)
	}
	if job.Kind == "" || job.DedupKey == "" || job.PayloadVersion < 0 || job.AttemptCount < 0 || job.Version < 0 || expectedVersion < 0 {
		return failed("validate job", domain.ErrInvalidValue)
	}
	switch job.State {
	case contract.JobStatePending, contract.JobStateRunning, contract.JobStateSucceeded, contract.JobStateFailed:
	default:
		return failed("validate job state", domain.ErrInvalidValue)
	}
	b := r.builder()
	query := "UPDATE jobs SET updated_at = " + databaseNowMicros(r.dialect) + ", version = " + b.Add(job.Version.Int64()) +
		", kind = " + b.Add(job.Kind) + ", dedup_key = " + b.Add(job.DedupKey) + ", payload_version = " + b.Add(job.PayloadVersion) +
		", payload_json = " + b.Add(string(job.Payload)) + ", state = " + b.Add(string(job.State)) + ", available_at = " + b.Add(job.AvailableAt.UnixMicro()) +
		", lease_until = " + b.Add(nullableTime(job.LeaseUntil.UnixMicro())) + ", attempt_count = " + b.Add(job.AttemptCount) +
		", last_error_code = " + b.Add(job.LastErrorCode) + " WHERE id = " + b.Add(string(job.ID)) + " AND version = " + b.Add(expectedVersion.Int64())
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return duplicateOrFailed("save job", err)
	}
	n, err := rowsAffected(result, nil)
	if err != nil {
		return failed("save job rows affected", err)
	}
	if n != 0 {
		return nil
	}
	return r.versionMiss(ctx, job.ID, expectedVersion)
}

func (r *JobRepository) versionMiss(ctx context.Context, id domain.JobID, expected domain.Version) error {
	b := r.builder()
	var version int64
	err := r.queryRow(ctx, "SELECT version FROM jobs WHERE id = "+b.Add(string(id)), b.Args()...).Scan(&version)
	if err != nil {
		return missing(err)
	}
	if domain.Version(version) != expected {
		return port.ErrVersionConflict
	}
	return nil
}

func (r *JobRepository) GetForUpdate(ctx context.Context, jobID domain.JobID) (port.Job, error) {
	if err := checkContext(ctx); err != nil {
		return port.Job{}, err
	}
	b := r.builder()
	query := "SELECT id, created_at, updated_at, version, kind, dedup_key, payload_version, payload_json, state, available_at, lease_until, attempt_count, last_error_code FROM jobs WHERE id = " + b.Add(string(jobID)) + r.dialect.RowLockClause()
	job, err := scanJob(r.queryRow(ctx, query, b.Args()...))
	if err != nil {
		return port.Job{}, failed("read job for update", err)
	}
	return job, nil
}

func (r *JobRepository) ListRecoveryRequired(ctx context.Context) ([]port.Job, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	rows, err := r.executor.QueryContext(ctx, "SELECT id, created_at, updated_at, version, kind, dedup_key, payload_version, payload_json, state, available_at, lease_until, attempt_count, last_error_code FROM jobs WHERE state = 'running' ORDER BY id")
	if err != nil {
		return nil, failed("list recovery jobs", err)
	}
	defer rows.Close()
	jobs := make([]port.Job, 0)
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, failed("decode recovery job", err)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, failed("iterate recovery jobs", err)
	}
	return jobs, nil
}

func scanJob(row rowScanner) (port.Job, error) {
	var rawID, kind, dedup, payload, state string
	var version, payloadVersion, available, attempts int64
	var created, updated int64
	var lease sql.NullInt64
	var lastErr sql.NullString
	if err := row.Scan(&rawID, &created, &updated, &version, &kind, &dedup, &payloadVersion, &payload, &state, &available, &lease, &attempts, &lastErr); err != nil {
		return port.Job{}, missing(err)
	}
	id, err := domain.ParseJobID(rawID)
	if err != nil {
		return port.Job{}, fmt.Errorf("invalid job id in database: %w", err)
	}
	if version < 0 || payloadVersion < 0 || payloadVersion > int64(^uint(0)>>1) || attempts < 0 {
		return port.Job{}, fmt.Errorf("invalid job counters in database")
	}
	job := port.Job{ID: id, Kind: kind, DedupKey: dedup, PayloadVersion: int(payloadVersion), Payload: []byte(payload), State: contract.JobState(state), AvailableAt: domain.InstantFromUnixMicro(available), AttemptCount: attempts, Version: domain.Version(version)}
	if lease.Valid {
		job.LeaseUntil = domain.InstantFromUnixMicro(lease.Int64)
	}
	if lastErr.Valid {
		job.LastErrorCode = lastErr.String
	}
	if job.Kind == "" || job.DedupKey == "" {
		return port.Job{}, fmt.Errorf("invalid job fields in database")
	}
	switch job.State {
	case contract.JobStatePending, contract.JobStateRunning, contract.JobStateSucceeded, contract.JobStateFailed:
	default:
		return port.Job{}, fmt.Errorf("invalid job state in database")
	}
	return job, nil
}

func cloneJob(job port.Job) port.Job {
	job.Payload = cloneBytes(job.Payload)
	return job
}

func newUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}
