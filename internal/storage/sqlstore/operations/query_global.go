package operations

import (
	"context"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/workflow"
)

func (r *QueryRepository) ListImports(ctx context.Context, query contract.ImportListQuery, scope port.QueryScope) (contract.Page[port.ImportBatch], error) {
	if err := checkContext(ctx); err != nil {
		return contract.Page[port.ImportBatch]{}, err
	}
	if err := query.Validate(); err != nil {
		return contract.Page[port.ImportBatch]{}, failed("validate import list", err)
	}
	if !r.visible(scope) {
		return contract.Page[port.ImportBatch]{Items: []port.ImportBatch{}}, nil
	}
	b := r.builder()
	conditions := []string{"1 = 1"}
	limit, tail := addPageClause(b, &conditions, "id", query.Page)
	ids, next, err := r.selectIDs(ctx, "SELECT id FROM import_batches WHERE "+joinConditions(conditions)+tail, b.Args(), limit)
	if err != nil {
		return contract.Page[port.ImportBatch]{}, err
	}
	repos, err := workflow.New(r.executor, r.dialect)
	if err != nil {
		return contract.Page[port.ImportBatch]{}, failed("construct import reader", err)
	}
	items := make([]port.ImportBatch, 0, len(ids))
	for _, raw := range ids {
		id, e := domain.ParseImportBatchID(raw)
		if e != nil {
			return contract.Page[port.ImportBatch]{}, failed("decode import id", e)
		}
		item, e := repos.Imports.GetBatch(ctx, id)
		if e != nil {
			return contract.Page[port.ImportBatch]{}, failed("read import batch", e)
		}
		items = append(items, item)
	}
	return pageResult(items, next), nil
}

func (r *QueryRepository) GetImport(ctx context.Context, id domain.ImportBatchID, scope port.QueryScope) (port.ImportBatch, error) {
	if err := checkContext(ctx); err != nil {
		return port.ImportBatch{}, err
	}
	if !r.visible(scope) {
		return port.ImportBatch{}, port.ErrNotFound
	}
	repos, err := workflow.New(r.executor, r.dialect)
	if err != nil {
		return port.ImportBatch{}, failed("construct import reader", err)
	}
	item, err := repos.Imports.GetBatch(ctx, id)
	if err != nil {
		return port.ImportBatch{}, failed("read import batch", err)
	}
	return item, nil
}

func (r *QueryRepository) ListJobs(ctx context.Context, query contract.JobListQuery, scope port.QueryScope) (contract.Page[port.Job], error) {
	if err := checkContext(ctx); err != nil {
		return contract.Page[port.Job]{}, err
	}
	if err := query.Validate(); err != nil {
		return contract.Page[port.Job]{}, failed("validate job list", err)
	}
	if !r.visible(scope) {
		return contract.Page[port.Job]{Items: []port.Job{}}, nil
	}
	b := r.builder()
	conditions := []string{"1 = 1"}
	limit, tail := addPageClause(b, &conditions, "id", query.Page)
	ids, next, err := r.selectIDs(ctx, "SELECT id FROM jobs WHERE "+joinConditions(conditions)+tail, b.Args(), limit)
	if err != nil {
		return contract.Page[port.Job]{}, err
	}
	items := make([]port.Job, 0, len(ids))
	for _, raw := range ids {
		id, e := domain.ParseJobID(raw)
		if e != nil {
			return contract.Page[port.Job]{}, failed("decode job id", e)
		}
		b := r.builder()
		query := "SELECT id,created_at,updated_at,version,kind,dedup_key,payload_version,payload_json,state,available_at,lease_until,attempt_count,last_error_code FROM jobs WHERE id = " + b.Add(string(id))
		item, e := scanJob(r.queryRow(ctx, query, b.Args()...))
		if e != nil {
			return contract.Page[port.Job]{}, failed("read job", e)
		}
		items = append(items, item)
	}
	return pageResult(items, next), nil
}

func (r *QueryRepository) GetJob(ctx context.Context, id domain.JobID, scope port.QueryScope) (port.Job, error) {
	if err := checkContext(ctx); err != nil {
		return port.Job{}, err
	}
	if !r.visible(scope) {
		return port.Job{}, port.ErrNotFound
	}
	b := r.builder()
	query := "SELECT id,created_at,updated_at,version,kind,dedup_key,payload_version,payload_json,state,available_at,lease_until,attempt_count,last_error_code FROM jobs WHERE id = " + b.Add(string(id))
	job, err := scanJob(r.queryRow(ctx, query, b.Args()...))
	if err != nil {
		return port.Job{}, failed("read job", err)
	}
	return job, nil
}
