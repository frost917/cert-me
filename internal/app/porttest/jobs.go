package porttest

import (
	"context"
	"sort"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type jobRepo struct{ s *state }

var _ port.JobRepository = jobRepo{}

// UpsertDemand merges a new demand into any pending job with the same dedup
// key rather than queueing a second one. CRL work is deduplicated per CA key
// this way (docs/backend-implementation.md §9: "CRL은 CA 키별 dedup_key로
// 요구 generation을 병합한다"), so a burst of revocations produces one job.
//
// A job that is already running is NOT merged into: its snapshot was taken
// before this demand existed, so the demand must survive as a fresh pending
// job (§9: "완료 시 처리한 generation보다 새 요구가 있으면 pending으로
// 남긴다"). This double models that by keying the dedup index only on
// pending rows.
func (r jobRepo) UpsertDemand(_ context.Context, dedupKey, kind string, payloadVersion int, payload []byte) error {
	if id, ok := r.s.jobByDedup[dedupKey]; ok {
		existing := r.s.jobs[id]
		if existing.State == contract.JobStatePending {
			existing.Kind = kind
			existing.PayloadVersion = payloadVersion
			existing.Payload = cloneBytes(payload)
			r.s.jobs[id] = existing
			return nil
		}
	}
	id := domain.JobID(dedupKey + ":" + itoa(len(r.s.jobs)+1))
	r.s.jobs[id] = port.Job{
		ID:             id,
		Kind:           kind,
		DedupKey:       dedupKey,
		PayloadVersion: payloadVersion,
		Payload:        cloneBytes(payload),
		State:          contract.JobStatePending,
	}
	r.s.jobByDedup[dedupKey] = id
	return nil
}

// ClaimDue takes up to limit due jobs and stamps a lease on each. The lease
// and the version are what let a second worker tell a live claim from one
// abandoned by a killed process (docs/backend-implementation.md §9).
func (r jobRepo) ClaimDue(_ context.Context, now, leaseUntil domain.Instant, limit int) ([]port.Job, error) {
	due := make([]port.Job, 0)
	for _, job := range r.s.jobs {
		if job.State != contract.JobStatePending {
			continue
		}
		if !job.AvailableAt.IsZero() && !job.AvailableAt.IsExpiredAt(now) {
			continue
		}
		due = append(due, job)
	}
	sort.Slice(due, func(i, j int) bool { return due[i].ID < due[j].ID })
	if limit > 0 && len(due) > limit {
		due = due[:limit]
	}
	claimed := make([]port.Job, 0, len(due))
	for _, job := range due {
		job.State = contract.JobStateRunning
		job.LeaseUntil = leaseUntil
		job.AttemptCount++
		job.Version = job.Version.Next()
		r.s.jobs[job.ID] = cloneJob(job)
		claimed = append(claimed, cloneJob(job))
	}
	return claimed, nil
}

func (r jobRepo) Save(_ context.Context, job port.Job, expectedVersion domain.Version) error {
	existing, ok := r.s.jobs[job.ID]
	if !ok {
		return port.ErrNotFound
	}
	if existing.Version != expectedVersion {
		return ErrVersionConflict
	}
	r.s.jobs[job.ID] = cloneJob(job)
	if job.State == contract.JobStatePending {
		r.s.jobByDedup[job.DedupKey] = job.ID
	}
	return nil
}

func (r jobRepo) GetForUpdate(_ context.Context, jobID domain.JobID) (port.Job, error) {
	job, ok := r.s.jobs[jobID]
	if !ok {
		return port.Job{}, port.ErrNotFound
	}
	return cloneJob(job), nil
}

// ListRecoveryRequired returns jobs left running by a process that died:
// their lease has expired but they were never finished.
func (r jobRepo) ListRecoveryRequired(_ context.Context) ([]port.Job, error) {
	out := make([]port.Job, 0)
	for _, job := range r.s.jobs {
		if job.State == contract.JobStateRunning {
			out = append(out, cloneJob(job))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
