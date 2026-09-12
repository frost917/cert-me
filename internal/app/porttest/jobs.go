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

// UpsertDemand merges a new demand into whatever job row already holds the
// same dedup key, pending or running, rather than queueing a second one.
// docs/data-model.md:151 declares dedup_key UNIQUE across the whole jobs
// table (not just among pending rows), so a real insert for a second row
// sharing dedup_key with a running job would fail the constraint outright;
// this double must reject that shape too, by never creating a second row
// for a key that already has one in any state.
//
// A running row's lease is left untouched by the merge -- the merge only
// updates the demand fields (Kind/PayloadVersion/Payload) and bumps
// Version, it does not touch State/LeaseUntil/AttemptCount. Whether the
// newer generation must survive as a fresh pending job once the running
// attempt completes is the completing worker's decision, made by
// re-reading this row and comparing the generation it processed against
// what it finds (docs/data-model.md:159: "완료 시 처리한 generation보다 새
// 요구가 있으면 pending으로 남긴다") -- UpsertDemand's only job is to make
// sure that newer generation is durably recorded on the one row for this
// key, never dropped and never split into a second row.
//
// Every merge bumps Version, including the already-existing pending-merge
// path: without that, a worker that read the row before this merge landed
// could Save with the pre-merge version and silently overwrite the newer
// demand instead of losing the optimistic lock.
func (r jobRepo) UpsertDemand(_ context.Context, dedupKey, kind string, payloadVersion int, payload []byte) error {
	if id, ok := r.s.jobByDedup[dedupKey]; ok {
		existing := r.s.jobs[id]
		existing.Kind = kind
		existing.PayloadVersion = payloadVersion
		existing.Payload = cloneBytes(payload)
		// A finished row must go back to pending. Merging a new demand into a
		// succeeded/failed row and leaving its state alone would mean CRL
		// publication never runs again after its first success, because the
		// row stays terminal and ClaimDue only considers pending and running
		// rows (docs/data-model.md:159 "작업 완료 시 같은 dedup_key에 새 작업
		// 요구가 들어왔는지 generation/version을 검사하고 그 요구까지 삭제하지
		// 않는다").
		//
		// The previous run's lease and retry backoff are cleared with it: the
		// demand is new work, not a continuation of the finished attempt, so
		// an AvailableAt left over from the old run's backoff must not delay
		// it and the old attempt count must not push it toward a retry limit.
		// A running row is deliberately left alone -- its lease still belongs
		// to a live worker, which re-reads the row on completion.
		if existing.State == contract.JobStateSucceeded || existing.State == contract.JobStateFailed {
			existing.State = contract.JobStatePending
			existing.LeaseUntil = domain.Instant{}
			existing.AvailableAt = domain.Instant{}
			existing.AttemptCount = 0
			existing.LastErrorCode = ""
		}
		existing.Version = existing.Version.Next()
		r.s.jobs[id] = existing
		return nil
	}
	// jobs.id is a uuid in the real schema, and contract commands that carry
	// a job id validate it as one, so the double must mint the same shape --
	// a counter-based "dedupkey:3" would make a service that round-trips a
	// job id through a command untestable here for the wrong reason.
	id := domain.JobID(syntheticUUID(len(r.s.jobs) + 1))
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
//
// A row is due under one of two separate conditions depending on its
// current state, per this method's own doc comment on
// port.JobRepository.ClaimDue ("A job whose lease has already expired is
// due again for claiming, which is how a crashed worker's job gets picked
// up after restart"): a pending row is due once its AvailableAt has passed,
// a running row is due once its LeaseUntil has passed. Expiry is `now >= t`
// project-wide (domain.Instant.IsExpiredAt), so a running row is only
// reclaimed once its lease has actually lapsed, never while it is still
// live.
func (r jobRepo) ClaimDue(_ context.Context, now, leaseUntil domain.Instant, limit int) ([]port.Job, error) {
	due := make([]port.Job, 0)
	for _, job := range r.s.jobs {
		switch job.State {
		case contract.JobStatePending:
			if !job.AvailableAt.IsZero() && !job.AvailableAt.IsExpiredAt(now) {
				continue
			}
		case contract.JobStateRunning:
			if !job.LeaseUntil.IsExpiredAt(now) {
				continue
			}
		default:
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

// syntheticUUID builds a deterministic, validly-shaped uuid from a counter,
// so stored job ids are reproducible across a test run while still passing
// the uuid validation a contract command applies to them.
func syntheticUUID(n int) string {
	const hex = "0123456789abcdef"
	var buf [32]byte
	for i := 31; i >= 0; i-- {
		buf[i] = hex[n&0xf]
		n >>= 4
	}
	// version 4, variant 10xx: the shape domain.Parse*ID enforces.
	buf[12] = '4'
	buf[16] = '8'
	return string(buf[0:8]) + "-" + string(buf[8:12]) + "-" + string(buf[12:16]) + "-" + string(buf[16:20]) + "-" + string(buf[20:32])
}

// GetByDedupKey returns the job row holding dedupKey's work.
func (r jobRepo) GetByDedupKey(_ context.Context, dedupKey string) (port.Job, error) {
	id, ok := r.s.jobByDedup[dedupKey]
	if !ok {
		return port.Job{}, port.ErrNotFound
	}
	job, ok := r.s.jobs[id]
	if !ok {
		return port.Job{}, port.ErrNotFound
	}
	return cloneJob(job), nil
}
