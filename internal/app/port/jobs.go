package port

import (
	"context"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

// Job is the port-level projection of one jobs row: the persistent
// work-queue entry for CRL publication, delivery-expiry sweeps, audit
// pruning and recovery work (docs/data-model.md "내부 HTTPS·유지보수·작업·
// 감사"). It reuses contract.JobState rather than declaring a second state
// enum, since contract.JobView (the read-side projection of the same row)
// already names the fixed set of states and port is allowed to depend on
// contract.
type Job struct {
	ID             domain.JobID
	Kind           string
	DedupKey       string
	PayloadVersion int
	Payload        []byte
	State          contract.JobState
	AvailableAt    domain.Instant
	LeaseUntil     domain.Instant
	AttemptCount   int64
	LastErrorCode  string
	Version        domain.Version
}

// JobRepository is the storage boundary for the persistent job queue
// (docs/backend-implementation.md §4 table row "JobRepository";
// docs/data-model.md "jobs"). Jobs are at-least-once and per-kind
// idempotent (docs/data-model.md "jobs는 최소 한 번 실행을 전제로 하고 업무별
// 멱등성을 갖는다"): the worker, not this interface, is responsible for
// making a re-run of the same job safe.
type JobRepository interface {
	// UpsertDemand records that kind's work is needed for dedupKey, merging
	// into the EXISTING row for that key whatever its state rather than
	// creating a duplicate (docs/backend-implementation.md §5 "CRL은 CA 키별
	// dedup_key로 요구 generation을 병합한다"; docs/data-model.md declares
	// jobs.dedup_key unique across the whole table, not only among pending
	// rows). A caller passing a payload is expected to have already decided
	// the merged payload; this method does not itself compare generations.
	//
	// What the merge does to the row's state depends on where that row is:
	//   - A finished row (succeeded or failed) goes back to pending, and the
	//     finished run's lease, retry backoff, attempt count and error code
	//     are cleared with it. The demand is new work, not a continuation, so
	//     the previous run's backoff must not delay it. Without this, CRL
	//     publication would never run again after its first success, because
	//     ClaimDue only considers pending and running rows
	//     (docs/data-model.md "작업 완료 시 같은 dedup_key에 새 작업 요구가
	//     들어왔는지 generation/version을 검사하고 그 요구까지 삭제하지 않는다").
	//   - A running row is left alone: its lease belongs to a live worker,
	//     which re-reads the row on completion and leaves it pending if a
	//     newer demand arrived while it was working.
	// Either way the row's version advances, so a Save carrying a version
	// read before the merge loses rather than erasing the new demand.
	UpsertDemand(ctx context.Context, dedupKey, kind string, payloadVersion int, payload []byte) error

	// GetByDedupKey returns the single job row holding dedupKey's work, or
	// ErrNotFound when no demand has ever been recorded under it.
	//
	// UpsertDemand deliberately returns only an error: merging a demand is
	// the whole of its contract and every existing caller wants nothing
	// back. A caller that must NAME the resulting job -- CRLService.
	// RequestPublication, whose JobAccepted result is a job id -- reads it
	// back through this method instead, rather than UpsertDemand growing a
	// return value that four other call sites would have to ignore.
	//
	// Added in B04 under §13's rule that a consuming service gets the typed
	// port it needs.
	GetByDedupKey(ctx context.Context, dedupKey string) (Job, error)

	// ClaimDue selects up to limit jobs available at or before now, sets
	// their lease_until to leaseUntil and returns them. A job whose lease
	// has already expired is due again for claiming, which is how a crashed
	// worker's job gets picked up after restart
	// (docs/data-model.md "실행 임대 만료는 재시도 근거이며 개인키 수령
	// 권한을 복원하는 근거가 아니다").
	ClaimDue(ctx context.Context, now, leaseUntil domain.Instant, limit int) ([]Job, error)

	// Save persists job under the standard optimistic-lock contract (see
	// AccountRepository.SaveAccount). A long-running job extends its own
	// lease by re-saving with an advanced LeaseUntil
	// (docs/backend-implementation.md §9 "장기 작업은 1분마다 version 확인
	// 후 lease를 연장한다").
	Save(ctx context.Context, job Job, expectedVersion domain.Version) error

	// GetForUpdate locks and returns one job row by id.
	GetForUpdate(ctx context.Context, jobID domain.JobID) (Job, error)

	// ListRecoveryRequired returns jobs a restart must resolve before
	// resuming normal admission -- leftover leases from a process that
	// exited without releasing them, and any recovery-kind work
	// maintenance_crl_requirements left outstanding.
	//
	// It deliberately does NOT apply ClaimDue's expiry test. This runs on the
	// single-instance restart's exclusive recovery path, where every running
	// row was left by the previous process, so a lease whose time is still in
	// the future is a recovery target too -- that future time is precisely the
	// evidence the old process died mid-lease
	// (docs/backend-implementation.md §13). ClaimDue's `now >= lease_until`
	// test is the ordinary worker's rule and stays separate. This must not be
	// used as a path that steals work from another live process.
	ListRecoveryRequired(ctx context.Context) ([]Job, error)
}
