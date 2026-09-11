package porttest

import (
	"context"
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
)

// TestUpsertDemand_MergesIntoRunningRowInsteadOfSpawningSecond is J1's
// reproduction. docs/data-model.md:151 declares dedup_key UNIQUE across the
// *whole* jobs table, not just among pending rows, so a real Postgres
// insert for a second row sharing dedup_key with a running job would fail
// the constraint. UpsertDemand must instead merge into whatever row already
// holds that key -- pending or running -- leaving the lease on a running row
// untouched (docs/data-model.md:159: a completing worker, not UpsertDemand,
// decides whether the merged generation must survive as a fresh pending
// row).
func TestUpsertDemand_MergesIntoRunningRowInsteadOfSpawningSecond(t *testing.T) {
	repo := jobRepo{s: newState()}
	ctx := context.Background()

	if err := repo.UpsertDemand(ctx, "dedup-1", "crl", 1, []byte("gen1")); err != nil {
		t.Fatalf("UpsertDemand #1: %v", err)
	}
	claimed, err := repo.ClaimDue(ctx, instant(10), instant(100), 10)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("expected to claim 1 job, got %d", len(claimed))
	}
	running := claimed[0]
	if running.State != contract.JobStateRunning {
		t.Fatalf("expected claimed job running, got %v", running.State)
	}

	// A fresh demand for the same key arrives while the first is running.
	if err := repo.UpsertDemand(ctx, "dedup-1", "crl", 1, []byte("gen2")); err != nil {
		t.Fatalf("UpsertDemand #2: %v", err)
	}

	// There must be exactly one row for this dedup key: a second row would
	// violate the whole-table UNIQUE(dedup_key) the real schema enforces.
	var rowsForKey int
	for _, job := range repo.s.jobs {
		if job.DedupKey == "dedup-1" {
			rowsForKey++
		}
	}
	if rowsForKey != 1 {
		t.Fatalf("expected exactly 1 row for dedup key, got %d", rowsForKey)
	}

	merged := repo.s.jobs[running.ID]
	if merged.State != contract.JobStateRunning {
		t.Fatalf("merge must not disturb the running lease, got state %v", merged.State)
	}
	if merged.LeaseUntil != running.LeaseUntil {
		t.Fatalf("merge must not touch the running row's lease")
	}
	if merged.Version == running.Version {
		t.Fatalf("merge must bump the version so a stale Save loses, got unchanged version %v", merged.Version)
	}
	if string(merged.Payload) != "gen2" {
		t.Fatalf("merge must carry the latest demand's payload, got %q", merged.Payload)
	}

	// The completing worker re-reads the row after its own long-running
	// work and must see the newer generation merged in, so it knows to
	// leave a fresh pending job for it rather than deleting the demand
	// (docs/data-model.md:159).
	reread, err := repo.GetForUpdate(ctx, running.ID)
	if err != nil {
		t.Fatalf("GetForUpdate: %v", err)
	}
	if string(reread.Payload) != "gen2" {
		t.Fatalf("worker must observe the merged demand on re-read, got %q", reread.Payload)
	}
}

// TestUpsertDemand_PendingOverwriteAlsoBumpsVersion is the narrower part of
// J1: even the already-correct pending-merge branch must bump Version, or a
// worker's stale Save (taken before the merge landed) can silently clobber
// the newer demand instead of hitting ErrVersionConflict.
func TestUpsertDemand_PendingOverwriteAlsoBumpsVersion(t *testing.T) {
	repo := jobRepo{s: newState()}
	ctx := context.Background()

	if err := repo.UpsertDemand(ctx, "dedup-2", "crl", 1, []byte("gen1")); err != nil {
		t.Fatalf("UpsertDemand #1: %v", err)
	}
	before, err := repo.GetForUpdate(ctx, repo.s.jobByDedup["dedup-2"])
	if err != nil {
		t.Fatalf("GetForUpdate: %v", err)
	}

	if err := repo.UpsertDemand(ctx, "dedup-2", "crl", 1, []byte("gen2")); err != nil {
		t.Fatalf("UpsertDemand #2: %v", err)
	}
	after, err := repo.GetForUpdate(ctx, repo.s.jobByDedup["dedup-2"])
	if err != nil {
		t.Fatalf("GetForUpdate: %v", err)
	}

	if after.Version == before.Version {
		t.Fatalf("pending overwrite must bump version, still %v", before.Version)
	}

	// A worker holding the pre-merge version must now lose the optimistic
	// lock instead of overwriting gen2 with a stale save.
	stale := before
	stale.State = contract.JobStateRunning
	err = repo.Save(ctx, stale, before.Version)
	if err == nil {
		t.Fatalf("stale Save at old version must not succeed after the merge bumped version")
	}
	if err != ErrVersionConflict {
		t.Fatalf("expected ErrVersionConflict, got %v", err)
	}
}

// TestClaimDue_ReclaimsExpiredLease is J2's reproduction: a running job
// whose lease has expired must be claimable again, exactly as
// port.JobRepository.ClaimDue's own doc comment promises ("A job whose
// lease has already expired is due again for claiming, which is how a
// crashed worker's job gets picked up after restart",
// docs/data-model.md "실행 임대 만료는 재시도 근거").
func TestClaimDue_ReclaimsExpiredLease(t *testing.T) {
	repo := jobRepo{s: newState()}
	ctx := context.Background()

	if err := repo.UpsertDemand(ctx, "dedup-3", "crl", 1, []byte("payload")); err != nil {
		t.Fatalf("UpsertDemand: %v", err)
	}

	claimed, err := repo.ClaimDue(ctx, instant(100), instant(200), 10)
	if err != nil {
		t.Fatalf("first ClaimDue: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("expected to claim 1 job, got %d", len(claimed))
	}
	first := claimed[0]
	if first.AttemptCount != 1 {
		t.Fatalf("expected attempt count 1 after first claim, got %d", first.AttemptCount)
	}

	// Before the lease expires (now=199 < leaseUntil=200), the running job
	// must NOT be claimable.
	stillRunning, err := repo.ClaimDue(ctx, instant(199), instant(300), 10)
	if err != nil {
		t.Fatalf("ClaimDue before expiry: %v", err)
	}
	if len(stillRunning) != 0 {
		t.Fatalf("job must not be reclaimable before its lease expires, got %d claimed", len(stillRunning))
	}

	// now=201 >= leaseUntil=200: the crashed worker's job is due again.
	reclaimed, err := repo.ClaimDue(ctx, instant(201), instant(300), 10)
	if err != nil {
		t.Fatalf("ClaimDue after expiry: %v", err)
	}
	if len(reclaimed) != 1 {
		t.Fatalf("expected the expired-lease job to be reclaimable, got %d claimed", len(reclaimed))
	}
	second := reclaimed[0]
	if second.AttemptCount != 2 {
		t.Fatalf("expected attempt count to advance to 2, got %d", second.AttemptCount)
	}
	if second.Version == first.Version {
		t.Fatalf("expected version to advance on reclaim, still %v", first.Version)
	}
	if second.LeaseUntil != instant(300) {
		t.Fatalf("expected the new lease to be stamped, got %v", second.LeaseUntil)
	}
}

// A finished job must go back to pending when a new demand arrives under the
// same dedup key. Without this, CRL publication stops permanently after its
// first success: the row stays terminal and ClaimDue only considers pending
// and running rows.
func TestUpsertDemand_ResumesTerminalRowsOnANewDemand(t *testing.T) {
	for _, terminal := range []contract.JobState{contract.JobStateSucceeded, contract.JobStateFailed} {
		t.Run(string(terminal), func(t *testing.T) {
			store := NewStore()
			ctx := context.Background()
			const key = "crl:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("write: %v", err)
				}
			}

			must(store.Write(ctx, func(tx port.TxStores) error {
				return tx.Jobs().UpsertDemand(ctx, key, "crl_publish", 1, []byte("{}"))
			}))
			var claimed []port.Job
			must(store.Write(ctx, func(tx port.TxStores) error {
				var err error
				claimed, err = tx.Jobs().ClaimDue(ctx, instant(100), instant(200), 10)
				return err
			}))
			if len(claimed) != 1 {
				t.Fatalf("first claim returned %d jobs, want 1", len(claimed))
			}

			// The worker finishes the run and records the terminal state.
			done := claimed[0]
			done.State = terminal
			done.LastErrorCode = "previous_run"
			done.AvailableAt = instant(9999) // a retry backoff from the old run
			must(store.Write(ctx, func(tx port.TxStores) error {
				return tx.Jobs().Save(ctx, done, done.Version)
			}))

			// A new revocation arrives under the same dedup key.
			must(store.Write(ctx, func(tx port.TxStores) error {
				return tx.Jobs().UpsertDemand(ctx, key, "crl_publish", 1, []byte(`{"gen":2}`))
			}))

			var again []port.Job
			must(store.Write(ctx, func(tx port.TxStores) error {
				var err error
				again, err = tx.Jobs().ClaimDue(ctx, instant(300), instant(400), 10)
				return err
			}))
			if len(again) != 1 {
				t.Fatalf("after a new demand on a %s job, ClaimDue returned %d jobs, want 1", terminal, len(again))
			}
			// Still one row, and the old run's backoff and error must not
			// have followed the new demand.
			if again[0].ID != done.ID {
				t.Fatalf("a second row was created: %q then %q", done.ID, again[0].ID)
			}
			if again[0].LastErrorCode != "" {
				t.Fatalf("the previous run's error code survived: %q", again[0].LastErrorCode)
			}
			if again[0].AttemptCount != 1 {
				t.Fatalf("attempt count is %d, want 1 for a fresh demand's first claim", again[0].AttemptCount)
			}
		})
	}
}

// A running row's lease belongs to a live worker and must not be disturbed by
// a new demand: only terminal rows are resumed.
func TestUpsertDemand_LeavesARunningRowsLeaseAlone(t *testing.T) {
	store := NewStore()
	ctx := context.Background()
	const key = "crl:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	must(store.Write(ctx, func(tx port.TxStores) error {
		return tx.Jobs().UpsertDemand(ctx, key, "crl_publish", 1, []byte("{}"))
	}))
	var claimed []port.Job
	must(store.Write(ctx, func(tx port.TxStores) error {
		var err error
		claimed, err = tx.Jobs().ClaimDue(ctx, instant(100), instant(200), 10)
		return err
	}))
	must(store.Write(ctx, func(tx port.TxStores) error {
		return tx.Jobs().UpsertDemand(ctx, key, "crl_publish", 1, []byte(`{"gen":2}`))
	}))

	var got port.Job
	must(store.Read(ctx, func(tx port.TxStores) error {
		var err error
		got, err = tx.Jobs().GetForUpdate(ctx, claimed[0].ID)
		return err
	}))
	if got.State != contract.JobStateRunning {
		t.Fatalf("state is %q, want the running row left alone", got.State)
	}
	if !got.LeaseUntil.Equal(instant(200)) {
		t.Fatalf("lease is %v, want the live worker's lease preserved", got.LeaseUntil)
	}
}
