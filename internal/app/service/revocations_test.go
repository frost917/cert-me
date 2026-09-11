package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

// seqIDs is a deterministic port.IDGenerator: every call returns the next
// UUID in a fixed sequence, so an assertion can name the exact id a batch
// minted.
type seqIDs struct{ n int }

func (g *seqIDs) NewUUID() string {
	g.n++
	return fmt.Sprintf("11111111-1111-4111-8111-%012d", g.n)
}

type fixedClock struct{ now domain.Instant }

func (c fixedClock) Now() domain.Instant { return c.now }

func testNow() domain.Instant {
	return domain.NewInstant(time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC))
}

func caKeyID(t *testing.T, suffix int) domain.CAKeyGenerationID {
	t.Helper()
	id, err := domain.ParseCAKeyGenerationID(fmt.Sprintf("22222222-2222-4222-8222-%012d", suffix))
	if err != nil {
		t.Fatalf("ca key id: %v", err)
	}
	return id
}

func serial(t *testing.T, hex string) domain.SerialNumber {
	t.Helper()
	s, err := domain.ParseSerialNumber(hex)
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return s
}

func testMeta(ids port.IDGenerator) RevocationMeta {
	return RevocationMeta{
		ActorKind: contract.AuditActorAccount,
		ActorID:   "33333333-3333-4333-8333-333333333333",
		Action:    "revocation.revoke",
		Now:       testNow(),
		IDs:       ids,
	}
}

// seedCRLState creates the issuer's crl_states row, the serialization point
// applyRevocations locks.
func seedCRLState(t *testing.T, store *porttest.Store, issuer domain.CAKeyGenerationID) {
	t.Helper()
	state, err := domain.NewCRLState(domain.CRLStateFacts{
		CAKeyGenerationID: issuer,
		PublicationState:  domain.PublicationStateActive,
	})
	if err != nil {
		t.Fatalf("new crl state: %v", err)
	}
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.CRLs().SaveState(context.Background(), state, state.Version())
	}); err != nil {
		t.Fatalf("seed crl state: %v", err)
	}
}

func change(issuer domain.CAKeyGenerationID, s domain.SerialNumber, reason domain.RevocationReason) RevocationChange {
	return RevocationChange{
		IssuerID:  issuer,
		Serial:    s,
		RevokedAt: testNow(),
		Reason:    reason,
		Source:    domain.RevocationSourceManual,
	}
}

// apply runs one batch in its own committed transaction.
func apply(t *testing.T, store *porttest.Store, changes []RevocationChange, meta RevocationMeta) RevocationOutcome {
	t.Helper()
	var outcome RevocationOutcome
	err := store.Write(context.Background(), func(tx port.TxStores) error {
		var applyErr error
		outcome, applyErr = applyRevocations(context.Background(), tx, changes, meta)
		return applyErr
	})
	if err != nil {
		t.Fatalf("applyRevocations: %v", err)
	}
	return outcome
}

func storedRevocation(t *testing.T, store *porttest.Store, issuer domain.CAKeyGenerationID, s domain.SerialNumber) domain.Revocation {
	t.Helper()
	var found domain.Revocation
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		var readErr error
		found, readErr = tx.Revocations().FindForUpdate(context.Background(), issuer, s)
		return readErr
	})
	if err != nil {
		t.Fatalf("read revocation: %v", err)
	}
	return found
}

func crlState(t *testing.T, store *porttest.Store, issuer domain.CAKeyGenerationID) domain.CRLState {
	t.Helper()
	var state domain.CRLState
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		var readErr error
		state, readErr = tx.CRLs().GetStateForUpdate(context.Background(), issuer)
		return readErr
	})
	if err != nil {
		t.Fatalf("read crl state: %v", err)
	}
	return state
}

// crlDemand returns the CRL job row for issuer, or ok=false when no demand
// was recorded at all.
func crlDemand(t *testing.T, store *porttest.Store, issuer domain.CAKeyGenerationID) (port.Job, bool) {
	t.Helper()
	var jobs []port.Job
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		var readErr error
		// A far-future "now" makes every pending row due, so this sees
		// whatever demand exists regardless of backoff.
		jobs, readErr = tx.Jobs().ClaimDue(context.Background(),
			domain.NewInstant(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
			domain.NewInstant(time.Date(2030, 1, 1, 0, 5, 0, 0, time.UTC)), 100)
		return readErr
	})
	if err != nil {
		t.Fatalf("claim jobs: %v", err)
	}
	for _, job := range jobs {
		if job.DedupKey == CRLDedupKey(issuer) {
			return job, true
		}
	}
	return port.Job{}, false
}

func requiredGeneration(t *testing.T, job port.Job) int64 {
	t.Helper()
	var payload crlPublishPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		t.Fatalf("decode crl payload: %v", err)
	}
	return payload.RequiredGeneration
}

func TestApplyRevocationsInsertsBumpsGenerationAndRecordsDemand(t *testing.T) {
	store := porttest.NewStore()
	issuer := caKeyID(t, 1)
	seedCRLState(t, store, issuer)

	outcome := apply(t, store,
		[]RevocationChange{change(issuer, serial(t, "1a"), domain.RevocationReasonKeyCompromise)},
		testMeta(&seqIDs{}))

	if outcome.Changed != 1 {
		t.Fatalf("changed = %d, want 1", outcome.Changed)
	}
	if got := outcome.Generations[issuer]; got != 1 {
		t.Fatalf("generation = %d, want 1", got)
	}
	stored := storedRevocation(t, store, issuer, serial(t, "1a"))
	if stored.ChangeGeneration() != 1 {
		t.Fatalf("stored change generation = %d, want 1", stored.ChangeGeneration())
	}
	if got := crlState(t, store, issuer).RevocationGeneration(); got != 1 {
		t.Fatalf("issuer generation = %d, want 1", got)
	}
	job, ok := crlDemand(t, store, issuer)
	if !ok {
		t.Fatal("no CRL demand recorded")
	}
	if got := requiredGeneration(t, job); got != 1 {
		t.Fatalf("demand generation = %d, want 1", got)
	}
	if job.Kind != JobKindCRLPublish {
		t.Fatalf("job kind = %q, want %q", job.Kind, JobKindCRLPublish)
	}
	if len(store.AuditEvents()) != 1 {
		t.Fatalf("audit events = %d, want 1", len(store.AuditEvents()))
	}
}

// A batch whose every merge reports changed=false must leave the issuer
// generation and the CRL demand alone (§5 "batch 전체가 무변경이면 issuer
// generation과 CRL 작업 요구도 증가시키지 않는다").
func TestApplyRevocationsNoOpBatchLeavesGenerationAndDemandUntouched(t *testing.T) {
	store := porttest.NewStore()
	issuer := caKeyID(t, 1)
	seedCRLState(t, store, issuer)
	first := change(issuer, serial(t, "1a"), domain.RevocationReasonKeyCompromise)
	apply(t, store, []RevocationChange{first}, testMeta(&seqIDs{}))

	storeAuditBefore := len(store.AuditEvents())
	outcome := apply(t, store, []RevocationChange{first}, testMeta(&seqIDs{n: 100}))

	if outcome.Changed != 0 {
		t.Fatalf("changed = %d, want 0", outcome.Changed)
	}
	if len(outcome.Generations) != 0 {
		t.Fatalf("generations = %v, want empty", outcome.Generations)
	}
	if got := crlState(t, store, issuer).RevocationGeneration(); got != 1 {
		t.Fatalf("issuer generation = %d, want it to stay 1", got)
	}
	job, ok := crlDemand(t, store, issuer)
	if !ok {
		t.Fatal("first batch's demand disappeared")
	}
	if got := requiredGeneration(t, job); got != 1 {
		t.Fatalf("demand generation = %d, want it to stay 1", got)
	}
	if got := len(store.AuditEvents()); got != storeAuditBefore {
		t.Fatalf("audit events = %d, want it to stay %d", got, storeAuditBefore)
	}
}

// Several rows of one issuer share a single generation bump.
func TestApplyRevocationsSharesOneGenerationAcrossBatch(t *testing.T) {
	store := porttest.NewStore()
	issuer := caKeyID(t, 1)
	seedCRLState(t, store, issuer)

	outcome := apply(t, store, []RevocationChange{
		change(issuer, serial(t, "1a"), domain.RevocationReasonSuperseded),
		change(issuer, serial(t, "1b"), domain.RevocationReasonSuperseded),
		change(issuer, serial(t, "1c"), domain.RevocationReasonSuperseded),
	}, testMeta(&seqIDs{}))

	if outcome.Changed != 3 {
		t.Fatalf("changed = %d, want 3", outcome.Changed)
	}
	if got := crlState(t, store, issuer).RevocationGeneration(); got != 1 {
		t.Fatalf("issuer generation = %d, want one bump for the whole batch", got)
	}
	for _, hex := range []string{"1a", "1b", "1c"} {
		if got := storedRevocation(t, store, issuer, serial(t, hex)).ChangeGeneration(); got != 1 {
			t.Fatalf("serial %s generation = %d, want 1", hex, got)
		}
	}
}

// A partly-unchanged batch still bumps once, and the unchanged row keeps its
// old generation rather than being re-stamped.
func TestApplyRevocationsSkipsUnchangedRowsInsideAChangedBatch(t *testing.T) {
	store := porttest.NewStore()
	issuer := caKeyID(t, 1)
	seedCRLState(t, store, issuer)
	existing := change(issuer, serial(t, "1a"), domain.RevocationReasonSuperseded)
	apply(t, store, []RevocationChange{existing}, testMeta(&seqIDs{}))

	outcome := apply(t, store, []RevocationChange{
		existing,
		change(issuer, serial(t, "1b"), domain.RevocationReasonSuperseded),
	}, testMeta(&seqIDs{n: 100}))

	if outcome.Changed != 1 {
		t.Fatalf("changed = %d, want 1", outcome.Changed)
	}
	if got := storedRevocation(t, store, issuer, serial(t, "1a")).ChangeGeneration(); got != 1 {
		t.Fatalf("unchanged row generation = %d, want it to stay 1", got)
	}
	if got := storedRevocation(t, store, issuer, serial(t, "1b")).ChangeGeneration(); got != 2 {
		t.Fatalf("new row generation = %d, want 2", got)
	}
}

// A conflicting assertion for the same key flags review and counts as a
// change, so it is stamped and drives a new CRL demand.
func TestApplyRevocationsFlagsConflictingAssertion(t *testing.T) {
	store := porttest.NewStore()
	issuer := caKeyID(t, 1)
	seedCRLState(t, store, issuer)
	apply(t, store, []RevocationChange{change(issuer, serial(t, "1a"), domain.RevocationReasonSuperseded)}, testMeta(&seqIDs{}))

	outcome := apply(t, store,
		[]RevocationChange{change(issuer, serial(t, "1a"), domain.RevocationReasonKeyCompromise)},
		testMeta(&seqIDs{n: 100}))

	if outcome.Changed != 1 {
		t.Fatalf("changed = %d, want 1", outcome.Changed)
	}
	stored := storedRevocation(t, store, issuer, serial(t, "1a"))
	if !stored.NeedsReview() {
		t.Fatal("conflicting assertion did not flag the row for review")
	}
	if stored.ChangeGeneration() != 2 {
		t.Fatalf("generation = %d, want 2", stored.ChangeGeneration())
	}
}

// Each issuer gets its own generation, computed under its own CRLState.
func TestApplyRevocationsBumpsEachIssuerSeparately(t *testing.T) {
	store := porttest.NewStore()
	first, second := caKeyID(t, 1), caKeyID(t, 2)
	seedCRLState(t, store, first)
	seedCRLState(t, store, second)
	apply(t, store, []RevocationChange{change(second, serial(t, "1f"), domain.RevocationReasonSuperseded)}, testMeta(&seqIDs{}))

	outcome := apply(t, store, []RevocationChange{
		change(first, serial(t, "1a"), domain.RevocationReasonSuperseded),
		change(second, serial(t, "1b"), domain.RevocationReasonSuperseded),
	}, testMeta(&seqIDs{n: 100}))

	if outcome.Generations[first] != 1 {
		t.Fatalf("first issuer generation = %d, want 1", outcome.Generations[first])
	}
	if outcome.Generations[second] != 2 {
		t.Fatalf("second issuer generation = %d, want 2", outcome.Generations[second])
	}
}

// An unknown issuer is a validation failure, not a silent skip.
func TestApplyRevocationsRejectsIssuerWithoutCRLState(t *testing.T) {
	store := porttest.NewStore()
	issuer := caKeyID(t, 1)

	err := store.Write(context.Background(), func(tx port.TxStores) error {
		_, applyErr := applyRevocations(context.Background(), tx,
			[]RevocationChange{change(issuer, serial(t, "1a"), domain.RevocationReasonSuperseded)},
			testMeta(&seqIDs{}))
		return applyErr
	})

	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Kind() != contract.ErrorKindValidation {
		t.Fatalf("kind = %s, want validation", appErr.Kind())
	}
	if appErr.Code() != "revocation_issuer_unknown" {
		t.Fatalf("code = %q", appErr.Code())
	}
}

// A failure anywhere in the batch rolls the whole transaction back: no
// revocation row, no generation bump, no demand, no audit.
func TestApplyRevocationsRollsBackEverythingOnFailure(t *testing.T) {
	store := porttest.NewStore()
	good, bad := caKeyID(t, 1), caKeyID(t, 2)
	seedCRLState(t, store, good)

	err := store.Write(context.Background(), func(tx port.TxStores) error {
		_, applyErr := applyRevocations(context.Background(), tx, []RevocationChange{
			change(good, serial(t, "1a"), domain.RevocationReasonSuperseded),
			change(bad, serial(t, "1b"), domain.RevocationReasonSuperseded),
		}, testMeta(&seqIDs{}))
		return applyErr
	})
	if err == nil {
		t.Fatal("want the batch to fail on the issuer without CRL state")
	}

	if got := crlState(t, store, good).RevocationGeneration(); got != 0 {
		t.Fatalf("generation = %d, want 0 after rollback", got)
	}
	readErr := store.Read(context.Background(), func(tx port.TxStores) error {
		_, findErr := tx.Revocations().FindForUpdate(context.Background(), good, serial(t, "1a"))
		return findErr
	})
	if !errors.Is(readErr, port.ErrNotFound) {
		t.Fatalf("revocation lookup after rollback = %v, want ErrNotFound", readErr)
	}
	if _, ok := crlDemand(t, store, good); ok {
		t.Fatal("CRL demand survived the rollback")
	}
	if len(store.AuditEvents()) != 0 {
		t.Fatalf("audit events = %d, want 0 after rollback", len(store.AuditEvents()))
	}
}

// An empty batch is a no-op that does not even need meta.
func TestApplyRevocationsEmptyBatchIsANoOp(t *testing.T) {
	store := porttest.NewStore()
	outcome := apply(t, store, nil, RevocationMeta{})
	if outcome.Changed != 0 {
		t.Fatalf("changed = %d, want 0", outcome.Changed)
	}
}
