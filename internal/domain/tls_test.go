package domain

import (
	"testing"
	"time"
)

func mkTLSVersionID(t *testing.T, suffix byte) TLSVersionID {
	t.Helper()
	raw := "dddddddd-dddd-4ddd-8ddd-ddddddddddd" + string(suffix)
	id, err := ParseTLSVersionID(raw)
	if err != nil {
		t.Fatalf("parse tls version id: %v", err)
	}
	return id
}

func passingFacts() TLSValidationFacts {
	return TLSValidationFacts{
		KeyMatchesCertificate:    true,
		WithinValidityPeriod:     true,
		PurposeMatchesServerAuth: true,
		ServiceAddressMatches:    true,
		ChainVerified:            true,
	}
}

// planning.md: a candidate that fails validation must not change the active
// version - Commit refuses an unvalidated/failed candidate outright.
func TestTLSChange_FailedValidationBlocksCommit(t *testing.T) {
	c, err := NewCandidateTLSChange(mkTLSVersionID(t, '1'), mkTLSVersionID(t, '2'))
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}

	failing := passingFacts()
	failing.KeyMatchesCertificate = false
	afterValidate, err := c.ValidateCandidate(failing)
	if err != nil {
		t.Fatalf("expected failed validation to be a normal (non-error) result: %v", err)
	}
	if afterValidate.Validated() {
		t.Fatalf("expected candidate to remain unvalidated after failure")
	}
	if afterValidate.Phase() != TLSChangePhasePrepared {
		t.Fatalf("expected phase to remain prepared after failed validation")
	}

	if _, err := afterValidate.Commit(t0()); err == nil {
		t.Fatalf("expected commit of an unvalidated candidate to be refused")
	}
}

func TestTLSChange_ValidatedCandidateCanCommitApply(t *testing.T) {
	c, err := NewCandidateTLSChange(mkTLSVersionID(t, '1'), mkTLSVersionID(t, '2'))
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}
	validated, err := c.ValidateCandidate(passingFacts())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !validated.Validated() {
		t.Fatalf("expected candidate to be validated")
	}
	committed, err := validated.Commit(t0())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !committed.CanActivate() {
		t.Fatalf("expected committed change to be activatable")
	}
	applied, err := committed.Apply(t0())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied.IsActive() {
		t.Fatalf("expected applied change to be active")
	}
}

// backend-implementation.md §9: Apply failure must revert, never leaving
// the candidate active.
func TestTLSChange_ApplyFailureRollsBack(t *testing.T) {
	c, err := NewCandidateTLSChange(mkTLSVersionID(t, '1'), mkTLSVersionID(t, '2'))
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}
	validated, err := c.ValidateCandidate(passingFacts())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	committed, err := validated.Commit(t0())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	rolledBack, err := committed.RollbackApply("installer_bind_failed", t0())
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rolledBack.IsActive() {
		t.Fatalf("expected rolled back change to not be active")
	}
	if rolledBack.Phase() != TLSChangePhaseRolledBack {
		t.Fatalf("expected rolled_back phase")
	}
}

// A committed change whose outcome is unknown (crash mid-apply) must be
// marked recovery_required, not silently treated as applied or rolled back.
func TestTLSChange_UnclearOutcomeRequiresRecovery(t *testing.T) {
	c, err := NewCandidateTLSChange(mkTLSVersionID(t, '1'), mkTLSVersionID(t, '2'))
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}
	validated, err := c.ValidateCandidate(passingFacts())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	committed, err := validated.Commit(t0())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	recovery, err := committed.MarkRecoveryRequired("apply_result_unknown", t0())
	if err != nil {
		t.Fatalf("mark recovery required: %v", err)
	}
	if recovery.Phase() != TLSChangePhaseRecoveryRequired {
		t.Fatalf("expected recovery_required phase")
	}
	// A terminal change cannot be re-marked for recovery.
	applied, err := committed.Apply(t0())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, err := applied.MarkRecoveryRequired("late_signal", t0()); err == nil {
		t.Fatalf("expected recovery marker on a terminal (applied) change to be refused")
	}
}

func TestNewTLSVersion_ManagedRequiresCertificate(t *testing.T) {
	if _, err := NewTLSVersion(TLSVersionFacts{
		ID: mkTLSVersionID(t, '1'), Source: TLSSourceManaged,
		KeyMaterialID: mkKeyMaterialID(t), LeafDER: []byte{1, 2, 3},
		ValidatedServiceURL: "https://cert-me.internal", NotAfter: plus(t0(), 24*time.Hour),
	}); err == nil {
		t.Fatalf("expected managed tls version without certificate id to be rejected")
	}
}

// architecture.md: "부트스트랩은 임시 HTTPS 용도이며 실제 접속 DNS/IP를 수집하거나
// 인증서에 반영하는 것을 초기 구동의 조건으로 요구하지 않는다." A bootstrap snapshot
// must be constructible before any service URL has been configured.
func TestNewTLSVersion_BootstrapAllowsEmptyServiceURL(t *testing.T) {
	if _, err := NewTLSVersion(TLSVersionFacts{
		ID: mkTLSVersionID(t, '1'), Source: TLSSourceBootstrap,
		KeyMaterialID: mkKeyMaterialID(t), LeafDER: []byte{1, 2, 3},
		ValidatedServiceURL: "", NotAfter: plus(t0(), 24*time.Hour),
	}); err != nil {
		t.Fatalf("expected bootstrap tls version without a service url to be accepted: %v", err)
	}
}

// architecture.md: a bootstrap candidate has no real service address to
// check, so validation must not be blocked on ServiceAddressMatches, and the
// full prepare -> validate -> commit -> apply path must succeed for it.
func TestTLSChange_BootstrapCandidateValidatesWithoutServiceAddress(t *testing.T) {
	c, err := NewCandidateTLSChange("", mkTLSVersionID(t, '1'))
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}

	bootstrapFacts := passingFacts()
	bootstrapFacts.CandidateSource = TLSSourceBootstrap
	bootstrapFacts.ServiceAddressMatches = false

	validated, err := c.ValidateCandidate(bootstrapFacts)
	if err != nil {
		t.Fatalf("expected bootstrap candidate without a service address to validate: %v", err)
	}
	if !validated.Validated() {
		t.Fatalf("expected bootstrap candidate to be validated")
	}

	committed, err := validated.Commit(t0())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	applied, err := committed.Apply(t0())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied.IsActive() {
		t.Fatalf("expected applied bootstrap change to be active")
	}
}

// architecture.md: "운영 인증서 교체 후보에는 실제 서비스 주소 검증을 적용한다."
// The bootstrap exception must not become a loophole for managed/external
// candidates: planning.md requires rejecting HTTPS replacement candidates on
// address mismatch and keeping the existing certificate.
func TestTLSChange_ManagedCandidateStillRequiresServiceAddress(t *testing.T) {
	c, err := NewCandidateTLSChange(mkTLSVersionID(t, '1'), mkTLSVersionID(t, '2'))
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}

	managedFacts := passingFacts()
	managedFacts.CandidateSource = TLSSourceManaged
	managedFacts.ServiceAddressMatches = false

	afterValidate, err := c.ValidateCandidate(managedFacts)
	if err != nil {
		t.Fatalf("expected failed validation to be a normal (non-error) result: %v", err)
	}
	if afterValidate.Validated() {
		t.Fatalf("expected managed candidate to remain unvalidated")
	}
	if afterValidate.ErrorCode() != "tls_candidate_address_mismatch" {
		t.Fatalf("expected tls_candidate_address_mismatch, got %q", afterValidate.ErrorCode())
	}
	if _, err := afterValidate.Commit(t0()); err == nil {
		t.Fatalf("expected commit of an unvalidated managed candidate to be refused")
	}
}

// Same as above for an external candidate, whose default (zero-value)
// CandidateSource must not be mistaken for a bootstrap exemption either.
func TestTLSChange_ExternalCandidateStillRequiresServiceAddress(t *testing.T) {
	c, err := NewCandidateTLSChange(mkTLSVersionID(t, '1'), mkTLSVersionID(t, '2'))
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}

	externalFacts := passingFacts()
	externalFacts.CandidateSource = TLSSourceExternal
	externalFacts.ServiceAddressMatches = false

	afterValidate, err := c.ValidateCandidate(externalFacts)
	if err != nil {
		t.Fatalf("expected failed validation to be a normal (non-error) result: %v", err)
	}
	if afterValidate.Validated() {
		t.Fatalf("expected external candidate to remain unvalidated")
	}
	if afterValidate.ErrorCode() != "tls_candidate_address_mismatch" {
		t.Fatalf("expected tls_candidate_address_mismatch, got %q", afterValidate.ErrorCode())
	}
}

func mkKeyMaterialID(t *testing.T) KeyMaterialID {
	t.Helper()
	id, err := ParseKeyMaterialID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
	if err != nil {
		t.Fatalf("parse key material id: %v", err)
	}
	return id
}

func mkRecoveryRequiredChange(t *testing.T, previousSuffix, candidateSuffix byte) TLSChange {
	t.Helper()
	c, err := NewCandidateTLSChange(mkTLSVersionID(t, previousSuffix), mkTLSVersionID(t, candidateSuffix))
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}
	validated, err := c.ValidateCandidate(passingFacts())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	committed, err := validated.Commit(t0())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	recovery, err := committed.MarkRecoveryRequired("apply_result_unknown", t0())
	if err != nil {
		t.Fatalf("mark recovery required: %v", err)
	}
	return recovery
}

// Reproduces the reviewer's dead end: from recovery_required, both Apply and
// RollbackApply refuse because the phase is not committed, and
// ValidateCandidate/Commit refuse because the phase is not prepared. Without
// an explicit recovery-completing transition there is no way out.
func TestTLSChange_RecoveryRequiredIsADeadEndWithoutReconcile(t *testing.T) {
	recovery := mkRecoveryRequiredChange(t, '1', '2')

	if _, err := recovery.Apply(t0()); err == nil {
		t.Fatalf("expected Apply from recovery_required to be refused")
	}
	if _, err := recovery.RollbackApply("x", t0()); err == nil {
		t.Fatalf("expected RollbackApply from recovery_required to be refused")
	}
	if _, err := recovery.ValidateCandidate(passingFacts()); err == nil {
		t.Fatalf("expected ValidateCandidate from recovery_required to be refused")
	}
	if _, err := recovery.Commit(t0()); err == nil {
		t.Fatalf("expected Commit from recovery_required to be refused")
	}
}

// Case (1): the recorded candidate re-validates against a stored snapshot ->
// Reconcile completes the change as applied.
func TestTLSChange_ReconcileCandidateRevalidatesCompletesApplied(t *testing.T) {
	recovery := mkRecoveryRequiredChange(t, '1', '2')

	resolved, err := recovery.Reconcile(TLSReconcileFacts{
		CandidateVersionID: recovery.CandidateVersionID(),
		CandidateFacts:     passingFacts(),
	}, t0())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if resolved.Phase() != TLSChangePhaseApplied {
		t.Fatalf("expected applied phase, got %s", resolved.Phase())
	}
	if !resolved.IsActive() {
		t.Fatalf("expected reconciled candidate to be active")
	}
}

// Case (2): the candidate cannot be used, but the recorded previous version
// re-validates -> Reconcile completes the change as rolled_back.
func TestTLSChange_ReconcileCandidateUnusableRollsBackToPrevious(t *testing.T) {
	recovery := mkRecoveryRequiredChange(t, '1', '2')

	failingCandidate := passingFacts()
	failingCandidate.ChainVerified = false

	resolved, err := recovery.Reconcile(TLSReconcileFacts{
		CandidateVersionID: recovery.CandidateVersionID(),
		CandidateFacts:     failingCandidate,
		PreviousVersionID:  recovery.PreviousVersionID(),
		PreviousFacts:      passingFacts(),
	}, t0())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if resolved.Phase() != TLSChangePhaseRolledBack {
		t.Fatalf("expected rolled_back phase, got %s", resolved.Phase())
	}
	if resolved.IsActive() {
		t.Fatalf("rolled back change must not be active")
	}
}

// Case (3): neither the candidate nor the previous version can be
// re-validated -> the change must stay recovery_required (maintenance), not
// silently flip to any success outcome.
func TestTLSChange_ReconcileBothUnusableStaysRecoveryRequired(t *testing.T) {
	recovery := mkRecoveryRequiredChange(t, '1', '2')

	failing := passingFacts()
	failing.ChainVerified = false

	resolved, err := recovery.Reconcile(TLSReconcileFacts{
		CandidateVersionID: recovery.CandidateVersionID(),
		CandidateFacts:     failing,
		PreviousVersionID:  recovery.PreviousVersionID(),
		PreviousFacts:      failing,
	}, t0())
	if err == nil {
		t.Fatalf("expected reconcile to report that nothing could be resolved")
	}
	if resolved.Phase() != TLSChangePhaseRecoveryRequired {
		t.Fatalf("expected change to remain recovery_required, got %s", resolved.Phase())
	}
}

// Reconcile must not let an unrelated version id complete this change's
// recovery, even if that unrelated version would itself validate cleanly.
func TestTLSChange_ReconcileRejectsMismatchedTargetVersion(t *testing.T) {
	recovery := mkRecoveryRequiredChange(t, '1', '2')
	wrongVersion := mkTLSVersionID(t, '9')

	if _, err := recovery.Reconcile(TLSReconcileFacts{
		CandidateVersionID: wrongVersion,
		CandidateFacts:     passingFacts(),
	}, t0()); err == nil {
		t.Fatalf("expected reconcile with a mismatched candidate version id to be refused")
	}

	if _, err := recovery.Reconcile(TLSReconcileFacts{
		CandidateVersionID: recovery.CandidateVersionID(),
		CandidateFacts:     func() TLSValidationFacts { f := passingFacts(); f.ChainVerified = false; return f }(),
		PreviousVersionID:  wrongVersion,
		PreviousFacts:      passingFacts(),
	}, t0()); err == nil {
		t.Fatalf("expected reconcile with a mismatched previous version id to be refused")
	}
}

// §9: Reconcile never activates a merely prepared candidate. Reconcile must
// refuse a prepared (not recovery_required) change outright.
func TestTLSChange_ReconcileRefusesPreparedCandidate(t *testing.T) {
	c, err := NewCandidateTLSChange(mkTLSVersionID(t, '1'), mkTLSVersionID(t, '2'))
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}
	if _, err := c.Reconcile(TLSReconcileFacts{
		CandidateVersionID: c.CandidateVersionID(),
		CandidateFacts:     passingFacts(),
	}, t0()); err == nil {
		t.Fatalf("expected reconcile of a merely prepared change to be refused")
	}

	// Also refused once merely committed (not yet stuck in recovery).
	validated, err := c.ValidateCandidate(passingFacts())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	committed, err := validated.Commit(t0())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := committed.Reconcile(TLSReconcileFacts{
		CandidateVersionID: committed.CandidateVersionID(),
		CandidateFacts:     passingFacts(),
	}, t0()); err == nil {
		t.Fatalf("expected reconcile of a committed (not recovery_required) change to be refused")
	}
}

// Reviewer finding (round 3, #1): a prepared candidate must never be able to
// reach recovery_required and then get laundered into applied by Reconcile,
// since that would bypass Commit's !c.validated gate entirely
// (backend-implementation.md §9: "Reconcile는 prepared 후보는 활성화하지
// 않고..."). This reproduces the reviewer's exact three-step path and
// verifies it is refused at the first opportunity: MarkRecoveryRequired must
// reject a merely prepared (never committed) candidate, so Reconcile never
// even gets a chance to see it.
func TestTLSChange_PreparedCandidateCannotLaunderThroughRecoveryRequired(t *testing.T) {
	c, err := NewCandidateTLSChange(mkTLSVersionID(t, '1'), mkTLSVersionID(t, '2'))
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}
	if c.Phase() != TLSChangePhasePrepared || c.Validated() {
		t.Fatalf("expected a fresh candidate to be prepared and unvalidated")
	}

	// Step 2 of the reviewer's repro: mark the still-prepared (never
	// committed, never validated) candidate as recovery_required directly.
	if _, err := c.MarkRecoveryRequired("boom", t0()); err == nil {
		t.Fatalf("expected MarkRecoveryRequired on a prepared (not committed) change to be refused")
	}

	// Belt and suspenders: even if that guard were somehow bypassed, Reconcile
	// itself must still refuse to activate a candidate that was never
	// Commit-validated. We can't construct a recovery_required change that
	// skipped Commit anymore (that's exactly what the guard above prevents),
	// so this asserts the same rule holds for a legitimately-reached
	// recovery_required change too: Reconcile only ever completes a change
	// that passed through committed.
	recovery := mkRecoveryRequiredChange(t, '3', '4')
	if recovery.Phase() != TLSChangePhaseRecoveryRequired {
		t.Fatalf("expected legitimate recovery path to still reach recovery_required")
	}
}

// Reviewer finding (round 3, #1), continued: only a committed change may
// become recovery_required. A prepared candidate is refused (covered above);
// this also checks the other non-committed phases so the allowed-phase set
// is exactly {committed}, not "everything except terminal" as it was before.
func TestTLSChange_MarkRecoveryRequiredOnlyFromCommitted(t *testing.T) {
	// prepared -> refused (see TestTLSChange_PreparedCandidateCannotLaunderThroughRecoveryRequired).

	// recovery_required -> refused (already recovery_required, re-marking is
	// not a committed->recovery_required transition).
	recovery := mkRecoveryRequiredChange(t, '1', '2')
	if _, err := recovery.MarkRecoveryRequired("again", t0()); err == nil {
		t.Fatalf("expected MarkRecoveryRequired on an already recovery_required change to be refused")
	}

	// applied and rolled_back -> refused (terminal; also covered by
	// TestTLSChange_UnclearOutcomeRequiresRecovery for applied).
	c, err := NewCandidateTLSChange(mkTLSVersionID(t, '5'), mkTLSVersionID(t, '6'))
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}
	validated, err := c.ValidateCandidate(passingFacts())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	committed, err := validated.Commit(t0())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	rolledBack, err := committed.RollbackApply("installer_bind_failed", t0())
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := rolledBack.MarkRecoveryRequired("late_signal", t0()); err == nil {
		t.Fatalf("expected MarkRecoveryRequired on a rolled_back change to be refused")
	}

	// committed -> the only allowed starting phase.
	if _, err := committed.MarkRecoveryRequired("apply_result_unknown", t0()); err != nil {
		t.Fatalf("expected MarkRecoveryRequired from committed to succeed: %v", err)
	}
}

// Reviewer finding (round 3, #2): ValidateCandidate must bump the optimistic
// concurrency version like every other transition in this file, on both the
// pass and fail path, so a SaveTLSChange(change, expectedVersion) call after
// validation rejects a stale concurrent writer instead of silently
// overwriting it.
func TestTLSChange_ValidateCandidateAdvancesVersion(t *testing.T) {
	c, err := NewTLSChange(TLSChangeFacts{
		PreviousVersionID:  mkTLSVersionID(t, '1'),
		CandidateVersionID: mkTLSVersionID(t, '2'),
		Phase:              TLSChangePhasePrepared,
		Version:            7,
	})
	if err != nil {
		t.Fatalf("new tls change: %v", err)
	}

	passed, err := c.ValidateCandidate(passingFacts())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if passed.Version() != 8 {
		t.Fatalf("expected version to advance to 8 on successful validation, got %d", passed.Version())
	}

	failing := passingFacts()
	failing.ChainVerified = false
	failed, err := c.ValidateCandidate(failing)
	if err != nil {
		t.Fatalf("expected failed validation to be a normal (non-error) result: %v", err)
	}
	if failed.Version() != 8 {
		t.Fatalf("expected version to advance to 8 on failed validation too, got %d", failed.Version())
	}
}

// Reviewer finding (round 3, #3): a failing candidate validation is a normal
// business result (planning.md: keep the existing certificate and record why),
// not an error, so callers using the common `next, err := ...; if err != nil
// { return err }` idiom must still receive the errorCode-bearing change
// rather than discarding it. The error return stays reserved for genuine
// caller misuse (wrong starting phase), which - like every other transition
// in this file - yields a zero value.
func TestTLSChange_ValidateCandidateFailureIsNotAnError(t *testing.T) {
	c, err := NewCandidateTLSChange(mkTLSVersionID(t, '1'), mkTLSVersionID(t, '2'))
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}

	failing := passingFacts()
	failing.WithinValidityPeriod = false

	// Simulate the idiom a careless caller would use.
	next, err := c.ValidateCandidate(failing)
	if err != nil {
		t.Fatalf("a failed validation must not be reported as an error: %v", err)
	}
	if next.Validated() {
		t.Fatalf("expected candidate to remain unvalidated")
	}
	if next.ErrorCode() != "tls_candidate_out_of_validity" {
		t.Fatalf("expected errorCode to survive the nil-error path, got %q", next.ErrorCode())
	}

	// Misuse (wrong phase) is still reported as an error, with a zero value,
	// matching every other transition in this file.
	committed, err := func() (TLSChange, error) {
		validated, err := c.ValidateCandidate(passingFacts())
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		return validated.Commit(t0())
	}()
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	zero, err := committed.ValidateCandidate(passingFacts())
	if err == nil {
		t.Fatalf("expected ValidateCandidate on a non-prepared change to be refused")
	}
	if zero != (TLSChange{}) {
		t.Fatalf("expected zero value on caller-misuse error, got %+v", zero)
	}
}
