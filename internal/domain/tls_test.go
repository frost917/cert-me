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
	if err == nil {
		t.Fatalf("expected validation failure error")
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
	if err == nil {
		t.Fatalf("expected managed candidate with a mismatched service address to fail validation")
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

	if _, err := c.ValidateCandidate(externalFacts); err == nil {
		t.Fatalf("expected external candidate with a mismatched service address to fail validation")
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
