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

func mkKeyMaterialID(t *testing.T) KeyMaterialID {
	t.Helper()
	id, err := ParseKeyMaterialID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
	if err != nil {
		t.Fatalf("parse key material id: %v", err)
	}
	return id
}
