package domain

import (
	"testing"
)

func mkAuthorityID(t *testing.T, suffix byte) AuthorityID {
	t.Helper()
	raw := "99999999-9999-4999-8999-99999999999" + string(suffix)
	id, err := ParseAuthorityID(raw)
	if err != nil {
		t.Fatalf("parse authority id: %v", err)
	}
	return id
}

func mkTransitionID(t *testing.T) TransitionID {
	t.Helper()
	id, err := ParseTransitionID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("parse transition id: %v", err)
	}
	return id
}

func mkAccountID(t *testing.T) AccountID {
	t.Helper()
	id, err := ParseAccountID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	if err != nil {
		t.Fatalf("parse account id: %v", err)
	}
	return id
}

// data-model.md: emergency reports can register with no successor CA yet.
// B02 ruling: whether a successor has been chosen is expressed by
// TargetAuthorityID, not by a separate state -- SetTarget stays legal while
// in_progress regardless of whether a target was already set.
func TestTransition_EmergencyCanBeCreatedWithoutTarget(t *testing.T) {
	tr, err := NewTransition(TransitionFacts{
		ID:                mkTransitionID(t),
		SourceAuthorityID: mkAuthorityID(t, '1'),
		Mode:              TransitionModeEmergency,
		State:             TransitionStateInProgress,
		ReportedBy:        mkAccountID(t),
		ReportedAt:        t0(),
		Reason:            "key compromise reported",
	})
	if err != nil {
		t.Fatalf("new transition: %v", err)
	}
	if tr.TargetAuthorityID() != "" {
		t.Fatalf("expected no target authority yet")
	}

	if _, err := tr.Complete(TransitionClosureFacts{AllImpactsAddressed: true, ManualDeploymentConfirmed: true}, t0()); err == nil {
		t.Fatalf("expected Complete without a target authority to fail")
	}

	withTarget, err := tr.SetTarget(mkAuthorityID(t, '2'), t0())
	if err != nil {
		t.Fatalf("set target: %v", err)
	}
	if withTarget.TargetAuthorityID() != mkAuthorityID(t, '2') {
		t.Fatalf("expected target authority to be recorded")
	}
	// B02 ruling: setting a target does not advance the state machine --
	// it stays in_progress, since target presence is tracked by
	// TargetAuthorityID alone, not by a "target_set" state.
	if withTarget.State() != TransitionStateInProgress {
		t.Fatalf("expected state to remain in_progress after SetTarget, got %q", withTarget.State())
	}

	// B02 ruling: SetTarget is legal in_progress even when a target is
	// already recorded (replacing the successor), and rejected once the
	// transition has moved past in_progress.
	replaced, err := withTarget.SetTarget(mkAuthorityID(t, '3'), t0())
	if err != nil {
		t.Fatalf("expected replacing an already-set target to be legal in_progress: %v", err)
	}
	if replaced.TargetAuthorityID() != mkAuthorityID(t, '3') {
		t.Fatalf("expected target authority to be replaced")
	}
}

// Rewritten for B02: the old test asserted Complete moved the transition
// straight to a single terminal "completed" state. The ruling replaces that
// with externally_completed (Complete) and closed (a separate transition,
// Close) -- Complete alone must never reach closed, and re-running Complete
// once externally_completed must fail exactly like the old "already
// completed" case did.
func TestTransition_CompleteRequiresBothImpactsAndDeployment(t *testing.T) {
	tr, err := NewTransition(TransitionFacts{
		ID: mkTransitionID(t), SourceAuthorityID: mkAuthorityID(t, '1'),
		TargetAuthorityID: mkAuthorityID(t, '2'), Mode: TransitionModeNormal,
		State: TransitionStateInProgress, ReportedBy: mkAccountID(t), ReportedAt: t0(),
	})
	if err != nil {
		t.Fatalf("new transition: %v", err)
	}

	if _, err := tr.Complete(TransitionClosureFacts{AllImpactsAddressed: false, ManualDeploymentConfirmed: true}, t0()); err == nil {
		t.Fatalf("expected incomplete impacts to block completion")
	}
	if _, err := tr.Complete(TransitionClosureFacts{AllImpactsAddressed: true, ManualDeploymentConfirmed: false}, t0()); err == nil {
		t.Fatalf("expected unconfirmed deployment to block completion")
	}
	done, err := tr.Complete(TransitionClosureFacts{AllImpactsAddressed: true, ManualDeploymentConfirmed: true}, t0())
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !done.IsExternallyCompleted() {
		t.Fatalf("expected transition to reach externally_completed")
	}
	if done.IsClosed() {
		t.Fatalf("expected Complete alone to never reach closed (B02 ruling)")
	}
	if _, err := done.Complete(TransitionClosureFacts{AllImpactsAddressed: true, ManualDeploymentConfirmed: true}, t0()); err == nil {
		t.Fatalf("expected completing an already-externally_completed transition to fail")
	}
}

// New for B02: closed must be reached only via the separate Close
// transition, and Close itself must check the source CA's
// publication-termination fact rather than assume it.
func TestTransition_CloseRequiresExternallyCompletedAndPublicationEnded(t *testing.T) {
	tr, err := NewTransition(TransitionFacts{
		ID: mkTransitionID(t), SourceAuthorityID: mkAuthorityID(t, '1'),
		TargetAuthorityID: mkAuthorityID(t, '2'), Mode: TransitionModeNormal,
		State: TransitionStateInProgress, ReportedBy: mkAccountID(t), ReportedAt: t0(),
	})
	if err != nil {
		t.Fatalf("new transition: %v", err)
	}

	// Close must be refused while still in_progress -- closed requires
	// externally_completed first.
	if _, err := tr.Close(TransitionTerminationFacts{SourceCAPublicationEnded: true}, t0()); err == nil {
		t.Fatalf("expected Close to be refused while in_progress")
	}

	done, err := tr.Complete(TransitionClosureFacts{AllImpactsAddressed: true, ManualDeploymentConfirmed: true}, t0())
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	// Close must be refused when the CRL-termination fact says the source
	// CA's publication has not ended, even though externally_completed.
	if _, err := done.Close(TransitionTerminationFacts{SourceCAPublicationEnded: false}, t0()); err == nil {
		t.Fatalf("expected Close to be refused when publication has not ended")
	}

	closed, err := done.Close(TransitionTerminationFacts{SourceCAPublicationEnded: true}, t0())
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	if !closed.IsClosed() {
		t.Fatalf("expected transition to be closed")
	}
	if _, err := closed.Close(TransitionTerminationFacts{SourceCAPublicationEnded: true}, t0()); err == nil {
		t.Fatalf("expected closing an already-closed transition to fail")
	}
}

// planning.md/U11: an upper-level (CA) impact is not itself an individual
// certificate revocation. TransitionImpact carries no reference to, and no
// method that produces, a Revocation - recording one and resolving it never
// touches revocation state.
func TestTransitionImpact_DoesNotImplyRevocation(t *testing.T) {
	impact, err := NewTransitionImpact(TransitionImpactFacts{
		TransitionID:  mkTransitionID(t),
		CertificateID: mkCertID(t),
	})
	if err != nil {
		t.Fatalf("new transition impact: %v", err)
	}
	if impact.IsResolved() {
		t.Fatalf("expected a fresh impact to be unresolved")
	}

	resolved, err := impact.RecordReplacement(mkAuthorityIDAsCert(t), t0())
	if err != nil {
		t.Fatalf("record replacement: %v", err)
	}
	if !resolved.IsResolved() {
		t.Fatalf("expected replacement to resolve the impact")
	}
	// Recording a replacement twice is rejected (a failed reissue retry must
	// go through a fresh replacement id, not silently reuse a resolved slot).
	if _, err := resolved.RecordReplacement(mkAuthorityIDAsCert(t), t0()); err == nil {
		t.Fatalf("expected re-recording a resolved impact to fail")
	}
}

// mkAuthorityIDAsCert produces a syntactically valid CertificateID distinct
// from mkCertID, used purely as "some other certificate id" in tests.
func mkAuthorityIDAsCert(t *testing.T) CertificateID {
	t.Helper()
	id, err := ParseCertificateID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	if err != nil {
		t.Fatalf("parse certificate id: %v", err)
	}
	return id
}

func TestDeploymentConfirmation_ConstructionValidatesFields(t *testing.T) {
	_, err := NewDeploymentConfirmation(DeploymentConfirmationFacts{
		TransitionID: mkTransitionID(t),
		TargetLabel:  "edge-lb-01",
		Action:       DeploymentActionTrustAdded,
		ConfirmedBy:  mkAccountID(t),
		ConfirmedAt:  t0(),
	})
	if err != nil {
		t.Fatalf("expected valid confirmation to construct: %v", err)
	}
	if _, err := NewDeploymentConfirmation(DeploymentConfirmationFacts{
		TransitionID: mkTransitionID(t), Action: DeploymentActionTrustAdded,
		ConfirmedBy: mkAccountID(t), ConfirmedAt: t0(),
	}); err == nil {
		t.Fatalf("expected missing target label to be rejected")
	}
}

// B02 ruling on Decision 2: certificate_installed is recordable for an
// ordinary same-key renewal too, so construction must not require a new key
// to have been generated -- it only needs the usual required fields.
func TestDeploymentConfirmation_CertificateInstalledDoesNotRequireNewKey(t *testing.T) {
	_, err := NewDeploymentConfirmation(DeploymentConfirmationFacts{
		TransitionID:  mkTransitionID(t),
		TargetLabel:   "edge-lb-01",
		CertificateID: mkCertID(t),
		Action:        DeploymentActionCertificateInstalled,
		ConfirmedBy:   mkAccountID(t),
		ConfirmedAt:   t0(),
	})
	if err != nil {
		t.Fatalf("expected certificate_installed confirmation for a same-key renewal to construct: %v", err)
	}
}

func TestTransition_ConfirmDeploymentRefusedAfterCompletion(t *testing.T) {
	tr, err := NewTransition(TransitionFacts{
		ID: mkTransitionID(t), SourceAuthorityID: mkAuthorityID(t, '1'),
		TargetAuthorityID: mkAuthorityID(t, '2'), Mode: TransitionModeNormal,
		State: TransitionStateInProgress, ReportedBy: mkAccountID(t), ReportedAt: t0(),
	})
	if err != nil {
		t.Fatalf("new transition: %v", err)
	}
	done, err := tr.Complete(TransitionClosureFacts{AllImpactsAddressed: true, ManualDeploymentConfirmed: true}, t0())
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if err := done.ConfirmDeployment(t0()); err == nil {
		t.Fatalf("expected confirmation to be refused after completion")
	}
}

// New for B02: SetTarget must be rejected once the transition has moved
// past in_progress, not just once fully closed.
func TestTransition_SetTargetRejectedAfterComplete(t *testing.T) {
	tr, err := NewTransition(TransitionFacts{
		ID: mkTransitionID(t), SourceAuthorityID: mkAuthorityID(t, '1'),
		TargetAuthorityID: mkAuthorityID(t, '2'), Mode: TransitionModeNormal,
		State: TransitionStateInProgress, ReportedBy: mkAccountID(t), ReportedAt: t0(),
	})
	if err != nil {
		t.Fatalf("new transition: %v", err)
	}
	done, err := tr.Complete(TransitionClosureFacts{AllImpactsAddressed: true, ManualDeploymentConfirmed: true}, t0())
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if _, err := done.SetTarget(mkAuthorityID(t, '3'), t0()); err == nil {
		t.Fatalf("expected SetTarget to be refused once externally_completed")
	}
}
