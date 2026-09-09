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
func TestTransition_EmergencyCanBeCreatedWithoutTarget(t *testing.T) {
	tr, err := NewTransition(TransitionFacts{
		ID:                mkTransitionID(t),
		SourceAuthorityID: mkAuthorityID(t, '1'),
		Mode:              TransitionModeEmergency,
		State:             TransitionStateReported,
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
	if withTarget.State() != TransitionStateTargetSet {
		t.Fatalf("expected state to advance to target_set")
	}
}

func TestTransition_CompleteRequiresBothImpactsAndDeployment(t *testing.T) {
	tr, err := NewTransition(TransitionFacts{
		ID: mkTransitionID(t), SourceAuthorityID: mkAuthorityID(t, '1'),
		TargetAuthorityID: mkAuthorityID(t, '2'), Mode: TransitionModeNormal,
		State: TransitionStateTargetSet, ReportedBy: mkAccountID(t), ReportedAt: t0(),
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
	if !done.IsCompleted() {
		t.Fatalf("expected transition to complete")
	}
	if _, err := done.Complete(TransitionClosureFacts{AllImpactsAddressed: true, ManualDeploymentConfirmed: true}, t0()); err == nil {
		t.Fatalf("expected completing an already-completed transition to fail")
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

func TestTransition_ConfirmDeploymentRefusedAfterCompletion(t *testing.T) {
	tr, err := NewTransition(TransitionFacts{
		ID: mkTransitionID(t), SourceAuthorityID: mkAuthorityID(t, '1'),
		TargetAuthorityID: mkAuthorityID(t, '2'), Mode: TransitionModeNormal,
		State: TransitionStateTargetSet, ReportedBy: mkAccountID(t), ReportedAt: t0(),
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
