package contract

import (
	"encoding/json"
	"strings"
	"testing"

	"cert-me/internal/domain"
)

const testTransitionID = "00000000-0000-4000-8000-000000000006"
const testAuthorityID2 = "00000000-0000-4000-8000-000000000007"

func TestTransitionCreateCommand_ValidateRejectsForeignID(t *testing.T) {
	cmd := TransitionCreateCommand{SourceAuthorityID: "not-a-uuid", Mode: "normal", Reason: "planned"}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected malformed source authority id to be rejected")
	}
}

func TestTransitionCreateCommand_ValidateRequiredFields(t *testing.T) {
	base := TransitionCreateCommand{SourceAuthorityID: domain.AuthorityID(testAuthorityID), Mode: "normal", Reason: "planned"}
	if err := base.Validate(); err != nil {
		t.Fatalf("expected valid command, got %v", err)
	}

	missingReason := base
	missingReason.Reason = ""
	if err := missingReason.Validate(); err == nil {
		t.Fatal("expected missing reason to be rejected")
	}

	badMode := base
	badMode.Mode = "not_a_mode"
	if err := badMode.Validate(); err == nil {
		t.Fatal("expected unsupported mode to be rejected")
	}

	badTarget := base
	badTarget.TargetAuthorityID = "not-a-uuid"
	if err := badTarget.Validate(); err == nil {
		t.Fatal("expected malformed target authority id to be rejected")
	}
}

func TestTransitionSetTargetCommand_ValidateRejectsForeignID(t *testing.T) {
	cmd := TransitionSetTargetCommand{TransitionID: "not-a-uuid", TargetAuthorityID: domain.AuthorityID(testAuthorityID)}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected malformed transition id to be rejected")
	}
}

func TestTransitionSetTargetCommand_DecodeRejectsServerFilledID(t *testing.T) {
	body := `{"target_authority_id":"` + testAuthorityID + `","transition_id":"` + testTransitionID + `"}`
	var cmd TransitionSetTargetCommand
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cmd); err == nil {
		t.Fatal("expected DisallowUnknownFields to reject a body-supplied transition_id")
	}
	if cmd.TransitionID != "" {
		t.Fatal("transition_id must not be settable from the request body")
	}
}

func TestTransitionConfirmDeploymentCommand_ValidateRequiredFields(t *testing.T) {
	base := TransitionConfirmDeploymentCommand{
		TransitionID: domain.TransitionID(testTransitionID),
		TargetLabel:  "load-balancer-1",
		Action:       DeploymentActionInputTrustAdded,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("expected valid command, got %v", err)
	}

	missingLabel := base
	missingLabel.TargetLabel = ""
	if err := missingLabel.Validate(); err == nil {
		t.Fatal("expected missing target_label to be rejected")
	}

	badAction := base
	badAction.Action = "not_a_real_action"
	if err := badAction.Validate(); err == nil {
		t.Fatal("expected unsupported action to be rejected")
	}

	badCert := base
	badCert.CertificateID = "not-a-uuid"
	if err := badCert.Validate(); err == nil {
		t.Fatal("expected malformed certificate id to be rejected")
	}
}

func TestDeploymentActionInput_RoundTrip(t *testing.T) {
	cases := []DeploymentActionInput{
		DeploymentActionInputTrustAdded,
		DeploymentActionInputCertificateInstalled,
		DeploymentActionInputTrustRemoved,
	}
	for _, wire := range cases {
		d, err := wire.Domain()
		if err != nil {
			t.Fatalf("wire value %q should map to a domain action: %v", wire, err)
		}
		if back := DeploymentActionView(d); DeploymentActionInput(back) != wire {
			t.Fatalf("round-trip mismatch: %q -> %q -> %q", wire, d, back)
		}
	}
}

func TestTransitionCompleteCommand_ValidateRejectsForeignID(t *testing.T) {
	cmd := TransitionCompleteCommand{TransitionID: "not-a-uuid"}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected malformed transition id to be rejected")
	}
}
