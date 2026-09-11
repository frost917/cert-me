package contract

import (
	"encoding/json"
	"reflect"
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

// TestDeploymentView_ActionFieldIsWireType pins DeploymentView.Action's
// static type to DeploymentActionInput. Now that B02 settled Decision 2 --
// domain.DeploymentAction and the wire enum use identical values -- this is
// no longer guarding a translation, just keeping the wire-shaped view types
// consistent between the input and output sides.
func TestDeploymentView_ActionFieldIsWireType(t *testing.T) {
	field, ok := reflect.TypeOf(DeploymentView{}).FieldByName("Action")
	if !ok {
		t.Fatal("DeploymentView has no Action field")
	}
	wantType := reflect.TypeOf(DeploymentActionInput(""))
	if field.Type != wantType {
		t.Fatalf("DeploymentView.Action must be %s (the wire-view type), got %s", wantType, field.Type)
	}
}

// TestDeploymentActionEnum_MatchesOpenAPIExhaustively is the B02-era
// replacement for the old bijective-mapping guard: since domain and wire
// values are now identical (Decision 2 ruling: DeploymentActionCertReplaced
// / cert_key_replaced became DeploymentActionCertificateInstalled /
// certificate_installed, matching OpenAPI exactly), what still needs
// guarding is that domain.DeploymentAction's value set and
// api/openapi.json's Deployment.action enum never drift apart. Verified
// against the live OpenAPI document, listing domain.DeploymentAction's
// constants by hand since the type exports no enumerator, so a future
// domain action added without a matching OpenAPI entry (or vice versa)
// fails here.
func TestDeploymentActionEnum_MatchesOpenAPIExhaustively(t *testing.T) {
	wireEnum := loadOpenAPIStringEnum(t, "Deployment", "action")
	wireEnumSet := make(map[string]struct{}, len(wireEnum))
	for _, w := range wireEnum {
		wireEnumSet[w] = struct{}{}
	}

	domainActions := []domain.DeploymentAction{
		domain.DeploymentActionTrustAdded,
		domain.DeploymentActionCertificateInstalled,
		domain.DeploymentActionTrustRemoved,
	}
	if len(domainActions) != len(wireEnum) {
		t.Fatalf("domain.DeploymentAction has %d values but api/openapi.json Deployment.action enum has %d -- the two vocabularies are no longer in lockstep", len(domainActions), len(wireEnum))
	}

	seenWire := make(map[DeploymentActionInput]domain.DeploymentAction, len(domainActions))
	for _, d := range domainActions {
		wire := DeploymentActionInput(DeploymentActionView(d))
		if _, ok := wireEnumSet[string(wire)]; !ok {
			t.Fatalf("domain action %q renders as %q, which is not in api/openapi.json's Deployment.action enum %v", d, wire, wireEnum)
		}
		if prev, dup := seenWire[wire]; dup {
			t.Fatalf("domain actions %q and %q both render as the same wire value %q -- values are no longer distinct", prev, d, wire)
		}
		seenWire[wire] = d

		back, err := wire.Domain()
		if err != nil {
			t.Fatalf("wire value %q (from domain action %q) failed to parse back: %v", wire, d, err)
		}
		if back != d {
			t.Fatalf("round-trip mismatch: domain %q -> wire %q -> domain %q", d, wire, back)
		}
	}
}

// TestTransitionStateEnum_MatchesOpenAPIExhaustively guards the other half
// of B02 Decision 1: domain.TransitionState now uses the exact same
// vocabulary as api/openapi.json's Transition.state enum, so this checks
// the two stay in lockstep going forward.
func TestTransitionStateEnum_MatchesOpenAPIExhaustively(t *testing.T) {
	wireEnum := loadOpenAPIStringEnum(t, "Transition", "state")
	wireEnumSet := make(map[string]struct{}, len(wireEnum))
	for _, w := range wireEnum {
		wireEnumSet[w] = struct{}{}
	}

	domainStates := []domain.TransitionState{
		domain.TransitionStateInProgress,
		domain.TransitionStateExternallyCompleted,
		domain.TransitionStateClosed,
	}
	if len(domainStates) != len(wireEnum) {
		t.Fatalf("domain.TransitionState has %d values but api/openapi.json Transition.state enum has %d -- the two vocabularies are no longer in lockstep", len(domainStates), len(wireEnum))
	}

	seen := make(map[TransitionStateView]domain.TransitionState, len(domainStates))
	for _, s := range domainStates {
		wire := TransitionStateViewOf(s)
		if _, ok := wireEnumSet[string(wire)]; !ok {
			t.Fatalf("domain state %q renders as %q, which is not in api/openapi.json's Transition.state enum %v", s, wire, wireEnum)
		}
		if prev, dup := seen[wire]; dup {
			t.Fatalf("domain states %q and %q both render as the same wire value %q -- values are no longer distinct", prev, s, wire)
		}
		seen[wire] = s
	}
}

func TestTransitionCompleteCommand_ValidateRejectsForeignID(t *testing.T) {
	cmd := TransitionCompleteCommand{TransitionID: "not-a-uuid"}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected malformed transition id to be rejected")
	}
}
