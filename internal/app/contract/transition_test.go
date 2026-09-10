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

// TestDeploymentView_ActionFieldIsWireType is Q1: transition.go's file
// header says "Views below expose the OpenAPI wire values directly
// (TransitionStateView, DeploymentActionInput/View) with an explicit
// mapping to the domain enum" -- but DeploymentView.Action was declared as
// domain.DeploymentAction (domain values like "cert_key_replaced"), not the
// wire enum (api/openapi.json Deployment.action: trust_added /
// certificate_installed / trust_removed). An adapter trusting the header
// comment and emitting DeploymentView.Action as-is would produce a value
// the OpenAPI schema rejects. This test pins the field's static type to
// DeploymentActionInput, the wire-view type already used for the input
// side.
func TestDeploymentView_ActionFieldIsWireType(t *testing.T) {
	field, ok := reflect.TypeOf(DeploymentView{}).FieldByName("Action")
	if !ok {
		t.Fatal("DeploymentView has no Action field")
	}
	wantType := reflect.TypeOf(DeploymentActionInput(""))
	if field.Type != wantType {
		t.Fatalf("DeploymentView.Action must be %s (the OpenAPI wire enum view type), got %s -- "+
			"the file header claims views expose wire values directly, so a domain-typed Action "+
			"would let an adapter emit a value api/openapi.json's Deployment.action enum rejects",
			wantType, field.Type)
	}
}

// TestDeploymentActionMapping_ExhaustiveRoundTrip is Q1/Q2: every
// domain.DeploymentAction constant (internal/domain/transition.go lines
// 287-289: DeploymentActionTrustAdded, DeploymentActionCertReplaced,
// DeploymentActionTrustRemoved -- domain.DeploymentAction exports no
// enumerator, so they are listed here by hand) must map to a distinct,
// valid entry of api/openapi.json's Deployment.action enum, and mapping
// back must reproduce the original domain value. This is the "total
// mapping function, both directions" the finding calls for, verified
// against the live OpenAPI document rather than a hardcoded wire list, so
// a future domain action added without updating the mapping table fails
// here.
func TestDeploymentActionMapping_ExhaustiveRoundTrip(t *testing.T) {
	wireEnum := loadOpenAPIStringEnum(t, "Deployment", "action")
	wireEnumSet := make(map[string]struct{}, len(wireEnum))
	for _, w := range wireEnum {
		wireEnumSet[w] = struct{}{}
	}

	domainActions := []domain.DeploymentAction{
		domain.DeploymentActionTrustAdded,
		domain.DeploymentActionCertReplaced,
		domain.DeploymentActionTrustRemoved,
	}
	if len(domainActions) != len(wireEnum) {
		t.Fatalf("domain.DeploymentAction has %d values but api/openapi.json Deployment.action enum has %d -- mapping table is no longer total", len(domainActions), len(wireEnum))
	}

	seenWire := make(map[DeploymentActionInput]domain.DeploymentAction, len(domainActions))
	for _, d := range domainActions {
		wire := DeploymentActionInput(DeploymentActionView(d))
		if _, ok := wireEnumSet[string(wire)]; !ok {
			t.Fatalf("domain action %q maps to wire value %q, which is not in api/openapi.json's Deployment.action enum %v", d, wire, wireEnum)
		}
		if prev, dup := seenWire[wire]; dup {
			t.Fatalf("domain actions %q and %q both map to the same wire value %q -- mapping is not bijective", prev, d, wire)
		}
		seenWire[wire] = d

		back, err := wire.Domain()
		if err != nil {
			t.Fatalf("wire value %q (from domain action %q) failed to map back: %v", wire, d, err)
		}
		if back != d {
			t.Fatalf("round-trip mismatch: domain %q -> wire %q -> domain %q", d, wire, back)
		}
	}
}

func TestTransitionCompleteCommand_ValidateRejectsForeignID(t *testing.T) {
	cmd := TransitionCompleteCommand{TransitionID: "not-a-uuid"}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected malformed transition id to be rejected")
	}
}
