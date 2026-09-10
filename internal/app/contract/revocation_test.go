package contract

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"cert-me/internal/domain"
)

const testCertID = "00000000-0000-4000-8000-000000000001"
const testKeyMaterialID = "00000000-0000-4000-8000-000000000002"
const testRevocationID = "00000000-0000-4000-8000-000000000003"

func TestRevocationRevokeCommand_ValidateRejectsForeignOrMalformedID(t *testing.T) {
	cases := []struct {
		name string
		id   string
	}{
		{"empty", ""},
		{"too short", "not-a-uuid"},
		{"uppercase", "00000000-0000-4000-8000-00000000000A"},
		{"wrong length", "00000000-0000-4000-8000-0000000000011"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := RevocationRevokeCommand{
				CertificateID: domain.CertificateID(tc.id),
				Reason:        "keyCompromise",
				Justification: "compromised",
			}
			if err := cmd.Validate(); err == nil {
				t.Fatalf("expected rejection for id %q", tc.id)
			}
		})
	}
}

func TestRevocationRevokeCommand_ValidateRequiredFields(t *testing.T) {
	base := RevocationRevokeCommand{
		CertificateID: domain.CertificateID(testCertID),
		Reason:        "keyCompromise",
		Justification: "compromised",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("expected valid command to pass, got %v", err)
	}

	missingReason := base
	missingReason.Reason = ""
	if err := missingReason.Validate(); err == nil {
		t.Fatal("expected missing reason to be rejected")
	}

	missingJustification := base
	missingJustification.Justification = ""
	if err := missingJustification.Validate(); err == nil {
		t.Fatal("expected missing justification to be rejected")
	}

	unknownReason := base
	unknownReason.Reason = "not_a_real_reason"
	if err := unknownReason.Validate(); err == nil {
		t.Fatal("expected unknown reason to be rejected")
	}

	tooLong := base
	tooLong.Justification = strings.Repeat("a", maxJustificationLength+1)
	if err := tooLong.Validate(); err == nil {
		t.Fatal("expected over-length justification to be rejected")
	}
}

// TestRevocationRevokeCommand_DecodeRejectsServerFilledField is the
// "잘못된 ID/소속 거부" + server-filled-field test for Revoke: a body trying
// to set certificate_id (a json:"-" field, filled from the URL path) must be
// rejected by DisallowUnknownFields, and the zero value must survive.
func TestRevocationRevokeCommand_DecodeRejectsServerFilledField(t *testing.T) {
	body := []byte(`{"reason":"keyCompromise","justification":"x","certificate_id":"` + testCertID + `"}`)
	var cmd RevocationRevokeCommand
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cmd); err == nil {
		t.Fatal("expected DisallowUnknownFields to reject a body-supplied certificate_id")
	}
	if cmd.CertificateID != "" {
		t.Fatal("certificate_id must not be settable from the request body")
	}
}

func TestRevocationCompromiseCommand_ValidateRejectsForeignID(t *testing.T) {
	cmd := RevocationCompromiseCommand{KeyMaterialID: "bogus", Justification: "leaked"}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected rejection for malformed key material id")
	}
}

func TestRevocationCompromiseCommand_ValidateRequiresJustification(t *testing.T) {
	cmd := RevocationCompromiseCommand{KeyMaterialID: domain.KeyMaterialID(testKeyMaterialID)}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected missing justification to be rejected")
	}
}

func TestRevocationCorrectCommand_ValidateRequiredFields(t *testing.T) {
	base := RevocationCorrectCommand{
		RevocationID:  domain.RevocationID(testRevocationID),
		RevokedAt:     "2025-01-01T00:00:00Z",
		Reason:        "keyCompromise",
		Justification: "correction",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("expected valid command, got %v", err)
	}

	badID := base
	badID.RevocationID = "not-a-uuid"
	if err := badID.Validate(); err == nil {
		t.Fatal("expected malformed revocation id to be rejected")
	}

	badTime := base
	badTime.RevokedAt = "not-a-time"
	if err := badTime.Validate(); err == nil {
		t.Fatal("expected malformed revoked_at to be rejected")
	}

	missingTime := base
	missingTime.RevokedAt = ""
	if err := missingTime.Validate(); err == nil {
		t.Fatal("expected missing revoked_at to be rejected")
	}

	missingJustification := base
	missingJustification.Justification = ""
	if err := missingJustification.Validate(); err == nil {
		t.Fatal("expected missing justification to be rejected")
	}
}

func TestRevocationCorrectCommand_DecodeRejectsServerFilledID(t *testing.T) {
	body := `{"revoked_at":"2025-01-01T00:00:00Z","reason":"keyCompromise","justification":"x","revocation_id":"` + testRevocationID + `"}`
	var cmd RevocationCorrectCommand
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cmd); err == nil {
		t.Fatal("expected DisallowUnknownFields to reject a body-supplied revocation_id")
	}
}

func TestRevocationReasonInput_RoundTrip(t *testing.T) {
	wireValues := []string{
		"unspecified", "keyCompromise", "caCompromise", "affiliationChanged",
		"superseded", "cessationOfOperation", "privilegeWithdrawn", "aACompromise",
	}
	for _, wire := range wireValues {
		d, err := RevocationReasonInput(wire).Domain()
		if err != nil {
			t.Fatalf("wire value %q should map to a domain reason: %v", wire, err)
		}
		if back := RevocationReasonView(d); back != wire {
			t.Fatalf("round-trip mismatch: %q -> %q -> %q", wire, d, back)
		}
	}
}

func TestValidateJustification_LengthLimit(t *testing.T) {
	if err := validateJustification(strings.Repeat("a", maxJustificationLength), true); err != nil {
		t.Fatalf("max length justification should be accepted: %v", err)
	}
	if err := validateJustification(strings.Repeat("a", maxJustificationLength+1), true); err == nil {
		t.Fatal("over max length justification should be rejected")
	}
}

// TestRevocationCommands_SecretFree is a placeholder documenting that none
// of RevocationService's commands carry a secret.Input, unlike Distribution
// and Import; a plain json.Marshal of each must succeed and must not error,
// confirming there is nothing here that needs the secret-blocking rule.
func TestRevocationCommands_SecretFree(t *testing.T) {
	cmd := RevocationRevokeCommand{CertificateID: domain.CertificateID(testCertID), Reason: "keyCompromise", Justification: "j"}
	if _, err := json.Marshal(cmd); err != nil {
		t.Fatalf("a secret-free command must marshal cleanly: %v", err)
	}
	_ = fmt.Sprintf("%v", cmd)
}
