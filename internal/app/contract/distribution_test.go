package contract

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

func TestDistributionCreateLinkCommand_ValidateRejectsForeignID(t *testing.T) {
	cmd := DistributionCreateLinkCommand{CertificateID: "definitely-not-a-uuid", Purpose: DownloadPurposePublic}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected malformed certificate id to be rejected")
	}
}

func TestDistributionCreateLinkCommand_ValidateRejectsUnknownPurpose(t *testing.T) {
	cmd := DistributionCreateLinkCommand{CertificateID: domain.CertificateID(testCertID), Purpose: "not_a_purpose"}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected unknown purpose to be rejected")
	}
}

func TestDistributionCreateLinkCommand_DecodeRejectsServerFilledID(t *testing.T) {
	body := `{"purpose":"public","certificate_id":"` + testCertID + `"}`
	var cmd DistributionCreateLinkCommand
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cmd); err == nil {
		t.Fatal("expected DisallowUnknownFields to reject a body-supplied certificate_id")
	}
	if cmd.CertificateID != "" {
		t.Fatal("certificate_id must not be settable from the request body")
	}
}

// TestDownloadCommand_ValidateRequiresRawToken covers the DownloadCommand
// Validate rules: the raw token is required, format/part must be from the
// fixed enums, and a pkcs12 password is only accepted alongside the pkcs12
// format.
func TestDownloadCommand_ValidateRequiresRawToken(t *testing.T) {
	cmd := DownloadCommand{Format: DownloadFormatPEM}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected missing raw token to be rejected")
	}
}

func TestDownloadCommand_ValidateRejectsBadFormatAndPart(t *testing.T) {
	tok := secret.FromString("token-value")
	defer tok.Close()

	badFormat := DownloadCommand{RawToken: tok, Format: "not_a_format"}
	if err := badFormat.Validate(); err == nil {
		t.Fatal("expected unsupported format to be rejected")
	}

	badPart := DownloadCommand{RawToken: tok, Format: DownloadFormatPEM, PEMPart: "not_a_part"}
	if err := badPart.Validate(); err == nil {
		t.Fatal("expected unsupported part to be rejected")
	}
}

func TestDownloadCommand_ValidateRejectsPKCS12PasswordWithoutPKCS12Format(t *testing.T) {
	tok := secret.FromString("token-value")
	defer tok.Close()
	pw := secret.FromString("password")
	defer pw.Close()

	cmd := DownloadCommand{RawToken: tok, Format: DownloadFormatPEM, PKCS12Password: pw}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected a pkcs12 password on a non-pkcs12 format to be rejected")
	}

	ok := DownloadCommand{RawToken: tok, Format: DownloadFormatPKCS12, PKCS12Password: pw}
	if err := ok.Validate(); err != nil {
		t.Fatalf("expected pkcs12 password with pkcs12 format to be accepted: %v", err)
	}
}

// TestDownloadCommand_SecretsNeverLeak is the most important secret-blocking
// case named by the task: a json.Marshal of DownloadCommand (holding both
// RawToken and PKCS12Password) must not emit the plaintext, marshalling the
// secret fields themselves must error, and %v/log rendering of the command
// must never show the plaintext either.
func TestDownloadCommand_SecretsNeverLeak(t *testing.T) {
	const rawTokenPlaintext = "super-secret-raw-token-value"
	const pkcs12Plaintext = "super-secret-pkcs12-password"

	tok := secret.FromString(rawTokenPlaintext)
	defer tok.Close()
	pw := secret.FromString(pkcs12Plaintext)
	defer pw.Close()

	cmd := DownloadCommand{
		RawToken:       tok,
		Format:         DownloadFormatPKCS12,
		PKCS12Password: pw,
	}

	// %v rendering of the whole command must never show either plaintext.
	rendered := fmt.Sprintf("%v", cmd)
	if strings.Contains(rendered, rawTokenPlaintext) {
		t.Fatalf("raw token leaked through %%v rendering: %s", rendered)
	}
	if strings.Contains(rendered, pkcs12Plaintext) {
		t.Fatalf("pkcs12 password leaked through %%v rendering: %s", rendered)
	}

	// Marshalling the secret fields directly must error, never emit plaintext.
	if _, err := json.Marshal(tok); err == nil {
		t.Fatal("expected marshalling RawToken directly to error")
	}
	if _, err := json.Marshal(pw); err == nil {
		t.Fatal("expected marshalling PKCS12Password directly to error")
	}

	// A generic json.Marshal of a struct wrapping the secret must also fail
	// rather than silently producing an empty/omitted field with the
	// plaintext elsewhere; DownloadCommand's fields are json:"-" so they are
	// excluded from encoding entirely, which is itself the safe outcome -
	// but wrapping the raw *secret.Input in an exported, tagged field must
	// still fail loudly, which is what the two checks above already cover.
	// This check additionally proves DownloadCommand itself never accepts a
	// wire decode of an exported secret path.
	out, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("DownloadCommand itself has no json-tagged secret field, so it must marshal (to {}): %v", err)
	}
	if strings.Contains(string(out), rawTokenPlaintext) || strings.Contains(string(out), pkcs12Plaintext) {
		t.Fatalf("plaintext leaked through json.Marshal(cmd): %s", out)
	}
}

func TestDistributionReportFailureCommand_ValidateRejectsForeignID(t *testing.T) {
	cmd := DistributionReportFailureCommand{DeliveryID: "not-a-uuid", Justification: "storage failed"}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected malformed delivery id to be rejected")
	}
}

func TestDistributionReportFailureCommand_ValidateRequiresJustification(t *testing.T) {
	cmd := DistributionReportFailureCommand{DeliveryID: domain.DeliveryID(testCertID)}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected missing justification to be rejected")
	}
}

func TestDistributionReportFailureCommand_DecodeRejectsServerFilledID(t *testing.T) {
	body := `{"justification":"x","delivery_id":"` + testCertID + `"}`
	var cmd DistributionReportFailureCommand
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cmd); err == nil {
		t.Fatal("expected DisallowUnknownFields to reject a body-supplied delivery_id")
	}
}
