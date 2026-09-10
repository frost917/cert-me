package contract

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

func TestTLSUploadCandidateCommand_ValidateRequiresCertificateAndKey(t *testing.T) {
	if err := (TLSUploadCandidateCommand{}).Validate(); err == nil {
		t.Fatal("expected empty command to be rejected")
	}
	missingKey := TLSUploadCandidateCommand{Certificate: []byte("cert")}
	if err := missingKey.Validate(); err == nil {
		t.Fatal("expected missing key to be rejected")
	}
	ok := TLSUploadCandidateCommand{Certificate: []byte("cert"), Key: []byte("key")}
	if err := ok.Validate(); err != nil {
		t.Fatalf("expected valid upload to pass, got %v", err)
	}
}

func TestTLSUploadCandidateCommand_PassphraseNeverLeaks(t *testing.T) {
	const plaintext = "super-secret-tls-key-passphrase"
	pw := secret.FromString(plaintext)
	defer pw.Close()
	cmd := TLSUploadCandidateCommand{Certificate: []byte("cert"), Key: []byte("key"), Passphrase: pw}
	rendered := fmt.Sprintf("%v", cmd)
	if strings.Contains(rendered, plaintext) {
		t.Fatalf("passphrase leaked through %%v rendering: %s", rendered)
	}
	if _, err := json.Marshal(pw); err == nil {
		t.Fatal("expected marshalling the passphrase secret directly to error")
	}
}

func TestTLSIssueCandidateCommand_ValidateRequiredFields(t *testing.T) {
	base := TLSIssueCandidateCommand{
		AuthorityID: domain.AuthorityID(testAuthorityID),
		Subject:     SubjectInput{CommonName: "internal.example"},
		SANs:        []SANInput{{Type: "dns", Value: "internal.example"}},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("expected valid command to pass, got %v", err)
	}

	badAuthority := base
	badAuthority.AuthorityID = "not-a-uuid"
	if err := badAuthority.Validate(); err == nil {
		t.Fatal("expected malformed authority id to be rejected")
	}

	missingSANs := base
	missingSANs.SANs = nil
	if err := missingSANs.Validate(); err == nil {
		t.Fatal("expected missing sans to be rejected")
	}

	badAlgorithm := base
	badAlgorithm.KeyAlgorithm = "not_a_real_algorithm"
	if err := badAlgorithm.Validate(); err == nil {
		t.Fatal("expected unsupported key_algorithm to be rejected")
	}
}

func TestTLSActivateCommand_ValidateRejectsForeignID(t *testing.T) {
	cmd := TLSActivateCommand{CandidateID: "not-a-uuid"}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected malformed candidate id to be rejected")
	}
}

func TestTLSActivateCommand_DecodeRejectsUnknownField(t *testing.T) {
	body := `{"candidate_id":"` + testCAKeyGenID + `","extra_field":"x"}`
	var cmd TLSActivateCommand
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cmd); err == nil {
		t.Fatal("expected DisallowUnknownFields to reject an unknown field")
	}
}

func TestTLSEmptyCommands_Validate(t *testing.T) {
	if err := (TLSStatusQuery{}).Validate(); err != nil {
		t.Fatalf("empty status query should validate: %v", err)
	}
	if err := (TLSReloadCommand{}).Validate(); err != nil {
		t.Fatalf("empty reload command should validate: %v", err)
	}
	if err := (TLSBootstrapCommand{}).Validate(); err != nil {
		t.Fatalf("empty bootstrap command should validate: %v", err)
	}
	if err := (TLSReconcileCommand{}).Validate(); err != nil {
		t.Fatalf("empty reconcile command should validate: %v", err)
	}
}
