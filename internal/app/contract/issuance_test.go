package contract

import (
	"bytes"
	"encoding/json"
	"testing"

	"cert-me/internal/domain"
)

func validIssueCommand() IssuanceIssueCommand {
	return IssuanceIssueCommand{
		Name:        "fixture.internal",
		AuthorityID: domain.AuthorityID(fixtureUUID),
		Profile:     "server_tls",
		Subject:     SubjectInput{CommonName: "fixture.internal"},
		SANs:        []SANInput{{Type: "dns", Value: "fixture.internal"}},
	}
}

func TestIssuanceIssueCommand_Validate_RejectsMissingRequired(t *testing.T) {
	valid := validIssueCommand()
	cases := map[string]IssuanceIssueCommand{
		"missing name": func() IssuanceIssueCommand { c := valid; c.Name = ""; return c }(),
		"missing authority_id": func() IssuanceIssueCommand {
			c := valid
			c.AuthorityID = ""
			return c
		}(),
		"malformed authority_id": func() IssuanceIssueCommand {
			c := valid
			c.AuthorityID = "not-a-uuid"
			return c
		}(),
		"missing profile": func() IssuanceIssueCommand { c := valid; c.Profile = ""; return c }(),
		"missing subject common_name": func() IssuanceIssueCommand {
			c := valid
			c.Subject = SubjectInput{}
			return c
		}(),
		"server_tls without dns/ip san": func() IssuanceIssueCommand {
			c := valid
			c.SANs = nil
			return c
		}(),
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cmd.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestIssuanceIssueCommand_Validate_Accepts(t *testing.T) {
	if err := validIssueCommand().Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	clientCmd := validIssueCommand()
	clientCmd.Profile = "client_mtls"
	clientCmd.SANs = nil
	if err := clientCmd.Validate(); err != nil {
		t.Fatalf("client_mtls without sans should be valid: %v", err)
	}
}

func TestIssuanceIssueCommand_Validate_RejectsTooManySANs(t *testing.T) {
	cmd := validIssueCommand()
	sans := make([]SANInput, maxSANCount+1)
	for i := range sans {
		sans[i] = SANInput{Type: "dns", Value: "fixture.internal"}
	}
	cmd.SANs = sans
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected more than 100 sans to be rejected")
	}
}

// TestIssuanceRenewCommand_Validate_RejectsMalformedOrForeignID is the B02
// "잘못된 ID/소속 거부" criterion.
func TestIssuanceRenewCommand_Validate_RejectsMalformedOrForeignID(t *testing.T) {
	base := IssuanceRenewCommand{SeriesID: domain.SeriesID(fixtureUUID), SourceCertificateID: domain.CertificateID(fixtureUUID)}
	cases := map[string]IssuanceRenewCommand{
		"malformed series id":        func() IssuanceRenewCommand { c := base; c.SeriesID = "not-a-uuid"; return c }(),
		"malformed source cert id":   func() IssuanceRenewCommand { c := base; c.SourceCertificateID = "not-a-uuid"; return c }(),
		"missing source cert id":     func() IssuanceRenewCommand { c := base; c.SourceCertificateID = ""; return c }(),
		"malformed target authority": func() IssuanceRenewCommand { c := base; c.TargetAuthorityID = "not-a-uuid"; return c }(),
		"malformed transition id":    func() IssuanceRenewCommand { c := base; c.TransitionID = "not-a-uuid"; return c }(),
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cmd.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("unexpected error on the well-formed base case: %v", err)
	}
}

func TestIssuanceRenewCommand_JSONCannotSetSeriesID(t *testing.T) {
	body := []byte(`{"SeriesID":"` + fixtureUUID + `","source_certificate_id":"` + fixtureUUID + `"}`)
	var cmd IssuanceRenewCommand
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cmd); err == nil {
		t.Fatal("expected decode to reject an attempt to set the path-derived series id")
	}
	if cmd.SeriesID != "" {
		t.Fatal("series id must not have been populated from the body")
	}
}

func TestIssuanceReissueCommand_Validate_RejectsMissingRequired(t *testing.T) {
	base := IssuanceReissueCommand{
		SeriesID:            domain.SeriesID(fixtureUUID),
		SourceCertificateID: domain.CertificateID(fixtureUUID),
		Reason:              ReissueReasonManualRotation,
	}
	cases := map[string]IssuanceReissueCommand{
		"missing source_certificate_id": func() IssuanceReissueCommand { c := base; c.SourceCertificateID = ""; return c }(),
		"missing reason":                func() IssuanceReissueCommand { c := base; c.Reason = ""; return c }(),
		"unsupported reason":            func() IssuanceReissueCommand { c := base; c.Reason = "bogus"; return c }(),
		"malformed series id":           func() IssuanceReissueCommand { c := base; c.SeriesID = "not-a-uuid"; return c }(),
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cmd.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("unexpected error on the well-formed base case: %v", err)
	}
}

func TestIssuanceUpdateSeriesCommand_Validate(t *testing.T) {
	if err := (IssuanceUpdateSeriesCommand{SeriesID: domain.SeriesID(fixtureUUID)}).Validate(); err == nil {
		t.Fatal("expected an empty patch to be rejected (minProperties: 1)")
	}
	if err := (IssuanceUpdateSeriesCommand{SeriesID: "not-a-uuid", Name: strPtr("n")}).Validate(); err == nil {
		t.Fatal("expected malformed series id to be rejected")
	}
	if err := (IssuanceUpdateSeriesCommand{SeriesID: domain.SeriesID(fixtureUUID), Name: strPtr("n")}).Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIssuanceUpdateSeriesCommand_JSONCannotSetSeriesID(t *testing.T) {
	body := []byte(`{"SeriesID":"` + fixtureUUID + `","name":"n"}`)
	var cmd IssuanceUpdateSeriesCommand
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cmd); err == nil {
		t.Fatal("expected decode to reject an attempt to set the path-derived series id")
	}
}

func TestIssuanceArchiveSeriesCommand_Validate(t *testing.T) {
	if err := (IssuanceArchiveSeriesCommand{SeriesID: "not-a-uuid"}).Validate(); err == nil {
		t.Fatal("expected malformed series id to be rejected")
	}
	if err := (IssuanceArchiveSeriesCommand{SeriesID: domain.SeriesID(fixtureUUID)}).Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
