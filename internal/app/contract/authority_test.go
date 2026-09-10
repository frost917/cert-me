package contract

import (
	"bytes"
	"encoding/json"
	"testing"

	"cert-me/internal/domain"
)

const fixtureUUID = "00000000-0000-4000-8000-000000000001"
const otherFixtureUUID = "00000000-0000-4000-8000-000000000002"

func validAuthorityCreateCommand() AuthorityCreateCommand {
	return AuthorityCreateCommand{
		Kind:    "root",
		Name:    "Fixture Root",
		Subject: SubjectInput{CommonName: "Fixture Root CA"},
	}
}

func TestAuthorityCreateCommand_Validate_RejectsMissingRequired(t *testing.T) {
	cases := map[string]AuthorityCreateCommand{
		"missing kind":                {Name: "n", Subject: SubjectInput{CommonName: "cn"}},
		"missing name":                {Kind: "root", Subject: SubjectInput{CommonName: "cn"}},
		"missing subject common_name": {Kind: "root", Name: "n"},
		"unsupported kind":            {Kind: "bogus", Name: "n", Subject: SubjectInput{CommonName: "cn"}},
		"bootstrap kind rejected":     {Kind: "bootstrap", Name: "n", Subject: SubjectInput{CommonName: "cn"}},
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cmd.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestAuthorityCreateCommand_Validate_IntermediateRequiresParent(t *testing.T) {
	cmd := AuthorityCreateCommand{Kind: "intermediate", Name: "n", Subject: SubjectInput{CommonName: "cn"}}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected intermediate without parent_authority_id to be rejected")
	}
	cmd.ParentAuthorityID = domain.AuthorityID(fixtureUUID)
	if err := cmd.Validate(); err != nil {
		t.Fatalf("unexpected error once parent is set: %v", err)
	}
}

func TestAuthorityCreateCommand_Validate_RootForbidsParent(t *testing.T) {
	cmd := validAuthorityCreateCommand()
	cmd.ParentAuthorityID = domain.AuthorityID(fixtureUUID)
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected root with a parent_authority_id to be rejected")
	}
}

func TestAuthorityCreateCommand_Validate_RejectsMalformedParentID(t *testing.T) {
	cmd := AuthorityCreateCommand{Kind: "intermediate", Name: "n", Subject: SubjectInput{CommonName: "cn"}, ParentAuthorityID: "not-a-uuid"}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected malformed parent_authority_id to be rejected")
	}
}

// TestAuthorityRenameCommand_Validate_RejectsMalformedOrForeignID is the B02
// "잘못된 ID/소속 거부" criterion: a target id that is not a well-formed uuid
// must never reach the service layer.
func TestAuthorityRenameCommand_Validate_RejectsMalformedOrForeignID(t *testing.T) {
	cases := []domain.AuthorityID{"", "not-a-uuid", "00000000-0000-0000-0000-00000000000"}
	for _, id := range cases {
		cmd := AuthorityRenameCommand{AuthorityID: id, Name: "New Name"}
		if err := cmd.Validate(); err == nil {
			t.Fatalf("expected malformed authority id %q to be rejected", id)
		}
	}
}

func TestAuthorityRenameCommand_JSONCannotSetAuthorityID(t *testing.T) {
	body := []byte(`{"AuthorityID":"` + fixtureUUID + `","name":"New Name"}`)
	var cmd AuthorityRenameCommand
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cmd); err == nil {
		t.Fatal("expected decode to reject an attempt to set the path-derived authority id")
	}
	if cmd.AuthorityID != "" {
		t.Fatal("authority id must not have been populated from the body")
	}
}

func TestAuthorityRenameCommand_Validate_RejectsMissingName(t *testing.T) {
	cmd := AuthorityRenameCommand{AuthorityID: domain.AuthorityID(fixtureUUID), Name: ""}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected missing name to be rejected")
	}
}

func TestAuthoritySetIssuanceStateCommand_Validate(t *testing.T) {
	valid := AuthoritySetIssuanceStateCommand{AuthorityID: domain.AuthorityID(fixtureUUID), State: "enabled"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	badState := valid
	badState.State = "inventory"
	if err := badState.Validate(); err == nil {
		t.Fatal("expected the storage-only inventory state to be rejected")
	}
	badID := valid
	badID.AuthorityID = "not-a-uuid"
	if err := badID.Validate(); err == nil {
		t.Fatal("expected malformed authority id to be rejected")
	}
}

// F2: KeyDestruction lists "justification" as required in the OpenAPI
// document, so an empty justification must be rejected, not merely one that
// is too long.
func TestAuthorityDestroyKeyCommand_Validate_RejectsMissingRequired(t *testing.T) {
	cases := map[string]AuthorityDestroyKeyCommand{
		"missing key_generation_id":   {AuthorityID: domain.AuthorityID(fixtureUUID), Justification: "reason"},
		"malformed authority id":      {AuthorityID: "bad", KeyGenerationID: domain.CAKeyGenerationID(fixtureUUID), Justification: "reason"},
		"malformed key generation id": {AuthorityID: domain.AuthorityID(fixtureUUID), KeyGenerationID: "bad", Justification: "reason"},
		"missing justification":       {AuthorityID: domain.AuthorityID(fixtureUUID), KeyGenerationID: domain.CAKeyGenerationID(fixtureUUID), Justification: ""},
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cmd.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestAuthorityArchiveCommand_Validate_RejectsMalformedID(t *testing.T) {
	if err := (AuthorityArchiveCommand{AuthorityID: "not-a-uuid"}).Validate(); err == nil {
		t.Fatal("expected malformed authority id to be rejected")
	}
	if err := (AuthorityArchiveCommand{AuthorityID: domain.AuthorityID(otherFixtureUUID)}).Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthorityArchiveCommand_JSONBodyMustBeEmpty(t *testing.T) {
	// The archive route has an empty request body; a client that tries to
	// smuggle the target id through the body must be rejected the same way
	// as every other server-filled field.
	body := []byte(`{"AuthorityID":"` + fixtureUUID + `"}`)
	var cmd AuthorityArchiveCommand
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cmd); err == nil {
		t.Fatal("expected decode to reject the field")
	}
}
