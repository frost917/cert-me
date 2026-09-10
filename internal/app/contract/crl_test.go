package contract

import (
	"testing"

	"cert-me/internal/domain"
)

const testJobID = "00000000-0000-4000-8000-000000000008"

func TestCRLRequestPublicationCommand_ValidateRejectsForeignID(t *testing.T) {
	cmd := CRLRequestPublicationCommand{AuthorityID: "not-a-uuid"}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected malformed authority id to be rejected")
	}
}

func TestCRLRequestPublicationCommand_ValidateAcceptsWellFormedID(t *testing.T) {
	cmd := CRLRequestPublicationCommand{AuthorityID: domain.AuthorityID(testAuthorityID)}
	if err := cmd.Validate(); err != nil {
		t.Fatalf("expected well-formed authority id to validate, got %v", err)
	}
}

func TestCRLPublishCommand_ValidateRejectsForeignIDs(t *testing.T) {
	valid := CRLPublishCommand{JobID: domain.JobID(testJobID), CAKeyGenerationID: domain.CAKeyGenerationID(testCAKeyGenID)}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid command, got %v", err)
	}

	badJob := valid
	badJob.JobID = "not-a-uuid"
	if err := badJob.Validate(); err == nil {
		t.Fatal("expected malformed job id to be rejected")
	}

	badKey := valid
	badKey.CAKeyGenerationID = "not-a-uuid"
	if err := badKey.Validate(); err == nil {
		t.Fatal("expected malformed ca key generation id to be rejected")
	}
}
