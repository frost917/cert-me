package contract

import (
	"testing"

	"cert-me/internal/domain"
)

func TestMaintenanceRotateCommand_ValidateRequiresBothGenerations(t *testing.T) {
	if err := (MaintenanceRotateCommand{}).Validate(); err == nil {
		t.Fatal("expected empty command to be rejected")
	}
	missingNew := MaintenanceRotateCommand{OldEncryptionGenerationID: "gen-1"}
	if err := missingNew.Validate(); err == nil {
		t.Fatal("expected missing new generation to be rejected")
	}
	same := MaintenanceRotateCommand{OldEncryptionGenerationID: "gen-1", NewEncryptionGenerationID: "gen-1"}
	if err := same.Validate(); err == nil {
		t.Fatal("expected identical old/new generations to be rejected")
	}
	ok := MaintenanceRotateCommand{OldEncryptionGenerationID: "gen-1", NewEncryptionGenerationID: "gen-2"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("expected valid command to pass, got %v", err)
	}
}

func TestMaintenanceFinalizeRestoreCommand_ValidateRejectsForeignRunID(t *testing.T) {
	cmd := MaintenanceFinalizeRestoreCommand{Options: MaintenanceFinalizeRestoreOptions{RunID: "not-a-uuid"}}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected malformed run id to be rejected")
	}
	ok := MaintenanceFinalizeRestoreCommand{Options: MaintenanceFinalizeRestoreOptions{RunID: domain.JobID(testJobID)}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("expected valid command to pass, got %v", err)
	}
}

func TestMaintenancePruneAuditCommand_ValidateRequiresCutoff(t *testing.T) {
	if err := (MaintenancePruneAuditCommand{}).Validate(); err == nil {
		t.Fatal("expected zero cutoff to be rejected")
	}
	ok := MaintenancePruneAuditCommand{Cutoff: domain.NewInstant(mustParseTime(t, "2025-01-01T00:00:00Z"))}
	if err := ok.Validate(); err != nil {
		t.Fatalf("expected valid command to pass, got %v", err)
	}
}

func TestMaintenanceRecoverTransfersCommand_Validate(t *testing.T) {
	if err := (MaintenanceRecoverTransfersCommand{}).Validate(); err != nil {
		t.Fatalf("empty command should validate: %v", err)
	}
}

func TestMaintenanceKind_Validate(t *testing.T) {
	if err := MaintenanceKindKeyRotation.Validate(); err != nil {
		t.Fatalf("expected key_rotation to validate: %v", err)
	}
	if err := MaintenanceKind("bogus").Validate(); err == nil {
		t.Fatal("expected unknown kind to be rejected")
	}
}
