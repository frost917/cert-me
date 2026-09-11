package port

import (
	"context"

	"cert-me/internal/domain"
)

// SetupStage mirrors installation.setup_stage
// (docs/data-model.md "설치·관리자·인증": "account_required → pki_required →
// complete"). There is no domain object for the singleton installation row;
// it is pure setup-progress bookkeeping with the ordering itself as its only
// rule, enforced by SetupService rather than by a domain transition.
type SetupStage string

const (
	SetupStageAccountRequired SetupStage = "account_required"
	SetupStagePKIRequired     SetupStage = "pki_required"
	SetupStageComplete        SetupStage = "complete"
)

// Installation is the port-level projection of the fixed-PK=1 installation
// row: the anchor for first-admin creation, the active encryption
// generation and the active HTTPS version pointer
// (docs/data-model.md "설치·관리자·인증").
type Installation struct {
	SetupStage                   SetupStage
	FirstAdminID                 domain.AccountID // empty until the first admin exists
	ActiveEncryptionGenerationID string
	ActiveTLSVersionID           domain.TLSVersionID // empty before any HTTPS version is active
	ServiceMode                  string
	Version                      domain.Version
}

// Settings is the port-level projection of the fixed-PK=1 service_settings
// row. The JSON payload's structure is service-owned and validated
// (docs/data-model.md "검증된 형식만 저장"); the repository stores and
// returns it as an opaque, already-validated blob rather than parsing it.
type Settings struct {
	SchemaVersion int
	SettingsJSON  []byte
	Version       domain.Version
	UpdatedBy     domain.AccountID
}

// InstallationRepository is the storage boundary for the singleton
// installation and service_settings rows
// (docs/backend-implementation.md §4 table row "InstallationRepository").
type InstallationRepository interface {
	// GetForUpdate locks and returns the installation row. SetupService uses
	// it to re-confirm setup_stage inside the commit before creating the
	// first admin (docs/backend-implementation.md §8 "installation 미설정
	// 재확인").
	GetForUpdate(ctx context.Context) (Installation, error)

	// Save persists installation. See AccountRepository.SaveAccount for the
	// expectedVersion/finalVersion contract every Save method in this
	// package follows.
	Save(ctx context.Context, installation Installation, expectedVersion domain.Version) error

	// GetSettings returns the current settings row without locking; a
	// service that is about to write it re-reads with the version it gets
	// back as its own expectedVersion input to Save.
	GetSettings(ctx context.Context) (Settings, error)

	// SaveSettings persists settings under the standard optimistic-lock
	// contract. SettingsService.Update requires the version (§3 "Update에
	// version 필수"); this method does not itself decide whether a version
	// was supplied, only enforce whichever one it is given.
	SaveSettings(ctx context.Context, settings Settings, expectedVersion domain.Version) error
}
