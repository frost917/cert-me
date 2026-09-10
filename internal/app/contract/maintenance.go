package contract

import (
	"cert-me/internal/domain"
)

// This file is MaintenanceService's command/result contract
// (docs/backend-implementation.md §3, §9): Rotate, FinalizeRestore,
// RecoverTransfers, PruneAudit.
//
// Every method here is runtime-only (§5 "runtime이 오프라인 허가 또는 제한된
// 복구 실행 경로로 호출") so none of these commands carry JSON tags, and
// none of the results below are OpenAPI schemas -- §3 says so explicitly for
// MaintenanceResult/RecoverySummary ("이들은 내부 결과이며 새 공개 HTTP
// API를 만들지 않는다"), and PruneAudit's plain count never needed one
// either.

// MaintenanceKind names which maintenance run produced a MaintenanceResult,
// so one result shape can serve Rotate and FinalizeRestore without a
// separate struct per operation.
type MaintenanceKind string

const (
	MaintenanceKindKeyRotation     MaintenanceKind = "key_rotation"
	MaintenanceKindRestoreFinalize MaintenanceKind = "restore_finalize"
)

func (k MaintenanceKind) Validate() error {
	switch k {
	case MaintenanceKindKeyRotation, MaintenanceKindRestoreFinalize:
		return nil
	default:
		return NewAppError(ErrorKindValidation, "maintenance_kind_invalid", "unsupported maintenance kind")
	}
}

// MaintenancePhase is the run's own progress marker, distinct from
// Completed: a run can be Completed=false while still reporting which phase
// it stopped in (e.g. blocked on BlockingCAIDs).
type MaintenancePhase string

const (
	MaintenancePhaseStarted  MaintenancePhase = "started"
	MaintenancePhaseBlocked  MaintenancePhase = "blocked"
	MaintenancePhaseFinished MaintenancePhase = "finished"
)

// MaintenanceRotateCommand is Rotate's command
// (§3 "Rotate(oldKey,newKey) → MaintenanceResult"). Both keys are handled by
// the KeyEngine/secret adapters, not carried as bytes here: Rotate's own
// job is to name which encryption generations are involved, matching §9
// "외부 Secret 파일을 변경하지 않고 UoW 하나로 암호문·verifier·키 세대를
// 바꾼다."
type MaintenanceRotateCommand struct {
	OldEncryptionGenerationID string
	NewEncryptionGenerationID string
}

func (c MaintenanceRotateCommand) Validate() error {
	if c.OldEncryptionGenerationID == "" {
		return NewAppError(ErrorKindValidation, "old_encryption_generation_required", "old encryption generation id must not be empty")
	}
	if c.NewEncryptionGenerationID == "" {
		return NewAppError(ErrorKindValidation, "new_encryption_generation_required", "new encryption generation id must not be empty")
	}
	if c.OldEncryptionGenerationID == c.NewEncryptionGenerationID {
		return NewAppError(ErrorKindValidation, "encryption_generation_unchanged", "new encryption generation must differ from the old one")
	}
	return nil
}

// MaintenanceFinalizeRestoreOptions carries the operator's restore choices
// that FinalizeRestore needs before it can run
// (§9 "FinalizeRestore는 세션/토큰 무효화·대기 키 삭제/폐기와 필요한 CRL
// 작업을 먼저 커밋하고 영속 복구 단계로 추적한다").
type MaintenanceFinalizeRestoreOptions struct {
	RunID                 domain.JobID
	InvalidateAllSessions bool
	DeletePendingKeys     bool
}

// MaintenanceFinalizeRestoreCommand is FinalizeRestore's command.
type MaintenanceFinalizeRestoreCommand struct {
	Options MaintenanceFinalizeRestoreOptions
}

func (c MaintenanceFinalizeRestoreCommand) Validate() error {
	_, err := domain.ParseJobID(string(c.Options.RunID))
	if err != nil {
		return FromDomainError(err)
	}
	return nil
}

// MaintenanceResult is the internal result §3 names explicitly:
// "MaintenanceResult는 RunID, Kind, Phase, Completed, BlockingCAIDs다."
type MaintenanceResult struct {
	RunID         domain.JobID
	Kind          MaintenanceKind
	Phase         MaintenancePhase
	Completed     bool
	BlockingCAIDs []domain.AuthorityID
}

// MaintenanceRecoverTransfersCommand is the empty command for
// RecoverTransfers.
type MaintenanceRecoverTransfersCommand struct{}

func (MaintenanceRecoverTransfersCommand) Validate() error { return nil }

// RecoverySummary is the internal result §3 names explicitly:
// "RecoverySummary는 Checked/Changed/Failed 카운터와 비밀 없는 FailedIDs다."
// FailedIDs is deliberately typed as DeliveryID: the recovery scan this
// summarizes is the restart transferring-delivery sweep
// (§9 "초기 재시작 복구에서 transferring을 failed로 바꾸는 동안"), never a
// key material id or any other value that could carry secret-adjacent
// meaning.
type RecoverySummary struct {
	Checked   int64
	Changed   int64
	Failed    int64
	FailedIDs []domain.DeliveryID
}

// MaintenancePruneAuditCommand is PruneAudit's command
// (§3 "PruneAudit(cutoff) → count").
type MaintenancePruneAuditCommand struct {
	Cutoff domain.Instant
}

func (c MaintenancePruneAuditCommand) Validate() error {
	if c.Cutoff.IsZero() {
		return NewAppError(ErrorKindValidation, "cutoff_required", "cutoff must be set")
	}
	return nil
}

// MaintenancePruneAuditResult is PruneAudit's plain count result.
type MaintenancePruneAuditResult struct {
	Deleted int64
}
