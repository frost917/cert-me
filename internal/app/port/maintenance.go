package port

import (
	"context"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

// MaintenanceRun is the storage projection of one maintenance_runs row.
// Maintenance runs are durable execution history, not jobs: jobs are a
// worker queue, while this row records the phase, completion and restore
// blocking evidence that controls whether normal service may resume.
type MaintenanceRun struct {
	ID          domain.JobID
	CreatedAt   domain.Instant
	UpdatedAt   domain.Instant
	Version     domain.Version
	Kind        contract.MaintenanceKind
	Phase       contract.MaintenancePhase
	DetailsJSON []byte
	StartedAt   domain.Instant
	CompletedAt domain.Instant
	ErrorCode   string
}

// MaintenanceCRLRequirement is the storage projection of one
// maintenance_crl_requirements row. SatisfiedCRLID is the durable evidence
// that a published CRL covers both minimum values; it remains empty while the
// restore run blocks service resumption.
type MaintenanceCRLRequirement struct {
	MaintenanceRunID  domain.JobID
	CAKeyGenerationID domain.CAKeyGenerationID
	MinimumGeneration int64
	MinimumNumber     domain.CRLNumber
	SatisfiedCRLID    domain.CRLDocumentID
}

// MaintenanceRepository stores execution history and its per-CA CRL
// requirements. It is intentionally separate from JobRepository.
type MaintenanceRepository interface {
	GetRunForUpdate(ctx context.Context, id domain.JobID) (MaintenanceRun, error)
	InsertRun(ctx context.Context, run MaintenanceRun) error
	SaveRun(ctx context.Context, run MaintenanceRun, expectedVersion domain.Version) error

	UpsertCRLRequirement(ctx context.Context, requirement MaintenanceCRLRequirement) error
	ListCRLRequirements(ctx context.Context, runID domain.JobID) ([]MaintenanceCRLRequirement, error)
}
