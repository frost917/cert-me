package porttest

import (
	"context"
	"sort"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type maintenanceRepo struct{ s *state }

var _ port.MaintenanceRepository = maintenanceRepo{}

func (r maintenanceRepo) GetRunForUpdate(_ context.Context, id domain.JobID) (port.MaintenanceRun, error) {
	run, ok := r.s.maintenanceRuns[id]
	if !ok {
		return port.MaintenanceRun{}, port.ErrNotFound
	}
	return cloneMaintenanceRun(run), nil
}

func (r maintenanceRepo) InsertRun(_ context.Context, run port.MaintenanceRun) error {
	if _, ok := r.s.maintenanceRuns[run.ID]; ok {
		return ErrDuplicate
	}
	r.s.maintenanceRuns[run.ID] = cloneMaintenanceRun(run)
	return nil
}

func (r maintenanceRepo) SaveRun(_ context.Context, run port.MaintenanceRun, expectedVersion domain.Version) error {
	existing, ok := r.s.maintenanceRuns[run.ID]
	if !ok {
		return port.ErrNotFound
	}
	if existing.Version != expectedVersion {
		return ErrVersionConflict
	}
	r.s.maintenanceRuns[run.ID] = cloneMaintenanceRun(run)
	return nil
}

func (r maintenanceRepo) UpsertCRLRequirement(_ context.Context, requirement port.MaintenanceCRLRequirement) error {
	if _, ok := r.s.maintenanceRuns[requirement.MaintenanceRunID]; !ok {
		return port.ErrNotFound
	}
	if _, err := domain.ParseCAKeyGenerationID(string(requirement.CAKeyGenerationID)); err != nil {
		return err
	}
	if requirement.MinimumGeneration < 0 || requirement.MinimumNumber.IsZero() {
		return domain.ErrInvalidValue
	}
	key := maintenanceRequirementKey{runID: requirement.MaintenanceRunID, issuer: requirement.CAKeyGenerationID}
	r.s.maintenanceCRLRequirements[key] = requirement
	return nil
}

func (r maintenanceRepo) ListCRLRequirements(_ context.Context, runID domain.JobID) ([]port.MaintenanceCRLRequirement, error) {
	if _, ok := r.s.maintenanceRuns[runID]; !ok {
		return nil, port.ErrNotFound
	}
	out := make([]port.MaintenanceCRLRequirement, 0)
	for key, requirement := range r.s.maintenanceCRLRequirements {
		if key.runID == runID {
			out = append(out, requirement)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CAKeyGenerationID < out[j].CAKeyGenerationID })
	return out, nil
}
