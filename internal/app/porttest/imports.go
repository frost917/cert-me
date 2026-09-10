package porttest

import (
	"context"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type importRepo struct{ s *state }

var _ port.ImportRepository = importRepo{}

// InsertBatch stores one completed import run. import_batches has no
// version column, so a duplicate id is the only conflict this can raise --
// see port.ImportBatch's doc comment for why there is no expectedVersion
// Save variant.
func (r importRepo) InsertBatch(_ context.Context, batch port.ImportBatch) error {
	if _, ok := r.s.importBatches[batch.ID]; ok {
		return ErrDuplicate
	}
	r.s.importBatches[batch.ID] = batch
	return nil
}

// GetBatch looks up an import batch by its own id.
func (r importRepo) GetBatch(_ context.Context, id domain.ImportBatchID) (port.ImportBatch, error) {
	b, ok := r.s.importBatches[id]
	if !ok {
		return port.ImportBatch{}, port.ErrNotFound
	}
	return b, nil
}

// InsertTakeover creates a new ca_takeovers row and, when it starts pending,
// indexes it by CA key generation so GetPendingTakeoverForUpdate can find it
// -- the same lookup the real schema's ix_ca_takeovers_1
// (ca_key_generation_id,state) index serves.
func (r importRepo) InsertTakeover(_ context.Context, takeover port.Takeover) error {
	if _, ok := r.s.takeovers[takeover.ID]; ok {
		return ErrDuplicate
	}
	r.s.takeovers[takeover.ID] = takeover
	if takeover.State == contract.TakeoverStatePending {
		r.s.pendingTakeover[takeover.CAKeyGenerationID] = takeover.ID
	}
	return nil
}

// GetPendingTakeoverForUpdate locks and returns the pending takeover row for
// caKeyGenerationID. It returns ErrNotFound when there is none.
func (r importRepo) GetPendingTakeoverForUpdate(_ context.Context, caKeyGenerationID domain.CAKeyGenerationID) (port.Takeover, error) {
	id, ok := r.s.pendingTakeover[caKeyGenerationID]
	if !ok {
		return port.Takeover{}, port.ErrNotFound
	}
	t, ok := r.s.takeovers[id]
	if !ok {
		return port.Takeover{}, port.ErrNotFound
	}
	return t, nil
}

// SaveTakeover persists takeover under the standard optimistic-lock
// contract. When the saved state is no longer pending, the pending index
// entry for its CA key generation is removed, so a subsequent
// GetPendingTakeoverForUpdate correctly reports ErrNotFound.
func (r importRepo) SaveTakeover(_ context.Context, takeover port.Takeover, expectedVersion domain.Version) error {
	existing, ok := r.s.takeovers[takeover.ID]
	if !ok {
		return port.ErrNotFound
	}
	if existing.Version != expectedVersion {
		return ErrVersionConflict
	}
	r.s.takeovers[takeover.ID] = takeover
	if takeover.State == contract.TakeoverStatePending {
		r.s.pendingTakeover[takeover.CAKeyGenerationID] = takeover.ID
	} else if r.s.pendingTakeover[takeover.CAKeyGenerationID] == takeover.ID {
		delete(r.s.pendingTakeover, takeover.CAKeyGenerationID)
	}
	return nil
}
