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
	// Clone on the way in: batch.Manifest.Files/Result's slices and nested
	// pointers are public and mutable, so storing batch as-is would let the
	// caller mutate published state after Insert returns (the reviewer's
	// [P2] finding).
	r.s.importBatches[batch.ID] = cloneImportBatch(batch)
	return nil
}

// GetBatch looks up an import batch by its own id.
func (r importRepo) GetBatch(_ context.Context, id domain.ImportBatchID) (port.ImportBatch, error) {
	b, ok := r.s.importBatches[id]
	if !ok {
		return port.ImportBatch{}, port.ErrNotFound
	}
	// Clone on the way out for the same reason as InsertBatch: a caller
	// mutating the returned batch's Manifest.Files or Result must not reach
	// the map's stored value, even (per the reviewer's exact scenario) when
	// the mutation happens inside a later Write whose callback then errors
	// and rolls back.
	return cloneImportBatch(b), nil
}

// InsertTakeover creates a new ca_takeovers row and, when it starts pending,
// indexes it by CA key generation so GetPendingTakeoverForUpdate can find it
// -- the same lookup the real schema's ix_ca_takeovers_1
// (ca_key_generation_id,state) index serves.
func (r importRepo) InsertTakeover(_ context.Context, takeover port.Takeover) error {
	if _, ok := r.s.takeovers[takeover.ID]; ok {
		return ErrDuplicate
	}
	// Clone on the way in: Evidence.CRLSHA256Hex is a public mutable slice
	// (the reviewer's other named field).
	r.s.takeovers[takeover.ID] = cloneTakeover(takeover)
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
	return cloneTakeover(t), nil
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
	r.s.takeovers[takeover.ID] = cloneTakeover(takeover)
	if takeover.State == contract.TakeoverStatePending {
		r.s.pendingTakeover[takeover.CAKeyGenerationID] = takeover.ID
	} else if r.s.pendingTakeover[takeover.CAKeyGenerationID] == takeover.ID {
		delete(r.s.pendingTakeover, takeover.CAKeyGenerationID)
	}
	return nil
}
