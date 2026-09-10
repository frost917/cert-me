package porttest

import (
	"context"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type tlsRepo struct{ s *state }

var _ port.TLSRepository = tlsRepo{}

// GetActiveForUpdate returns the change row for the currently active TLS
// candidate. Before any change has been applied there is nothing active, so
// the caller gets ErrNotFound rather than a zero TLSChange that would read
// as a prepared candidate.
func (r tlsRepo) GetActiveForUpdate(_ context.Context) (domain.TLSChange, error) {
	if r.s.activeTLSChangeKey == "" {
		return domain.TLSChange{}, port.ErrNotFound
	}
	change, ok := r.s.tlsChanges[r.s.activeTLSChangeKey]
	if !ok {
		return domain.TLSChange{}, port.ErrNotFound
	}
	return change, nil
}

func (r tlsRepo) InsertVersion(_ context.Context, version domain.TLSVersion) error {
	if _, ok := r.s.tlsVersions[version.ID()]; ok {
		return ErrDuplicate
	}
	r.s.tlsVersions[version.ID()] = version
	return nil
}

func (r tlsRepo) GetVersion(_ context.Context, id domain.TLSVersionID) (domain.TLSVersion, error) {
	v, ok := r.s.tlsVersions[id]
	if !ok {
		return domain.TLSVersion{}, port.ErrNotFound
	}
	return v, nil
}

// SaveChange upserts the change row keyed by its candidate version id. The
// first Save for a candidate creates the row (expectedVersion 0); later ones
// take the optimistic lock, so two concurrent activations of the same
// candidate cannot both proceed.
func (r tlsRepo) SaveChange(_ context.Context, change domain.TLSChange, expectedVersion domain.Version) error {
	key := change.CandidateVersionID()
	existing, ok := r.s.tlsChanges[key]
	if !ok {
		if expectedVersion != 0 {
			return port.ErrNotFound
		}
		r.s.tlsChanges[key] = change
		return nil
	}
	if existing.Version() != expectedVersion {
		return ErrVersionConflict
	}
	r.s.tlsChanges[key] = change
	return nil
}

// SetActive moves the active pointer. Activate re-checks the version under
// the process-wide TLS mutex and then commits this pointer move before
// calling Installer.Apply (docs/backend-implementation.md §9), so the lock
// check here is what makes a stale activation fail instead of silently
// pointing production at an older candidate.
func (r tlsRepo) SetActive(_ context.Context, expectedVersion domain.Version, versionID domain.TLSVersionID) error {
	if _, ok := r.s.tlsVersions[versionID]; !ok {
		return port.ErrNotFound
	}
	change, ok := r.s.tlsChanges[versionID]
	if !ok {
		return port.ErrNotFound
	}
	if change.Version() != expectedVersion {
		return ErrVersionConflict
	}
	r.s.activeTLSChangeKey = versionID
	return nil
}
