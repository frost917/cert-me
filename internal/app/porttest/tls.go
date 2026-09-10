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

// SetActive moves the installation's active_tls_version_id pointer to
// versionID. Per port.TLSRepository.SetActive's doc comment, expectedVersion
// guards the *installation* row's own version, not the TLSChange's --
// Activate's sequence is "version 재검사 → DB committed 기록/활성 포인터
// 변경 → Installer.Apply → DB applied 기록" (docs/backend-implementation.md
// §9), and the installation pointer change is a separate optimistic-locked
// write from the TLSChange row SaveChange advances alongside it. So this
// checks and bumps r.s.installation.Version, and writes
// Installation.ActiveTLSVersionID, leaving the TLSChange row itself
// untouched (that row's own version is SaveChange's concern).
func (r tlsRepo) SetActive(_ context.Context, expectedVersion domain.Version, versionID domain.TLSVersionID) error {
	if _, ok := r.s.tlsVersions[versionID]; !ok {
		return port.ErrNotFound
	}
	if _, ok := r.s.tlsChanges[versionID]; !ok {
		return port.ErrNotFound
	}
	if !r.s.installationSet {
		return port.ErrNotFound
	}
	if r.s.installation.Version != expectedVersion {
		return ErrVersionConflict
	}
	installation := r.s.installation
	installation.ActiveTLSVersionID = versionID
	installation.Version = installation.Version.Next()
	r.s.installation = installation
	r.s.activeTLSChangeKey = versionID
	return nil
}
