package porttest

import (
	"context"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type installationRepo struct{ s *state }

var _ port.InstallationRepository = installationRepo{}

func (r installationRepo) GetForUpdate(_ context.Context) (port.Installation, error) {
	if !r.s.installationSet {
		return port.Installation{}, port.ErrNotFound
	}
	return r.s.installation, nil
}

// Save follows the standard optimistic-lock contract: check against
// expectedVersion, then store the object's own final Version()
// (docs/backend-implementation.md §5).
func (r installationRepo) Save(_ context.Context, installation port.Installation, expectedVersion domain.Version) error {
	if !r.s.installationSet {
		// The singleton row is created by the first Save, which a caller
		// signals with expectedVersion 0; anything else is a lost update.
		if expectedVersion != 0 {
			return port.ErrNotFound
		}
		r.s.installation = installation
		r.s.installationSet = true
		return nil
	}
	if r.s.installation.Version != expectedVersion {
		return ErrVersionConflict
	}
	r.s.installation = installation
	return nil
}

func (r installationRepo) GetSettings(_ context.Context) (port.Settings, error) {
	if !r.s.settingsSet {
		return port.Settings{}, port.ErrNotFound
	}
	return cloneSettings(r.s.settings), nil
}

func (r installationRepo) SaveSettings(_ context.Context, settings port.Settings, expectedVersion domain.Version) error {
	if !r.s.settingsSet {
		if expectedVersion != 0 {
			return port.ErrNotFound
		}
		r.s.settings = cloneSettings(settings)
		r.s.settingsSet = true
		return nil
	}
	if r.s.settings.Version != expectedVersion {
		return ErrVersionConflict
	}
	r.s.settings = cloneSettings(settings)
	return nil
}
