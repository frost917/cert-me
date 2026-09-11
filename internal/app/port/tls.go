package port

import (
	"context"

	"cert-me/internal/domain"
)

// TLSRepository is the storage boundary for internal HTTPS candidates and
// the change-of-active-version ledger
// (docs/backend-implementation.md §4 table row "TLSRepository";
// docs/data-model.md "내부 HTTPS·유지보수·작업·감사").
type TLSRepository interface {
	// GetActiveForUpdate locks and returns the currently active tls_changes
	// row (the one in the applied phase, i.e. the change whose candidate is
	// live), so Activate can re-check its version before the installer
	// swap. On a fresh installation with no HTTPS history yet it returns
	// ErrNotFound.
	GetActiveForUpdate(ctx context.Context) (domain.TLSChange, error)

	// InsertVersion stores a newly validated TLS snapshot (candidate or
	// bootstrap).
	InsertVersion(ctx context.Context, version domain.TLSVersion) error

	// GetVersion returns one stored TLS version by id, used to re-validate a
	// stored snapshot during Reconcile
	// (docs/backend-implementation.md §9 "DB의 검증된 snapshot만 사용한다").
	GetVersion(ctx context.Context, id domain.TLSVersionID) (domain.TLSVersion, error)

	// SaveChange persists change under the standard optimistic-lock contract
	// (see AccountRepository.SaveAccount). It also serves as the insert path
	// for a freshly prepared candidate's first tls_changes row.
	SaveChange(ctx context.Context, change domain.TLSChange, expectedVersion domain.Version) error

	// SetActive moves the installation's active_tls_version_id pointer to
	// versionID. expectedVersion guards the installation row's own version,
	// not the TLSChange's -- Activate's sequence is "version 재검사 → DB
	// committed 기록/활성 포인터 변경 → Installer.Apply → DB applied 기록"
	// (docs/backend-implementation.md §9), and the installation pointer
	// change is a separate optimistic-locked write from the TLSChange row
	// SaveChange advances alongside it in the same commit.
	SetActive(ctx context.Context, expectedVersion domain.Version, versionID domain.TLSVersionID) error
}
