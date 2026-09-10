package porttest

import (
	"context"
	"sort"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type revocationRepo struct{ s *state }

var _ port.RevocationRepository = revocationRepo{}

func (r revocationRepo) FindForUpdate(_ context.Context, issuer domain.CAKeyGenerationID, serial domain.SerialNumber) (domain.Revocation, error) {
	rev, ok := r.s.revocations[revocationKey{issuer: issuer, serial: serial.Hex()}]
	if !ok {
		return domain.Revocation{}, port.ErrNotFound
	}
	return rev, nil
}

func (r revocationRepo) Insert(_ context.Context, revocation domain.Revocation) error {
	key := revocationKey{issuer: revocation.IssuerID(), serial: revocation.Serial().Hex()}
	if _, ok := r.s.revocations[key]; ok {
		return ErrDuplicate
	}
	r.s.revocations[key] = revocation
	return nil
}

// Save checks expectedVersion and then stores the revocation's OWN final
// version. applyRevocations merges and then stamps a generation, so a single
// request legitimately arrives here with Version() == expectedVersion+2
// (docs/backend-implementation.md §5: "저장소는 ... 객체의 최종 version을
// 그대로 저장하며 finalVersion=expectedVersion+1을 강제하지 않는다"). A
// store that recomputed the version would silently corrupt exactly that path.
func (r revocationRepo) Save(_ context.Context, revocation domain.Revocation, expectedVersion domain.Version) error {
	key := revocationKey{issuer: revocation.IssuerID(), serial: revocation.Serial().Hex()}
	existing, ok := r.s.revocations[key]
	if !ok {
		return port.ErrNotFound
	}
	if existing.Version() != expectedVersion {
		return ErrVersionConflict
	}
	r.s.revocations[key] = revocation
	return nil
}

// AppendRevision records one correction in the append-only history. A
// revision number may never be reused for the same revocation: the ledger is
// evidence, not mutable state.
func (r revocationRepo) AppendRevision(_ context.Context, revision port.RevocationRevision) error {
	key := revisionKey{revocationID: revision.RevocationID, revisionNo: revision.RevisionNo}
	if _, ok := r.s.revocationRevisions[key]; ok {
		return ErrDuplicate
	}
	r.s.revocationRevisions[key] = cloneRevision(revision)
	return nil
}

// ListByIssuer returns the CRL snapshot input for one CA key generation,
// ordered by serial so a captured snapshot is reproducible.
func (r revocationRepo) ListByIssuer(_ context.Context, issuer domain.CAKeyGenerationID) ([]domain.Revocation, error) {
	out := make([]domain.Revocation, 0)
	for key, rev := range r.s.revocations {
		if key.issuer == issuer {
			out = append(out, rev)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Serial().Compare(out[j].Serial()) < 0 })
	return out, nil
}

// Revisions exposes the stored correction history to tests.
func (s *Store) Revisions() []port.RevocationRevision {
	snapshot := s.root.Load()
	out := make([]port.RevocationRevision, 0, len(snapshot.revocationRevisions))
	for _, rev := range snapshot.revocationRevisions {
		out = append(out, cloneRevision(rev))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RevocationID != out[j].RevocationID {
			return out[i].RevocationID < out[j].RevocationID
		}
		return out[i].RevisionNo < out[j].RevisionNo
	})
	return out
}
