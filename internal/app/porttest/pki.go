package porttest

import (
	"context"
	"sort"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type pkiRepo struct{ s *state }

var _ port.PKIRepository = pkiRepo{}

// GetIssuerForUpdate returns the stored authority. The docs table calls this
// "IssuerContext", but domain.IssuerContext is the request-specific facts a
// repository read cannot know (see port.PKIRepository's doc comment).
func (r pkiRepo) GetIssuerForUpdate(_ context.Context, authorityID domain.AuthorityID) (domain.Authority, error) {
	a, ok := r.s.authorities[authorityID]
	if !ok {
		return domain.Authority{}, port.ErrNotFound
	}
	return a, nil
}

// GetSeriesForUpdate returns the series together with the key generation its
// own current_key_generation_id points at, both from this one locked read,
// so a renewal cannot be planned against a generation the series has already
// moved past.
func (r pkiRepo) GetSeriesForUpdate(_ context.Context, seriesID domain.SeriesID) (port.SeriesSnapshot, error) {
	series, ok := r.s.series[seriesID]
	if !ok {
		return port.SeriesSnapshot{}, port.ErrNotFound
	}
	snapshot := port.SeriesSnapshot{Series: series}
	if genID := series.CurrentKeyGenerationID(); genID != "" {
		gen, ok := r.s.leafKeyGenerations[genID]
		if !ok {
			return port.SeriesSnapshot{}, port.ErrNotFound
		}
		snapshot.CurrentKeyGeneration = gen
	}
	return snapshot, nil
}

func (r pkiRepo) FindCertificateByDER(_ context.Context, derSHA256 domain.Fingerprint) (domain.Certificate, error) {
	id, ok := r.s.certificatesByDER[derSHA256.Hex()]
	if !ok {
		return domain.Certificate{}, port.ErrNotFound
	}
	return r.s.certificates[id], nil
}

// GetCertificate looks up a certificate by its own id, the read
// Renew/Reissue need to resolve a command's source_certificate_id (see
// port.PKIRepository.GetCertificate's doc comment).
func (r pkiRepo) GetCertificate(_ context.Context, id domain.CertificateID) (domain.Certificate, error) {
	cert, ok := r.s.certificates[id]
	if !ok {
		return domain.Certificate{}, port.ErrNotFound
	}
	return cert, nil
}

func (r pkiRepo) FindKeyBySPKI(_ context.Context, spkiSHA256 domain.Fingerprint) (port.KeyMaterial, error) {
	id, ok := r.s.keyMaterialsBySPKI[spkiSHA256.Hex()]
	if !ok {
		return port.KeyMaterial{}, port.ErrNotFound
	}
	return r.s.keyMaterials[id], nil
}

// SerialExists checks certificates and revocations both, since a serial may
// be recorded as revoked for a certificate this installation never stored
// (docs/backend-implementation.md §8: "commit에서 certificates·revocations
// 양쪽과 충돌 검사한다").
func (r pkiRepo) SerialExists(_ context.Context, issuer domain.CAKeyGenerationID, serial domain.SerialNumber) (bool, error) {
	for _, cert := range r.s.certificates {
		if cert.IssuerCAKeyGenerationID() == issuer && cert.Serial().Equal(serial) {
			return true, nil
		}
	}
	if _, ok := r.s.revocations[revocationKey{issuer: issuer, serial: serial.Hex()}]; ok {
		return true, nil
	}
	return false, nil
}

func (r pkiRepo) InsertAuthority(_ context.Context, authority domain.Authority) error {
	if _, ok := r.s.authorities[authority.ID()]; ok {
		return ErrDuplicate
	}
	r.s.authorities[authority.ID()] = authority
	return nil
}

func (r pkiRepo) InsertKeyGeneration(_ context.Context, generation port.CAKeyGeneration) error {
	if _, ok := r.s.caKeyGenerations[generation.ID]; ok {
		return ErrDuplicate
	}
	r.s.caKeyGenerations[generation.ID] = generation
	return nil
}

// InsertKeyMaterial creates a new key_materials row, keyed by id and indexed
// by SPKI fingerprint the same way FindKeyBySPKI reads it back.
func (r pkiRepo) InsertKeyMaterial(_ context.Context, material port.KeyMaterial) error {
	if _, ok := r.s.keyMaterials[material.ID]; ok {
		return ErrDuplicate
	}
	spkiHex := material.PublicKey.Fingerprint().Hex()
	if _, ok := r.s.keyMaterialsBySPKI[spkiHex]; ok {
		return ErrDuplicate
	}
	r.s.keyMaterials[material.ID] = material
	r.s.keyMaterialsBySPKI[spkiHex] = material.ID
	return nil
}

// InsertLeafKeyGeneration creates a new leaf_key_generations row.
func (r pkiRepo) InsertLeafKeyGeneration(_ context.Context, generation domain.LeafKeyGeneration) error {
	if _, ok := r.s.leafKeyGenerations[generation.ID()]; ok {
		return ErrDuplicate
	}
	r.s.leafKeyGenerations[generation.ID()] = generation
	return nil
}

// SaveLeafKeyGeneration persists generation's renewal_count when a renewal
// reuses the current key. See port.PKIRepository.SaveLeafKeyGeneration's doc
// comment for why this takes no expectedVersion.
func (r pkiRepo) SaveLeafKeyGeneration(_ context.Context, generation domain.LeafKeyGeneration) error {
	if _, ok := r.s.leafKeyGenerations[generation.ID()]; !ok {
		return port.ErrNotFound
	}
	r.s.leafKeyGenerations[generation.ID()] = generation
	return nil
}

func (r pkiRepo) InsertCertificate(_ context.Context, certificate domain.Certificate) error {
	if _, ok := r.s.certificates[certificate.ID()]; ok {
		return ErrDuplicate
	}
	fingerprint := domain.NewFingerprint(certificate.DER()).Hex()
	if _, ok := r.s.certificatesByDER[fingerprint]; ok {
		return ErrDuplicate
	}
	r.s.certificates[certificate.ID()] = certificate
	r.s.certificatesByDER[fingerprint] = certificate.ID()
	return nil
}

func (r pkiRepo) InsertSeries(_ context.Context, series domain.LeafSeries) error {
	if _, ok := r.s.series[series.ID()]; ok {
		return ErrDuplicate
	}
	r.s.series[series.ID()] = series
	return nil
}

func (r pkiRepo) SaveSeries(_ context.Context, series domain.LeafSeries, expectedVersion domain.Version) error {
	existing, ok := r.s.series[series.ID()]
	if !ok {
		return port.ErrNotFound
	}
	if existing.Version() != expectedVersion {
		return ErrVersionConflict
	}
	r.s.series[series.ID()] = series
	return nil
}

func (r pkiRepo) SaveAuthority(_ context.Context, authority domain.Authority, expectedVersion domain.Version) error {
	existing, ok := r.s.authorities[authority.ID()]
	if !ok {
		return port.ErrNotFound
	}
	if existing.Version() != expectedVersion {
		return ErrVersionConflict
	}
	r.s.authorities[authority.ID()] = authority
	return nil
}

// ListCertificatesUsingKey backs the compromise path, which must revoke every
// valid certificate sharing a leaked public key
// (docs/certificate-lifecycle.md). Results are ordered by id so a test can
// assert on the whole set deterministically.
func (r pkiRepo) ListCertificatesUsingKey(_ context.Context, keyMaterialID domain.KeyMaterialID) ([]domain.Certificate, error) {
	out := make([]domain.Certificate, 0)
	for _, cert := range r.s.certificates {
		if cert.KeyMaterialID() == keyMaterialID {
			out = append(out, cert)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out, nil
}

// ListAffectedDescendants walks the management-parent chain downward from
// authorityID, so an emergency transition's impact list is built from stored
// relations rather than from anything the caller supplied.
func (r pkiRepo) ListAffectedDescendants(_ context.Context, authorityID domain.AuthorityID) ([]domain.Authority, error) {
	out := make([]domain.Authority, 0)
	frontier := []domain.AuthorityID{authorityID}
	seen := map[domain.AuthorityID]bool{authorityID: true}
	for len(frontier) > 0 {
		parent := frontier[0]
		frontier = frontier[1:]
		for _, a := range r.s.authorities {
			if a.ManagementParentID() != parent || seen[a.ID()] {
				continue
			}
			seen[a.ID()] = true
			out = append(out, a)
			frontier = append(frontier, a.ID())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out, nil
}
