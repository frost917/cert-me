package port

import (
	"context"

	"cert-me/internal/domain"
)

// KeyMaterial is the port-level projection of one key_materials row: the
// public-key identity that survives private-key deletion
// (docs/data-model.md "공개키와 암호화된 개인키": "개인키가 삭제돼도 남는
// 공개키 식별자"). There is no domain object for it because nothing here is
// a policy transition -- it is the durable public-key record Import/Rotate
// look up and compare against.
type KeyMaterial struct {
	ID            domain.KeyMaterialID
	PublicKey     domain.PublicKey
	Origin        string // "generated" or "imported"
	CompromisedAt domain.Instant
}

// CAKeyGeneration is the port-level projection of one ca_key_generations
// row: the CA signing-key generation and serial/CRL namespace for an
// authority (docs/data-model.md "CA·인증서·갱신 계보").
type CAKeyGeneration struct {
	ID             domain.CAKeyGenerationID
	AuthorityID    domain.AuthorityID
	KeyMaterialID  domain.KeyMaterialID
	GenerationNo   int
	KeyDestroyedAt domain.Instant
}

// SeriesSnapshot bundles a leaf series with the key generation its own
// current_key_generation_id points at. RenewalFacts.CurrentGeneration needs
// exactly this pair to call LeafSeries.PlanRenewal, and both rows must come
// from the same locked read so a concurrent rotation cannot be planned
// against a generation the series has already moved past
// (docs/backend-implementation.md §2 "Facts에는 검증 대상의 ID/version도
// 포함하고 서비스가 commit 안에서 최신 사실을 다시 구성한다").
type SeriesSnapshot struct {
	Series               domain.LeafSeries
	CurrentKeyGeneration domain.LeafKeyGeneration
}

// PKIRepository is the storage boundary for authorities, CA key
// generations, certificates and leaf series
// (docs/backend-implementation.md §4 table row "PKIRepository").
//
// GetIssuerForUpdate returns the stored domain.Authority, not the
// docs table's literal "IssuerContext": domain.IssuerContext
// (internal/domain/authority.go) is deliberately the *request-specific*
// facts Authority.CanIssue cannot know about itself (the requested
// validity window, an operator's takeover confirmation, which of the three
// issuance paths is being used) -- it is never something a repository read
// alone could produce. Every persisted fact CanIssue actually needs
// (issuance_state, key availability, affected, pending_takeover, the
// authority's own certificate window) already lives on domain.Authority, so
// the service builds the domain.IssuerContext itself from this locked read
// plus the caller's own request, then calls Authority.CanIssue(ctx, now).
// This is an interpretation of a terse table entry, not a literal reading of
// it; flagged for the lead in the B02 report.
type PKIRepository interface {
	// GetIssuerForUpdate locks and returns the authority row identified by
	// authorityID.
	GetIssuerForUpdate(ctx context.Context, authorityID domain.AuthorityID) (domain.Authority, error)

	// GetSeriesForUpdate locks the series row and its current key
	// generation together.
	GetSeriesForUpdate(ctx context.Context, seriesID domain.SeriesID) (SeriesSnapshot, error)

	// FindCertificateByDER looks up a certificate by the SHA-256 of its DER,
	// the import/renewal dedup key (data-model.md certificates.der_sha256
	// UQ). It returns ErrNotFound when no certificate has this exact DER.
	FindCertificateByDER(ctx context.Context, derSHA256 domain.Fingerprint) (domain.Certificate, error)

	// FindKeyBySPKI looks up a key_material row by the SHA-256 of its SPKI
	// (key_materials.spki_sha256 UQ), the same-public-key check import and
	// issuance use. It returns ErrNotFound when the public key is unknown.
	FindKeyBySPKI(ctx context.Context, spkiSHA256 domain.Fingerprint) (KeyMaterial, error)

	// SerialExists reports whether serial is already used by a certificate
	// or a revocation entry under issuer, the collision check serial
	// generation runs before signing commits
	// (docs/backend-implementation.md §8 "serial은 서명 전 생성하고 commit에서
	// certificates·revocations 양쪽과 충돌 검사한다").
	SerialExists(ctx context.Context, issuer domain.CAKeyGenerationID, serial domain.SerialNumber) (bool, error)

	// InsertAuthority creates a new authority row (Root/Intermediate/
	// bootstrap creation, or the successor half of a transition).
	InsertAuthority(ctx context.Context, authority domain.Authority) error

	// InsertKeyGeneration creates a new CA key generation row.
	InsertKeyGeneration(ctx context.Context, generation CAKeyGeneration) error

	// InsertCertificate stores a freshly signed or imported certificate.
	// certificates.der_sha256 is unique, so a duplicate DER surfaces as a
	// conflict error rather than a silent second row.
	InsertCertificate(ctx context.Context, certificate domain.Certificate) error

	// InsertSeries creates a new leaf series row (first issuance to a new
	// logical certificate).
	InsertSeries(ctx context.Context, series domain.LeafSeries) error

	// SaveSeries persists series under the standard optimistic-lock
	// contract (see AccountRepository.SaveAccount).
	SaveSeries(ctx context.Context, series domain.LeafSeries, expectedVersion domain.Version) error

	// SaveAuthority persists authority under the standard optimistic-lock
	// contract.
	SaveAuthority(ctx context.Context, authority domain.Authority, expectedVersion domain.Version) error

	// ListCertificatesUsingKey returns every certificate signed for
	// keyMaterialID, the compromise-cascade lookup
	// (docs/backend-implementation.md §11 U09 "유출 공개키의 유효 인증서
	// 모두 폐기").
	ListCertificatesUsingKey(ctx context.Context, keyMaterialID domain.KeyMaterialID) ([]domain.Certificate, error)

	// ListAffectedDescendants returns every authority whose management
	// chain descends from authorityID, the set an emergency transition marks
	// affected/stops issuance for
	// (docs/data-model.md "긴급 신고 트랜잭션은 source 및 관리 하위 CA 발급을
	// 차단").
	ListAffectedDescendants(ctx context.Context, authorityID domain.AuthorityID) ([]domain.Authority, error)
}
