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

// Certificate issuance operations, the leaf_certificates.operation values
// docs/data-model.md fixes.
const (
	CertificateOperationInitial   = "initial"
	CertificateOperationRenew     = "renew"
	CertificateOperationRekey     = "rekey"
	CertificateOperationMigrate   = "migrate"
	CertificateOperationEmergency = "emergency"
	CertificateOperationImport    = "import"
)

// LeafCertificateRecord is the leaf_certificates subtype row
// (docs/data-model.md): what a leaf certificate was issued as, and -- the
// part docs/backend-implementation.md §14.2 turns into a hard requirement --
// which CA certificate actually signed it. A chain is walked through this
// stored issuer link, never reconstructed from the authority's current
// IssuanceCertificateID, so a certificate signed before a CA rotated still
// resolves to the chain it was issued under.
type LeafCertificateRecord struct {
	CertificateID         domain.CertificateID
	SeriesID              domain.SeriesID
	LeafKeyGenerationID   domain.LeafKeyGenerationID
	IssuerCACertificateID domain.CertificateID
	PreviousCertificateID domain.CertificateID // zero for a series' first certificate
	Operation             string
	RenewalCountAtIssue   int
	PolicySnapshotJSON    []byte
}

// CACertificateRecord is the ca_certificates subtype row: the certificate
// that certifies one CA key generation. IssuerCACertificateID is zero for a
// self-signed Root, which is where a chain walk terminates
// (docs/data-model.md "self-signed Root는 issuer 인증서 NULL").
type CACertificateRecord struct {
	CertificateID         domain.CertificateID
	CAKeyGenerationID     domain.CAKeyGenerationID
	IssuerCACertificateID domain.CertificateID // zero for a self-signed Root
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

	// FindCertificateByIssuerSerial finds a certificate occupying one
	// issuer/serial namespace, used by import to distinguish an exact DER
	// duplicate from a serial collision.
	FindCertificateByIssuerSerial(ctx context.Context, issuer domain.CAKeyGenerationID, serial domain.SerialNumber) (domain.Certificate, error)

	// FindKeyBySPKI looks up a key_material row by the SHA-256 of its SPKI
	// (key_materials.spki_sha256 UQ), the same-public-key check import and
	// issuance use. It returns ErrNotFound when the public key is unknown.
	FindKeyBySPKI(ctx context.Context, spkiSHA256 domain.Fingerprint) (KeyMaterial, error)

	// GetCertificate looks up a certificate by its own id. Renew/Reissue
	// commands carry a source_certificate_id (docs/data-model.md "CA·인증서·
	// 갱신 계보"; docs/backend-implementation.md §8 "Leaf 발급/갱신" row lists
	// "기대 version·issuer/키/수령/폐기 검사" among the facts re-checked inside
	// the single commit Write, and the certificate being renewed is exactly
	// the fact FindCertificateByDER/FindKeyBySPKI cannot recover -- those are
	// dedup lookups by content hash, not an id lookup for "the certificate
	// this renewal names"). It returns ErrNotFound when id is unknown.
	GetCertificate(ctx context.Context, id domain.CertificateID) (domain.Certificate, error)

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

	// InsertKeyMaterial creates a new key_materials row: the public-key
	// identity a freshly generated or imported key pair gets before anything
	// else (a CA key generation, a leaf key generation) can reference its
	// KeyMaterialID (docs/data-model.md "key_materials ... 개인키가 삭제돼도
	// 남는 공개키 식별자"; §4 table row lists InsertKeyMaterial explicitly).
	// key_materials.spki_sha256 is unique, so a duplicate public key surfaces
	// as a conflict error rather than a second row -- the same-public-key
	// check FindKeyBySPKI performs before calling this is what makes that
	// conflict unreachable in the normal path.
	InsertKeyMaterial(ctx context.Context, material KeyMaterial) error

	// InsertLeafKeyGeneration creates a new leaf_key_generations row: the
	// first generation of a new series' key, or the new generation a key
	// rotation (RenewalAction == RotateKey) or an emergency reissue creates
	// (docs/data-model.md "leaf_key_generations ... (series_id,generation_no)
	// UQ"; docs/backend-implementation.md §4 table row lists
	// InsertLeafKeyGeneration explicitly; internal/domain/series.go
	// RenewalPlan's doc comment: "possibly create a new leaf_key_generations
	// row"). It does not itself update the series' current_key_generation_id
	// -- that is SaveSeries' job, in the same Write.
	InsertLeafKeyGeneration(ctx context.Context, generation domain.LeafKeyGeneration) error

	// SaveLeafKeyGeneration persists generation's renewal_count when a
	// renewal reuses the current key (RenewalAction == ReuseKey) rather than
	// rotating to a new generation row (internal/domain/series.go
	// RenewalPlan's doc comment: the caller must "update counts" after
	// PlanRenewal decides to reuse a key). Unlike SaveSeries/SaveAuthority
	// this takes no expectedVersion: domain.LeafKeyGeneration
	// (internal/domain/series.go) has no version field of its own, and
	// docs/data-model.md's leaf_key_generations row lists no version column
	// either, only the caller-owned renewal_count/generation_no. The
	// concurrency guard for this update instead comes from the enclosing
	// transaction: SaveLeafKeyGeneration is only ever called next to
	// SaveSeries(series, expectedVersion) inside the same renewal Write, both
	// against the pair GetSeriesForUpdate locked together, so a losing
	// concurrent renewal is already rejected by the series' own optimistic
	// lock before this call is reached.
	//
	// The §4 table's terse "SaveLeafKeyGeneration/Series/Authority(
	// expectedVersion)" reads as if expectedVersion applied to all three,
	// which it cannot for LeafKeyGeneration. That was raised as an open
	// question and the planning team ruled on it: the method stays without a
	// version, saved in the same Write as the GetSeriesForUpdate lock, the
	// membership/current-generation re-check and SaveSeries(expectedVersion),
	// with everything rolled back on conflict; no version column is added
	// (§13).
	SaveLeafKeyGeneration(ctx context.Context, generation domain.LeafKeyGeneration) error

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

	// SaveCAKeyGeneration persists the destruction marker on an existing CA
	// generation. Authority destruction uses the locked Authority row for
	// serialization because CA generations have no version column.
	SaveCAKeyGeneration(ctx context.Context, generation CAKeyGeneration) error

	// ListCertificatesByIssuer returns every certificate signed under one CA key
	// generation, used to verify closure conditions before archival or key
	// destruction.
	ListCertificatesByIssuer(ctx context.Context, issuer domain.CAKeyGenerationID) ([]domain.Certificate, error)

	// ListCACertificates returns every stored CA certificate. Import uses this
	// public-facts view to resolve bundled CA keys/CRLs by issuer subject and
	// authority key identifier without accepting a client-provided relation as
	// authoritative.
	ListCACertificates(ctx context.Context) ([]domain.Certificate, error)

	// ListCertificatesUsingKey returns every certificate signed for
	// keyMaterialID, the compromise-cascade lookup
	// (docs/backend-implementation.md §11 U09 "유출 공개키의 유효 인증서
	// 모두 폐기").
	ListCertificatesUsingKey(ctx context.Context, keyMaterialID domain.KeyMaterialID) ([]domain.Certificate, error)

	// GetKeyMaterial looks up a key_material row by its own id -- the
	// ID-based read §13's closing paragraph names as a gap ("PKI의 키 유출
	// 표시·ID 기반 조회도 포함한다"). FindKeyBySPKI is a same-public-key
	// dedup lookup by content hash; it cannot serve a caller that already
	// knows the id (e.g. Certificate.KeyMaterialID from a certificate
	// ListCertificatesUsingKey returned) and wants the current row,
	// including CompromisedAt, without also having the public key bytes in
	// hand. It returns ErrNotFound when id is unknown.
	GetKeyMaterial(ctx context.Context, id domain.KeyMaterialID) (KeyMaterial, error)

	// MarkCompromised sets key_materials.compromised_at for id, the write
	// §13's closing paragraph names as a gap ("PKI의 키 유출 표시"). A
	// previous round deliberately did not add a general SaveKeyMaterial,
	// reasoning that the compromise cascade revokes certificates via
	// ListCertificatesUsingKey rather than mutating the key row; that
	// reasoning covered the cascade's revocation side, not the fact of the
	// leak itself, which docs/data-model.md's own transition rule requires
	// recording precisely: "key_material.compromised_at은 실제 해당 키
	// 유출에만 설정하며 상위 CA 영향만으로 Leaf 개인키가 유출됐다고 기록하지
	// 않는다" (line 140) -- there must be a way to set it for the actual
	// leaked key, distinct from the CA-impact marking a transition records
	// on affected descendant authorities. docs/certificate-lifecycle.md line
	// 67's "개인키 유출 | 같은 키를 사용하는 유효 인증서 모두 폐기, 새
	// 키·인증서 발급" is the flow this unblocks: mark the key, then look up
	// and revoke every certificate ListCertificatesUsingKey returns.
	//
	// key_materials has no version column (docs/data-model.md's row lists
	// none), so this takes no expectedVersion -- the same reasoning
	// SaveLeafKeyGeneration documents.
	//
	// Repeated reports are idempotent and the EARLIEST report wins: a later
	// compromisedAt is accepted and ignored rather than rejected. No doc
	// settles this directly, but a compromise cannot be walked back anywhere
	// else in this system -- a revocation has no release
	// (docs/certificate-lifecycle.md) and CRL numbers and generations never
	// regress -- and moving compromised_at later would narrow the window in
	// which certificates on this key are treated as untrustworthy. The safe
	// direction is therefore the only one implemented.
	MarkCompromised(ctx context.Context, id domain.KeyMaterialID, compromisedAt domain.Instant) error

	// GetCAKeyGeneration looks up one ca_key_generations row by its id.
	// docs/backend-implementation.md §14.9 makes this the required path to a
	// CA's signing key: Authority.CAKeyGenerationID -> this row ->
	// KeyMaterialID -> the ca_signing secret. Going through the authority's
	// own certificate instead cannot see the generation's KeyDestroyedAt,
	// and the CA certificate exists to validate issuer DN, extensions and
	// validity -- not to stand in for the generation row. It returns
	// ErrNotFound when id is unknown.
	GetCAKeyGeneration(ctx context.Context, id domain.CAKeyGenerationID) (CAKeyGeneration, error)

	// GetLeafCertificateRecord returns the leaf_certificates subtype row for
	// certificateID, whose IssuerCACertificateID is the first hop of the
	// chain walk §14.2 requires. It returns ErrNotFound when certificateID
	// is not a leaf certificate.
	GetLeafCertificateRecord(ctx context.Context, certificateID domain.CertificateID) (LeafCertificateRecord, error)

	// GetCACertificateRecord returns the ca_certificates subtype row for
	// certificateID, each further hop of that walk. It returns ErrNotFound
	// when certificateID is not a CA certificate.
	GetCACertificateRecord(ctx context.Context, certificateID domain.CertificateID) (CACertificateRecord, error)

	// InsertLeafCertificateRecord stores the leaf subtype row in the same
	// Write as its certificate (§14.2 "인증서·subtype·계보 변경을 같은
	// Write에 저장한다"). Storing the certificate without it would leave a
	// certificate whose chain can never be resolved.
	InsertLeafCertificateRecord(ctx context.Context, record LeafCertificateRecord) error

	// InsertCACertificateRecord stores the CA subtype row, same rule.
	InsertCACertificateRecord(ctx context.Context, record CACertificateRecord) error

	// ListAffectedDescendants returns every authority whose management
	// chain descends from authorityID, the set an emergency transition marks
	// affected/stops issuance for
	// (docs/data-model.md "긴급 신고 트랜잭션은 source 및 관리 하위 CA 발급을
	// 차단").
	ListAffectedDescendants(ctx context.Context, authorityID domain.AuthorityID) ([]domain.Authority, error)
}
