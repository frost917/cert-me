package port

import (
	"context"

	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

// KeySpec is the information decided before a key exists: which stored
// identity it will become and what it is for
// (docs/backend-implementation.md §6 "KeySpec은 발급 전에 정한
// KeyMaterialID·Algorithm·Purpose를 포함한다").
type KeySpec struct {
	KeyMaterialID domain.KeyMaterialID
	Algorithm     domain.KeyAlgorithm
	Purpose       domain.SecretPurpose
}

// GeneratedKey is everything KeyEngine ever hands back for a new or
// imported key: the public half and its encrypted private half. There is no
// field for the plaintext key -- app never receives it
// (docs/backend-implementation.md §6 "평문 키가 app에 반환되지 않는다").
type GeneratedKey struct {
	PublicKey       domain.PublicKey
	EncryptedSecret domain.EncryptedSecret
}

// RotationKeys names the encryption-generation move Reencrypt performs. The
// actual key-encryption keys stay inside the crypto adapter; port only
// carries which generation a ciphertext is leaving and which one it is
// entering, so a rotate call cannot accidentally read a plaintext KEK
// through this boundary.
type RotationKeys struct {
	SourceGenerationID string
	TargetGenerationID string
}

// ValidatedCAKeyInput is a private CA key an import upload has already been
// parsed and format/passphrase-checked for (docs/backend-implementation.md
// §6 "PKIParser는 지원 형식·암호화 조합만 받아들이며..."), ready for
// KeyEngine.ImportCA to encrypt at rest. PrivateKey is a secret.Input the
// caller owns and closes after the call; ImportCA must not retain a
// reference to it past the call returning (docs/backend-implementation.md
// §6 "callback이 참조를 보존하지 않는 것은 어댑터 계약"), matching the same
// non-retention rule secret.Input.Use documents for every adapter that reads
// one.
type ValidatedCAKeyInput struct {
	PrivateKey *secret.Input
	Algorithm  domain.KeyAlgorithm
	PublicKey  domain.PublicKey // precomputed by the parser so the engine does not need to re-derive it from the private key
}

// ValidatedTLSKeyInput is the internal_tls-purpose counterpart of
// ValidatedCAKeyInput, used for the bootstrap/managed HTTPS import path.
// Same non-retention rule for PrivateKey.
type ValidatedTLSKeyInput struct {
	PrivateKey *secret.Input
	Algorithm  domain.KeyAlgorithm
	PublicKey  domain.PublicKey
}

// KeyEngine is the private-key generation, import and re-encryption
// boundary (docs/backend-implementation.md §6). Every method returns only
// GeneratedKey/domain.EncryptedSecret -- plaintext never crosses back into
// app.
type KeyEngine interface {
	// Generate creates a fresh key pair for spec and returns it encrypted.
	// Admission to the CPU-bound generation work is gated by a
	// process-wide semaphore of size 2 shared with import/reencrypt
	// (docs/backend-implementation.md §6 "CPU가 큰 키 생성·변환은 프로세스
	// 전체 semaphore 2개로 제한한다"); a caller that cannot get in within 5
	// seconds gets an unavailable error rather than blocking the commit.
	Generate(ctx context.Context, spec KeySpec) (GeneratedKey, error)

	// ImportCA encrypts an already-validated CA private key under spec.
	// input.PrivateKey is used synchronously and not retained; the caller
	// closes it once this call returns. spec.Purpose must be ca_signing or
	// bootstrap_ca -- ImportCA rejects any other purpose
	// (docs/backend-implementation.md §6 "서명 어댑터는 해당 secret 목적이
	// ca_signing/bootstrap_ca인지 검사").
	ImportCA(ctx context.Context, input ValidatedCAKeyInput, spec KeySpec) (GeneratedKey, error)

	// ImportTLS encrypts an already-validated internal-HTTPS private key
	// under spec. spec.Purpose must be internal_tls
	// (docs/backend-implementation.md §6 "TLSInstaller는 internal_tls 목적만
	// 받는다" -- the same purpose restriction applies here, one step
	// earlier, at the point the key is first encrypted).
	ImportTLS(ctx context.Context, input ValidatedTLSKeyInput, spec KeySpec) (GeneratedKey, error)

	// Reencrypt decrypts secret under its current encryption generation and
	// re-encrypts it under keys.TargetGenerationID, without ever exposing
	// the plaintext to the caller. MaintenanceService.Rotate calls this once
	// per stored secret and per verifier inside one UnitOfWork.
	Reencrypt(ctx context.Context, encrypted domain.EncryptedSecret, keys RotationKeys) (domain.EncryptedSecret, error)
}

// CertificateSigner signs a prepared issuance plan with an already-encrypted
// CA key (docs/backend-implementation.md §6). The signing adapter checks
// that caKey's purpose is ca_signing or bootstrap_ca and decrypts it only
// for the lifetime of this call -- it is never cached across calls.
type CertificateSigner interface {
	Sign(ctx context.Context, plan domain.IssuancePlan, caKey domain.EncryptedSecret) (domain.Certificate, error)
}

// CRLSnapshot is the point-in-time input a CRL signing call needs, captured
// under the CRLState lock before any signing happens
// (docs/backend-implementation.md §8 "CRL 생성" row: "번호 예약·폐기
// snapshot·generation 캡처"; docs/data-model.md "CRL snapshot 예약은 번호와
// 목록을 같은 순간의 상태로 캡처한다").
type CRLSnapshot struct {
	CAKeyGenerationID domain.CAKeyGenerationID
	Number            domain.CRLNumber
	ThisUpdate        domain.Instant
	NextUpdate        domain.Instant
	CoveredGeneration int64
	Revoked           []domain.Revocation
}

// SignedCRL is the signing adapter's output: the DER and its digest, ready
// for CRLRepository.InsertDocument. There is no domain object for it because
// a signed CRL document is immutable and has no transitions of its own once
// produced -- CRLState.MarkPublished is what decides whether it becomes the
// published one.
type SignedCRL struct {
	DER       []byte
	DERSHA256 domain.Fingerprint
}

// CRLSigner signs a captured CRL snapshot with an already-encrypted CA key.
// Signing runs outside the reservation transaction
// (docs/backend-implementation.md §8 "CRL 게시" row: "예약 snapshot과 CA
// 암호문으로 서명" under "트랜잭션 밖 준비"); the caller re-checks
// CRLState.CanPublish against current state before persisting the result.
type CRLSigner interface {
	SignCRL(ctx context.Context, snapshot CRLSnapshot, caKey domain.EncryptedSecret) (SignedCRL, error)
}
