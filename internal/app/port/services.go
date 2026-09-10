package port

import (
	"context"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

// Clock is the only source of the current time app code may observe
// (docs/backend-implementation.md §1 "domain은 ... 전역 시계를 참조하지
// 않는다"; §5 lists Clock as a dependency every service shares). Every
// service call reads now once from this and threads it explicitly into the
// domain methods that need it, so a test can supply a deterministic clock.
type Clock interface {
	Now() domain.Instant
}

// IDGenerator is domain.IDGenerator, re-exported under the port package so
// XDeps structs (docs/backend-implementation.md §5) can name it as
// port.IDGenerator without a second, duplicate interface declaration. The
// generator produces raw UUID strings; callers parse them into the typed ID
// they need (domain.ParseCertificateID, etc.) immediately after minting so
// an unparsed string never travels further than the call site.
type IDGenerator = domain.IDGenerator

// AuthorizationScope is the set of authorities an authorization check is
// evaluated against. Its field is unexported and only reachable through
// NewAuthorizationScope, mirroring how contract.Principal keeps its fields
// unexported and only reachable through NewAdminPrincipal/
// InternalPrincipalFactory: docs/backend-implementation.md §2's rule that
// "권한 검사 입력의 Scope는 DB 관계에서 구성하며 사용자 제공 Root ID를
// 신뢰하지 않는다" is a rule about *where a service gets its authority IDs
// from*, not something the port layer's own types can fully enforce by
// themselves -- NewAuthorizationScope cannot tell a caller-read
// domain.Authority.ID() apart from a raw path parameter. What this type does
// enforce is the narrower, checkable half: a scope can only be built through
// this one constructor, so it is never satisfied by silently passing a
// bare []domain.AuthorityID (or worse, a []string) through some other call
// shape, and every Authorizer implementation sees the same normalized shape
// regardless of how many authorities a multi-CA operation touches. The
// "build it from stored relations" half is a convention services must
// still follow by construction (read the row, take its own ID field, pass
// that in) -- flagged for the lead as a design point this layer cannot fully
// close by itself.
type AuthorizationScope struct {
	authorityIDs []domain.AuthorityID
}

// NewAuthorizationScope builds a scope from the given authority ids. Callers
// are expected to have just read each id off a domain object this
// transaction loaded (an Authority, a LeafSeries' ManagementAuthorityID, a
// Certificate's issuer chain), never off an unvalidated request field.
func NewAuthorizationScope(authorityIDs ...domain.AuthorityID) AuthorizationScope {
	return AuthorizationScope{authorityIDs: append([]domain.AuthorityID(nil), authorityIDs...)}
}

// AuthorityIDs returns a copy so a caller cannot widen a scope in place
// after it was constructed.
func (s AuthorizationScope) AuthorityIDs() []domain.AuthorityID {
	if len(s.authorityIDs) == 0 {
		return nil
	}
	out := make([]domain.AuthorityID, len(s.authorityIDs))
	copy(out, s.authorityIDs)
	return out
}

// Authorizer decides whether principal may perform action against scope.
// MVP Authorization only allows the global admin
// (docs/backend-implementation.md §2 "MVP Authorization은 전체 관리자만
// 허용한다"), but the interface itself does not encode that restriction so a
// later role model can implement it without a signature change.
type Authorizer interface {
	Authorize(ctx context.Context, principal contract.Principal, action string, scope AuthorizationScope) error
}

// PasswordHasher hashes and verifies administrator passwords. It never sees
// the domain.PasswordHash's internal encoding requirements beyond producing
// a value that satisfies domain.NewPasswordHash; the KDF profile itself is
// the adapter's concern (docs/backend-implementation.md §6 "PasswordHasher는
// 지원 프로필 외 DB 파라미터를 실행하지 않는다"). password is a secret.Input
// the caller owns and closes after the call; neither method retains it.
type PasswordHasher interface {
	Hash(ctx context.Context, password *secret.Input) (domain.PasswordHash, error)
	Verify(ctx context.Context, password *secret.Input, hash domain.PasswordHash) (bool, error)
}

// TokenCodec mints and hashes the 32-byte random bearer tokens behind
// sessions, CSRF secrets, reset links and download grants
// (docs/backend-implementation.md §6 "TokenCodec은 32바이트 암호학적 난수를
// base64url(패딩 없음)로 발급하고 SHA-256 해시만 저장한다"). NewToken's raw
// value is returned only as a secret.Input: the caller is the one place
// (login/reset/link-creation response mapper) that may read it, inside a
// Use callback, before closing it -- it is never logged or stored.
type TokenCodec interface {
	// NewToken mints a fresh raw token and its stored hash together, so a
	// caller can never persist the hash without also having had the chance
	// to hand back the matching raw value.
	NewToken(ctx context.Context) (*secret.Input, domain.TokenHash, error)

	// Hash hashes a client-presented raw token for a lookup-by-hash query.
	// token is used synchronously and not retained.
	Hash(ctx context.Context, token *secret.Input) (domain.TokenHash, error)
}

// DeliveryFormat is the requested private-key bundle encoding.
type DeliveryFormat string

const (
	DeliveryFormatPEM    DeliveryFormat = "pem"
	DeliveryFormatPKCS12 DeliveryFormat = "pkcs12"
)

// DeliveryEncodeInput is what DeliveryEncoder needs to build one leaf
// private-key bundle. LeafSecret must carry SecretPurposeLeafDelivery --
// DeliveryEncoder rejects any other purpose and rejects a certificate whose
// public key does not match the secret it is paired with
// (docs/backend-implementation.md §6 "DeliveryEncoder는 leaf_delivery
// 암호문만 허용하며 검증된 delivery·인증서와 동일 공개키인지 확인한다").
// PKCS12Password is required (and used synchronously, not retained) when
// Format is DeliveryFormatPKCS12, and must be absent otherwise.
type DeliveryEncodeInput struct {
	Certificate    domain.Certificate
	ChainDER       [][]byte
	LeafSecret     domain.EncryptedSecret
	Format         DeliveryFormat
	PEMPart        string
	PKCS12Password *secret.Input
}

// EncodedBundle is the completed, in-memory download payload
// (docs/backend-implementation.md §7 "encoder가 메모리 payload를 완성한다").
// It is produced before the consuming transaction commits and only handed to
// a DownloadSink after that commit succeeds.
type EncodedBundle struct {
	Data        []byte
	ContentType string
}

// DeliveryEncoder turns a certificate and its encrypted private key into the
// bundle format the client asked for.
type DeliveryEncoder interface {
	Encode(ctx context.Context, input DeliveryEncodeInput) (EncodedBundle, error)
}

// ProfileValidator checks a requested certificate profile/SAN/algorithm
// combination against operator-configured policy beyond the fixed shape
// rules domain.ValidateSANsForProfile already enforces (e.g. an allowed-SAN
// domain allowlist, or a disabled key algorithm) -- product-configurable
// checks that do not belong in the domain package because they can change
// per installation.
type ProfileValidator interface {
	Validate(ctx context.Context, profile domain.CertificateProfile, sans []domain.SAN, algorithm domain.KeyAlgorithm) error
}

// URLValidator checks that a service URL is well-formed and reachable
// enough to be trusted as the validated_service_url a Settings update or a
// managed/external TLS candidate records (docs/backend-implementation.md §5
// "Settings: URLValidator, 현재 TLS 공개 스냅샷 조회").
type URLValidator interface {
	Validate(ctx context.Context, rawURL string) error
}

// ImportBundleInput is the raw uploaded import material: a certificate (and
// optional chain) plus an optional private key whose passphrase, if any,
// arrives as a secret.Input the parser uses synchronously and does not
// retain.
//
// This type's exact shape is under-specified by docs/backend-
// implementation.md §5, which names PKIParser as an Import dependency but
// gives no method signatures (unlike KeyEngine/CertificateSigner/CRLSigner
// in §6, which are literal code). This is this file's own best-effort
// completion of that gap, flagged for the lead in the B02 report rather than
// treated as settled product behavior.
type ImportBundleInput struct {
	CertificateDER []byte
	ChainDER       [][]byte
	PrivateKeyDER  []byte // empty when no private key was uploaded
	Passphrase     *secret.Input
}

// ImportBundleFacts is PKIParser's validated output: the parsed certificate
// facts plus, when a private key was supplied and matches the certificate's
// public key, the validated key input KeyEngine.ImportCA/ImportTLS expects.
type ImportBundleFacts struct {
	Certificate domain.CertificateFacts
	CAKey       *ValidatedCAKeyInput  // nil when no private key was uploaded, or it was not a CA key
	TLSKey      *ValidatedTLSKeyInput // nil unless the caller specifically requested the internal_tls import path
}

// PKIParser parses an uploaded import bundle into validated facts. It only
// accepts the fixed set of supported format/encryption combinations
// (docs/backend-implementation.md §6 "PKIParser는 지원 형식·암호화 조합만
// 받아들이며 라이브러리의 더 넓은 지원 목록을 그대로 노출하지 않는다. 임의
// OID나 scrypt로 자동 fallback하지 않는다").
type PKIParser interface {
	Parse(ctx context.Context, input ImportBundleInput) (ImportBundleFacts, error)
}

// ChainValidator verifies that a leaf certificate chains to a trusted root
// through the given intermediates, at the given time. Used by Import (does
// the uploaded chain actually validate) and by TLS candidate validation
// (docs/backend-implementation.md §5 "TLS: ... ChainValidator ...").
type ChainValidator interface {
	Validate(ctx context.Context, leafDER []byte, chainDER [][]byte, now domain.Instant) error
}

// PreparedTLSConfig is the in-memory, ready-to-swap-in HTTPS configuration
// TLSInstaller.Prepare produces. It is a sealed marker interface rather than
// a struct: only a TLSInstaller implementation may produce one, so app code
// can never fabricate a "prepared" config and hand it straight to Apply
// without it having actually been built and validated by the installer
// (docs/backend-implementation.md §9 "준비한 후보를 TLSInstaller.Prepare에
// 넣어 실제 적용 가능한 메모리 설정을 먼저 만든다").
type PreparedTLSConfig interface {
	sealedPreparedTLSConfig()
}

// TLSInstaller separates building a candidate's in-memory configuration from
// actually swapping the live listener onto it
// (docs/backend-implementation.md §9). Apply's failure must leave the
// previous configuration untouched; the caller (TLSService.Activate) owns
// reverting the DB side on that failure.
type TLSInstaller interface {
	// Prepare validates candidate and its decrypted key long enough to build
	// a ready-to-apply in-memory configuration, then re-encrypts/discards
	// any plaintext it touched. It does not change the live listener.
	Prepare(ctx context.Context, candidate domain.TLSVersion, key domain.EncryptedSecret) (PreparedTLSConfig, error)

	// Apply swaps the live listener onto a previously prepared
	// configuration. A failure here must leave the previously active
	// configuration serving traffic unchanged
	// (docs/backend-implementation.md §9 "Apply 실패는 DB/메모리 모두
	// 원복한다").
	Apply(ctx context.Context, prepared PreparedTLSConfig) error
}
