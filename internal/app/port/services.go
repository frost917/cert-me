package port

import (
	"context"
	"fmt"

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

// Action names one authorization check. It is a named type rather than a
// bare string precisely because every other enum in this codebase already
// gets that treatment (docs/backend-implementation.md §2's domain ID types,
// domain.KeyAlgorithm, domain.SecretPurpose, ...): an unvalidated string
// typo silently becomes a *different*, possibly-passing permission check
// instead of a compile error or a caught validation failure.
//
// The constants below are the service.Method pairs docs/backend-
// implementation.md §3's table names explicitly and unambiguously. Two
// parts of §3 do NOT let this file pin a complete set, and are deliberately
// left out rather than guessed at:
//   - QueryService's row lists its methods only as the combinatorial
//     "List/Get Authority, Series, Certificate, Revocation, Transition,
//     Import, Job, Audit" plus GetCRLStatus/ReadPublicCA -- it does not
//     spell out whether List and Get on each noun are one action or two,
//     or what the exact method name is for each.
//   - TLSService's row lists "Bootstrap/Reconcile → 내부 결과" as a single
//     slash-joined cell, which does not say whether Bootstrap and Reconcile
//     are one action or two, or confirm their exact spelling.
//
// Declaring a guessed name for either would be inventing product behavior
// this interface's implementers would then be held to, which is exactly
// what finding P4 flags ProfileValidator's comment for doing elsewhere in
// this file -- so QueryService's and TLSService's internal actions are
// absent here rather than filled in with an invented name.
type Action string

const (
	ActionSetupStatus                 Action = "Setup.Status"
	ActionSetupCreateAdmin            Action = "Setup.CreateAdmin"
	ActionSetupComplete               Action = "Setup.Complete"
	ActionIdentityLogin               Action = "Identity.Login"
	ActionIdentityLogout              Action = "Identity.Logout"
	ActionIdentityAuthenticate        Action = "Identity.Authenticate"
	ActionIdentityBeginReset          Action = "Identity.BeginReset"
	ActionIdentityCompleteReset       Action = "Identity.CompleteReset"
	ActionIdentityIssueCSRF           Action = "Identity.IssueCSRF"
	ActionSettingsGet                 Action = "Settings.Get"
	ActionSettingsUpdate              Action = "Settings.Update"
	ActionAuthorityCreate             Action = "Authority.Create"
	ActionAuthorityRename             Action = "Authority.Rename"
	ActionAuthoritySetIssuanceState   Action = "Authority.SetIssuanceState"
	ActionAuthorityDestroyKey         Action = "Authority.DestroyKey"
	ActionAuthorityArchive            Action = "Authority.Archive"
	ActionIssuanceIssue               Action = "Issuance.Issue"
	ActionIssuanceRenew               Action = "Issuance.Renew"
	ActionIssuanceReissue             Action = "Issuance.Reissue"
	ActionIssuanceUpdateSeries        Action = "Issuance.UpdateSeries"
	ActionIssuanceArchiveSeries       Action = "Issuance.ArchiveSeries"
	ActionDistributionCreateLink      Action = "Distribution.CreateLink"
	ActionDistributionDeliver         Action = "Distribution.Deliver"
	ActionDistributionReportFailure   Action = "Distribution.ReportFailure"
	ActionRevocationRevoke            Action = "Revocation.Revoke"
	ActionRevocationCompromise        Action = "Revocation.Compromise"
	ActionRevocationCorrect           Action = "Revocation.Correct"
	ActionImportPreview               Action = "Import.Preview"
	ActionImportCommit                Action = "Import.Commit"
	ActionImportAttachSigningKey      Action = "Import.AttachSigningKey"
	ActionImportConfirmTakeover       Action = "Import.ConfirmTakeover"
	ActionTransitionCreate            Action = "Transition.Create"
	ActionTransitionSetTarget         Action = "Transition.SetTarget"
	ActionTransitionConfirmDeployment Action = "Transition.ConfirmDeployment"
	ActionTransitionComplete          Action = "Transition.Complete"
	ActionCRLRequestPublication       Action = "CRL.RequestPublication"
	ActionCRLPublish                  Action = "CRL.Publish"
	ActionTLSStatus                   Action = "TLS.Status"
	ActionTLSUploadCandidate          Action = "TLS.UploadCandidate"
	ActionTLSIssueCandidate           Action = "TLS.IssueCandidate"
	ActionTLSReload                   Action = "TLS.Reload"
	ActionTLSActivate                 Action = "TLS.Activate"
	ActionMaintenanceRotate           Action = "Maintenance.Rotate"
	ActionMaintenanceFinalizeRestore  Action = "Maintenance.FinalizeRestore"
	ActionMaintenanceRecoverTransfers Action = "Maintenance.RecoverTransfers"
	ActionMaintenancePruneAudit       Action = "Maintenance.PruneAudit"
)

// definedActions backs Validate. It is not exported: callers compare
// against the constants above, not against membership in this set directly.
var definedActions = map[Action]bool{
	ActionSetupStatus: true, ActionSetupCreateAdmin: true, ActionSetupComplete: true,
	ActionIdentityLogin: true, ActionIdentityLogout: true, ActionIdentityAuthenticate: true,
	ActionIdentityBeginReset: true, ActionIdentityCompleteReset: true, ActionIdentityIssueCSRF: true,
	ActionSettingsGet: true, ActionSettingsUpdate: true,
	ActionAuthorityCreate: true, ActionAuthorityRename: true, ActionAuthoritySetIssuanceState: true,
	ActionAuthorityDestroyKey: true, ActionAuthorityArchive: true,
	ActionIssuanceIssue: true, ActionIssuanceRenew: true, ActionIssuanceReissue: true,
	ActionIssuanceUpdateSeries: true, ActionIssuanceArchiveSeries: true,
	ActionDistributionCreateLink: true, ActionDistributionDeliver: true, ActionDistributionReportFailure: true,
	ActionRevocationRevoke: true, ActionRevocationCompromise: true, ActionRevocationCorrect: true,
	ActionImportPreview: true, ActionImportCommit: true, ActionImportAttachSigningKey: true,
	ActionImportConfirmTakeover: true,
	ActionTransitionCreate:      true, ActionTransitionSetTarget: true, ActionTransitionConfirmDeployment: true,
	ActionTransitionComplete:    true,
	ActionCRLRequestPublication: true, ActionCRLPublish: true,
	ActionTLSStatus: true, ActionTLSUploadCandidate: true, ActionTLSIssueCandidate: true,
	ActionTLSReload: true, ActionTLSActivate: true,
	ActionMaintenanceRotate: true, ActionMaintenanceFinalizeRestore: true,
	ActionMaintenanceRecoverTransfers: true, ActionMaintenancePruneAudit: true,
}

// Validate reports an error for any Action outside the fixed constant set
// above -- an empty or typo'd value included.
func (a Action) Validate() error {
	if !definedActions[a] {
		return fmt.Errorf("port: invalid action %q", string(a))
	}
	return nil
}

// Authorizer decides whether principal may perform action against scope.
// MVP Authorization only allows the global admin
// (docs/backend-implementation.md §2 "MVP Authorization은 전체 관리자만
// 허용한다"), but the interface itself does not encode that restriction so a
// later role model can implement it without a signature change.
type Authorizer interface {
	Authorize(ctx context.Context, principal contract.Principal, action Action, scope AuthorizationScope) error
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
	DeliveryFormatZIP    DeliveryFormat = "zip"
	DeliveryFormatPKCS12 DeliveryFormat = "pkcs12"
)

// Validate rejects a format outside the set the download endpoint offers.
// The three values are fixed by api/openapi.json's /download/{token} format
// query parameter (pem/zip/pkcs12); an encoder must not silently fall back
// to a different encoding when asked for one it does not recognise.
func (f DeliveryFormat) Validate() error {
	switch f {
	case DeliveryFormatPEM, DeliveryFormatZIP, DeliveryFormatPKCS12:
		return nil
	default:
		return fmt.Errorf("%w: unsupported delivery format %q", domain.ErrInvalidValue, string(f))
	}
}

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

// EncodedBundle is the completed, in-memory download payload -- a DECRYPTED
// leaf private-key bundle -- (docs/backend-implementation.md §7 "encoder가
// 메모리 payload를 완성한다"). It is produced before the consuming
// transaction commits and only handed to a DownloadSink after that commit
// succeeds.
//
// Ownership: DeliveryEncoder.Encode's caller (DistributionService.Deliver)
// owns the returned EncodedBundle from the moment Encode returns. It must
// call Close in a defer covering every path out of Deliver -- the ordinary
// return after sink.Send, the pre-commit failure path, and a panic -- so
// that Data never outlives step 5 of §7's Deliver sequence: "Send가 반환하거나
// panic하면 payload를 정리한다." No other component may retain a reference to
// Data past that point.
//
// This mirrors the non-retention/zeroing contract secret.Input already
// documents (internal/secret/input.go: "Close()는 소유 버퍼를 지우고 참조를
// 끊으며 여러 번 호출해도 안전하다"): Close zeroes the owned buffer and drops
// the reference, and is safe to call more than once, including on a zero
// value. As with secret.Input, zeroing removes the value from this buffer;
// it is not an absolute guarantee of memory-safe erasure, since the runtime
// may have copied the bytes before Close ever gets a chance to run.
type EncodedBundle struct {
	Data        []byte
	ContentType string
}

// Close zeroes Data and drops the reference. Safe to call more than once and
// safe on a zero-value EncodedBundle.
func (b *EncodedBundle) Close() {
	if b == nil {
		return
	}
	for i := range b.Data {
		b.Data[i] = 0
	}
	b.Data = nil
}

// DeliveryEncoder turns a certificate and its encrypted private key into the
// bundle format the client asked for.
type DeliveryEncoder interface {
	Encode(ctx context.Context, input DeliveryEncodeInput) (EncodedBundle, error)
}

// ProfileValidator checks a requested certificate profile/SAN/algorithm
// combination against operator-configured policy beyond the fixed shape
// rules domain.ValidateSANsForProfile already enforces
// (docs/backend-implementation.md §5 lists ProfileValidator as an
// Authority/Issuance dependency, alongside KeyEngine and
// CertificateSigner). Neither docs/backend-implementation.md nor
// api/openapi.json's Settings schema currently defines what that
// operator-configurable policy consists of -- there is no allowed-SAN
// domain allowlist or per-algorithm enable/disable field anywhere in
// Settings today. The concrete policy set this interface will check is
// therefore not yet specified; this comment intentionally does not guess
// at one so a B05 implementer is not held to product behavior nobody has
// actually decided on.
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
