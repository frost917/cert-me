package port

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

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

// AuthorizationScopeKind identifies the relation an authorization check is
// evaluated against. The explicit kind keeps an installation-wide check
// distinct from an authority-scoped check; an empty authority list is not a
// wildcard.
type AuthorizationScopeKind string

const (
	AuthorizationScopeInstallation AuthorizationScopeKind = "installation"
	AuthorizationScopeAuthorities  AuthorizationScopeKind = "authorities"
)

// AuthorizationScope is the typed set of stored authority relations an
// authorization check is evaluated against. Its fields are private so a
// caller cannot silently construct a different shape in an Authorize call.
// Services still have to obtain the ids from rows they read in the current
// transaction; the port type makes the resulting installation/authorities
// distinction explicit and validates its invariants.
type AuthorizationScope struct {
	kind         AuthorizationScopeKind
	authorityIDs []domain.AuthorityID
}

// NewInstallationAuthorizationScope creates an installation-wide scope.
func NewInstallationAuthorizationScope() AuthorizationScope {
	return AuthorizationScope{kind: AuthorizationScopeInstallation}
}

// NewAuthoritiesAuthorizationScope creates an authority scope. Duplicate
// ids are removed while preserving their first-seen order; an empty input is
// still invalid and is rejected by Validate/Authorizer implementations.
func NewAuthoritiesAuthorizationScope(ids ...domain.AuthorityID) AuthorizationScope {
	seen := make(map[domain.AuthorityID]struct{}, len(ids))
	unique := make([]domain.AuthorityID, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	return AuthorizationScope{kind: AuthorizationScopeAuthorities, authorityIDs: unique}
}

// NewAuthorizationScope is kept as a compatibility helper for existing
// service call sites: no ids means installation, one or more ids means
// authorities. New code may use the explicit constructors when the scope
// kind itself is part of the intent.
func NewAuthorizationScope(authorityIDs ...domain.AuthorityID) AuthorizationScope {
	if len(authorityIDs) == 0 {
		return NewInstallationAuthorizationScope()
	}
	return NewAuthoritiesAuthorizationScope(authorityIDs...)
}

// Kind returns the scope relation.
func (s AuthorizationScope) Kind() AuthorizationScopeKind { return s.kind }

// Validate checks the authorization-scope invariants.
func (s AuthorizationScope) Validate() error {
	switch s.kind {
	case AuthorizationScopeInstallation:
		if len(s.authorityIDs) != 0 {
			return errors.New("installation authorization scope must not contain authority ids")
		}
		return nil
	case AuthorizationScopeAuthorities:
		if len(s.authorityIDs) == 0 {
			return errors.New("authority authorization scope must contain at least one authority id")
		}
		seen := make(map[domain.AuthorityID]struct{}, len(s.authorityIDs))
		for _, id := range s.authorityIDs {
			if id == "" {
				return errors.New("authority authorization scope must not contain an empty authority id")
			}
			if _, ok := seen[id]; ok {
				return errors.New("authority authorization scope must not contain duplicate authority ids")
			}
			seen[id] = struct{}{}
		}
		return nil
	default:
		return fmt.Errorf("port: invalid authorization scope kind %q", string(s.kind))
	}
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
// implementation.md §3's table names explicitly and unambiguously, plus the
// QueryService and TLS internal actions docs/backend-implementation.md §13
// ruling 5 has since settled:
//   - QueryService gets one Action per List/Get pair the ruling names --
//     Authority, Series, Certificate, Revocation, Transition, Import, Job --
//     plus separate ListAudit/ExportAudit (not List+Get; there is no
//     single-item Audit read in the real API) and GetCRLStatus/ReadPublicCA.
//     Ruling 5 is explicit that no single-audit-get action is added for
//     symmetry with the others: "실제 API에 없는 단일 Audit 조회는 신설하지
//     않는다".
//   - TLS.Bootstrap and TLS.Reconcile are separate actions, each gated to
//     its one matching contract.InternalOperation -- see
//     actionInternalOperations below.
//
// Ruling 5's closing sentence, "미정의 Action은 거부한다", is Validate's
// existing default-deny behavior; it did not need a new action.
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
	// ActionTransitionClose is the separate authorization for the closing
	// half of §13 ruling 1. Complete and Close are different operations on
	// different preconditions -- Complete checks impacts and the manual
	// deployment confirmation to reach externally_completed, Close checks
	// that the source CA's publication has actually ended, and the ruling is
	// explicit that "closed는 ... Complete만으로 추정하지 않는다". Ruling 5
	// declares one Action per operation, so reusing Complete's here would
	// leave an Authorizer unable to tell the two apart the moment the role
	// model stops being admin-only.
	ActionTransitionClose             Action = "Transition.Close"
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

	// TLS.Bootstrap/TLS.Reconcile: internal-only, each paired to exactly one
	// contract.InternalOperation via actionInternalOperations
	// (docs/backend-implementation.md §13 ruling 5 "TLS.Bootstrap과
	// TLS.Reconcile도 별도 Action이며 대응 내부 operation만 허용한다").
	ActionTLSBootstrap Action = "TLS.Bootstrap"
	ActionTLSReconcile Action = "TLS.Reconcile"

	// Query actions (docs/backend-implementation.md §13 ruling 5). Each
	// List/Get pair on a noun is two separate actions; Audit is the named
	// exception with ListAudit/ExportAudit instead of ListAudit/GetAudit,
	// matching the real API's audit export endpoint.
	ActionQueryListAuthority   Action = "Query.ListAuthority"
	ActionQueryGetAuthority    Action = "Query.GetAuthority"
	ActionQueryListSeries      Action = "Query.ListSeries"
	ActionQueryGetSeries       Action = "Query.GetSeries"
	ActionQueryListCertificate Action = "Query.ListCertificate"
	ActionQueryGetCertificate  Action = "Query.GetCertificate"
	ActionQueryListRevocation  Action = "Query.ListRevocation"
	ActionQueryGetRevocation   Action = "Query.GetRevocation"
	ActionQueryListTransition  Action = "Query.ListTransition"
	ActionQueryGetTransition   Action = "Query.GetTransition"
	ActionQueryListImport      Action = "Query.ListImport"
	ActionQueryGetImport       Action = "Query.GetImport"
	ActionQueryListJob         Action = "Query.ListJob"
	ActionQueryGetJob          Action = "Query.GetJob"
	ActionQueryListAudit       Action = "Query.ListAudit"
	ActionQueryExportAudit     Action = "Query.ExportAudit"
	ActionQueryGetCRLStatus    Action = "Query.GetCRLStatus"
	ActionQueryReadPublicCA    Action = "Query.ReadPublicCA"
)

// actionInternalOperations pairs an internal-only Action to the single
// contract.InternalOperation an internal principal must hold to exercise
// it (docs/backend-implementation.md §13 ruling 5 "대응 내부 operation만
// 허용한다"). An Authorizer implementation checks this pairing --
// principal.Can(op) for the op this map names -- rather than each
// implementation inventing its own Action<->InternalOperation guess; a
// principal minted for InternalOperationTLSBootstrap has Can(TLSBootstrap)
// true and Can(TLSReconcile) false (contract.Principal.Can/
// InternalPrincipalFactory.Principal already enforce a principal carries
// only the operation(s) it was minted for), so pairing ActionTLSReconcile
// to a *different* operation here is what makes that principal unable to
// exercise ActionTLSReconcile.
var actionInternalOperations = map[Action]contract.InternalOperation{
	ActionTLSBootstrap: contract.InternalOperationTLSBootstrap,
	ActionTLSReconcile: contract.InternalOperationTLSReconcile,
}

// RequiredInternalOperation reports the single contract.InternalOperation
// an internal principal must hold to exercise a, and whether a is paired to
// one at all (most actions are not internal-only and have no entry).
func (a Action) RequiredInternalOperation() (contract.InternalOperation, bool) {
	op, ok := actionInternalOperations[a]
	return op, ok
}

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
	ActionTransitionComplete: true, ActionTransitionClose: true,
	ActionCRLRequestPublication: true, ActionCRLPublish: true,
	ActionTLSStatus: true, ActionTLSUploadCandidate: true, ActionTLSIssueCandidate: true,
	ActionTLSReload: true, ActionTLSActivate: true,
	ActionTLSBootstrap: true, ActionTLSReconcile: true,
	ActionMaintenanceRotate: true, ActionMaintenanceFinalizeRestore: true,
	ActionMaintenanceRecoverTransfers: true, ActionMaintenancePruneAudit: true,
	ActionQueryListAuthority: true, ActionQueryGetAuthority: true,
	ActionQueryListSeries: true, ActionQueryGetSeries: true,
	ActionQueryListCertificate: true, ActionQueryGetCertificate: true,
	ActionQueryListRevocation: true, ActionQueryGetRevocation: true,
	ActionQueryListTransition: true, ActionQueryGetTransition: true,
	ActionQueryListImport: true, ActionQueryGetImport: true,
	ActionQueryListJob: true, ActionQueryGetJob: true,
	ActionQueryListAudit: true, ActionQueryExportAudit: true,
	ActionQueryGetCRLStatus: true, ActionQueryReadPublicCA: true,
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
// S1 fix: the payload used to be a public Data []byte field, which
// json.Marshal would happily base64-encode and which fmt/slog would print
// verbatim -- neither is acceptable for B02's acceptance criterion "비밀
// JSON/로그 차단" (docs/backend-implementation.md §11's B02 row), and holding
// a decrypted leaf key is explicitly the case this type documents. The
// plaintext is now reachable only through Use, exactly like
// internal/secret/input.go's Input: a synchronous callback that must not
// retain the slice, plus String/GoString/Format/LogValue that are always
// redacted and a MarshalJSON that always errors.
//
// Ownership: DeliveryEncoder.Encode's caller (DistributionService.Deliver)
// owns the returned EncodedBundle from the moment Encode returns. It must
// call Close in a defer covering every path out of Deliver -- the ordinary
// return after sink.Send, the pre-commit failure path, and a panic -- so
// that the plaintext never outlives step 5 of §7's Deliver sequence: "Send가
// 반환하거나 panic하면 payload를 정리한다." No other component may retain a
// reference to the plaintext past that point.
type EncodedBundle struct {
	payload     *secret.Input
	ContentType string
}

// NewEncodedBundle takes ownership of data (not copied) and returns a bundle
// that only releases it through Use, mirroring secret.New's ownership rule.
func NewEncodedBundle(data []byte, contentType string) EncodedBundle {
	return EncodedBundle{payload: secret.New(data), ContentType: contentType}
}

// Use grants synchronous access to the decrypted bundle bytes. The callback
// must not retain the slice; see secret.Input.Use for the exact contract
// (this type delegates to one). A zero-value EncodedBundle behaves as
// already closed.
func (b EncodedBundle) Use(fn func([]byte) error) error {
	return b.payload.Use(fn)
}

// Len reports the plaintext length, which is not itself secret.
func (b EncodedBundle) Len() int { return b.payload.Len() }

// Close zeroes the owned plaintext and drops the reference. Safe to call
// more than once and safe on a zero-value or nil-receiver EncodedBundle.
func (b *EncodedBundle) Close() {
	if b == nil {
		return
	}
	_ = b.payload.Close()
}

// String, GoString, Format and LogValue are always redacted so no format
// verb or slog attribute can reach the plaintext -- the same discipline
// secret.Input applies, restated here because EncodedBundle is a struct
// with its own exported ContentType field rather than a bare *secret.Input.
func (b EncodedBundle) String() string   { return secretRedacted }
func (b EncodedBundle) GoString() string { return secretRedacted }

func (b EncodedBundle) Format(f fmt.State, verb rune) {
	switch verb {
	case 'q':
		fmt.Fprintf(f, "%q", secretRedacted)
	default:
		_, _ = io.WriteString(f, secretRedacted)
	}
}

func (b EncodedBundle) LogValue() slog.Value { return slog.StringValue(secretRedacted) }

// MarshalJSON always fails: the decrypted bundle is written to a
// DownloadSink through Use, never marshalled as part of a command or result.
func (b EncodedBundle) MarshalJSON() ([]byte, error) { return nil, secret.ErrNotSerializable }

// secretRedacted is the fixed textual form every plaintext-carrying port
// type produces, matching internal/secret/input.go's own constant so a log
// line looks the same regardless of which type produced it.
const secretRedacted = "<redacted>"

var (
	_ fmt.Formatter  = EncodedBundle{}
	_ fmt.Stringer   = EncodedBundle{}
	_ slog.LogValuer = EncodedBundle{}
)

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

// ParsedCertificateFacts is one certificate's parsed, public facts.
// Deliberately absent: any storage identifier (CertificateID,
// KeyMaterialID, IssuerCAKeyGenerationID, CreatedByAccountID, Version) and
// any issuer *relationship* -- docs/backend-implementation.md §13 ruling 4
// "파서가 DB ID나 issuer 관계를 임의 생성하지 않고 app이 검증 후 연결한다".
// IssuerSubject/AuthorityKeyID/SubjectKeyID are raw facts read off the DER
// (not a resolved relationship) so the app can look up the matching stored
// Authority itself, inside a transaction, instead of trusting a parser-
// picked ID. SPKIFingerprint is the normalized-SPKI hash docs/pki-import.md
// "중복·충돌 처리" uses for public-key-duplicate detection; it is a pure
// function of PublicKey so computing it here does not mint anything.
type ParsedCertificateFacts struct {
	DER             []byte
	PublicKey       domain.PublicKey
	SPKIFingerprint domain.Fingerprint
	KeyAlgorithm    domain.KeyAlgorithm
	Serial          domain.SerialNumber
	Validity        domain.ValidityWindow
	Subject         domain.Subject
	SANs            []domain.SAN
	Kind            domain.CertificateKind    // from the BasicConstraints CA boolean, not assigned by the parser
	Profile         domain.CertificateProfile // required for imported Leaf certificates; empty for CA certificates
	IssuerSubject   domain.Subject            // the DER's own issuer DN, for the app's own issuer lookup
	AuthorityKeyID  []byte                    // raw AKI keyIdentifier, nil if the extension is absent
	SubjectKeyID    []byte                    // raw SKI, nil if the extension is absent
}

// CertificateBundleInput is a raw upload of one or more PEM- or DER-encoded
// certificates (docs/backend-implementation.md §13 ruling 4 "인증서 PEM/DER
// 묶음"). Format/encoding limits are docs/pki-import.md's "지원 범위와 반영
// 계약" and "import 자원·공개 기록 경계" sections, not restated here.
type CertificateBundleInput struct {
	Data []byte
}

// CertificateBundleFacts is ParseCertificateBundle's output: one
// ParsedCertificateFacts per certificate found in Data, in upload order.
type CertificateBundleFacts struct {
	Certificates []ParsedCertificateFacts
}

// RevokedEntryFacts is one CRL entry's public facts. It carries no
// RevocationID or CAKeyGenerationID -- those are the app's to assign after
// it has matched the CRL's issuer to a stored Authority
// (docs/backend-implementation.md §13 ruling 4).
type RevokedEntryFacts struct {
	Serial    domain.SerialNumber
	RevokedAt domain.Instant
	Reason    domain.RevocationReason
}

// CRLInput is a raw upload of one PEM- or DER-encoded CRL
// (docs/backend-implementation.md §13 ruling 4 "CRL PEM/DER").
type CRLInput struct {
	Data []byte
}

// ParsedCRLFacts is ParseCRL's output. DER is the exact signed bytes the CRL
// arrived as, kept so the app can re-verify (or hand to a signature
// verifier) the issuer/signature relationship against whichever stored
// Authority it matches IssuerSubject/AuthorityKeyID to -- the parser itself
// does not decide that relationship (ruling 4 "CRL의 issuer·서명 검증에
// 필요한 정보 ... 를 포함한다" plus the same "파서가 ... issuer 관계를 임의
// 생성하지 않는다" restriction that applies to certificates). Number,
// ThisUpdate/NextUpdate and Revoked are the "번호·기간·폐기 항목" the ruling
// names explicitly.
type ParsedCRLFacts struct {
	DER            []byte
	IssuerSubject  domain.Subject
	AuthorityKeyID []byte // raw AKI keyIdentifier off the CRL, nil if absent
	Number         domain.CRLNumber
	ThisUpdate     domain.Instant
	NextUpdate     domain.Instant
	Revoked        []RevokedEntryFacts
}

// CAKeyInput is an uploaded CA private key plus the certificate public key
// it must match. Data is the raw PEM or DER key material (public by
// construction: it is still encrypted-or-plaintext key bytes, never a
// secret.Input by itself, since the passphrase -- not the ciphertext -- is
// what must never be retained). Passphrase is nil for an unencrypted key.
// ExpectedPublicKey is normally the PublicKey a prior ParseCertificateBundle
// call returned for the certificate this key is claimed to belong to.
type CAKeyInput struct {
	Data              []byte
	Passphrase        *secret.Input
	ExpectedPublicKey domain.PublicKey
}

// TLSKeyInput is CAKeyInput's internal_tls-purpose counterpart.
type TLSKeyInput struct {
	Data              []byte
	Passphrase        *secret.Input
	ExpectedPublicKey domain.PublicKey
}

// PKIParser parses uploaded import material into validated, public facts.
// It only accepts the fixed set of supported format/encryption combinations
// (docs/backend-implementation.md §6 "PKIParser는 지원 형식·암호화 조합만
// 받아들이며 라이브러리의 더 넓은 지원 목록을 그대로 노출하지 않는다. 임의
// OID나 scrypt로 자동 fallback하지 않는다"); the numeric format, encryption
// and resource limits themselves are docs/pki-import.md's "지원 범위와 반영
// 계약" and "import 자원·공개 기록 경계" sections and are not restated here.
//
// The four material kinds -- certificate bundle, CRL, CA private key,
// internal TLS private key -- are separate typed methods rather than one
// polymorphic Parse, per docs/backend-implementation.md §13 ruling 4
// ("인증서 PEM/DER 묶음, CRL PEM/DER, CA 개인키, 내부 TLS 개인키를 구분하는
// typed 입력/출력 메서드"). There is deliberately no method for an ordinary
// leaf private key: ruling 4's "일반 leaf 개인키 import는 허용하지 않는다"
// is expressed structurally here, not just documented -- ParseCAKey and
// ParseInternalTLSKey are the only two ways to hand this interface a
// private key at all, and each hardcodes its own KeySpec purpose
// (ca_signing/bootstrap_ca or internal_tls) internally rather than
// accepting a caller-supplied domain.SecretPurpose that could be set to
// leaf_delivery or anything else. A caller wanting to import a leaf key has
// no method on this interface to call; there is no third, purpose-parameterized
// method whose argument could be misused to reach a leaf import path.
type PKIParser interface {
	// ParseCertificateBundle parses every certificate in input.Data.
	ParseCertificateBundle(ctx context.Context, input CertificateBundleInput) (CertificateBundleFacts, error)

	// ParseCRL parses one CRL.
	ParseCRL(ctx context.Context, input CRLInput) (ParsedCRLFacts, error)

	// ParseCAKey decrypts (if input.Passphrase is set) and validates a CA
	// private key, checking that its derived public key equals
	// input.ExpectedPublicKey (docs/backend-implementation.md §13 ruling 4
	// "키 입력은 secret.Input이고 CA/internal_tls 목적과 인증서 공개키
	// 일치를 검증한다"). On success the returned ValidatedCAKeyInput.PrivateKey
	// is a secret.Input this call created; the caller takes ownership of it,
	// passes it to KeyEngine.ImportCA, and Closes it once that call returns
	// (docs/backend-implementation.md §13 ruling 4 "검증된 키 입력은
	// 호출자가 KeyEngine.Import 후 Close"). On error -- including a public
	// key mismatch discovered only after the key was already decrypted into
	// a secret.Input -- ParseCAKey must Close any secret.Input it created
	// before returning, rather than leaking it to a caller that has nothing
	// to Close (ruling 4 "중간 실패 시 파서가 이미 만든 비밀을 닫는다").
	ParseCAKey(ctx context.Context, input CAKeyInput) (ValidatedCAKeyInput, error)

	// ParseInternalTLSKey is ParseCAKey's internal_tls-purpose counterpart,
	// with the identical validation and close-on-failure ownership contract.
	ParseInternalTLSKey(ctx context.Context, input TLSKeyInput) (ValidatedTLSKeyInput, error)
}

// ChainValidator verifies that a leaf certificate chains to a trusted root
// through the given intermediates, at the given time. Used by Import (does
// the uploaded chain actually validate) and by TLS candidate validation
// (docs/backend-implementation.md §5 "TLS: ... ChainValidator ...").
type ChainValidator interface {
	Validate(ctx context.Context, leafDER []byte, chainDER [][]byte, now domain.Instant) error
}

// TLSFileSourceInput is the configured, application-owned source material for
// TLSService.Reload. The source resolves a configured file location inside
// runtime/config; requests never carry a path and no path is read from
// context. Passphrase is owned by the caller after Load succeeds and must be
// closed after the key parser returns. The source must not modify its original
// files while producing this snapshot.
type TLSFileSourceInput struct {
	Certificate []byte
	Chain       []byte
	Key         []byte
	Passphrase  *secret.Input
}

// TLSFileSource loads the configured TLS certificate, chain and key for an
// explicit Reload command. It is deliberately narrow: it has no arbitrary
// path argument, directory traversal, watcher callback or activation method.
// Implementations return a point-in-time copy/snapshot of the source bytes;
// Reload validates and stores that snapshot through the same path as an
// uploaded candidate.
type TLSFileSource interface {
	Load(ctx context.Context) (TLSFileSourceInput, error)
}

// CRLVerifier verifies a signed CRL against the DER of the CA certificate
// the application resolved from stored/bundled relationships. It deliberately
// accepts public bytes rather than an issuer id so the adapter performs the
// cryptographic check against the exact certificate selected by the app.
type CRLVerifier interface {
	Verify(ctx context.Context, crlDER []byte, issuerCertificateDER []byte) error
}

// S2 fix (round 1): PreparedTLSConfig used to be a marker interface with an
// unexported method (sealedPreparedTLSConfig), which meant nothing outside
// this package -- including the real B05 TLS installer in adapter/tls --
// could ever construct a value satisfying it. There was also no constructor
// inside port itself, so no concrete "prepared" value existed anywhere. The
// type was unimplementable by the very adapter
// docs/backend-implementation.md §9 requires to implement TLSInstaller.
//
// Round 1 replaced the marker interface with a concrete struct carrying an
// installer-minted TLSPrepareToken plus a public `Payload any` field, and
// Apply called token.Verify(prepared) before trusting a handle. That closed
// constructibility and rejected foreign/hand-built handles, but left a
// second hole open (P2 on this PR): Verify only checks *which installer*
// minted the handle, never *what configuration* it carries. Payload being a
// public field meant any caller holding a legitimately Prepared handle
// could overwrite it with an unvalidated value between Prepare and Apply,
// and token.Verify(prepared) still reported true -- so Apply would install a
// configuration that was never run through Prepare's validation, defeating
// the property docs/backend-implementation.md §9 depends on ("준비한 후보를
// TLSInstaller.Prepare에 넣어 실제 적용 가능한 메모리 설정을 먼저 만든다").
// A getter exposing a mutable concrete config (e.g. *tls.Config) would have
// reopened the identical hole one level down, since the caller could mutate
// whatever the getter's pointer points at.
//
// Round 2 (this fix) removes the payload from PreparedTLSConfig entirely.
// The handle now carries only the installer's token (who minted it) and an
// opaque per-Prepare-call identity (which specific Prepare call minted it).
// The actual configuration never leaves the TLSInstaller implementation
// that built it: a real Prepare stores the config in a private registry
// keyed by the handle's identity (see ID below) and a real Apply looks the
// config up from that same private registry after Verify succeeds. Because
// port itself never stores or exposes the payload, there is no field or
// getter anywhere in this package for an outside caller to overwrite or
// mutate -- the substitution the reviewer reproduced is a compile error
// now, not a runtime check. See TestPreparedTLSConfig_ApplyRejectsAForeignHandle,
// TestPreparedTLSConfig_ApplyRejectsAZeroValueHandle and
// TestPreparedTLSConfig_PayloadCannotBeSubstitutedExternally in the
// external port_test package. A TLSInstaller implementation that skips the
// Verify call, or that hands its config out through some other exported
// getter of its own, does not get this guarantee for free -- port can only
// enforce what travels through PreparedTLSConfig itself.
type PreparedTLSConfig struct {
	token  TLSPrepareToken
	handle *byte
}

// ID returns an opaque, comparable identity for this specific Prepare call,
// suitable as a map key in the installer's own handle -> config registry
// (see PreparedTLSConfig's doc comment for why the registry lives in the
// installer, not here). Two handles from different Prepare calls -- even by
// the same installer, even for the same candidate -- never compare equal,
// because each wraps its own freshly allocated byte. The zero value's ID is
// nil, matching no registry entry an installer would ever create with
// NewPreparedTLSConfig.
func (p PreparedTLSConfig) ID() any { return p.handle }

// TLSPrepareToken is an opaque, comparable identity a TLSInstaller
// implementation mints once -- typically in its own constructor -- and
// keeps for the lifetime of the listener it manages. The same token must be
// used both to stamp every PreparedTLSConfig that installer's Prepare
// returns (via NewPreparedTLSConfig) and to check every PreparedTLSConfig
// its own Apply receives (via Verify); mixing tokens between two installer
// instances, or never minting one at all, is what lets Verify tell a
// genuine handle apart from a foreign or hand-built one.
type TLSPrepareToken struct{ id *byte }

// NewTLSPrepareToken mints a fresh token, distinct from every other token
// ever minted (it wraps a freshly allocated pointer, so equality is
// identity, not value equality). The pointee is a byte, not a zero-size
// struct{} -- the Go runtime is free to hand out the same address for every
// zero-size allocation, which would make two independently minted tokens
// compare equal and defeat Verify entirely.
func NewTLSPrepareToken() TLSPrepareToken { return TLSPrepareToken{id: new(byte)} }

// NewPreparedTLSConfig mints a handle stamped with token, identifying one
// specific Prepare call. Call it only from inside the Prepare that just
// finished validating candidate/key and building the real in-memory config;
// TLSInstaller.Prepare's doc comment says as much. The caller must record
// its own config against the returned handle's ID() in a private registry
// before returning the handle, since the handle itself carries no payload
// (see PreparedTLSConfig's doc comment for why).
func NewPreparedTLSConfig(token TLSPrepareToken) PreparedTLSConfig {
	return PreparedTLSConfig{token: token, handle: new(byte)}
}

// Verify reports whether prepared was stamped with this exact token. A
// TLSInstaller's Apply must call this on its own token before trusting
// prepared -- i.e. before looking prepared.ID() up in its own registry; a
// zero-value PreparedTLSConfig (never passed through NewPreparedTLSConfig)
// always fails Verify, since its token has a nil id.
func (t TLSPrepareToken) Verify(prepared PreparedTLSConfig) bool {
	return t.id != nil && prepared.token.id == t.id
}

// TLSInstaller separates building a candidate's in-memory configuration from
// actually swapping the live listener onto it
// (docs/backend-implementation.md §9). Apply's failure must leave the
// previous configuration untouched; the caller (TLSService.Activate) owns
// reverting the DB side on that failure.
type TLSInstaller interface {
	// Prepare validates candidate and its decrypted key long enough to build
	// a ready-to-apply in-memory configuration, then re-encrypts/discards
	// any plaintext it touched. It does not change the live listener. The
	// returned PreparedTLSConfig must be built with NewPreparedTLSConfig
	// using a TLSPrepareToken this same implementation holds, so its own
	// Apply can Verify it later. Because PreparedTLSConfig carries no
	// payload (see its doc comment), the implementation must record the
	// config it just built in its own private registry, keyed by the
	// returned handle's ID(), before returning -- otherwise its own Apply
	// has nothing to look up.
	Prepare(ctx context.Context, candidate domain.TLSVersion, key domain.EncryptedSecret) (PreparedTLSConfig, error)

	// Apply swaps the live listener onto a previously prepared
	// configuration. It must call its TLSPrepareToken.Verify(prepared)
	// before trusting prepared, rejecting a handle that was never built by
	// this installer's own Prepare -- app code must never be able to
	// fabricate one and have it accepted. Once Verify succeeds, it must
	// look the real configuration up from its own private registry by
	// prepared.ID(); nothing reachable from prepared itself can have been
	// substituted after Prepare returned it, so the config that gets
	// applied is always the one this installer's own Prepare built and
	// validated. A failure here must leave the previously active
	// configuration serving traffic unchanged (docs/backend-implementation.md
	// §9 "Apply 실패는 DB/메모리 모두 원복한다").
	//
	// Apply consumes the handle exactly once. On success it removes the
	// registry entry and hands that configuration's ownership to the live
	// listener; on failure it removes the entry but keeps the previous
	// listener. Re-applying a handle that was already consumed or discarded
	// is rejected (docs/backend-implementation.md §13 "Apply는 handle을 한 번만
	// 소비한다 ... 이미 소비·폐기된 handle의 재Apply는 거부한다").
	Apply(ctx context.Context, prepared PreparedTLSConfig) error

	// Discard releases a prepared entry that will never be applied.
	//
	// The registry the handle-ID design requires means a successful Prepare
	// leaves state behind, and Apply is not always reached: the surrounding
	// DB write can roll back, come back commit_unknown, or the request can be
	// cancelled or panic. A service therefore defers Discard immediately
	// after a successful Prepare, so none of those paths leak an entry
	// (docs/backend-implementation.md §13 "서비스는 Prepare 성공 직후 Discard를
	// defer해 DB rollback·commit_unknown·취소·panic에서도 미적용 registry
	// 항목을 정리한다").
	//
	// Required behaviour:
	//   - Idempotent. Calling it twice, or after Apply already consumed the
	//     handle, is not an error -- which is what makes the deferred call
	//     safe on the success path.
	//   - A deferred Discard after a SUCCESSFUL Apply must not tear down the
	//     now-active configuration: Apply transferred ownership to the live
	//     listener, so there is no longer a prepared entry to release.
	//   - It releases only entries this installer itself prepared, the same
	//     ownership check Apply performs through Verify.
	//   - It must not depend on a request context. It runs precisely on the
	//     paths where that context is already cancelled, so it takes none.
	//   - It never changes the live listener.
	//
	// It returns no error: a caller in a defer has nothing useful to do with
	// one, and a failure to release an unapplied entry must not mask the
	// error that caused the cleanup in the first place.
	Discard(prepared PreparedTLSConfig)
}
