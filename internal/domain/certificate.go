package domain

import (
	"fmt"
	"net/url"
	"strings"
)

// Subject carries the distinguished-name fields the server sets on an issued
// certificate. Only common_name is required; the rest are optional per the
// OpenAPI Subject schema. [backend-implementation.md §2, certificate-lifecycle.md]
type Subject struct {
	commonName         string
	organization       string
	organizationalUnit string
	country            string
}

// SubjectFacts is the constructor input for Subject.
type SubjectFacts struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
}

const maxSubjectFieldLength = 255

// NewSubject validates field lengths and the ISO 3166-1 alpha-2 country code.
func NewSubject(facts SubjectFacts) (Subject, error) {
	cn := strings.TrimSpace(facts.CommonName)
	if cn == "" {
		return Subject{}, fmt.Errorf("%w: subject common_name must not be empty", ErrInvalidValue)
	}
	if len(cn) > maxSubjectFieldLength {
		return Subject{}, fmt.Errorf("%w: subject common_name too long", ErrInvalidValue)
	}
	if len(facts.Organization) > maxSubjectFieldLength {
		return Subject{}, fmt.Errorf("%w: subject organization too long", ErrInvalidValue)
	}
	if len(facts.OrganizationalUnit) > maxSubjectFieldLength {
		return Subject{}, fmt.Errorf("%w: subject organizational_unit too long", ErrInvalidValue)
	}
	if facts.Country != "" {
		if len(facts.Country) != 2 || !isUppercaseASCIILetters(facts.Country) {
			return Subject{}, fmt.Errorf("%w: subject country must be a 2 letter uppercase code", ErrInvalidValue)
		}
	}
	return Subject{
		commonName:         cn,
		organization:       facts.Organization,
		organizationalUnit: facts.OrganizationalUnit,
		country:            facts.Country,
	}, nil
}

func isUppercaseASCIILetters(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

func (s Subject) CommonName() string         { return s.commonName }
func (s Subject) Organization() string       { return s.organization }
func (s Subject) OrganizationalUnit() string { return s.organizationalUnit }
func (s Subject) Country() string            { return s.country }

// SANType names a supported subjectAltName kind. Email SANs are out of MVP
// scope. [certificate-lifecycle.md]
type SANType string

const (
	SANTypeDNS SANType = "dns"
	SANTypeIP  SANType = "ip"
	SANTypeURI SANType = "uri"
)

func (t SANType) Validate() error {
	switch t {
	case SANTypeDNS, SANTypeIP, SANTypeURI:
		return nil
	default:
		return fmt.Errorf("%w: unsupported san type %q", ErrInvalidValue, string(t))
	}
}

// SAN is one validated subjectAltName entry.
type SAN struct {
	kind  SANType
	value string
}

const maxSANValueLength = 2048

// NewSAN validates the SAN shape. A DNS wildcard is only accepted as a
// single leftmost label ("*.example.internal"); a URI must be absolute.
func NewSAN(kind SANType, value string) (SAN, error) {
	if err := kind.Validate(); err != nil {
		return SAN{}, err
	}
	v := strings.TrimSpace(value)
	if v == "" {
		return SAN{}, fmt.Errorf("%w: san value must not be empty", ErrInvalidValue)
	}
	if len(v) > maxSANValueLength {
		return SAN{}, fmt.Errorf("%w: san value too long", ErrInvalidValue)
	}
	switch kind {
	case SANTypeDNS:
		if err := validateDNSSANValue(v); err != nil {
			return SAN{}, err
		}
	case SANTypeURI:
		parsed, err := url.Parse(v)
		if err != nil || !parsed.IsAbs() {
			return SAN{}, fmt.Errorf("%w: uri san must be an absolute uri", ErrInvalidValue)
		}
	}
	return SAN{kind: kind, value: v}, nil
}

func validateDNSSANValue(v string) error {
	labels := strings.Split(v, ".")
	for i, label := range labels {
		if label == "" {
			return fmt.Errorf("%w: dns san must not contain empty labels", ErrInvalidValue)
		}
		if label == "*" {
			// A wildcard is only permitted as the single leftmost label.
			if i != 0 {
				return fmt.Errorf("%w: wildcard must be the leftmost dns label", ErrInvalidValue)
			}
			continue
		}
		if strings.Contains(label, "*") {
			return fmt.Errorf("%w: wildcard may only replace the entire leftmost label", ErrInvalidValue)
		}
	}
	if len(labels) < 2 {
		return fmt.Errorf("%w: dns san must contain at least one dot", ErrInvalidValue)
	}
	return nil
}

func (s SAN) Type() SANType  { return s.kind }
func (s SAN) Value() string  { return s.value }
func (s SAN) String() string { return string(s.kind) + ":" + s.value }

// CertificateProfile selects the key usage / EKU bundle the server applies.
// A dual profile must be chosen explicitly. [certificate-lifecycle.md]
type CertificateProfile string

const (
	CertificateProfileServerTLS  CertificateProfile = "server_tls"
	CertificateProfileClientMTLS CertificateProfile = "client_mtls"
	CertificateProfileDual       CertificateProfile = "dual"
)

func (p CertificateProfile) Validate() error {
	switch p {
	case CertificateProfileServerTLS, CertificateProfileClientMTLS, CertificateProfileDual:
		return nil
	default:
		return fmt.Errorf("%w: unsupported certificate profile %q", ErrInvalidValue, string(p))
	}
}

// RequiresServerSAN reports whether the profile needs at least one DNS or IP
// SAN. server_tls and dual do; client_mtls only requires the subject name.
func (p CertificateProfile) RequiresServerSAN() bool {
	return p == CertificateProfileServerTLS || p == CertificateProfileDual
}

// ValidateSANsForProfile enforces the per-profile SAN requirement.
// client_mtls SANs (if any) are optional; server_tls/dual need >=1 dns/ip.
func ValidateSANsForProfile(profile CertificateProfile, sans []SAN) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	if !profile.RequiresServerSAN() {
		return nil
	}
	for _, s := range sans {
		if s.Type() == SANTypeDNS || s.Type() == SANTypeIP {
			return nil
		}
	}
	return fmt.Errorf("%w: %s profile requires at least one dns or ip san", ErrPolicyViolation, string(profile))
}

// CertificateOrigin distinguishes server-generated certificates from
// imported ones, matching certificates.origin. [data-model.md §CA·인증서·갱신 계보]
type CertificateOrigin string

const (
	CertificateOriginGenerated CertificateOrigin = "generated"
	CertificateOriginImported  CertificateOrigin = "imported"
)

func (o CertificateOrigin) Validate() error {
	switch o {
	case CertificateOriginGenerated, CertificateOriginImported:
		return nil
	default:
		return fmt.Errorf("%w: unsupported certificate origin %q", ErrInvalidValue, string(o))
	}
}

// Certificate is the immutable signed original: raw DER plus the identifiers
// and period an adapter's cryptographic parser extracted from it. The domain
// never parses ASN.1/x509 itself -- CertificateFacts is produced by the
// crypto adapter's ParseCertificate step and handed in here.
// [backend-implementation.md §2: "암호학적 파싱은 어댑터, 원본 기간/식별자는 객체"]
type Certificate struct {
	id                      CertificateID
	der                     []byte
	keyMaterialID           KeyMaterialID
	issuerCAKeyGenerationID CAKeyGenerationID
	serial                  SerialNumber
	validity                ValidityWindow
	subject                 Subject
	sans                    []SAN
	profile                 CertificateProfile
	keyAlgorithm            KeyAlgorithm
	origin                  CertificateOrigin
	createdByAccountID      AccountID
	version                 Version
}

// CertificateFacts is the constructor input for Certificate. It is what an
// adapter's ParseCertificate returns plus the storage identifiers assigned
// around it; the domain trusts these facts rather than re-deriving them from
// DER. [backend-implementation.md §2]
type CertificateFacts struct {
	ID                      CertificateID
	DER                     []byte
	KeyMaterialID           KeyMaterialID
	IssuerCAKeyGenerationID CAKeyGenerationID
	Serial                  SerialNumber
	Validity                ValidityWindow
	Subject                 Subject
	SANs                    []SAN
	Profile                 CertificateProfile
	KeyAlgorithm            KeyAlgorithm
	Origin                  CertificateOrigin
	CreatedByAccountID      AccountID // empty for import/system-created certificates
	Version                 Version
}

// NewCertificate validates facts already produced by ParseCertificate (the
// adapter-side cryptographic parse) and stores an immutable copy of the DER.
func NewCertificate(facts CertificateFacts) (Certificate, error) {
	if _, err := ParseCertificateID(string(facts.ID)); err != nil {
		return Certificate{}, err
	}
	if len(facts.DER) == 0 {
		return Certificate{}, fmt.Errorf("%w: certificate der must not be empty", ErrInvalidValue)
	}
	if _, err := ParseKeyMaterialID(string(facts.KeyMaterialID)); err != nil {
		return Certificate{}, err
	}
	if _, err := ParseCAKeyGenerationID(string(facts.IssuerCAKeyGenerationID)); err != nil {
		return Certificate{}, err
	}
	if facts.Serial.IsZero() {
		return Certificate{}, fmt.Errorf("%w: certificate serial must be set", ErrInvalidValue)
	}
	if facts.Validity.IsZero() {
		return Certificate{}, fmt.Errorf("%w: certificate validity window must be set", ErrInvalidValue)
	}
	if facts.Subject.CommonName() == "" {
		return Certificate{}, fmt.Errorf("%w: certificate subject must be set", ErrInvalidValue)
	}
	if err := ValidateSANsForProfile(facts.Profile, facts.SANs); err != nil {
		return Certificate{}, err
	}
	if err := facts.KeyAlgorithm.Validate(); err != nil {
		return Certificate{}, err
	}
	if err := facts.Origin.Validate(); err != nil {
		return Certificate{}, err
	}
	return Certificate{
		id:                      facts.ID,
		der:                     cloneBytes(facts.DER),
		keyMaterialID:           facts.KeyMaterialID,
		issuerCAKeyGenerationID: facts.IssuerCAKeyGenerationID,
		serial:                  facts.Serial,
		validity:                facts.Validity,
		subject:                 facts.Subject,
		sans:                    append([]SAN(nil), facts.SANs...),
		profile:                 facts.Profile,
		keyAlgorithm:            facts.KeyAlgorithm,
		origin:                  facts.Origin,
		createdByAccountID:      facts.CreatedByAccountID,
		version:                 facts.Version,
	}, nil
}

func (c Certificate) ID() CertificateID                          { return c.id }
func (c Certificate) DER() []byte                                { return cloneBytes(c.der) }
func (c Certificate) KeyMaterialID() KeyMaterialID               { return c.keyMaterialID }
func (c Certificate) IssuerCAKeyGenerationID() CAKeyGenerationID { return c.issuerCAKeyGenerationID }
func (c Certificate) Serial() SerialNumber                       { return c.serial }
func (c Certificate) Validity() ValidityWindow                   { return c.validity }
func (c Certificate) Subject() Subject                           { return c.subject }
func (c Certificate) SANs() []SAN                                { return append([]SAN(nil), c.sans...) }
func (c Certificate) Profile() CertificateProfile                { return c.profile }
func (c Certificate) KeyAlgorithm() KeyAlgorithm                 { return c.keyAlgorithm }
func (c Certificate) Origin() CertificateOrigin                  { return c.origin }
func (c Certificate) CreatedByAccountID() AccountID              { return c.createdByAccountID }
func (c Certificate) Version() Version                           { return c.version }

// IsValidAt reports whether now falls within the certificate's own validity
// window. It says nothing about revocation, delivery, or issuer state --
// those live in team-owned Facts/objects and are combined by the app layer.
func (c Certificate) IsValidAt(now Instant) bool { return c.validity.ContainsAt(now) }

// IsExpiredAt applies the project-wide now >= not_after rule.
func (c Certificate) IsExpiredAt(now Instant) bool { return c.validity.NotAfter().IsExpiredAt(now) }

// IssuanceRequest is the normalized, domain-validated shape of a requested
// certificate before an issuer has approved it.
type IssuanceRequest struct {
	Profile      CertificateProfile
	Subject      Subject
	SANs         []SAN
	KeyAlgorithm KeyAlgorithm
	Window       ValidityWindow
}

// Validate checks the request's own shape, independent of any issuer.
func (r IssuanceRequest) Validate() error {
	if err := r.Profile.Validate(); err != nil {
		return err
	}
	if r.Subject.CommonName() == "" {
		return fmt.Errorf("%w: issuance request subject must be set", ErrInvalidValue)
	}
	if err := ValidateSANsForProfile(r.Profile, r.SANs); err != nil {
		return err
	}
	if err := r.KeyAlgorithm.Validate(); err != nil {
		return err
	}
	if r.Window.IsZero() {
		return fmt.Errorf("%w: issuance request validity window must be set", ErrInvalidValue)
	}
	return nil
}

// IssuancePlan is the pure result of checking an IssuanceRequest against an
// issuing Authority: the concrete issuer key generation and window the
// certificate will be signed with. Producing a plan never mutates the
// Authority or issues anything itself -- application services turn a plan
// into a signing call.
// [backend-implementation.md §2: LeafSeries/Authority "입력 객체를 미리 변경하지 않음"]
type IssuancePlan struct {
	Profile               CertificateProfile
	Subject               Subject
	SANs                  []SAN
	KeyAlgorithm          KeyAlgorithm
	Window                ValidityWindow
	IssuerAuthorityID     AuthorityID
	IssuerKeyGenerationID CAKeyGenerationID
}

// PlanIssuance validates req and checks it against issuer's own CanIssue
// policy (state, key availability, compromise/parent impact, takeover, and
// -- via IssuerContext.RequestedWindow -- the issuer-period-covers-leaf-
// period rule from certificate-lifecycle.md: "하위 인증서 만료일은 발급 CA
// 만료일을 넘지 않는다. 초과 요청은 자동 축소하지 않고 가능한 기간을 안내한다."
// The request is rejected outright, never silently shrunk.
func PlanIssuance(issuer Authority, req IssuanceRequest, now Instant) (IssuancePlan, error) {
	if err := req.Validate(); err != nil {
		return IssuancePlan{}, err
	}
	ctx := IssuerContext{RequestedWindow: req.Window}
	if err := issuer.CanIssue(ctx, now); err != nil {
		return IssuancePlan{}, err
	}
	return IssuancePlan{
		Profile:               req.Profile,
		Subject:               req.Subject,
		SANs:                  append([]SAN(nil), req.SANs...),
		KeyAlgorithm:          req.KeyAlgorithm,
		Window:                req.Window,
		IssuerAuthorityID:     issuer.ID(),
		IssuerKeyGenerationID: issuer.KeyGenerationID(),
	}, nil
}
