package contract

import (
	"fmt"

	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

// This file is DistributionService's command/result contract
// (docs/backend-implementation.md §3, §7): CreateLink, Deliver,
// ReportFailure.

// DownloadPurposeInput mirrors the OpenAPI DownloadLinkRequest.purpose enum,
// which uses "public"/"private" rather than domain.GrantPurpose's
// "leaf_public"/"leaf_private" wire values.
type DownloadPurposeInput string

const (
	DownloadPurposePublic  DownloadPurposeInput = "public"
	DownloadPurposePrivate DownloadPurposeInput = "private"
)

// Domain converts to the grant purpose the domain layer understands.
func (p DownloadPurposeInput) Domain() (domain.GrantPurpose, error) {
	switch p {
	case DownloadPurposePublic:
		return domain.GrantPurposeLeafPublic, nil
	case DownloadPurposePrivate:
		return domain.GrantPurposeLeafPrivate, nil
	default:
		return "", fmt.Errorf("%w: unsupported download purpose %q", domain.ErrInvalidValue, string(p))
	}
}

// DistributionCreateLinkCommand is the OpenAPI DownloadLinkRequest schema.
// CertificateID is the path target the new link is issued against.
type DistributionCreateLinkCommand struct {
	CertificateID domain.CertificateID `json:"-"`
	Purpose       DownloadPurposeInput `json:"purpose"`
}

func (c DistributionCreateLinkCommand) Validate() error {
	if _, err := domain.ParseCertificateID(string(c.CertificateID)); err != nil {
		return FromDomainError(err)
	}
	if _, err := c.Purpose.Domain(); err != nil {
		return FromDomainError(err)
	}
	return nil
}

// DownloadLinkView is the OpenAPI DownloadLink data object. URL carries the
// one-time raw bearer token and is the only field that is a secret
// (backend-implementation.md §6: "Login/CSRF/DownloadLink/ResetLink처럼 원문을
// 반드시 전달하는 결과는 해당 필드만 secret.Input으로 보유한다"). The HTTP
// mapper must write it inside a URL.Use callback and Close it once the
// response is written; a plain json.Marshal(view) must never be used to
// serialize this type for exactly that reason.
type DownloadLinkView struct {
	URL       *secret.Input
	ExpiresAt domain.Instant
	TokenID   domain.GrantID
}

// DownloadFormat mirrors the /download/{token} format query parameter.
type DownloadFormat string

const (
	DownloadFormatPEM    DownloadFormat = "pem"
	DownloadFormatZIP    DownloadFormat = "zip"
	DownloadFormatPKCS12 DownloadFormat = "pkcs12"
)

func (f DownloadFormat) Validate() error {
	switch f {
	case DownloadFormatPEM, DownloadFormatZIP, DownloadFormatPKCS12:
		return nil
	default:
		return fmt.Errorf("%w: unsupported download format %q", domain.ErrInvalidValue, string(f))
	}
}

// DownloadPart mirrors the /download/{token} part query parameter. It is
// optional on the wire; PartUnspecified is its zero value.
type DownloadPart string

const (
	DownloadPartUnspecified DownloadPart = ""
	DownloadPartCertificate DownloadPart = "certificate"
	DownloadPartChain       DownloadPart = "chain"
	DownloadPartPrivateKey  DownloadPart = "private_key"
)

func (p DownloadPart) Validate() error {
	switch p {
	case DownloadPartUnspecified, DownloadPartCertificate, DownloadPartChain, DownloadPartPrivateKey:
		return nil
	default:
		return fmt.Errorf("%w: unsupported download part %q", domain.ErrInvalidValue, string(p))
	}
}

// DownloadCommand is exactly the shape docs/backend-implementation.md §7
// fixes: "DownloadCommand는 RawToken(secret.Input), Format, PEMPart,
// PKCS12Password(secret.Input)이다." There is deliberately no actor/
// principal field here beyond what RequestMeta already carries anonymous:
// the real authentication for Deliver is the grant hash/purpose/deadline,
// not a caller-asserted identity (§7: "RequestMeta의 Principal은 익명이며
// 실제 인증은 grant 해시·목적·기한으로 수행한다"). RawToken and
// PKCS12Password are owned by this command; the HTTP adapter that builds it
// Closes both once Deliver returns, matching the upload/secret-command
// convention used for every command in this file that carries a secret.
type DownloadCommand struct {
	RawToken       *secret.Input  `json:"-"`
	Format         DownloadFormat `json:"-"`
	PEMPart        DownloadPart   `json:"-"`
	PKCS12Password *secret.Input  `json:"-"`
}

// Validate checks the query-derived fields. RawToken presence/shape is
// intentionally not string-inspected here: the token is a secret and its
// only real validation is the grant hash lookup Deliver performs inside the
// transaction, not a client-visible format check.
func (c DownloadCommand) Validate() error {
	if c.RawToken == nil || c.RawToken.IsEmpty() {
		return NewAppError(ErrorKindValidation, "raw_token_required", "a download token is required")
	}
	if err := c.Format.Validate(); err != nil {
		return FromDomainError(err)
	}
	if err := c.PEMPart.Validate(); err != nil {
		return FromDomainError(err)
	}
	if c.Format != DownloadFormatPKCS12 && c.PKCS12Password != nil && !c.PKCS12Password.IsEmpty() {
		return NewAppError(ErrorKindValidation, "pkcs12_password_not_applicable", "a pkcs12 password is only accepted for the pkcs12 format")
	}
	return nil
}

// TransferSummary is the internal result named in
// docs/backend-implementation.md §3/§7: "TransferSummary는 비밀 없는
// tokenID/deliveryID·서버 관측 결과다." It is not an OpenAPI schema and must
// not become one: Deliver streams the payload through DownloadSink and
// never returns it, so this result only ever reports bookkeeping.
type TransferSummary struct {
	TokenID      domain.GrantID
	DeliveryID   domain.DeliveryID // zero for a public (non-private-key) transfer
	Completed    bool
	BytesWritten int64
	FinishedAt   domain.Instant
}

// DistributionReportFailureCommand is the OpenAPI Justification schema used
// as ReportFailure's command. DeliveryID is the path target; §3 requires the
// Delivery version via MutationMeta, not a body field.
type DistributionReportFailureCommand struct {
	DeliveryID    domain.DeliveryID `json:"-"`
	Justification string            `json:"justification"`
}

func (c DistributionReportFailureCommand) Validate() error {
	if _, err := domain.ParseDeliveryID(string(c.DeliveryID)); err != nil {
		return FromDomainError(err)
	}
	if err := validateJustification(c.Justification, true); err != nil {
		return err
	}
	return nil
}

// DeliveryFailureView is the OpenAPI DeliveryFailure data object: the
// failed delivery plus the revocation ReportFailure's shared
// applyRevocations path produced for the now-untrusted key.
type DeliveryFailureView struct {
	Delivery   DeliveryView
	Revocation RevocationView
}
