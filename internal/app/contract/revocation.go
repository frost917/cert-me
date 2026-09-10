package contract

import (
	"fmt"
	"time"

	"cert-me/internal/domain"
)

// parseRFC3339 is the one shared wire-timestamp parser for every command in
// this developer's files (RevocationCorrection.revoked_at, Compromise.
// compromised_at, Takeover.external_issuer_stopped_at, and so on). OpenAPI
// declares every one of these as format: date-time, i.e. RFC3339.
func parseRFC3339(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, fmt.Errorf("%w: timestamp must not be empty", domain.ErrInvalidValue)
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: timestamp must be RFC3339", domain.ErrInvalidValue)
	}
	return t, nil
}

// This file is RevocationService's command/result contract
// (docs/backend-implementation.md §3 table row "RevocationService"): Revoke,
// Compromise and Correct. The path target id (CertificateID/KeyMaterialID/
// RevocationID) is a typed, json:"-" field per §3's own rule so a request
// body can never set the id the handler validated from the URL.

// revocationReasonEnum is the OpenAPI Revoke/RevocationCorrection reason
// enum. It intentionally differs in case convention from
// domain.RevocationReason (camelCase on the wire vs snake_case in domain),
// so the mapping below is the one deliberate translation point between the
// two; nothing else in this package needs to know about the mismatch.
var revocationReasonToDomain = map[string]domain.RevocationReason{
	"unspecified":          domain.RevocationReasonUnspecified,
	"keyCompromise":        domain.RevocationReasonKeyCompromise,
	"caCompromise":         domain.RevocationReasonCACompromise,
	"affiliationChanged":   domain.RevocationReasonAffiliationChanged,
	"superseded":           domain.RevocationReasonSuperseded,
	"cessationOfOperation": domain.RevocationReasonCessationOfOperation,
	"privilegeWithdrawn":   domain.RevocationReasonPrivilegeWithdrawn,
	"aACompromise":         domain.RevocationReasonAACompromise,
}

var domainToRevocationReason = func() map[domain.RevocationReason]string {
	out := make(map[domain.RevocationReason]string, len(revocationReasonToDomain))
	for wire, d := range revocationReasonToDomain {
		out[d] = wire
	}
	return out
}()

// RevocationReasonInput mirrors the OpenAPI reason enum on the wire.
type RevocationReasonInput string

// Domain converts the wire enum value to its domain reason, rejecting
// anything outside the fixed mapping above.
func (r RevocationReasonInput) Domain() (domain.RevocationReason, error) {
	reason, ok := revocationReasonToDomain[string(r)]
	if !ok {
		return "", fmt.Errorf("%w: unsupported revocation reason %q", domain.ErrInvalidValue, string(r))
	}
	return reason, nil
}

// RevocationReasonView renders a domain reason back to its wire form.
func RevocationReasonView(r domain.RevocationReason) string {
	return domainToRevocationReason[r]
}

const maxJustificationLength = 4096

// validateJustification is shared by every command in this file that carries
// a free-text justification (Revoke, Correct, ReportFailure in
// distribution.go). The OpenAPI Justification/Revoke/RevocationCorrection
// schemas all cap it at 4096 characters.
func validateJustification(justification string, required bool) error {
	if justification == "" {
		if required {
			return NewAppError(ErrorKindValidation, "justification_required", "justification must not be empty")
		}
		return nil
	}
	if len(justification) > maxJustificationLength {
		return NewAppError(ErrorKindValidation, "justification_too_long", "justification must be at most 4096 characters")
	}
	return nil
}

// RevocationRevokeCommand is the OpenAPI Revoke schema. CertificateID is the
// path target: the certificate being revoked, filled by the handler from the
// validated URL, never from the body.
type RevocationRevokeCommand struct {
	CertificateID domain.CertificateID  `json:"-"`
	Reason        RevocationReasonInput `json:"reason"`
	Justification string                `json:"justification"`
}

// Validate parses/validates every OpenAPI-required field: reason and
// justification are both required on Revoke.
func (c RevocationRevokeCommand) Validate() error {
	if _, err := domain.ParseCertificateID(string(c.CertificateID)); err != nil {
		return FromDomainError(err)
	}
	if _, err := c.Reason.Domain(); err != nil {
		return FromDomainError(err)
	}
	if err := validateJustification(c.Justification, true); err != nil {
		return err
	}
	return nil
}

// RevocationCompromiseCommand is the OpenAPI Justification schema used as
// Compromise's command (§3: "Compromise: Justification → Compromise").
// KeyMaterialID is the path target.
type RevocationCompromiseCommand struct {
	KeyMaterialID domain.KeyMaterialID `json:"-"`
	Justification string               `json:"justification"`
}

func (c RevocationCompromiseCommand) Validate() error {
	if _, err := domain.ParseKeyMaterialID(string(c.KeyMaterialID)); err != nil {
		return FromDomainError(err)
	}
	// Justification schema declares minLength 1: required and non-empty.
	if err := validateJustification(c.Justification, true); err != nil {
		return err
	}
	return nil
}

// RevocationCorrectCommand is the OpenAPI RevocationCorrection schema.
// RevocationID is the path target, per §3's Correct rule (Revocation
// version required via MutationMeta, not a body field).
type RevocationCorrectCommand struct {
	RevocationID  domain.RevocationID   `json:"-"`
	RevokedAt     string                `json:"revoked_at"`
	Reason        RevocationReasonInput `json:"reason"`
	Justification string                `json:"justification"`
}

func (c RevocationCorrectCommand) Validate() error {
	if _, err := domain.ParseRevocationID(string(c.RevocationID)); err != nil {
		return FromDomainError(err)
	}
	if _, err := parseRFC3339(c.RevokedAt); err != nil {
		return NewAppError(ErrorKindValidation, "revoked_at_invalid", "revoked_at must be an RFC3339 timestamp")
	}
	if _, err := c.Reason.Domain(); err != nil {
		return FromDomainError(err)
	}
	if err := validateJustification(c.Justification, true); err != nil {
		return err
	}
	return nil
}

// RevokedAtInstant parses RevokedAt into a domain.Instant. Validate must be
// called first; this is the app-layer conversion step, kept next to the
// command so the RFC3339 parsing rule lives in one place.
func (c RevocationCorrectCommand) RevokedAtInstant() (domain.Instant, error) {
	t, err := parseRFC3339(c.RevokedAt)
	if err != nil {
		return domain.Instant{}, err
	}
	return domain.NewInstant(t), nil
}

// RevocationView is the OpenAPI Revocation data object.
type RevocationView struct {
	ID               domain.RevocationID
	IssuerID         domain.CAKeyGenerationID
	Serial           domain.SerialNumber
	CertificateID    *domain.CertificateID
	RevokedAt        domain.Instant
	Reason           domain.RevocationReason
	Source           domain.RevocationSource
	ChangeGeneration int64
	CRLPending       bool
	Version          domain.Version
	CreatedAt        domain.Instant
}

// CompromiseView is the OpenAPI Compromise data object: the result of
// RevocationService.Compromise, not a request shape.
type CompromiseView struct {
	KeyMaterialID domain.KeyMaterialID
	CompromisedAt domain.Instant
	Revocations   []RevocationView
}
