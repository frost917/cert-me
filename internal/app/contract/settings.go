package contract

import (
	"cert-me/internal/domain"
)

const (
	minRotateEverySetting = 1
	maxRotateEverySetting = 100

	minPrivateDeliverySeconds = 300
	maxPrivateDeliverySeconds = 86400

	minPublicLinkSeconds = 60
	maxPublicLinkSeconds = 10800

	minCRLIntervalSeconds = 300
	maxCRLIntervalSeconds = 86400

	minCRLValiditySeconds = 600
	maxCRLValiditySeconds = 604800

	minAuditRetentionDays = 30
	maxAuditRetentionDays = 3650
)

// SettingsView is the OpenAPI Settings data object. The three validity
// policies keep their calendar meaning as domain.CalendarValidity rather than
// being collapsed into a duration, matching the schema's Validity sub-object.
// The remaining seconds/day fields are stored as domain.Duration so a result
// view never carries a bare int the way a wire schema does.
type SettingsView struct {
	ServiceURL              string
	LeafValidity            domain.CalendarValidity
	RootValidity            domain.CalendarValidity
	IntermediateValidity    domain.CalendarValidity
	RotateEvery             int
	PrivateDeliveryLifetime domain.Duration
	PublicLinkLifetime      domain.Duration
	CRLInterval             domain.Duration
	CRLValidity             domain.Duration
	AuditRetentionDays      int
	Version                 domain.Version
}

// SettingsGetCommand carries no client fields.
type SettingsGetCommand struct{}

func (SettingsGetCommand) Validate() error { return nil }

// SettingsUpdateCommand is the JSON decode target for the OpenAPI
// SettingsPatch schema. Every field is a pointer so "not present" (leave
// unchanged) is distinguishable from the zero value, matching the schema's
// minProperties: 1 partial-update shape.
type SettingsUpdateCommand struct {
	ServiceURL             *string        `json:"service_url,omitempty"`
	LeafValidity           *ValidityInput `json:"leaf_validity,omitempty"`
	RootValidity           *ValidityInput `json:"root_validity,omitempty"`
	IntermediateValidity   *ValidityInput `json:"intermediate_validity,omitempty"`
	RotateEvery            *int           `json:"rotate_every,omitempty"`
	PrivateDeliverySeconds *int           `json:"private_delivery_seconds,omitempty"`
	PublicLinkSeconds      *int           `json:"public_link_seconds,omitempty"`
	CRLIntervalSeconds     *int           `json:"crl_interval_seconds,omitempty"`
	CRLValiditySeconds     *int           `json:"crl_validity_seconds,omitempty"`
	AuditRetentionDays     *int           `json:"audit_retention_days,omitempty"`
}

// Validate enforces minProperties:1 plus every field's own OpenAPI bound, and
// the schema description's cross-field rule that crl_validity_seconds must be
// at least twice crl_interval_seconds when both are given. service_url's
// "must match active operational TLS certificate" half of that same
// description is not checkable here: it needs the current TLS snapshot the
// doc's §5 dependency table gives to SettingsService, not to the command.
func (c SettingsUpdateCommand) Validate() error {
	if c.ServiceURL == nil && c.LeafValidity == nil && c.RootValidity == nil &&
		c.IntermediateValidity == nil && c.RotateEvery == nil && c.PrivateDeliverySeconds == nil &&
		c.PublicLinkSeconds == nil && c.CRLIntervalSeconds == nil && c.CRLValiditySeconds == nil &&
		c.AuditRetentionDays == nil {
		return NewAppError(ErrorKindValidation, "empty_patch", "at least one settings field is required")
	}
	if c.ServiceURL != nil {
		if !hasHTTPSPrefix(*c.ServiceURL) {
			return NewAppError(ErrorKindValidation, "invalid_service_url", "service_url must be an https:// uri")
		}
	}
	for _, f := range []struct {
		name string
		v    *ValidityInput
	}{
		{"leaf_validity", c.LeafValidity},
		{"root_validity", c.RootValidity},
		{"intermediate_validity", c.IntermediateValidity},
	} {
		if f.v == nil {
			continue
		}
		if _, err := f.v.Domain(); err != nil {
			return WrapAppError(ErrorKindValidation, "invalid_validity", "validity must have a positive value and a supported unit", err).WithField("field", f.name)
		}
	}
	if c.RotateEvery != nil && (*c.RotateEvery < minRotateEverySetting || *c.RotateEvery > maxRotateEverySetting) {
		return NewAppError(ErrorKindValidation, "invalid_rotate_every", "rotate_every must be 1..100")
	}
	if c.PrivateDeliverySeconds != nil && (*c.PrivateDeliverySeconds < minPrivateDeliverySeconds || *c.PrivateDeliverySeconds > maxPrivateDeliverySeconds) {
		return NewAppError(ErrorKindValidation, "invalid_private_delivery_seconds", "private_delivery_seconds must be 300..86400")
	}
	if c.PublicLinkSeconds != nil && (*c.PublicLinkSeconds < minPublicLinkSeconds || *c.PublicLinkSeconds > maxPublicLinkSeconds) {
		return NewAppError(ErrorKindValidation, "invalid_public_link_seconds", "public_link_seconds must be 60..10800")
	}
	if c.CRLIntervalSeconds != nil && (*c.CRLIntervalSeconds < minCRLIntervalSeconds || *c.CRLIntervalSeconds > maxCRLIntervalSeconds) {
		return NewAppError(ErrorKindValidation, "invalid_crl_interval_seconds", "crl_interval_seconds must be 300..86400")
	}
	if c.CRLValiditySeconds != nil && (*c.CRLValiditySeconds < minCRLValiditySeconds || *c.CRLValiditySeconds > maxCRLValiditySeconds) {
		return NewAppError(ErrorKindValidation, "invalid_crl_validity_seconds", "crl_validity_seconds must be 600..604800")
	}
	if c.CRLIntervalSeconds != nil && c.CRLValiditySeconds != nil && *c.CRLValiditySeconds < 2*(*c.CRLIntervalSeconds) {
		return NewAppError(ErrorKindValidation, "crl_validity_too_short", "crl_validity_seconds must be at least twice crl_interval_seconds")
	}
	if c.AuditRetentionDays != nil && (*c.AuditRetentionDays < minAuditRetentionDays || *c.AuditRetentionDays > maxAuditRetentionDays) {
		return NewAppError(ErrorKindValidation, "invalid_audit_retention_days", "audit_retention_days must be 30..3650")
	}
	return nil
}

func hasHTTPSPrefix(s string) bool {
	const prefix = "https://"
	return len(s) > len(prefix) && s[:len(prefix)] == prefix
}
