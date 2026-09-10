package contract

import (
	"cert-me/internal/domain"
)

// LeafSeriesView is the OpenAPI LeafSeries data object.
type LeafSeriesView struct {
	ID                     domain.SeriesID
	Name                   string
	Purpose                domain.SeriesPurpose
	ManagementAuthorityID  domain.AuthorityID
	CurrentCertificateID   *domain.CertificateID
	CurrentKeyGenerationID *domain.LeafKeyGenerationID
	Validity               domain.CalendarValidity
	RotateEvery            int
	RenewalCount           int64
	PriorHistoryUnknown    bool
	Delivery               *DeliveryView
	ArchivedAt             *domain.Instant
	Version                domain.Version
	CreatedAt              domain.Instant
}

// IssuanceView is the OpenAPI Issuance data object.
type IssuanceView struct {
	SeriesID        domain.SeriesID
	CertificateID   domain.CertificateID
	KeyGenerationID domain.LeafKeyGenerationID
	RenewalCount    int64
	KeyRotated      bool
	Delivery        *DeliveryView
	CertificateURL  string
	SeriesURL       string
}

const maxLeafNameLength = 255

// IssuanceIssueCommand is the JSON decode target for the OpenAPI LeafCreate
// schema. It has no path target id: Issue creates a brand new series
// (backend-implementation.md §3 lists it among the three idempotent
// issuance methods, whose retry key lives on MutationMeta, not here).
type IssuanceIssueCommand struct {
	Name         string             `json:"name"`
	AuthorityID  domain.AuthorityID `json:"authority_id"`
	Profile      string             `json:"profile"`
	Subject      SubjectInput       `json:"subject"`
	SANs         []SANInput         `json:"sans,omitempty"`
	KeyAlgorithm string             `json:"key_algorithm,omitempty"`
	Validity     *ValidityInput     `json:"validity,omitempty"`
	RotateEvery  *int               `json:"rotate_every,omitempty"`
}

// DomainProfile converts and validates the profile field.
func (c IssuanceIssueCommand) DomainProfile() (domain.CertificateProfile, error) {
	profile := domain.CertificateProfile(c.Profile)
	if err := profile.Validate(); err != nil {
		return "", err
	}
	return profile, nil
}

// DomainKeyAlgorithm converts the optional key_algorithm, returning the
// product default when the field was omitted.
func (c IssuanceIssueCommand) DomainKeyAlgorithm() (domain.KeyAlgorithm, error) {
	if c.KeyAlgorithm == "" {
		return domain.DefaultKeyAlgorithm, nil
	}
	alg := domain.KeyAlgorithm(c.KeyAlgorithm)
	if err := alg.Validate(); err != nil {
		return "", err
	}
	return alg, nil
}

// DomainSANs converts the optional SAN list, reporting the index of the
// first bad entry.
func (c IssuanceIssueCommand) DomainSANs() ([]domain.SAN, error) {
	return SANInputs(c.SANs)
}

// DomainRotateEvery returns the requested rotate_every, or the product
// default (3) when the field was omitted, matching the LeafCreate schema's
// declared default.
func (c IssuanceIssueCommand) DomainRotateEvery() int {
	if c.RotateEvery == nil {
		return 3
	}
	return *c.RotateEvery
}

const maxSANCount = 100

// Validate mirrors the LeafCreate schema's required set (name, authority_id,
// profile, subject) plus its description's rule: server_tls/dual require at
// least one DNS or IP SAN.
func (c IssuanceIssueCommand) Validate() error {
	if c.Name == "" || len(c.Name) > maxLeafNameLength {
		return NewAppError(ErrorKindValidation, "invalid_name", "name must be 1..255 characters")
	}
	if _, err := domain.ParseAuthorityID(string(c.AuthorityID)); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_authority_id", "authority_id must be a uuid")
	}
	profile, err := c.DomainProfile()
	if err != nil {
		return NewAppError(ErrorKindValidation, "invalid_profile", "profile is unsupported")
	}
	if len(c.SANs) > maxSANCount {
		return NewAppError(ErrorKindValidation, "too_many_sans", "sans must be at most 100 entries")
	}
	sans, err := c.DomainSANs()
	if err != nil {
		return NewAppError(ErrorKindValidation, "invalid_sans", "sans are invalid")
	}
	if _, err := c.Subject.Domain(); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_subject", "subject is invalid")
	}
	if err := domain.ValidateSANsForProfile(profile, sans); err != nil {
		return NewAppError(ErrorKindValidation, "sans_required_for_profile", "server_tls/dual require at least one dns or ip san")
	}
	if _, err := c.DomainKeyAlgorithm(); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_key_algorithm", "key_algorithm is unsupported")
	}
	if c.Validity != nil {
		if _, err := c.Validity.Domain(); err != nil {
			return NewAppError(ErrorKindValidation, "invalid_validity", "validity must have a positive value and a supported unit")
		}
	}
	if c.RotateEvery != nil && (*c.RotateEvery < minRotateEverySetting || *c.RotateEvery > maxRotateEverySetting) {
		return NewAppError(ErrorKindValidation, "invalid_rotate_every", "rotate_every must be 1..100")
	}
	return nil
}

// IssuanceRenewCommand is the JSON decode target for the OpenAPI Renew
// schema. SeriesID is the URL path target (POST
// /leaf-series/{id}/renewals); it is tagged json:"-" per
// backend-implementation.md §3.
type IssuanceRenewCommand struct {
	SeriesID            domain.SeriesID      `json:"-"`
	SourceCertificateID domain.CertificateID `json:"source_certificate_id"`
	TargetAuthorityID   domain.AuthorityID   `json:"target_authority_id,omitempty"`
	TransitionID        domain.TransitionID  `json:"transition_id,omitempty"`
}

// Validate mirrors the Renew schema's required set (source_certificate_id)
// plus the parsed shape of the two optional ids when present.
func (c IssuanceRenewCommand) Validate() error {
	if _, err := domain.ParseSeriesID(string(c.SeriesID)); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_series_id", "series id must be a uuid")
	}
	if _, err := domain.ParseCertificateID(string(c.SourceCertificateID)); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_source_certificate_id", "source_certificate_id must be a uuid")
	}
	if c.TargetAuthorityID != "" {
		if _, err := domain.ParseAuthorityID(string(c.TargetAuthorityID)); err != nil {
			return NewAppError(ErrorKindValidation, "invalid_target_authority_id", "target_authority_id must be a uuid")
		}
	}
	if c.TransitionID != "" {
		if _, err := domain.ParseTransitionID(string(c.TransitionID)); err != nil {
			return NewAppError(ErrorKindValidation, "invalid_transition_id", "transition_id must be a uuid")
		}
	}
	return nil
}

// ReissueReason mirrors the OpenAPI Reissue.reason enum.
type ReissueReason string

const (
	ReissueReasonDeliveryFailed  ReissueReason = "delivery_failed"
	ReissueReasonDeliveryExpired ReissueReason = "delivery_expired"
	ReissueReasonKeyCompromise   ReissueReason = "key_compromise"
	ReissueReasonManualRotation  ReissueReason = "manual_rotation"
	ReissueReasonEmergency       ReissueReason = "emergency"
)

func (r ReissueReason) Validate() error {
	switch r {
	case ReissueReasonDeliveryFailed, ReissueReasonDeliveryExpired, ReissueReasonKeyCompromise,
		ReissueReasonManualRotation, ReissueReasonEmergency:
		return nil
	default:
		return NewAppError(ErrorKindValidation, "invalid_reason", "reason is unsupported")
	}
}

// IssuanceReissueCommand is the JSON decode target for the OpenAPI Reissue
// schema. SeriesID is the URL path target (POST
// /leaf-series/{id}/reissues).
type IssuanceReissueCommand struct {
	SeriesID            domain.SeriesID      `json:"-"`
	SourceCertificateID domain.CertificateID `json:"source_certificate_id"`
	TargetAuthorityID   domain.AuthorityID   `json:"target_authority_id,omitempty"`
	TransitionID        domain.TransitionID  `json:"transition_id,omitempty"`
	Reason              ReissueReason        `json:"reason"`
}

// Validate mirrors the Reissue schema's required set (source_certificate_id,
// reason).
func (c IssuanceReissueCommand) Validate() error {
	if _, err := domain.ParseSeriesID(string(c.SeriesID)); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_series_id", "series id must be a uuid")
	}
	if _, err := domain.ParseCertificateID(string(c.SourceCertificateID)); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_source_certificate_id", "source_certificate_id must be a uuid")
	}
	if c.TargetAuthorityID != "" {
		if _, err := domain.ParseAuthorityID(string(c.TargetAuthorityID)); err != nil {
			return NewAppError(ErrorKindValidation, "invalid_target_authority_id", "target_authority_id must be a uuid")
		}
	}
	if c.TransitionID != "" {
		if _, err := domain.ParseTransitionID(string(c.TransitionID)); err != nil {
			return NewAppError(ErrorKindValidation, "invalid_transition_id", "transition_id must be a uuid")
		}
	}
	if err := c.Reason.Validate(); err != nil {
		return err
	}
	return nil
}

// IssuanceUpdateSeriesCommand is the JSON decode target for the OpenAPI
// LeafPatch schema. SeriesID is the URL path target (PATCH
// /leaf-series/{id}).
type IssuanceUpdateSeriesCommand struct {
	SeriesID    domain.SeriesID `json:"-"`
	Name        *string         `json:"name,omitempty"`
	Validity    *ValidityInput  `json:"validity,omitempty"`
	RotateEvery *int            `json:"rotate_every,omitempty"`
}

// Validate enforces the SeriesID path target plus the LeafPatch schema's
// minProperties:1 and each field's own bound.
func (c IssuanceUpdateSeriesCommand) Validate() error {
	if _, err := domain.ParseSeriesID(string(c.SeriesID)); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_series_id", "series id must be a uuid")
	}
	if c.Name == nil && c.Validity == nil && c.RotateEvery == nil {
		return NewAppError(ErrorKindValidation, "empty_patch", "at least one of name, validity or rotate_every is required")
	}
	if c.Name != nil && (*c.Name == "" || len(*c.Name) > maxLeafNameLength) {
		return NewAppError(ErrorKindValidation, "invalid_name", "name must be 1..255 characters")
	}
	if c.Validity != nil {
		if _, err := c.Validity.Domain(); err != nil {
			return NewAppError(ErrorKindValidation, "invalid_validity", "validity must have a positive value and a supported unit")
		}
	}
	if c.RotateEvery != nil && (*c.RotateEvery < minRotateEverySetting || *c.RotateEvery > maxRotateEverySetting) {
		return NewAppError(ErrorKindValidation, "invalid_rotate_every", "rotate_every must be 1..100")
	}
	return nil
}

// IssuanceArchiveSeriesCommand carries only the path target: the archive
// request body is empty, but it still acts on one series, so it cannot reuse
// the fieldless EmptyCommand.
type IssuanceArchiveSeriesCommand struct {
	SeriesID domain.SeriesID `json:"-"`
}

func (c IssuanceArchiveSeriesCommand) Validate() error {
	if _, err := domain.ParseSeriesID(string(c.SeriesID)); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_series_id", "series id must be a uuid")
	}
	return nil
}
