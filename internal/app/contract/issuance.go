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
	// Validity and RotateEvery are pointers so a nil value means "omitted",
	// not "zero". Both are installation Settings with a factory default
	// (leaf_validity, rotate_every on the Settings schema), not per-request
	// constants: an omitted value is resolved from current Settings by
	// IssuanceService at issuance time, not defaulted here (see
	// DomainRotateEvery's doc comment for the full citation). Validity is
	// already reported this way -- Validate only checks it when present, it
	// never substitutes a value -- and DomainRotateEvery keeps the same
	// shape for symmetry.
	Validity    *ValidityInput `json:"validity,omitempty"`
	RotateEvery *int           `json:"rotate_every,omitempty"`
}

// DomainProfile converts and validates the profile field.
func (c IssuanceIssueCommand) DomainProfile() (domain.CertificateProfile, error) {
	profile := domain.CertificateProfile(c.Profile)
	if err := profile.Validate(); err != nil {
		return "", WrapAppError(ErrorKindValidation, "invalid_profile", "profile is unsupported", err).WithField("profile", c.Profile)
	}
	return profile, nil
}

// DomainKeyAlgorithm converts the optional key_algorithm, returning the
// product default when the field was omitted. Unlike RotateEvery/Validity,
// key_algorithm genuinely has no Settings-level home -- the Settings schema
// has no key-algorithm field -- so domain.DefaultKeyAlgorithm is the correct
// source here, not a defaulting bug like F1.
func (c IssuanceIssueCommand) DomainKeyAlgorithm() (domain.KeyAlgorithm, error) {
	if c.KeyAlgorithm == "" {
		return domain.DefaultKeyAlgorithm, nil
	}
	alg := domain.KeyAlgorithm(c.KeyAlgorithm)
	if err := alg.Validate(); err != nil {
		return "", WrapAppError(ErrorKindValidation, "invalid_key_algorithm", "key_algorithm is unsupported", err).WithField("key_algorithm", c.KeyAlgorithm)
	}
	return alg, nil
}

// DomainSANs converts the optional SAN list, reporting the index of the
// first bad entry.
func (c IssuanceIssueCommand) DomainSANs() ([]domain.SAN, error) {
	return SANInputs(c.SANs)
}

// DomainRotateEvery reports the requested rotate_every and whether the
// field was present at all.
//
// rotate_every is an installation Setting, not a per-request constant: it is
// admin-configurable (docs/architecture.md:152 -- "키 교체 주기는 1~100회(기본
// 3회)로 설정한다") and the LeafCreate schema's declared default of 3 is the
// factory default OF THAT SETTING, not a fallback this contract layer may
// apply on its own. An omitted field must be resolved from the current
// Settings value at issuance time, by IssuanceService in B03
// (docs/api-contract.md:105 -- "생략된 기본값은 발급 시 확정해 결과에 포함한다"),
// and the resolved value is then captured on the series and must not be
// overwritten by a later change to the service default
// (docs/certificate-lifecycle.md:20). If this method defaulted to 3 itself,
// an admin who set rotate_every=10 would silently get new series created
// with 3 instead. So the contract layer only reports presence; it never
// guesses a value.
func (c IssuanceIssueCommand) DomainRotateEvery() (value int, present bool) {
	if c.RotateEvery == nil {
		return 0, false
	}
	return *c.RotateEvery, true
}

const maxSANCount = 100

// Validate mirrors the LeafCreate schema's required set (name, authority_id,
// profile, subject) plus its description's rule: server_tls/dual require at
// least one DNS or IP SAN.
func (c IssuanceIssueCommand) Validate() error {
	if c.Name == "" || len(c.Name) > maxLeafNameLength {
		return NewAppError(ErrorKindValidation, "invalid_name", "name must be 1..255 characters").WithField("name", c.Name)
	}
	if _, err := domain.ParseAuthorityID(string(c.AuthorityID)); err != nil {
		return WrapAppError(ErrorKindValidation, "invalid_authority_id", "authority_id must be a uuid", err).WithField("authority_id", string(c.AuthorityID))
	}
	// DomainProfile/DomainKeyAlgorithm already return a fully-formed
	// AppError with cause and field attached; passing it through keeps
	// both instead of discarding them behind a second, causeless error.
	profile, err := c.DomainProfile()
	if err != nil {
		return err
	}
	if len(c.SANs) > maxSANCount {
		return NewAppError(ErrorKindValidation, "too_many_sans", "sans must be at most 100 entries")
	}
	sans, err := c.DomainSANs()
	if err != nil {
		return WrapAppError(ErrorKindValidation, "invalid_sans", "sans are invalid", err)
	}
	if _, err := c.Subject.Domain(); err != nil {
		return WrapAppError(ErrorKindValidation, "invalid_subject", "subject is invalid", err)
	}
	if err := domain.ValidateSANsForProfile(profile, sans); err != nil {
		return WrapAppError(ErrorKindValidation, "sans_required_for_profile", "server_tls/dual require at least one dns or ip san", err)
	}
	if _, err := c.DomainKeyAlgorithm(); err != nil {
		return err
	}
	if c.Validity != nil {
		if _, err := c.Validity.Domain(); err != nil {
			return WrapAppError(ErrorKindValidation, "invalid_validity", "validity must have a positive value and a supported unit", err)
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
		return WrapAppError(ErrorKindValidation, "invalid_series_id", "series id must be a uuid", err)
	}
	if _, err := domain.ParseCertificateID(string(c.SourceCertificateID)); err != nil {
		return WrapAppError(ErrorKindValidation, "invalid_source_certificate_id", "source_certificate_id must be a uuid", err).WithField("source_certificate_id", string(c.SourceCertificateID))
	}
	if c.TargetAuthorityID != "" {
		if _, err := domain.ParseAuthorityID(string(c.TargetAuthorityID)); err != nil {
			return WrapAppError(ErrorKindValidation, "invalid_target_authority_id", "target_authority_id must be a uuid", err).WithField("target_authority_id", string(c.TargetAuthorityID))
		}
	}
	if c.TransitionID != "" {
		if _, err := domain.ParseTransitionID(string(c.TransitionID)); err != nil {
			return WrapAppError(ErrorKindValidation, "invalid_transition_id", "transition_id must be a uuid", err).WithField("transition_id", string(c.TransitionID))
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
		return NewAppError(ErrorKindValidation, "invalid_reason", "reason is unsupported").WithField("reason", string(r))
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
		return WrapAppError(ErrorKindValidation, "invalid_series_id", "series id must be a uuid", err)
	}
	if _, err := domain.ParseCertificateID(string(c.SourceCertificateID)); err != nil {
		return WrapAppError(ErrorKindValidation, "invalid_source_certificate_id", "source_certificate_id must be a uuid", err).WithField("source_certificate_id", string(c.SourceCertificateID))
	}
	if c.TargetAuthorityID != "" {
		if _, err := domain.ParseAuthorityID(string(c.TargetAuthorityID)); err != nil {
			return WrapAppError(ErrorKindValidation, "invalid_target_authority_id", "target_authority_id must be a uuid", err).WithField("target_authority_id", string(c.TargetAuthorityID))
		}
	}
	if c.TransitionID != "" {
		if _, err := domain.ParseTransitionID(string(c.TransitionID)); err != nil {
			return WrapAppError(ErrorKindValidation, "invalid_transition_id", "transition_id must be a uuid", err).WithField("transition_id", string(c.TransitionID))
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
		return WrapAppError(ErrorKindValidation, "invalid_series_id", "series id must be a uuid", err)
	}
	if c.Name == nil && c.Validity == nil && c.RotateEvery == nil {
		return NewAppError(ErrorKindValidation, "empty_patch", "at least one of name, validity or rotate_every is required")
	}
	if c.Name != nil && (*c.Name == "" || len(*c.Name) > maxLeafNameLength) {
		return NewAppError(ErrorKindValidation, "invalid_name", "name must be 1..255 characters").WithField("name", *c.Name)
	}
	if c.Validity != nil {
		if _, err := c.Validity.Domain(); err != nil {
			return WrapAppError(ErrorKindValidation, "invalid_validity", "validity must have a positive value and a supported unit", err)
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
		return WrapAppError(ErrorKindValidation, "invalid_series_id", "series id must be a uuid", err)
	}
	return nil
}
