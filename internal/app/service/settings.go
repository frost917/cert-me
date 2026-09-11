package service

import (
	"encoding/json"
	"fmt"
	"strings"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// settingsSchemaVersionV1 is the only service_settings.schema_version this
// codec understands (docs/backend-implementation.md §14.8). It is a column
// on the port.Settings row, not a field embedded in settings_json itself.
const settingsSchemaVersionV1 = 1

// SettingsV1 is the fully-resolved, typed shape of settings_json for
// schema_version=1: api/openapi.json's Settings schema with `version`
// removed, since that field is the port.Settings.Version optimistic-lock
// token, not part of the JSON body (§14.8 "OpenAPI Settings에서 version을
// 제외한 필드명/구조를 사용한다"). This is the "공통 typed codec"
// docs/backend-implementation.md §14.8 asks B03's reads and B04's writes to
// share; only Decode is used by this developer's assigned files (IssuanceService
// reading service_settings), but Encode is provided alongside it so B04 does
// not need a second, possibly-diverging encoder for the same wire shape.
type SettingsV1 struct {
	ServiceURL             string
	LeafValidity           domain.CalendarValidity
	RootValidity           domain.CalendarValidity
	IntermediateValidity   domain.CalendarValidity
	RotateEvery            int
	PrivateDeliverySeconds int
	PublicLinkSeconds      int
	CRLIntervalSeconds     int
	CRLValiditySeconds     int
	AuditRetentionDays     int
}

// Range bounds mirrored from api/openapi.json's Settings schema. A
// port.Settings.SettingsJSON blob is an opaque, already-validated store to
// the repository (docs/data-model.md "검증된 형식만 저장"), so nothing below
// the app layer enforces these; this codec is where "already validated" is
// actually checked, both on the way in (Encode) and on the way back out
// (Decode, for a row this process itself did not just write).
const (
	minValidityValue = 1
	maxValidityValue = 36500

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

// settingsValidityWireV1 mirrors api/openapi.json's Validity schema.
type settingsValidityWireV1 struct {
	Value int    `json:"value"`
	Unit  string `json:"unit"`
}

// settingsWireV1 is settings_json's on-the-wire shape for schema_version=1
// (§14.8): OpenAPI's Settings object minus `version`.
type settingsWireV1 struct {
	ServiceURL             string                 `json:"service_url"`
	LeafValidity           settingsValidityWireV1 `json:"leaf_validity"`
	RootValidity           settingsValidityWireV1 `json:"root_validity"`
	IntermediateValidity   settingsValidityWireV1 `json:"intermediate_validity"`
	RotateEvery            int                    `json:"rotate_every"`
	PrivateDeliverySeconds int                    `json:"private_delivery_seconds"`
	PublicLinkSeconds      int                    `json:"public_link_seconds"`
	CRLIntervalSeconds     int                    `json:"crl_interval_seconds"`
	CRLValiditySeconds     int                    `json:"crl_validity_seconds"`
	AuditRetentionDays     int                    `json:"audit_retention_days"`
}

// DecodeSettingsV1 decodes and fully validates a stored service_settings
// row. Per §14.8, an unknown schema_version, malformed JSON, or any missing/
// out-of-range field is an error -- never silently replaced with a factory
// default ("알 수 없는 schema version·깨진 JSON·누락/범위 오류를 공장
// 기본값으로 덮지 않는다"). A caller with no Settings row at all (ErrNotFound
// from InstallationRepository.GetSettings) is a separate case this function
// does not handle: §14.8 routes that through Setup's explicit initialization
// path, not through a default substituted here.
func DecodeSettingsV1(settings port.Settings) (SettingsV1, error) {
	if settings.SchemaVersion != settingsSchemaVersionV1 {
		return SettingsV1{}, contract.NewAppError(contract.ErrorKindUnavailable, "settings_schema_version_unsupported",
			"the stored settings schema version is not supported").
			WithField("schema_version", fmt.Sprint(settings.SchemaVersion))
	}
	var wire settingsWireV1
	if err := json.Unmarshal(settings.SettingsJSON, &wire); err != nil {
		return SettingsV1{}, contract.WrapAppError(contract.ErrorKindUnavailable, "settings_json_malformed",
			"stored settings_json could not be parsed", err)
	}
	leaf, err := decodeValidity(wire.LeafValidity, "leaf_validity")
	if err != nil {
		return SettingsV1{}, err
	}
	root, err := decodeValidity(wire.RootValidity, "root_validity")
	if err != nil {
		return SettingsV1{}, err
	}
	intermediate, err := decodeValidity(wire.IntermediateValidity, "intermediate_validity")
	if err != nil {
		return SettingsV1{}, err
	}
	out := SettingsV1{
		ServiceURL:             wire.ServiceURL,
		LeafValidity:           leaf,
		RootValidity:           root,
		IntermediateValidity:   intermediate,
		RotateEvery:            wire.RotateEvery,
		PrivateDeliverySeconds: wire.PrivateDeliverySeconds,
		PublicLinkSeconds:      wire.PublicLinkSeconds,
		CRLIntervalSeconds:     wire.CRLIntervalSeconds,
		CRLValiditySeconds:     wire.CRLValiditySeconds,
		AuditRetentionDays:     wire.AuditRetentionDays,
	}
	// A stored row that fails range validation is a server-side fault (this
	// process, or an earlier one, wrote something Encode should have
	// rejected), not bad input from the current caller -- unavailable, not
	// validation.
	if err := validateSettingsV1(out, contract.ErrorKindUnavailable); err != nil {
		return SettingsV1{}, err
	}
	return out, nil
}

// EncodeSettingsV1 validates v and marshals it into settings_json's
// schema_version=1 wire shape (§14.8 "저장 시 기본값을 모두 해석해 완전한
// snapshot을 저장한다" -- Encode is where a writer, i.e. B04's
// SettingsService, must have already resolved every field before calling
// this; there is no partial/omitted-field form here).
func EncodeSettingsV1(v SettingsV1) ([]byte, error) {
	if err := validateSettingsV1(v, contract.ErrorKindValidation); err != nil {
		return nil, err
	}
	wire := settingsWireV1{
		ServiceURL:             v.ServiceURL,
		LeafValidity:           settingsValidityWireV1{Value: v.LeafValidity.Value(), Unit: string(v.LeafValidity.Unit())},
		RootValidity:           settingsValidityWireV1{Value: v.RootValidity.Value(), Unit: string(v.RootValidity.Unit())},
		IntermediateValidity:   settingsValidityWireV1{Value: v.IntermediateValidity.Value(), Unit: string(v.IntermediateValidity.Unit())},
		RotateEvery:            v.RotateEvery,
		PrivateDeliverySeconds: v.PrivateDeliverySeconds,
		PublicLinkSeconds:      v.PublicLinkSeconds,
		CRLIntervalSeconds:     v.CRLIntervalSeconds,
		CRLValiditySeconds:     v.CRLValiditySeconds,
		AuditRetentionDays:     v.AuditRetentionDays,
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, contract.WrapAppError(contract.ErrorKindValidation, "settings_encode_failed",
			"could not encode settings", err)
	}
	return encoded, nil
}

// decodeValidity turns one wire Validity object into a validated
// domain.CalendarValidity, naming which of the three settings fields failed
// when it does not decode -- schema_version=1 has three of these and a bare
// "invalid validity" error would not say which.
func decodeValidity(w settingsValidityWireV1, field string) (domain.CalendarValidity, error) {
	v, err := domain.NewCalendarValidity(w.Value, domain.ValidityUnit(w.Unit))
	if err != nil {
		return domain.CalendarValidity{}, contract.WrapAppError(contract.ErrorKindUnavailable, "settings_field_invalid",
			"stored settings field is invalid", err).WithField("field", field)
	}
	return v, nil
}

// validateSettingsV1 checks every field against the ranges
// api/openapi.json's Settings schema fixes, plus the schema description's
// cross-field rule that CRL validity must be at least twice the interval.
// It is shared by Decode (a stored row failing this is a server-side fault:
// unavailable) and Encode (a caller failing this is bad input: validation) --
// the caller distinguishes which kind applies to its own error.
func validateSettingsV1(v SettingsV1, kind contract.ErrorKind) error {
	fail := func(field, detail string) error {
		return contract.NewAppError(kind, "settings_field_out_of_range", detail).WithField("field", field)
	}
	if !strings.HasPrefix(v.ServiceURL, "https://") {
		return fail("service_url", "service_url must be an https:// URL")
	}
	for field, validity := range map[string]domain.CalendarValidity{
		"leaf_validity": v.LeafValidity, "root_validity": v.RootValidity, "intermediate_validity": v.IntermediateValidity,
	} {
		if validity.Value() < minValidityValue || validity.Value() > maxValidityValue {
			return fail(field, fmt.Sprintf("%s.value must be %d..%d", field, minValidityValue, maxValidityValue))
		}
	}
	if v.RotateEvery < minRotateEverySetting || v.RotateEvery > maxRotateEverySetting {
		return fail("rotate_every", fmt.Sprintf("rotate_every must be %d..%d", minRotateEverySetting, maxRotateEverySetting))
	}
	if v.PrivateDeliverySeconds < minPrivateDeliverySeconds || v.PrivateDeliverySeconds > maxPrivateDeliverySeconds {
		return fail("private_delivery_seconds", fmt.Sprintf("private_delivery_seconds must be %d..%d", minPrivateDeliverySeconds, maxPrivateDeliverySeconds))
	}
	if v.PublicLinkSeconds < minPublicLinkSeconds || v.PublicLinkSeconds > maxPublicLinkSeconds {
		return fail("public_link_seconds", fmt.Sprintf("public_link_seconds must be %d..%d", minPublicLinkSeconds, maxPublicLinkSeconds))
	}
	if v.CRLIntervalSeconds < minCRLIntervalSeconds || v.CRLIntervalSeconds > maxCRLIntervalSeconds {
		return fail("crl_interval_seconds", fmt.Sprintf("crl_interval_seconds must be %d..%d", minCRLIntervalSeconds, maxCRLIntervalSeconds))
	}
	if v.CRLValiditySeconds < minCRLValiditySeconds || v.CRLValiditySeconds > maxCRLValiditySeconds {
		return fail("crl_validity_seconds", fmt.Sprintf("crl_validity_seconds must be %d..%d", minCRLValiditySeconds, maxCRLValiditySeconds))
	}
	if v.CRLValiditySeconds < 2*v.CRLIntervalSeconds {
		return fail("crl_validity_seconds", "crl_validity_seconds must be at least twice crl_interval_seconds")
	}
	if v.AuditRetentionDays < minAuditRetentionDays || v.AuditRetentionDays > maxAuditRetentionDays {
		return fail("audit_retention_days", fmt.Sprintf("audit_retention_days must be %d..%d", minAuditRetentionDays, maxAuditRetentionDays))
	}
	return nil
}
