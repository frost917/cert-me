package service

import (
	"encoding/json"
	"errors"
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
)

func TestDecodeSettingsV1DecodesTheNestedWireShape(t *testing.T) {
	settings := port.Settings{
		SchemaVersion: 1,
		SettingsJSON: []byte(`{
			"service_url": "https://cert.example.test",
			"leaf_validity": {"value": 1, "unit": "years"},
			"root_validity": {"value": 10, "unit": "years"},
			"intermediate_validity": {"value": 5, "unit": "years"},
			"rotate_every": 3,
			"private_delivery_seconds": 10800,
			"public_link_seconds": 600,
			"crl_interval_seconds": 43200,
			"crl_validity_seconds": 172800,
			"audit_retention_days": 365
		}`),
	}
	v, err := DecodeSettingsV1(settings)
	if err != nil {
		t.Fatalf("DecodeSettingsV1: %v", err)
	}
	if v.ServiceURL != "https://cert.example.test" {
		t.Fatalf("service_url = %q", v.ServiceURL)
	}
	if v.LeafValidity.Value() != 1 || v.LeafValidity.Unit() != "years" {
		t.Fatalf("leaf_validity = %+v", v.LeafValidity)
	}
	if v.RootValidity.Value() != 10 || v.RootValidity.Unit() != "years" {
		t.Fatalf("root_validity = %+v", v.RootValidity)
	}
	if v.IntermediateValidity.Value() != 5 || v.IntermediateValidity.Unit() != "years" {
		t.Fatalf("intermediate_validity = %+v", v.IntermediateValidity)
	}
	if v.RotateEvery != 3 {
		t.Fatalf("rotate_every = %d, want 3", v.RotateEvery)
	}
	if v.PrivateDeliverySeconds != 10800 || v.PublicLinkSeconds != 600 || v.CRLIntervalSeconds != 43200 ||
		v.CRLValiditySeconds != 172800 || v.AuditRetentionDays != 365 {
		t.Fatalf("decoded settings = %+v", v)
	}
}

// A fault check: a naive decoder that only reads the OLD flattened
// leaf_validity_value/leaf_validity_unit fields this developer's earlier
// (wrong) issuance.go draft assumed would decode the nested object above as
// all-zero, and zero fields must then fail range validation rather than
// succeed.
func TestDecodeSettingsV1RejectsTheOldFlattenedShape(t *testing.T) {
	settings := port.Settings{
		SchemaVersion: 1,
		SettingsJSON: []byte(`{
			"leaf_validity_value": 1,
			"leaf_validity_unit": "years",
			"service_url": "https://cert.example.test",
			"root_validity": {"value": 10, "unit": "years"},
			"intermediate_validity": {"value": 5, "unit": "years"},
			"rotate_every": 3,
			"private_delivery_seconds": 10800,
			"public_link_seconds": 600,
			"crl_interval_seconds": 43200,
			"crl_validity_seconds": 172800,
			"audit_retention_days": 365
		}`),
	}
	_, err := DecodeSettingsV1(settings)
	if err == nil {
		t.Fatal("want an error decoding the flattened shape: leaf_validity is absent under the real nested field name")
	}
}

func TestDecodeSettingsV1RejectsAnUnsupportedSchemaVersion(t *testing.T) {
	settings := port.Settings{SchemaVersion: 2, SettingsJSON: []byte(`{}`)}
	_, err := DecodeSettingsV1(settings)
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Code() != "settings_schema_version_unsupported" {
		t.Fatalf("code = %q, want settings_schema_version_unsupported", appErr.Code())
	}
}

func TestDecodeSettingsV1RejectsMalformedJSON(t *testing.T) {
	settings := port.Settings{SchemaVersion: 1, SettingsJSON: []byte(`{not json`)}
	_, err := DecodeSettingsV1(settings)
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Code() != "settings_json_malformed" {
		t.Fatalf("code = %q, want settings_json_malformed", appErr.Code())
	}
}

// Every one of these carries exactly one out-of-range/invalid field against
// an otherwise-valid encoding of defaultTestSettingsV1(); each must be
// rejected rather than silently accepted or covered by a default.
func TestDecodeSettingsV1RejectsOutOfRangeFields(t *testing.T) {
	base, err := EncodeSettingsV1(defaultTestSettingsV1())
	if err != nil {
		t.Fatalf("encode base settings: %v", err)
	}
	for _, tc := range []struct {
		name  string
		field string
		value string
	}{
		{"rotate_every_zero", "rotate_every", "0"},
		{"rotate_every_too_high", "rotate_every", "101"},
		{"private_delivery_seconds_too_low", "private_delivery_seconds", "100"},
		{"private_delivery_seconds_too_high", "private_delivery_seconds", "999999"},
		{"public_link_seconds_too_low", "public_link_seconds", "10"},
		{"crl_interval_seconds_too_low", "crl_interval_seconds", "10"},
		{"crl_validity_seconds_too_low", "crl_validity_seconds", "100"},
		{"audit_retention_days_too_low", "audit_retention_days", "1"},
		{"audit_retention_days_too_high", "audit_retention_days", "999999"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(base, &m); err != nil {
				t.Fatalf("unmarshal base: %v", err)
			}
			var raw any
			if err := json.Unmarshal([]byte(tc.value), &raw); err != nil {
				t.Fatalf("unmarshal override value: %v", err)
			}
			m[tc.field] = raw
			broken, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal broken settings: %v", err)
			}
			_, err = DecodeSettingsV1(port.Settings{SchemaVersion: 1, SettingsJSON: broken})
			if err == nil {
				t.Fatalf("want an error for out-of-range %s=%s", tc.field, tc.value)
			}
		})
	}
}

// The schema description requires CRL validity to be at least twice the
// interval; a value that satisfies its own individual range but breaks this
// cross-field rule must still be rejected.
func TestDecodeSettingsV1RejectsCRLValidityLessThanTwiceInterval(t *testing.T) {
	v := defaultTestSettingsV1()
	v.CRLIntervalSeconds = 43200
	v.CRLValiditySeconds = 43200 // equal, not >= 2x
	if _, err := EncodeSettingsV1(v); err == nil {
		t.Fatal("want EncodeSettingsV1 to reject crl_validity_seconds < 2x crl_interval_seconds")
	}
}

func TestEncodeSettingsV1RejectsAnInvalidServiceURL(t *testing.T) {
	v := defaultTestSettingsV1()
	v.ServiceURL = "http://not-https.example.test"
	if _, err := EncodeSettingsV1(v); err == nil {
		t.Fatal("want EncodeSettingsV1 to reject a non-https service_url")
	}
}

// Round-tripping through Encode then Decode must reproduce the same typed
// value -- the "B03 reads and B04 writes share one codec" requirement only
// holds if both directions agree on the wire shape.
func TestSettingsV1RoundTrips(t *testing.T) {
	original := defaultTestSettingsV1()
	encoded, err := EncodeSettingsV1(original)
	if err != nil {
		t.Fatalf("EncodeSettingsV1: %v", err)
	}
	decoded, err := DecodeSettingsV1(port.Settings{SchemaVersion: 1, SettingsJSON: encoded})
	if err != nil {
		t.Fatalf("DecodeSettingsV1: %v", err)
	}
	if decoded != original {
		t.Fatalf("round trip = %+v, want %+v", decoded, original)
	}
}
