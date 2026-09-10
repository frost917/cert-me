package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

// schemaProperties reads api/openapi.json (from the repo root, three levels
// above this package) and returns the property names declared on one
// components.schemas entry. It intentionally reads the file directly rather
// than trusting a cached copy, per the round's instruction to catch drift
// between this package's command fields and the OpenAPI document.
func schemaProperties(t *testing.T, schemaName string) map[string]bool {
	t.Helper()
	path := filepath.Join("..", "..", "..", "api", "openapi.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read openapi.json: %v", err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal openapi.json: %v", err)
	}
	schema, ok := doc.Components.Schemas[schemaName]
	if !ok {
		t.Fatalf("schema %s not found in openapi.json", schemaName)
	}
	out := make(map[string]bool, len(schema.Properties))
	for name := range schema.Properties {
		out[name] = true
	}
	return out
}

// jsonFieldNames returns the JSON property names a struct's json tags would
// decode/encode, skipping fields tagged "-" (path ids, secrets, and other
// server-filled fields never appear in a JSON tag by design).
func jsonFieldNames(v any) map[string]bool {
	out := map[string]bool{}
	t := reflect.TypeOf(v)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := tag
		if idx := indexComma(tag); idx >= 0 {
			name = tag[:idx]
		}
		if name == "-" || name == "" {
			continue
		}
		out[name] = true
	}
	return out
}

func indexComma(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			return i
		}
	}
	return -1
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// assertFieldSetMatches fails when the command's JSON-tagged field set,
// together with declaredSecretFields, is not exactly the schema's declared
// property set. A command never puts a secret behind a json tag (doc rule 5:
// "Secrets... json:"-". Never a plain string"), so a schema property that the
// OpenAPI document marks writeOnly is expected to be *missing* from the
// json-tagged set and is instead named explicitly here, once per command, so
// a schema field that is neither tagged nor declared secret still fails the
// check instead of silently passing.
func assertFieldSetMatches(t *testing.T, schemaName string, cmd any, declaredSecretFields ...string) {
	t.Helper()
	want := schemaProperties(t, schemaName)
	got := jsonFieldNames(cmd)
	for _, name := range declaredSecretFields {
		if got[name] {
			t.Fatalf("%s: %q is declared as a secret field but also has a json tag; a secret must never be json-tagged", schemaName, name)
		}
		got[name] = true
	}
	for name := range want {
		if !got[name] {
			t.Errorf("%s: schema property %q has no matching command field (command fields: %v)", schemaName, name, sortedKeys(got))
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("%s: command field %q has no matching schema property (schema properties: %v)", schemaName, name, sortedKeys(want))
		}
	}
}

// schemaRequired reads the required array of one components.schemas entry.
func schemaRequired(t *testing.T, schemaName string) []string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "api", "openapi.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read openapi.json: %v", err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Required []string `json:"required"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal openapi.json: %v", err)
	}
	schema, ok := doc.Components.Schemas[schemaName]
	if !ok {
		t.Fatalf("schema %s not found in openapi.json", schemaName)
	}
	return schema.Required
}

// requiredFieldCase is one command fixture plus the mutator that zeroes one
// required field on a copy of it, so assertRequiredFieldsRejected can drive
// the same "zero this field, expect Validate to fail" check the round asked
// for mechanically instead of by manual re-audit.
type requiredFieldCase struct {
	schemaName string
	valid      func() any
	// zero maps an OpenAPI property name to a function that returns a copy
	// of the valid command with that one field zeroed. A property with no
	// entry here is skipped (e.g. it is server-filled or has no zero value
	// that Validate could plausibly reject, such as a required object field
	// whose own zero value is still validated by a Domain() call already
	// covered elsewhere in this package's tests).
	zero map[string]func() any
}

// assertRequiredFieldsRejected is the mechanical version of the "every
// OpenAPI required property has a Validate case that rejects it when
// missing" claim: for every name the schema's own required array lists, it
// demands a zeroing case be registered and that Validate actually reject it.
// A required property with no registered case fails loudly instead of the
// claim being taken on faith.
func assertRequiredFieldsRejected(t *testing.T, tc requiredFieldCase) {
	t.Helper()
	required := schemaRequired(t, tc.schemaName)
	for _, prop := range required {
		zero, ok := tc.zero[prop]
		if !ok {
			t.Errorf("%s: required property %q has no registered zeroing case in the required-field conformance test", tc.schemaName, prop)
			continue
		}
		t.Run(prop, func(t *testing.T) {
			cmd := zero()
			v, ok := cmd.(validator)
			if !ok {
				t.Fatalf("%s: zeroed command does not implement Validate() error", tc.schemaName)
			}
			if err := v.Validate(); err == nil {
				t.Errorf("%s: zeroing required property %q did not cause Validate to fail", tc.schemaName, prop)
			}
		})
	}
}

type validator interface {
	Validate() error
}

func TestOpenAPIConformance_RequiredFieldsRejected(t *testing.T) {
	assertRequiredFieldsRejected(t, requiredFieldCase{
		schemaName: "Credentials",
		zero: map[string]func() any{
			"login_name": func() any { c := validLoginCommand(); c.LoginName = ""; return c },
			"password":   func() any { c := validLoginCommand(); c.Password = nil; return c },
		},
	})
	assertRequiredFieldsRejected(t, requiredFieldCase{
		schemaName: "PasswordReset",
		zero: map[string]func() any{
			"reset_token":  func() any { return IdentityCompleteResetCommand{ResetToken: nil, NewPassword: validSecret()} },
			"new_password": func() any { return IdentityCompleteResetCommand{ResetToken: validSecret(), NewPassword: nil} },
		},
	})
	assertRequiredFieldsRejected(t, requiredFieldCase{
		schemaName: "AuthorityCreate",
		zero: map[string]func() any{
			"kind":    func() any { c := validAuthorityCreateCommand(); c.Kind = ""; return c },
			"name":    func() any { c := validAuthorityCreateCommand(); c.Name = ""; return c },
			"subject": func() any { c := validAuthorityCreateCommand(); c.Subject = SubjectInput{}; return c },
		},
	})
	assertRequiredFieldsRejected(t, requiredFieldCase{
		schemaName: "NamePatch",
		zero: map[string]func() any{
			"name": func() any {
				return AuthorityRenameCommand{AuthorityID: domain.AuthorityID(fixtureUUID), Name: ""}
			},
		},
	})
	assertRequiredFieldsRejected(t, requiredFieldCase{
		schemaName: "IssuanceState",
		zero: map[string]func() any{
			"state": func() any {
				return AuthoritySetIssuanceStateCommand{AuthorityID: domain.AuthorityID(fixtureUUID), State: ""}
			},
		},
	})
	assertRequiredFieldsRejected(t, requiredFieldCase{
		schemaName: "KeyDestruction",
		zero: map[string]func() any{
			"key_generation_id": func() any {
				return AuthorityDestroyKeyCommand{AuthorityID: domain.AuthorityID(fixtureUUID), KeyGenerationID: "", Justification: "reason"}
			},
			"justification": func() any {
				return AuthorityDestroyKeyCommand{AuthorityID: domain.AuthorityID(fixtureUUID), KeyGenerationID: domain.CAKeyGenerationID(fixtureUUID), Justification: ""}
			},
		},
	})
	assertRequiredFieldsRejected(t, requiredFieldCase{
		schemaName: "LeafCreate",
		zero: map[string]func() any{
			"name":         func() any { c := validIssueCommand(); c.Name = ""; return c },
			"authority_id": func() any { c := validIssueCommand(); c.AuthorityID = ""; return c },
			"profile":      func() any { c := validIssueCommand(); c.Profile = ""; return c },
			"subject":      func() any { c := validIssueCommand(); c.Subject = SubjectInput{}; return c },
		},
	})
	assertRequiredFieldsRejected(t, requiredFieldCase{
		schemaName: "Renew",
		zero: map[string]func() any{
			"source_certificate_id": func() any {
				return IssuanceRenewCommand{SeriesID: domain.SeriesID(fixtureUUID), SourceCertificateID: ""}
			},
		},
	})
	assertRequiredFieldsRejected(t, requiredFieldCase{
		schemaName: "Reissue",
		zero: map[string]func() any{
			"source_certificate_id": func() any {
				return IssuanceReissueCommand{SeriesID: domain.SeriesID(fixtureUUID), SourceCertificateID: "", Reason: ReissueReasonManualRotation}
			},
			"reason": func() any {
				return IssuanceReissueCommand{SeriesID: domain.SeriesID(fixtureUUID), SourceCertificateID: domain.CertificateID(fixtureUUID), Reason: ""}
			},
		},
	})
}

func validSecret() *secret.Input {
	return secret.FromString("a-valid-password-12")
}

func TestOpenAPIConformance(t *testing.T) {
	assertFieldSetMatches(t, "Credentials", SetupCreateAdminCommand{}, "password")
	assertFieldSetMatches(t, "Credentials", IdentityLoginCommand{}, "password")
	assertFieldSetMatches(t, "PasswordReset", IdentityCompleteResetCommand{}, "reset_token", "new_password")
	assertFieldSetMatches(t, "SettingsPatch", SettingsUpdateCommand{})
	assertFieldSetMatches(t, "AuthorityCreate", AuthorityCreateCommand{})
	assertFieldSetMatches(t, "NamePatch", AuthorityRenameCommand{})
	assertFieldSetMatches(t, "IssuanceState", AuthoritySetIssuanceStateCommand{})
	assertFieldSetMatches(t, "KeyDestruction", AuthorityDestroyKeyCommand{})
	assertFieldSetMatches(t, "LeafCreate", IssuanceIssueCommand{})
	assertFieldSetMatches(t, "Renew", IssuanceRenewCommand{})
	assertFieldSetMatches(t, "Reissue", IssuanceReissueCommand{})
	assertFieldSetMatches(t, "LeafPatch", IssuanceUpdateSeriesCommand{})
}
