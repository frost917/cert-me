package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
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
