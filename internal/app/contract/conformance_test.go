package contract

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// TestCommandFieldsMatchOpenAPISchemas is the contract-conformance check the
// task requires: for every command in this developer's files whose JSON
// tags mirror an OpenAPI request schema 1:1 (i.e. excluding the server-filled
// json:"-" path/secret fields), the tagged property names must be exactly
// the OpenAPI schema's property names. It reads api/openapi.json itself,
// the same way api/openapi_test.go does.
func TestCommandFieldsMatchOpenAPISchemas(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromFile("../../../api/openapi.json")
	if err != nil {
		t.Fatalf("failed to load openapi.json: %v", err)
	}

	cases := []struct {
		schema  string
		command any
	}{
		{"Revoke", RevocationRevokeCommand{}},
		{"Justification", RevocationCompromiseCommand{}},
		{"RevocationCorrection", RevocationCorrectCommand{}},
		{"DownloadLinkRequest", DistributionCreateLinkCommand{}},
		{"TransitionCreate", TransitionCreateCommand{}},
		{"TransitionPatch", TransitionSetTargetCommand{}},
		{"DeploymentInput", TransitionConfirmDeploymentCommand{}},
		{"TLSActivation", TLSActivateCommand{}},
	}

	for _, tc := range cases {
		t.Run(tc.schema, func(t *testing.T) {
			schema, ok := doc.Components.Schemas[tc.schema]
			if !ok {
				t.Fatalf("openapi.json has no schema named %q", tc.schema)
			}
			want := make(map[string]struct{}, len(schema.Value.Properties))
			for name := range schema.Value.Properties {
				want[name] = struct{}{}
			}

			got := jsonTaggedFieldNames(tc.command)

			var missing, extra []string
			for name := range want {
				if _, ok := got[name]; !ok {
					missing = append(missing, name)
				}
			}
			for name := range got {
				if _, ok := want[name]; !ok {
					extra = append(extra, name)
				}
			}
			sort.Strings(missing)
			sort.Strings(extra)
			if len(missing) > 0 || len(extra) > 0 {
				t.Fatalf("%s field mismatch: missing=%v extra=%v", tc.schema, missing, extra)
			}
		})
	}
}

// jsonTaggedFieldNames returns the set of JSON property names a struct
// decodes, skipping json:"-" (server-filled) fields.
func jsonTaggedFieldNames(v any) map[string]struct{} {
	out := map[string]struct{}{}
	typ := reflect.TypeOf(v)
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}

// TestRequiredOpenAPIFieldsHaveValidateCases documents, rather than
// mechanically re-derives, that every OpenAPI-required property on the
// schemas above has a corresponding rejection case somewhere in this
// developer's *_test.go files when it is missing. The exhaustive per-field
// "missing X is rejected" cases live next to each command
// (RevocationRevokeCommand, RevocationCompromiseCommand,
// RevocationCorrectCommand, TransitionCreateCommand,
// TransitionConfirmDeploymentCommand, TLSActivateCommand, TLSIssueCandidateCommand,
// DistributionCreateLinkCommand, ImportAttachSigningKeyCommand,
// ImportConfirmTakeoverCommand); this test only re-confirms the OpenAPI
// schemas' required-field lists have not silently grown behind those cases.
func TestRequiredOpenAPIFieldsHaveValidateCases(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromFile("../../../api/openapi.json")
	if err != nil {
		t.Fatalf("failed to load openapi.json: %v", err)
	}
	known := map[string][]string{
		"Revoke":               {"reason", "justification"},
		"Justification":        {"justification"},
		"RevocationCorrection": {"revoked_at", "reason", "justification"},
		"DownloadLinkRequest":  {"purpose"},
		"TransitionCreate":     {"source_authority_id", "mode", "reason"},
		"TransitionPatch":      {"target_authority_id"},
		"DeploymentInput":      {"target_label", "action"},
		"TLSActivation":        {"candidate_id"},
	}
	for schemaName, expectedRequired := range known {
		schema, ok := doc.Components.Schemas[schemaName]
		if !ok {
			t.Fatalf("openapi.json has no schema named %q", schemaName)
		}
		got := append([]string{}, schema.Value.Required...)
		sort.Strings(got)
		want := append([]string{}, expectedRequired...)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s required fields changed: openapi=%v tracked=%v (add/adjust the matching Validate test case)", schemaName, got, want)
		}
	}
}
