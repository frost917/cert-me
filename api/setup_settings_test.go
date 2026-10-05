package api

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestInitialSettingsContract(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromFile("openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	path := doc.Paths.Find("/api/v1/setup/settings")
	if path == nil || path.Post == nil {
		t.Fatal("authenticated initial settings creation route is missing")
	}
	op := path.Post
	if op.Security != nil && len(*op.Security) == 0 {
		t.Fatal("initial settings must require the session security scheme")
	}
	csrf := false
	for _, parameter := range op.Parameters {
		if parameter.Value.Name == "X-CSRF-Token" {
			csrf = true
		}
		if parameter.Value.Name == "If-Match" {
			t.Fatal("initial creation has no existing settings version")
		}
	}
	if !csrf || op.Responses.Status(201) == nil {
		t.Fatal("initial creation must require CSRF and return 201")
	}
	schema := op.RequestBody.Value.Content["application/json"].Schema.Value
	if len(schema.Required) != 10 {
		t.Fatal("all settings must be explicitly supplied at creation")
	}
	if err := schema.VisitJSON(map[string]any{"service_url": "https://example.test"}); err == nil {
		t.Fatal("partial initial settings must be rejected")
	}
}
