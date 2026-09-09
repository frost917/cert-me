package api

import (
	"context"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestOpenAPI(t *testing.T) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile("openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if doc.Paths.Len() != 51 {
		t.Fatal("unexpected route set")
	}
	seen := map[string]bool{}
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if op.OperationID == "" || seen[op.OperationID] {
				t.Fatalf("duplicate/missing operation: %s %s", method, path)
			}
			seen[op.OperationID] = true
		}
	}
	if len(seen) != 59 {
		t.Fatal("unexpected operation count")
	}
}

func TestIssuanceAndInputSchemas(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromFile("openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	id := "00000000-0000-4000-8000-000000000001"
	renewal := map[string]any{"series_id": id, "certificate_id": id, "key_generation_id": id, "renewal_count": float64(1), "key_rotated": false, "delivery": nil}
	if err = doc.Components.Schemas["Issuance"].Value.VisitJSON(renewal); err != nil {
		t.Fatal("key reuse renewal must allow null delivery:", err)
	}
	input := map[string]any{"name": "fixture.internal", "authority_id": id, "profile": "server_tls", "subject": map[string]any{"common_name": "fixture.internal"}, "sans": []any{map[string]any{"type": "dns", "value": "fixture.internal"}}}
	schema := doc.Components.Schemas["LeafCreate"].Value
	if err = schema.VisitJSON(input); err != nil {
		t.Fatal(err)
	}
	input["private_key"] = "must never accept an arbitrary leaf private key"
	if schema.VisitJSON(input) == nil {
		t.Fatal("unknown private_key field accepted")
	}
	delete(input, "private_key")
	input["rotate_every"] = float64(0)
	if schema.VisitJSON(input) == nil {
		t.Fatal("invalid rotation interval accepted")
	}
}
