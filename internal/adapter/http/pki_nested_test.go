package httpadapter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cert-me/internal/app/contract"
)

func TestPKISubjectRequiredAndOptionalFields(t *testing.T) {
	for _, test := range []struct {
		body  string
		valid bool
	}{
		{`{"subject":{"common_name":"Root"}}`, true},
		{`{"subject":{"common_name":"Root","organization":"Example","country":"US"}}`, true},
		{`{"subject":{"organization":"Example"}}`, false},
		{`{"subject":{"common_name":"Root","organization":null}}`, false},
		{`{"subject":{"common_name":"Root","organization":""}}`, false},
		{`{"subject":{"common_name":"Root","country":""}}`, false},
		{`{"subject":{"common_name":"Root","extra":"value"}}`, false},
	} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/authorities", strings.NewReader(test.body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		var command contract.AuthorityCreateCommand
		ok := decodePKICommand(response, request, &command, []string{"subject"}, map[string][]string{"subject": {"common_name", "organization", "organizational_unit", "country"}}, nil)
		if ok != test.valid {
			t.Fatalf("subject validation result=%v want%v", ok, test.valid)
		}
	}
}
