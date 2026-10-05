package httpadapter

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"cert-me/internal/app/contract"
)

func TestPKIErrorStatusContract(t *testing.T) {
	for _, test := range []struct {
		code   string
		kind   contract.ErrorKind
		status int
	}{
		{"not_found", contract.ErrorKindValidation, 404},
		{"authority_not_found", contract.ErrorKindValidation, 404},
		{"authority_version_conflict", contract.ErrorKindConflict, 412},
		{"version_mismatch", contract.ErrorKindConflict, 412},
		{"version_conflict", contract.ErrorKindConflict, 412},
		{"malformed_request", contract.ErrorKindValidation, 400},
		{"request_input_conflict", contract.ErrorKindConflict, 409},
	} {
		t.Run(test.code, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeApplicationError(response, contract.NewAppError(test.kind, test.code, "The request was rejected."), "11111111-1111-4111-8111-111111111111")
			if response.Code != test.status {
				t.Fatalf("status=%d want%d", response.Code, test.status)
			}
			var body setupErrorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Error.Code != test.code {
				t.Fatal("error response did not retain the stable code")
			}
		})
	}
}
