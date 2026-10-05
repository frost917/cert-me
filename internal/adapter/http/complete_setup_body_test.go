package httpadapter

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"cert-me/internal/app/contract"
)

func TestCompleteSetupAllowsAbsentOrEmptyObjectBody(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "absent body"},
		{name: "empty JSON object", body: `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHTTPTestHarness(t, httpTestServiceURL)
			headers := httpTestAdminHeaders(httpTestServiceURL)
			headers.Set("If-Match", `"v7"`)
			response := h.request(http.MethodPost, "/api/v1/setup/complete", tt.body, headers, httpTestSessionCookie())
			if response.Code != http.StatusOK {
				t.Fatalf("setup completion status = %d; want %d", response.Code, http.StatusOK)
			}
			calls, version := h.setup.completeResult()
			if calls != 1 || version != 7 {
				t.Fatalf("Complete received calls=%d settings version=%d; want 1 and 7", calls, version)
			}
			var payload struct {
				Data setupStatusResponse `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatalf("setup completion response was not valid JSON: %v", err)
			}
			if payload.Data.SetupStage != string(contract.SetupStageComplete) {
				t.Fatal("setup completion response did not report complete stage")
			}
		})
	}
}

func TestCompleteSetupRejectsBodyContentBeforeCallingService(t *testing.T) {
	secretMarker := "sensitive-completion-body-marker"
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{name: "nonempty object", body: `{"unexpected":"` + secretMarker + `"}`, wantStatus: http.StatusUnprocessableEntity, wantCode: "unknown_field"},
		{name: "duplicate fields", body: `{"unexpected":"` + secretMarker + `","unexpected":true}`, wantStatus: http.StatusUnprocessableEntity, wantCode: "unknown_field"},
		{name: "array", body: `[]`, wantStatus: http.StatusBadRequest, wantCode: "malformed_request"},
		{name: "null", body: `null`, wantStatus: http.StatusBadRequest, wantCode: "malformed_request"},
		{name: "trailing JSON", body: `{} {}`, wantStatus: http.StatusBadRequest, wantCode: "malformed_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHTTPTestHarness(t, httpTestServiceURL)
			headers := httpTestAdminHeaders(httpTestServiceURL)
			headers.Set("If-Match", `"v7"`)
			response := h.request(http.MethodPost, "/api/v1/setup/complete", tt.body, headers, httpTestSessionCookie())
			if calls, _ := h.setup.completeResult(); calls != 0 {
				t.Fatalf("Complete was called %d times for rejected body", calls)
			}
			if response.Code != tt.wantStatus {
				t.Fatalf("invalid completion body status = %d; want %d", response.Code, tt.wantStatus)
			}
			if code := httpTestErrorCode(t, response); code != tt.wantCode {
				t.Fatalf("invalid completion body error code = %q; want %q", code, tt.wantCode)
			}
			if strings.Contains(response.Body.String(), secretMarker) {
				t.Fatal("completion error response exposed submitted body data")
			}
		})
	}
}
