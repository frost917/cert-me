package httpadapter

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPKIMutationMetadataRequiresUniqueUUIDRetryKey(t *testing.T) {
	h := newHTTPTestHarness(t, httpTestServiceURL)
	for _, values := range [][]string{nil, {"bad-key"}, {"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}} {
		request := httptest.NewRequest(http.MethodPost, httpTestServiceURL+"/api/v1/authorities", nil)
		request.Header = httpTestAdminHeaders(httpTestServiceURL)
		for _, value := range values {
			request.Header.Add("Idempotency-Key", value)
		}
		request.AddCookie(httpTestSessionCookie())
		response := httptest.NewRecorder()
		if _, ok := h.handlerPKI().pkiMutationMeta(response, request, false, true); ok {
			t.Fatal("invalid retry key must not produce mutation metadata")
		}
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want400", response.Code)
		}
	}
}

func (h *httpTestHarness) handlerPKI() *setupHandler {
	return &setupHandler{identity: h.identity, settings: h.settings, service: h.setup}
}

func TestPKIListQueryRejectsDuplicateUnknownAndInvalidLimit(t *testing.T) {
	for _, raw := range []string{"?limit=0", "?limit=201", "?limit=1&limit=2", "?unexpected=value", "?q=a&q=b"} {
		request := httptest.NewRequest(http.MethodGet, httpTestServiceURL+"/api/v1/authorities"+raw, nil)
		if _, _, _, err := pkiListValues(request, nil); err == nil {
			t.Fatal("invalid query was accepted")
		}
	}
	request := httptest.NewRequest(http.MethodGet, httpTestServiceURL+"/api/v1/authorities?q=Root", nil)
	_, page, search, err := pkiListValues(request, nil)
	if err != nil || page.Limit != 50 || search != "Root" {
		t.Fatal("valid query/default limit not preserved")
	}
}
