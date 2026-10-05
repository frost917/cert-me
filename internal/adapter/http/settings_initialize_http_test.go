package httpadapter

import (
	"net/http"
	"testing"
)

func TestInitialSettingsRequiresSession(t *testing.T) {
	h := newHTTPTestHarness(t, httpTestServiceURL)
	response := h.request(http.MethodPost, "/api/v1/setup/settings", `{}`, httpTestAdminHeaders(httpTestServiceURL))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("initial settings without a session: status %d, want 401", response.Code)
	}
}
