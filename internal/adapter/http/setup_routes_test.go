package httpadapter

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"cert-me/internal/app/contract"
)

func TestPublicSetupRoutesExposeOnlyInstallationState(t *testing.T) {
	t.Run("JSON setup status", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		response := h.request(http.MethodGet, "/api/v1/setup", "", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("setup status route returned %d; want %d", response.Code, http.StatusOK)
		}
		var payload struct {
			Data setupStatusResponse `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatalf("setup status response was not valid JSON: %v", err)
		}
		if payload.Data.SetupStage != string(contract.SetupStageAccountRequired) || !payload.Data.BootstrapHTTPS {
			t.Fatal("setup status response did not report the configured installation state")
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("setup status response did not disable caching")
		}
	})

	t.Run("invalid service stage becomes an internal error", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		h.setup.status.SetupStage = contract.SetupStage("unsupported")
		response := h.request(http.MethodGet, "/api/v1/setup", "", nil)
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("invalid setup stage status = %d; want %d", response.Code, http.StatusInternalServerError)
		}
		if code := httpTestErrorCode(t, response); code != "internal_error" {
			t.Fatalf("invalid setup stage code = %q", code)
		}
	})

	t.Run("HTML reset route does not render its path token", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		token := "reset-link-path-sentinel"
		response := h.request(http.MethodGet, "/reset-password/"+token, "", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("reset page status = %d; want %d", response.Code, http.StatusOK)
		}
		if !strings.Contains(response.Header().Get("Content-Type"), "text/html") {
			t.Fatal("reset page did not return HTML")
		}
		if strings.Contains(response.Body.String(), token) {
			t.Fatal("reset page copied the path token into server-rendered HTML")
		}
	})

	t.Run("setup status fragment reports stage", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		response := h.request(http.MethodGet, "/ui/setup-status", "", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("setup status fragment returned %d; want %d", response.Code, http.StatusOK)
		}
		if !strings.Contains(response.Header().Get("Content-Type"), "text/html") || !strings.Contains(response.Body.String(), string(contract.SetupStageAccountRequired)) {
			t.Fatal("setup status fragment omitted its HTML stage")
		}
	})
}
