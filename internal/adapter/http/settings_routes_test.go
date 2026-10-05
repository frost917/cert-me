package httpadapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cert-me/internal/app/contract"
)

func TestSettingsReadReturnsVersionETagAndPreservesMissingRowError(t *testing.T) {
	t.Run("read requires an authenticated session", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		response := h.request(http.MethodGet, "/api/v1/settings", "", nil)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("settings GET without session status = %d; want %d", response.Code, http.StatusUnauthorized)
		}
		if cookie := responseCookie(response, sessionCookieName); cookie == nil || cookie.MaxAge >= 0 {
			t.Fatal("unauthenticated settings read did not clear the absent session cookie")
		}
		if calls := h.settings.getCalls(); calls != 0 {
			t.Fatalf("settings Get ran %d times without an authenticated session", calls)
		}
	})

	t.Run("configured settings carry ETag", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		response := h.request(http.MethodGet, "/api/v1/settings", "", nil, httpTestSessionCookie())
		if response.Code != http.StatusOK {
			t.Fatalf("settings GET status = %d; want %d", response.Code, http.StatusOK)
		}
		if got := response.Header().Get("ETag"); got != `"v1"` {
			t.Fatalf("settings ETag = %q; want %q", got, `"v1"`)
		}
		var payload struct {
			Data struct {
				Version int64 `json:"version"`
			} `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatalf("settings response was not valid JSON: %v", err)
		}
		if payload.Data.Version != 1 {
			t.Fatalf("settings body version = %d; want 1", payload.Data.Version)
		}
	})

	t.Run("missing settings row remains a conflict", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		h.settings.getErr = contract.NewAppError(contract.ErrorKindConflict, "settings_not_configured", "service settings are not configured")
		response := h.request(http.MethodGet, "/api/v1/settings", "", nil, httpTestSessionCookie())
		if response.Code != http.StatusConflict {
			t.Fatalf("missing settings status = %d; want %d", response.Code, http.StatusConflict)
		}
		if code := httpTestErrorCode(t, response); code != "settings_not_configured" {
			t.Fatalf("missing settings error code = %q", code)
		}
	})
}

func TestSettingsPatchRequiresOriginAndCSRFBeforeUpdate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(http.Header)
	}{
		{
			name: "missing Origin",
			mutate: func(headers http.Header) {
				headers.Del("Origin")
			},
		},
		{
			name: "foreign Origin",
			mutate: func(headers http.Header) {
				headers.Set("Origin", "https://attacker.example")
				headers.Set("X-Forwarded-Host", "cert.example")
				headers.Set("X-Forwarded-Proto", "https")
			},
		},
		{
			name: "missing CSRF token",
			mutate: func(headers http.Header) {
				headers.Del("X-CSRF-Token")
			},
		},
		{
			name: "mismatched CSRF token",
			mutate: func(headers http.Header) {
				headers.Set("X-CSRF-Token", strings.Repeat("z", len(httpTestSessionCSRF)))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHTTPTestHarness(t, httpTestServiceURL)
			headers := httpTestAdminHeaders(httpTestServiceURL)
			headers.Set("If-Match", `"v1"`)
			tt.mutate(headers)
			response := h.request(http.MethodPatch, "/api/v1/settings", `{"rotate_every":4}`, headers, httpTestSessionCookie())
			if response.Code != http.StatusForbidden {
				t.Fatalf("unverified settings PATCH status = %d; want %d", response.Code, http.StatusForbidden)
			}
			if calls, _, _ := h.settings.updateState(); calls != 0 {
				t.Fatalf("settings Update ran %d times for a rejected request", calls)
			}
		})
	}
}

func TestSettingsPatchRequiresAndParsesIfMatch(t *testing.T) {
	tests := []struct {
		name       string
		values     []string
		wantStatus int
		wantCode   string
	}{
		{name: "missing", wantStatus: http.StatusPreconditionRequired, wantCode: "precondition_required"},
		{name: "weak tag", values: []string{`W/"v1"`}, wantStatus: http.StatusBadRequest, wantCode: "malformed_request"},
		{name: "noncanonical version", values: []string{`"v01"`}, wantStatus: http.StatusBadRequest, wantCode: "malformed_request"},
		{name: "unsupported wildcard", values: []string{"*"}, wantStatus: http.StatusBadRequest, wantCode: "malformed_request"},
		{name: "duplicate headers", values: []string{`"v1"`, `"v1"`}, wantStatus: http.StatusBadRequest, wantCode: "malformed_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHTTPTestHarness(t, httpTestServiceURL)
			headers := httpTestAdminHeaders(httpTestServiceURL)
			for _, value := range tt.values {
				headers.Add("If-Match", value)
			}
			response := h.request(http.MethodPatch, "/api/v1/settings", `{"rotate_every":4}`, headers, httpTestSessionCookie())
			if response.Code != tt.wantStatus {
				t.Fatalf("If-Match status = %d; want %d", response.Code, tt.wantStatus)
			}
			if code := httpTestErrorCode(t, response); code != tt.wantCode {
				t.Fatalf("If-Match error code = %q; want %q", code, tt.wantCode)
			}
			if calls, _, _ := h.settings.updateState(); calls != 0 {
				t.Fatalf("settings Update ran %d times without valid If-Match", calls)
			}
		})
	}
}

func TestSettingsPatchRejectsUnknownNullAndNestedFields(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{name: "unknown field", body: `{"rotate_every":4,"unexpected":true}`, wantStatus: http.StatusUnprocessableEntity, wantCode: "unknown_field"},
		{name: "null field", body: `{"service_url":null}`, wantStatus: http.StatusUnprocessableEntity, wantCode: "invalid_settings"},
		{name: "unknown nested field", body: `{"leaf_validity":{"value":1,"unit":"years","unexpected":true}}`, wantStatus: http.StatusUnprocessableEntity, wantCode: "invalid_validity"},
		{name: "duplicate field", body: `{"rotate_every":4,"rotate_every":5}`, wantStatus: http.StatusBadRequest, wantCode: "malformed_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHTTPTestHarness(t, httpTestServiceURL)
			headers := httpTestAdminHeaders(httpTestServiceURL)
			headers.Set("If-Match", `"v1"`)
			response := h.request(http.MethodPatch, "/api/v1/settings", tt.body, headers, httpTestSessionCookie())
			if response.Code != tt.wantStatus {
				t.Fatalf("invalid settings payload status = %d; want %d", response.Code, tt.wantStatus)
			}
			if code := httpTestErrorCode(t, response); code != tt.wantCode {
				t.Fatalf("invalid settings payload code = %q; want %q", code, tt.wantCode)
			}
			if calls, _, _ := h.settings.updateState(); calls != 0 {
				t.Fatalf("settings Update ran %d times for an invalid payload", calls)
			}
		})
	}
}

func TestSettingsPatchPassesVersionAndReturnsNewETag(t *testing.T) {
	h := newHTTPTestHarness(t, httpTestServiceURL)
	headers := httpTestAdminHeaders(httpTestServiceURL)
	headers.Set("If-Match", `"v1"`)
	response := h.request(http.MethodPatch, "/api/v1/settings", `{"rotate_every":4}`, headers, httpTestSessionCookie())
	if response.Code != http.StatusOK {
		t.Fatalf("settings PATCH status = %d; want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("ETag"); got != `"v2"` {
		t.Fatalf("settings PATCH ETag = %q; want %q", got, `"v2"`)
	}
	calls, version, command := h.settings.updateState()
	if calls != 1 || version != 1 || command.RotateEvery == nil || *command.RotateEvery != 4 {
		t.Fatalf("settings Update received calls=%d version=%d rotate_every=%v", calls, version, command.RotateEvery)
	}
}

func TestCompleteSetupPassesSettingsVersionAndMapsRootMissing(t *testing.T) {
	t.Run("successful completion", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		headers := httpTestAdminHeaders(httpTestServiceURL)
		headers.Set("If-Match", `"v7"`)
		response := h.request(http.MethodPost, "/api/v1/setup/complete", "", headers, httpTestSessionCookie())
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
		if payload.Data.SetupStage != string(contract.SetupStageComplete) || payload.Data.BootstrapHTTPS {
			t.Fatal("setup completion response did not report completed installation state")
		}
	})

	t.Run("missing If-Match is rejected before completion", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		response := h.request(http.MethodPost, "/api/v1/setup/complete", "", httpTestAdminHeaders(httpTestServiceURL), httpTestSessionCookie())
		if response.Code != http.StatusPreconditionRequired {
			t.Fatalf("setup completion without If-Match status = %d; want %d", response.Code, http.StatusPreconditionRequired)
		}
		if calls, _ := h.setup.completeResult(); calls != 0 {
			t.Fatalf("Complete ran %d times without If-Match", calls)
		}
	})

	t.Run("missing Root is returned as a conflict", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		h.setup.completeErr = contract.NewAppError(contract.ErrorKindConflict, "setup_root_required", "at least one Root authority is required before setup can be completed")
		headers := httpTestAdminHeaders(httpTestServiceURL)
		headers.Set("If-Match", `"v7"`)
		response := h.request(http.MethodPost, "/api/v1/setup/complete", "", headers, httpTestSessionCookie())
		if response.Code != http.StatusConflict {
			t.Fatalf("missing Root completion status = %d; want %d", response.Code, http.StatusConflict)
		}
		if code := httpTestErrorCode(t, response); code != "setup_root_required" {
			t.Fatalf("missing Root completion error code = %q", code)
		}
		if calls, version := h.setup.completeResult(); calls != 1 || version != 7 {
			t.Fatalf("Complete received calls=%d settings version=%d", calls, version)
		}
	})
}

func httpTestErrorCode(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("error response was not valid JSON: %v", err)
	}
	return payload.Error.Code
}
