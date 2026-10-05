package httpadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"cert-me/internal/app/contract"
)

const initialSettingsBody = `{"service_url":"https://cert.example","leaf_validity":{"value":1,"unit":"years"},"root_validity":{"value":20,"unit":"years"},"intermediate_validity":{"value":10,"unit":"years"},"rotate_every":3,"private_delivery_seconds":10800,"public_link_seconds":600,"crl_interval_seconds":43200,"crl_validity_seconds":172800,"audit_retention_days":365}`

type initialSettingsHTTPFake struct {
	*httpTestSettingsApplication
	calls   int
	err     error
	command contract.SettingsInitializeCommand
	meta    contract.MutationMeta
}

func (f *initialSettingsHTTPFake) Initialize(_ context.Context, meta contract.MutationMeta, command contract.SettingsInitializeCommand) (contract.SettingsView, error) {
	f.calls++
	f.meta, f.command = meta, command
	return f.view, f.err
}

func newInitialSettingsHTTPHarness(t *testing.T) (*httpTestHarness, *initialSettingsHTTPFake) {
	t.Helper()
	h := newHTTPTestHarness(t, httpTestServiceURL)
	fake := &initialSettingsHTTPFake{httpTestSettingsApplication: h.settings}
	var err error
	h.handler, err = NewSetupHandler(SetupHandlerConfig{Service: h.setup, Identity: h.identity, Settings: fake, ServiceURL: httpTestServiceURL})
	if err != nil {
		t.Fatal(err)
	}
	return h, fake
}

func TestInitialSettingsRequiresSession(t *testing.T) {
	h := newHTTPTestHarness(t, httpTestServiceURL)
	response := h.request(http.MethodPost, "/api/v1/setup/settings", `{}`, httpTestAdminHeaders(httpTestServiceURL))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("initial settings without a session: status %d, want 401", response.Code)
	}
}

func TestInitialSettingsCreationHTTP(t *testing.T) {
	h, fake := newInitialSettingsHTTPHarness(t)
	response := h.request(http.MethodPost, "/api/v1/setup/settings", initialSettingsBody, httpTestAdminHeaders(httpTestServiceURL), httpTestSessionCookie())
	if response.Code != http.StatusCreated || fake.calls != 1 {
		t.Fatalf("initial creation status=%d calls=%d", response.Code, fake.calls)
	}
	if fake.meta.ExpectedVersion != nil || !fake.meta.Principal.IsAdmin() {
		t.Fatal("creation must carry authenticated principal without an existing version")
	}
	if err := fake.command.Validate(); err != nil {
		t.Fatalf("creation command invalid: %v", err)
	}
	if response.Header().Get("ETag") != `"v1"` || response.Header().Get("Location") != "/api/v1/settings" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("creation omitted version, location or no-store")
	}
	var payload struct {
		Data settingsResponse `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Data.Version != 1 {
		t.Fatal("creation response is not the versioned settings DTO")
	}
}

func TestInitialSettingsRejectsInvalidHTTPInputBeforeService(t *testing.T) {
	for _, test := range []struct {
		name, body string
		headers    http.Header
		want       int
	}{
		{"missing field", `{"service_url":"https://cert.example"}`, httpTestAdminHeaders(httpTestServiceURL), 422},
		{"null", strings.Replace(initialSettingsBody, `"rotate_every":3`, `"rotate_every":null`, 1), httpTestAdminHeaders(httpTestServiceURL), 422},
		{"unknown", strings.Replace(initialSettingsBody, `"rotate_every":3`, `"unexpected":3`, 1), httpTestAdminHeaders(httpTestServiceURL), 422},
		{"duplicate", strings.Replace(initialSettingsBody, `"rotate_every":3`, `"rotate_every":3,"rotate_every":4`, 1), httpTestAdminHeaders(httpTestServiceURL), 400},
		{"nested unknown", strings.Replace(initialSettingsBody, `"value":1`, `"value":1,"extra":2`, 1), httpTestAdminHeaders(httpTestServiceURL), 422},
		{"cross field", strings.Replace(initialSettingsBody, `"crl_validity_seconds":172800`, `"crl_validity_seconds":600`, 1), httpTestAdminHeaders(httpTestServiceURL), 422},
		{"origin", initialSettingsBody, httpTestAdminHeaders("https://other.example"), 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, fake := newInitialSettingsHTTPHarness(t)
			response := h.request(http.MethodPost, "/api/v1/setup/settings", test.body, test.headers, httpTestSessionCookie())
			if response.Code != test.want || fake.calls != 0 {
				t.Fatalf("status=%d want=%d calls=%d", response.Code, test.want, fake.calls)
			}
		})
	}
}

func TestInitialSettingsConflictDoesNotPublishURL(t *testing.T) {
	h, fake := newInitialSettingsHTTPHarness(t)
	fake.err = contract.NewAppError(contract.ErrorKindConflict, "settings_already_configured", "Settings already exist.")
	response := h.request(http.MethodPost, "/api/v1/setup/settings", initialSettingsBody, httpTestAdminHeaders(httpTestServiceURL), httpTestSessionCookie())
	if response.Code != 409 {
		t.Fatalf("status=%d want409", response.Code)
	}
	csrf := h.request(http.MethodGet, "/api/v1/auth/csrf?mode=session", "", httpTestAdminHeaders(httpTestServiceURL), httpTestSessionCookie())
	if csrf.Code != 200 {
		t.Fatal("failed creation must preserve the original origin")
	}
}
