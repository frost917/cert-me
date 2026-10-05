package httpadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"cert-me/internal/app/contract"
)

func TestCSRFRoutesEnforceModeAndOriginEvidence(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		headers    http.Header
		wantStatus int
	}{
		{
			name:       "preauth accepts matching Origin",
			path:       "/api/v1/auth/csrf?mode=preauth",
			headers:    csrfReadHeaders("Origin", httpTestServiceURL),
			wantStatus: http.StatusOK,
		},
		{
			name:       "preauth accepts normalized host and default port",
			path:       "/api/v1/auth/csrf?mode=preauth",
			headers:    csrfReadHeaders("Origin", "https://CERT.EXAMPLE:443"),
			wantStatus: http.StatusOK,
		},
		{
			name:       "preauth accepts matching Referer",
			path:       "/api/v1/auth/csrf?mode=preauth",
			headers:    csrfReadHeaders("Referer", httpTestServiceURL+"/"),
			wantStatus: http.StatusOK,
		},
		{
			name:       "same-origin fetch metadata is evidence",
			path:       "/api/v1/auth/csrf?mode=preauth",
			headers:    header("Sec-Fetch-Site", "same-origin"),
			wantStatus: http.StatusOK,
		},
		{
			name:       "mismatched Origin is rejected",
			path:       "/api/v1/auth/csrf?mode=preauth",
			headers:    csrfReadHeaders("Origin", "https://attacker.example"),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "duplicate Origin is rejected",
			path:       "/api/v1/auth/csrf?mode=preauth",
			headers:    joinHeaders(header("Origin", httpTestServiceURL), header("Origin", httpTestServiceURL)),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "non-HTTPS Origin is rejected",
			path:       "/api/v1/auth/csrf?mode=preauth",
			headers:    csrfReadHeaders("Origin", "http://cert.example"),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "mismatched Referer is rejected even with same-origin fetch metadata",
			path:       "/api/v1/auth/csrf?mode=preauth",
			headers:    joinHeaders(header("Sec-Fetch-Site", "same-origin"), header("Referer", "https://attacker.example/path")),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "cross-site fetch metadata is rejected",
			path:       "/api/v1/auth/csrf?mode=preauth",
			headers:    joinHeaders(header("Origin", httpTestServiceURL), header("Sec-Fetch-Site", "cross-site")),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "missing same-origin evidence is rejected",
			path:       "/api/v1/auth/csrf?mode=preauth",
			headers:    make(http.Header),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "unsupported mode is rejected",
			path:       "/api/v1/auth/csrf?mode=automatic",
			headers:    csrfReadHeaders("Origin", httpTestServiceURL),
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:       "duplicate mode parameter is rejected",
			path:       "/api/v1/auth/csrf?mode=preauth&mode=session",
			headers:    csrfReadHeaders("Origin", httpTestServiceURL),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "extra query parameter is rejected",
			path:       "/api/v1/auth/csrf?mode=preauth&unexpected=value",
			headers:    csrfReadHeaders("Origin", httpTestServiceURL),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "session mode requires a session cookie",
			path:       "/api/v1/auth/csrf?mode=session",
			headers:    csrfReadHeaders("Origin", httpTestServiceURL),
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHTTPTestHarness(t, httpTestServiceURL)
			response := h.request(http.MethodGet, tt.path, "", tt.headers)
			if response.Code != tt.wantStatus {
				t.Fatalf("CSRF route status = %d; want %d", response.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusOK {
				if response.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("CSRF response did not disable caching")
				}
				if strings.Contains(tt.path, "preauth") {
					assertCookiePolicy(t, response, preAuthCookieName, true)
				}
			}
			if login, auth, issue, _ := h.identity.callCounts(); login != 0 || auth != 0 || issue != 0 {
				t.Fatalf("CSRF read unexpectedly called identity application: login=%d authenticate=%d issue=%d", login, auth, issue)
			}
		})
	}
}

func TestCSRFModesSelectPreauthOrAuthenticatedSession(t *testing.T) {
	t.Run("explicit preauth ignores an existing session", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		headers := csrfReadHeaders("Origin", httpTestServiceURL)
		response := h.request(http.MethodGet, "/api/v1/auth/csrf?mode=preauth", "", headers, httpTestSessionCookie())
		if response.Code != http.StatusOK {
			t.Fatalf("preauth mode status = %d; want %d", response.Code, http.StatusOK)
		}
		if _, auth, issue, _ := h.identity.callCounts(); auth != 0 || issue != 0 {
			t.Fatalf("preauth mode used the session: authenticate=%d issue=%d", auth, issue)
		}
		assertCookiePolicy(t, response, preAuthCookieName, true)
	})

	t.Run("default mode uses current session", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		response := h.request(http.MethodGet, "/api/v1/auth/csrf", "", csrfReadHeaders("Origin", httpTestServiceURL), httpTestSessionCookie())
		if response.Code != http.StatusOK {
			t.Fatalf("session CSRF status = %d; want %d", response.Code, http.StatusOK)
		}
		if _, auth, issue, _ := h.identity.callCounts(); auth != 1 || issue != 1 {
			t.Fatalf("default mode did not issue session CSRF: authenticate=%d issue=%d", auth, issue)
		}
		if cookie := responseCookie(response, preAuthCookieName); cookie != nil {
			t.Fatal("session CSRF response also issued a pre-auth cookie")
		}
		if !strings.Contains(response.Body.String(), httpTestIssuedCSRF) {
			t.Fatal("session CSRF response omitted the issued token")
		}
	})

	t.Run("default mode falls back to preauth and clears invalid session", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		invalid := &http.Cookie{Name: sessionCookieName, Value: strings.Repeat("x", len(httpTestSession))}
		response := h.request(http.MethodGet, "/api/v1/auth/csrf", "", csrfReadHeaders("Origin", httpTestServiceURL), invalid)
		if response.Code != http.StatusOK {
			t.Fatalf("fallback CSRF status = %d; want %d", response.Code, http.StatusOK)
		}
		if cookie := responseCookie(response, sessionCookieName); cookie == nil || cookie.MaxAge >= 0 {
			t.Fatal("invalid session cookie was not cleared")
		}
		assertCookiePolicy(t, response, preAuthCookieName, true)
		if _, auth, issue, _ := h.identity.callCounts(); auth != 1 || issue != 0 {
			t.Fatalf("invalid session fallback calls = authenticate %d, issue %d", auth, issue)
		}
	})

	t.Run("explicit session rejects invalid cookie and clears it", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		invalid := &http.Cookie{Name: sessionCookieName, Value: strings.Repeat("x", len(httpTestSession))}
		response := h.request(http.MethodGet, "/api/v1/auth/csrf?mode=session", "", csrfReadHeaders("Origin", httpTestServiceURL), invalid)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("invalid session mode status = %d; want %d", response.Code, http.StatusUnauthorized)
		}
		if cookie := responseCookie(response, sessionCookieName); cookie == nil || cookie.MaxAge >= 0 {
			t.Fatal("invalid session cookie was not cleared")
		}
	})
}

func TestSetupAdminUsesPreauthAndDoesNotLogInAutomatically(t *testing.T) {
	h := newHTTPTestHarness(t, httpTestServiceURL)
	csrf, nonce := h.preauth(t)
	secretValue := "test-password-value-never-echo"
	body := `{"login_name":"operator","password":"` + secretValue + `"}`
	headers := httpTestAdminHeaders(httpTestServiceURL)
	headers.Set("X-CSRF-Token", csrf)
	response := h.request(http.MethodPost, "/api/v1/setup/admin", body, headers, nonce)
	if response.Code != http.StatusCreated {
		t.Fatalf("initial administrator route status = %d; want %d", response.Code, http.StatusCreated)
	}
	if calls := h.setup.createAdminCalls(); calls != 1 {
		t.Fatalf("CreateAdmin calls = %d; want 1", calls)
	}
	if h.setup.createLoginName != "operator" || !h.setup.passwordPresent {
		t.Fatal("CreateAdmin did not receive the expected credential fields")
	}
	if login, _, _, _ := h.identity.callCounts(); login != 0 {
		t.Fatalf("initial administrator creation automatically called Login %d times", login)
	}
	if responseCookie(response, sessionCookieName) != nil {
		t.Fatal("initial administrator creation issued a session cookie")
	}
	if strings.Contains(response.Body.String(), secretValue) {
		t.Fatal("initial administrator response exposed the submitted password")
	}
}

func TestSetupAdminRejectsStrictJSONBeforeCallingService(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
		wantStatus  int
	}{
		{name: "unknown field", body: `{"login_name":"operator","password":"never-echo-this","admin":true}`, wantStatus: http.StatusUnprocessableEntity},
		{name: "duplicate field", body: `{"login_name":"operator","login_name":"other","password":"never-echo-this"}`, wantStatus: http.StatusBadRequest},
		{name: "nested password", body: `{"login_name":"operator","password":{"value":"never-echo-this"}}`, wantStatus: http.StatusBadRequest},
		{name: "null field", body: `{"login_name":null,"password":"never-echo-this"}`, wantStatus: http.StatusBadRequest},
		{name: "trailing JSON", body: `{"login_name":"operator","password":"never-echo-this"}{}`, wantStatus: http.StatusBadRequest},
		{name: "non JSON content type", body: `{"login_name":"operator","password":"never-echo-this"}`, contentType: "text/plain", wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHTTPTestHarness(t, httpTestServiceURL)
			csrf, nonce := h.preauth(t)
			headers := httpTestAdminHeaders(httpTestServiceURL)
			headers.Set("X-CSRF-Token", csrf)
			if tt.contentType != "" {
				headers.Set("Content-Type", tt.contentType)
			}
			response := h.request(http.MethodPost, "/api/v1/setup/admin", tt.body, headers, nonce)
			if response.Code != tt.wantStatus {
				t.Fatalf("strict JSON status = %d; want %d", response.Code, tt.wantStatus)
			}
			if calls := h.setup.createAdminCalls(); calls != 0 {
				t.Fatalf("CreateAdmin was called %d times for invalid JSON", calls)
			}
			if strings.Contains(response.Body.String(), "never-echo-this") {
				t.Fatal("strict JSON error response exposed submitted credential data")
			}
		})
	}
}

func TestLoginCookieAndLogoutCookieLifecycle(t *testing.T) {
	h := newHTTPTestHarness(t, httpTestServiceURL)
	csrf, nonce := h.preauth(t)
	secretValue := "login-password-value-never-echo"
	headers := httpTestAdminHeaders(httpTestServiceURL)
	headers.Set("X-CSRF-Token", csrf)
	loginResponse := h.request(http.MethodPost, "/api/v1/auth/login", `{"login_name":"operator","password":"`+secretValue+`"}`, headers, nonce)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login status = %d; want %d", loginResponse.Code, http.StatusOK)
	}
	assertCookiePolicy(t, loginResponse, sessionCookieName, true)
	if sessionCookie := responseCookie(loginResponse, sessionCookieName); sessionCookie == nil || sessionCookie.Value != httpTestSession {
		t.Fatal("login did not set the returned session credential")
	}
	if preauthCookie := responseCookie(loginResponse, preAuthCookieName); preauthCookie == nil || preauthCookie.MaxAge >= 0 {
		t.Fatal("login did not clear the pre-auth nonce cookie")
	}
	if strings.Contains(loginResponse.Body.String(), secretValue) || strings.Contains(loginResponse.Body.String(), httpTestSession) {
		t.Fatal("login response exposed the submitted password or session token")
	}

	logoutHeaders := httpTestAdminHeaders(httpTestServiceURL)
	logoutResponse := h.request(http.MethodPost, "/api/v1/auth/logout", "", logoutHeaders, httpTestSessionCookie())
	if logoutResponse.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d; want %d", logoutResponse.Code, http.StatusNoContent)
	}
	if cookie := responseCookie(logoutResponse, sessionCookieName); cookie == nil || cookie.MaxAge >= 0 || cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("logout did not clear the session cookie with host-cookie attributes")
	}
	if _, _, _, logoutCalls := h.identity.callCounts(); logoutCalls != 1 {
		t.Fatalf("Logout calls = %d; want 1", logoutCalls)
	}
}

func TestSessionRouteAuthenticatesAndClearsRejectedCookies(t *testing.T) {
	t.Run("valid session returns account and version ETag", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		response := h.request(http.MethodGet, "/api/v1/auth/me", "", nil, httpTestSessionCookie())
		if response.Code != http.StatusOK {
			t.Fatalf("session route status = %d; want %d", response.Code, http.StatusOK)
		}
		if got := response.Header().Get("ETag"); got != `"v1"` {
			t.Fatalf("session ETag = %q; want %q", got, `"v1"`)
		}
		if !strings.Contains(response.Body.String(), `"login_name":"operator"`) {
			t.Fatal("session response omitted the account identity")
		}
	})

	t.Run("rejected session is cleared", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		invalid := &http.Cookie{Name: sessionCookieName, Value: strings.Repeat("x", len(httpTestSession))}
		response := h.request(http.MethodGet, "/api/v1/auth/me", "", nil, invalid)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("invalid session route status = %d; want %d", response.Code, http.StatusUnauthorized)
		}
		if cookie := responseCookie(response, sessionCookieName); cookie == nil || cookie.MaxAge >= 0 {
			t.Fatal("rejected session cookie was not cleared")
		}
	})

	t.Run("duplicate session cookies are rejected before authentication", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		duplicate := &http.Cookie{Name: sessionCookieName, Value: httpTestSession + "x"}
		response := h.request(http.MethodGet, "/api/v1/auth/me", "", nil, httpTestSessionCookie(), duplicate)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("duplicate session cookie status = %d; want %d", response.Code, http.StatusUnauthorized)
		}
		if _, auth, _, _ := h.identity.callCounts(); auth != 0 {
			t.Fatalf("duplicate session cookies reached Authenticate %d times", auth)
		}
		if cookie := responseCookie(response, sessionCookieName); cookie == nil || cookie.MaxAge >= 0 {
			t.Fatal("duplicate session cookie was not cleared")
		}
	})
}

func TestLogoutAuthenticationFailureClearsSessionWithoutCallingLogout(t *testing.T) {
	h := newHTTPTestHarness(t, httpTestServiceURL)
	invalid := &http.Cookie{Name: sessionCookieName, Value: strings.Repeat("x", len(httpTestSession))}
	response := h.request(http.MethodPost, "/api/v1/auth/logout", "", httpTestAdminHeaders(httpTestServiceURL), invalid)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("logout with rejected session status = %d; want %d", response.Code, http.StatusUnauthorized)
	}
	if cookie := responseCookie(response, sessionCookieName); cookie == nil || cookie.MaxAge >= 0 {
		t.Fatal("rejected session cookie was not cleared")
	}
	if _, _, _, logoutCalls := h.identity.callCounts(); logoutCalls != 0 {
		t.Fatalf("Logout ran %d times for a rejected session", logoutCalls)
	}
}

func TestPasswordResetCompletesWithPreauthAndClearsCookies(t *testing.T) {
	h := newHTTPTestHarness(t, httpTestServiceURL)
	csrf, nonce := h.preauth(t)
	resetSecret := "reset-token-sentinel-do-not-return"
	password := "new-password-sentinel-do-not-return"
	headers := httpTestAdminHeaders(httpTestServiceURL)
	headers.Set("X-CSRF-Token", csrf)
	body := `{"reset_token":"` + resetSecret + `","new_password":"` + password + `"}`
	response := h.request(http.MethodPost, "/api/v1/auth/password-reset", body, headers, nonce, httpTestSessionCookie())
	if response.Code != http.StatusNoContent {
		t.Fatalf("password reset status = %d; want %d", response.Code, http.StatusNoContent)
	}
	if calls := h.identity.completeResetCalls(); calls != 1 {
		t.Fatalf("CompleteReset calls = %d; want 1", calls)
	}
	for _, name := range []string{sessionCookieName, preAuthCookieName} {
		cookie := responseCookie(response, name)
		if cookie == nil || cookie.MaxAge >= 0 {
			t.Fatalf("password reset did not clear cookie %q", name)
		}
	}
	if containsSecret(response.Body.String(), resetSecret, password) {
		t.Fatal("password reset response exposed a reset token or password")
	}
}

func TestPasswordResetRejectsMalformedFieldsBeforeCallingService(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{name: "missing reset token", body: `{"new_password":"reset-password-sentinel"}`, wantStatus: http.StatusBadRequest},
		{name: "missing new password", body: `{"reset_token":"reset-token-sentinel"}`, wantStatus: http.StatusBadRequest},
		{name: "wrong reset token shape", body: `{"reset_token":7,"new_password":"reset-password-sentinel"}`, wantStatus: http.StatusBadRequest},
		{name: "unknown field", body: `{"reset_token":"reset-token-sentinel","new_password":"reset-password-sentinel","extra":true}`, wantStatus: http.StatusUnprocessableEntity},
		{name: "trailing object", body: `{"reset_token":"reset-token-sentinel","new_password":"reset-password-sentinel"}{}`, wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHTTPTestHarness(t, httpTestServiceURL)
			csrf, nonce := h.preauth(t)
			headers := httpTestAdminHeaders(httpTestServiceURL)
			headers.Set("X-CSRF-Token", csrf)
			response := h.request(http.MethodPost, "/api/v1/auth/password-reset", tt.body, headers, nonce)
			if response.Code != tt.wantStatus {
				t.Fatalf("malformed reset request status = %d; want %d", response.Code, tt.wantStatus)
			}
			if calls := h.identity.completeResetCalls(); calls != 0 {
				t.Fatalf("CompleteReset ran %d times for malformed input", calls)
			}
			if strings.Contains(response.Body.String(), "reset-token-sentinel") || strings.Contains(response.Body.String(), "reset-password-sentinel") {
				t.Fatal("malformed reset response exposed credential data")
			}
		})
	}
}

func TestLoginFailureDoesNotExposeCredentialsOrRateLimitTimestamp(t *testing.T) {
	t.Run("invalid credentials", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		h.identity.loginFn = func(context.Context, contract.MutationMeta, contract.IdentityLoginCommand) (contract.LoginView, error) {
			return contract.LoginView{}, contract.NewAppError(contract.ErrorKindAuth, "invalid_credentials", "The login credentials are invalid.")
		}
		csrf, nonce := h.preauth(t)
		password := "credential-sentinel-do-not-echo"
		headers := httpTestAdminHeaders(httpTestServiceURL)
		headers.Set("X-CSRF-Token", csrf)
		response := h.request(http.MethodPost, "/api/v1/auth/login", `{"login_name":"operator","password":"`+password+`"}`, headers, nonce)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("invalid credentials status = %d; want %d", response.Code, http.StatusUnauthorized)
		}
		if strings.Contains(response.Body.String(), password) || strings.Contains(response.Body.String(), httpTestSession) {
			t.Fatal("login failure response exposed credential material")
		}
		if responseCookie(response, sessionCookieName) != nil {
			t.Fatal("failed login issued a session cookie")
		}
	})

	t.Run("rate limit returns Retry-After without internal timestamp", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		until := time.Now().Add(70 * time.Second).UnixMicro()
		h.identity.loginFn = func(context.Context, contract.MutationMeta, contract.IdentityLoginCommand) (contract.LoginView, error) {
			return contract.LoginView{}, contract.NewAppError(contract.ErrorKindConflict, "rate_limited", "Too many attempts.").WithField("retry_after_unix_micro", fmt.Sprint(until))
		}
		csrf, nonce := h.preauth(t)
		password := "rate-limit-sentinel-do-not-echo"
		headers := httpTestAdminHeaders(httpTestServiceURL)
		headers.Set("X-CSRF-Token", csrf)
		response := h.request(http.MethodPost, "/api/v1/auth/login", `{"login_name":"operator","password":"`+password+`"}`, headers, nonce)
		if response.Code != http.StatusTooManyRequests {
			t.Fatalf("rate limit status = %d; want %d", response.Code, http.StatusTooManyRequests)
		}
		retryAfter, err := strconv.Atoi(response.Header().Get("Retry-After"))
		if err != nil || retryAfter < 1 {
			t.Fatal("rate limit response omitted a positive Retry-After value")
		}
		body := response.Body.String()
		if strings.Contains(body, "retry_after_unix_micro") || strings.Contains(body, fmt.Sprint(until)) || strings.Contains(body, password) {
			t.Fatal("rate limit response exposed internal timing or submitted credentials")
		}
		var payload map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatalf("rate limit response was not valid JSON: %v", err)
		}
	})
}

func csrfReadHeaders(name, value string) http.Header {
	headers := make(http.Header)
	headers.Set(name, value)
	return headers
}

func header(name, value string) http.Header {
	headers := make(http.Header)
	headers.Set(name, value)
	return headers
}

func joinHeaders(values ...http.Header) http.Header {
	joined := make(http.Header)
	for _, value := range values {
		for name, entries := range value {
			for _, entry := range entries {
				joined.Add(name, entry)
			}
		}
	}
	return joined
}

func responseCookie(response *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func assertCookiePolicy(t *testing.T, response *httptest.ResponseRecorder, name string, hasPositiveMaxAge bool) {
	t.Helper()
	cookie := responseCookie(response, name)
	if cookie == nil {
		t.Fatalf("response did not set cookie %q", name)
	}
	if cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie %q did not have the required host-cookie policy", name)
	}
	if hasPositiveMaxAge && cookie.MaxAge <= 0 {
		t.Fatalf("cookie %q did not have a positive lifetime", name)
	}
}
