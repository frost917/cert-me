package httpadapter

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"cert-me/internal/app/contract"
)

type httpTestUpdateResult struct {
	serviceURL string
	status     int
}

func TestPreauthTokenFromOldCanonicalOriginIsRejectedAfterSettingsChange(t *testing.T) {
	h := newHTTPTestHarness(t, httpTestServiceURL)
	preauthToken, preauthCookie := h.preauth(t)

	patchHeaders := httpTestAdminHeaders(httpTestServiceURL)
	patchHeaders.Set("If-Match", `"v1"`)
	patch := h.request(http.MethodPatch, "/api/v1/settings", `{"service_url":"https://new.example"}`, patchHeaders, httpTestSessionCookie())
	if patch.Code != http.StatusOK {
		t.Fatalf("service URL update status = %d; want %d", patch.Code, http.StatusOK)
	}

	loginHeaders := httpTestAdminHeaders("https://new.example")
	loginHeaders.Set("X-CSRF-Token", preauthToken)
	password := "old-origin-preauth-sentinel"
	login := h.request(http.MethodPost, "/api/v1/auth/login", `{"login_name":"operator","password":"`+password+`"}`, loginHeaders, preauthCookie)
	if login.Code != http.StatusForbidden {
		t.Fatalf("login with an old-origin preauth token status = %d; want %d", login.Code, http.StatusForbidden)
	}
	if calls, _, _, _ := h.identity.callCounts(); calls != 0 {
		t.Fatalf("Login ran %d times with a preauth token bound to the previous origin", calls)
	}
	if login.Body.String() == "" || containsSecret(login.Body.String(), password, preauthToken) {
		t.Fatal("rejected login response exposed submitted or CSRF token material")
	}
}

func TestConcurrentSettingsResponsesPublishCanonicalURLByVersion(t *testing.T) {
	h := newHTTPTestHarness(t, httpTestServiceURL)
	olderURL := "https://older.example"
	newerURL := "https://newer.example"
	started := make(chan string, 2)
	release := map[string]chan struct{}{
		olderURL: make(chan struct{}),
		newerURL: make(chan struct{}),
	}
	views := map[string]contract.SettingsView{
		olderURL: mustHTTPTestSettingsView(t, olderURL, 2),
		newerURL: mustHTTPTestSettingsView(t, newerURL, 3),
	}
	h.settings.updateFn = func(_ context.Context, _ contract.MutationMeta, command contract.SettingsUpdateCommand) (contract.SettingsView, error) {
		if command.ServiceURL == nil {
			return contract.SettingsView{}, contract.NewAppError(contract.ErrorKindValidation, "service_url_required", "service URL is required")
		}
		serviceURL := *command.ServiceURL
		started <- serviceURL
		<-release[serviceURL]
		view, ok := views[serviceURL]
		if !ok {
			return contract.SettingsView{}, contract.NewAppError(contract.ErrorKindValidation, "service_url_invalid", "service URL is invalid")
		}
		return view, nil
	}

	done := make(chan httpTestUpdateResult, 2)
	for _, serviceURL := range []string{olderURL, newerURL} {
		serviceURL := serviceURL
		go func() {
			headers := httpTestAdminHeaders(httpTestServiceURL)
			headers.Set("If-Match", `"v1"`)
			body := fmt.Sprintf(`{"service_url":%q}`, serviceURL)
			response := h.request(http.MethodPatch, "/api/v1/settings", body, headers, httpTestSessionCookie())
			done <- httpTestUpdateResult{serviceURL: serviceURL, status: response.Code}
		}()
	}

	seen := map[string]bool{}
	for len(seen) < 2 {
		select {
		case serviceURL := <-started:
			seen[serviceURL] = true
		case <-time.After(3 * time.Second):
			close(release[olderURL])
			close(release[newerURL])
			t.Fatal("both settings updates did not reach the service")
		}
	}

	close(release[newerURL])
	newerResult := waitHTTPTestResult(t, done)
	if newerResult.serviceURL != newerURL || newerResult.status != http.StatusOK {
		close(release[olderURL])
		t.Fatalf("newer settings update result was unexpected: status=%d", newerResult.status)
	}
	close(release[olderURL])
	olderResult := waitHTTPTestResult(t, done)
	if olderResult.serviceURL != olderURL || olderResult.status != http.StatusOK {
		t.Fatalf("older settings update result was unexpected: status=%d", olderResult.status)
	}

	newOriginHeaders := csrfReadHeaders("Origin", newerURL)
	newOriginHeaders.Set("Sec-Fetch-Site", "same-origin")
	newOrigin := h.request(http.MethodGet, "/api/v1/auth/csrf?mode=preauth", "", newOriginHeaders)
	if newOrigin.Code != http.StatusOK {
		t.Fatalf("newest canonical origin was rejected after reverse completion; status=%d", newOrigin.Code)
	}

	oldOriginHeaders := csrfReadHeaders("Origin", olderURL)
	oldOriginHeaders.Set("Sec-Fetch-Site", "same-origin")
	oldOrigin := h.request(http.MethodGet, "/api/v1/auth/csrf?mode=preauth", "", oldOriginHeaders)
	if oldOrigin.Code != http.StatusForbidden {
		t.Fatalf("older canonical origin remained active after reverse completion; status=%d", oldOrigin.Code)
	}
}

func waitHTTPTestResult(t *testing.T, done <-chan httpTestUpdateResult) httpTestUpdateResult {
	t.Helper()
	select {
	case value := <-done:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("settings update handler did not finish after release")
		return httpTestUpdateResult{}
	}
}

func containsSecret(body string, values ...string) bool {
	for _, value := range values {
		if value != "" && strings.Contains(body, value) {
			return true
		}
	}
	return false
}
