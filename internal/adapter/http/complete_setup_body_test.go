package httpadapter

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
		{name: "oversized body", body: strings.Repeat(" ", maxSetupJSONBytes+1), wantStatus: http.StatusRequestEntityTooLarge, wantCode: "payload_too_large"},
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

func TestCompleteSetupAcceptsChunkedEmptyBody(t *testing.T) {
	h := newHTTPTestHarness(t, httpTestServiceURL)
	request := httptest.NewRequest(http.MethodPost, "http://cert.example/api/v1/setup/complete", httpTestEmptyBodyReader{})
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("Origin", httpTestServiceURL)
	request.Header.Set("X-CSRF-Token", httpTestSessionCSRF)
	request.Header.Set("If-Match", `"v7"`)
	request.AddCookie(httpTestSessionCookie())
	response := httptest.NewRecorder()
	h.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("chunked-empty setup completion status = %d; want %d", response.Code, http.StatusOK)
	}
	if calls, version := h.setup.completeResult(); calls != 1 || version != 7 {
		t.Fatalf("Complete received calls=%d settings version=%d; want 1 and 7", calls, version)
	}
}

func TestCompleteSetupBodyValidationPreservesAuthenticationAndVersionPrecedence(t *testing.T) {
	t.Run("authentication is checked before body", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		response := h.request(http.MethodPost, "/api/v1/setup/complete", `[]`, httpTestAdminHeaders(httpTestServiceURL))
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated completion status = %d; want %d", response.Code, http.StatusUnauthorized)
		}
		if calls, _ := h.setup.completeResult(); calls != 0 {
			t.Fatalf("Complete ran %d times without a session", calls)
		}
	})

	t.Run("If-Match is checked before body", func(t *testing.T) {
		h := newHTTPTestHarness(t, httpTestServiceURL)
		response := h.request(http.MethodPost, "/api/v1/setup/complete", `[]`, httpTestAdminHeaders(httpTestServiceURL), httpTestSessionCookie())
		if response.Code != http.StatusPreconditionRequired {
			t.Fatalf("completion without If-Match status = %d; want %d", response.Code, http.StatusPreconditionRequired)
		}
		if calls, _ := h.setup.completeResult(); calls != 0 {
			t.Fatalf("Complete ran %d times without If-Match", calls)
		}
	})
}

func TestCompleteSetupKeepsCloserWhenPeekingUnknownLengthBody(t *testing.T) {
	h := newHTTPTestHarness(t, httpTestServiceURL)
	body := &httpTestTrackingReadCloser{Reader: strings.NewReader(`{"unexpected":true}`)}
	request := httptest.NewRequest(http.MethodPost, "http://cert.example/api/v1/setup/complete", nil)
	request.Body = body
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("Origin", httpTestServiceURL)
	request.Header.Set("X-CSRF-Token", httpTestSessionCSRF)
	request.Header.Set("If-Match", `"v7"`)
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(httpTestSessionCookie())
	response := httptest.NewRecorder()
	h.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown-length JSON body status = %d; want %d", response.Code, http.StatusUnprocessableEntity)
	}
	if body.closed {
		t.Fatal("handler closed the original request body before the server cleanup")
	}
	if err := request.Body.Close(); err != nil {
		t.Fatalf("closing request body returned an error: %v", err)
	}
	if !body.closed {
		t.Fatal("buffered request body did not preserve the original closer")
	}
}

type httpTestEmptyBodyReader struct{}

func (httpTestEmptyBodyReader) Read([]byte) (int, error) { return 0, io.EOF }

type httpTestTrackingReadCloser struct {
	*strings.Reader
	closed bool
}

func (body *httpTestTrackingReadCloser) Close() error {
	body.closed = true
	return nil
}
