package httpadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

const (
	httpTestSeriesID        = "00000000-0000-4000-8000-000000000021"
	httpTestCertificateID   = "00000000-0000-4000-8000-000000000022"
	httpTestLeafKeyID       = "00000000-0000-4000-8000-000000000023"
	httpTestKeyMaterialID   = "00000000-0000-4000-8000-000000000024"
	httpTestIssuerKeyID     = "00000000-0000-4000-8000-000000000025"
	httpTestDeliveryID      = "00000000-0000-4000-8000-000000000026"
	httpTestTransitionID    = "00000000-0000-4000-8000-000000000027"
	httpTestTargetAuthority = "00000000-0000-4000-8000-000000000028"
	httpTestIdempotencyKey  = "00000000-0000-4000-8000-000000000029"
)

func TestLeafAndCertificateReadRoutesMapOpenAPIShapesAndTypedFilters(t *testing.T) {
	h := newLeafRoutesTestHarness(t)

	unauthorized := h.request(http.MethodGet, "/api/v1/leaf-series", "", make(http.Header))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated series list status=%d want=%d", unauthorized.Code, http.StatusUnauthorized)
	}
	if h.queries.listSeriesCalls != 0 {
		t.Fatalf("unauthenticated series list reached query service %d times", h.queries.listSeriesCalls)
	}

	seriesList := h.request(http.MethodGet, "/api/v1/leaf-series?q=web&cursor=next&limit=7&authority_id="+httpTestAuthorityID, "", make(http.Header), httpTestSessionCookie())
	if seriesList.Code != http.StatusOK {
		t.Fatalf("series list status=%d want=%d: %s", seriesList.Code, http.StatusOK, seriesList.Body.String())
	}
	if got := h.queries.lastSeriesList; got.Search != "web" || got.Page.Cursor != "next" || got.Page.Limit != 7 || got.AuthorityID == nil || string(*got.AuthorityID) != httpTestAuthorityID {
		t.Fatalf("series list query=%#v; filters were not forwarded as typed values", got)
	}
	var seriesListPayload struct {
		Data       []map[string]json.RawMessage `json:"data"`
		NextCursor *string                      `json:"next_cursor"`
	}
	if err := json.Unmarshal(seriesList.Body.Bytes(), &seriesListPayload); err != nil {
		t.Fatalf("series list response is not JSON: %v", err)
	}
	if len(seriesListPayload.Data) != 1 || seriesListPayload.NextCursor == nil || *seriesListPayload.NextCursor != "next-series" {
		t.Fatalf("series list envelope=%#v", seriesListPayload)
	}
	assertLeafSeriesDTOShape(t, seriesListPayload.Data[0])

	series := h.request(http.MethodGet, "/api/v1/leaf-series/"+httpTestSeriesID, "", make(http.Header), httpTestSessionCookie())
	if series.Code != http.StatusOK || series.Header().Get("ETag") != `"v7"` {
		t.Fatalf("series detail status=%d ETag=%q: %s", series.Code, series.Header().Get("ETag"), series.Body.String())
	}
	if h.queries.lastSeriesGet.SeriesID != domain.SeriesID(httpTestSeriesID) {
		t.Fatalf("series detail query id=%q; want path id", h.queries.lastSeriesGet.SeriesID)
	}
	var seriesPayload struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(series.Body.Bytes(), &seriesPayload); err != nil {
		t.Fatalf("series detail response is not JSON: %v", err)
	}
	assertLeafSeriesDTOShape(t, seriesPayload.Data)

	const expiresBefore = "2026-12-03T04:05:06+02:00"
	certificates := h.request(http.MethodGet, "/api/v1/certificates?q=service&cursor=cert-next&limit=4&authority_id="+httpTestAuthorityID+"&expires_before="+expiresBefore+"&revoked=false&affected=true", "", make(http.Header), httpTestSessionCookie())
	if certificates.Code != http.StatusOK {
		t.Fatalf("certificate list status=%d want=%d: %s", certificates.Code, http.StatusOK, certificates.Body.String())
	}
	query := h.queries.lastCertificateList
	if query.Search != "service" || query.Page.Cursor != "cert-next" || query.Page.Limit != 4 || query.AuthorityID == nil || string(*query.AuthorityID) != httpTestAuthorityID || query.ExpiresBefore == nil || !query.ExpiresBefore.Equal(domain.NewInstant(mustLeafTime(t, expiresBefore))) || query.Revoked == nil || *query.Revoked || query.Affected == nil || !*query.Affected {
		t.Fatalf("certificate list query=%#v; filters were not forwarded as typed values", query)
	}
	var certificateListPayload struct {
		Data       []map[string]json.RawMessage `json:"data"`
		NextCursor *string                      `json:"next_cursor"`
	}
	if err := json.Unmarshal(certificates.Body.Bytes(), &certificateListPayload); err != nil {
		t.Fatalf("certificate list response is not JSON: %v", err)
	}
	if len(certificateListPayload.Data) != 1 || certificateListPayload.NextCursor == nil || *certificateListPayload.NextCursor != "next-certificate" {
		t.Fatalf("certificate list envelope=%#v", certificateListPayload)
	}
	assertCertificateDTOShape(t, certificateListPayload.Data[0])

	certificate := h.request(http.MethodGet, "/api/v1/certificates/"+httpTestCertificateID, "", make(http.Header), httpTestSessionCookie())
	if certificate.Code != http.StatusOK {
		t.Fatalf("certificate detail status=%d want=%d: %s", certificate.Code, http.StatusOK, certificate.Body.String())
	}
	if certificate.Header().Get("ETag") != "" {
		t.Fatalf("immutable certificate response fabricated a version ETag: %q", certificate.Header().Get("ETag"))
	}
	if h.queries.lastCertificateGet.CertificateID != domain.CertificateID(httpTestCertificateID) {
		t.Fatalf("certificate detail query id=%q; want path id", h.queries.lastCertificateGet.CertificateID)
	}
	var certificatePayload struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(certificate.Body.Bytes(), &certificatePayload); err != nil {
		t.Fatalf("certificate detail response is not JSON: %v", err)
	}
	assertCertificateDTOShape(t, certificatePayload.Data)
	for _, body := range []string{seriesList.Body.String(), series.Body.String(), certificates.Body.String(), certificate.Body.String()} {
		if strings.Contains(body, "PRIVATE KEY") || strings.Contains(body, "download_token") || strings.Contains(body, `"token"`) {
			t.Fatal("leaf/certificate response exposed private key or delivery token material")
		}
	}
}

func TestLeafIssueRenewReissueUseSessionCSRFIdempotencyAndExpectedVersion(t *testing.T) {
	issueBody := `{"name":"web leaf","authority_id":"` + httpTestAuthorityID + `","profile":"server_tls","subject":{"common_name":"web.example"},"sans":[{"type":"dns","value":"web.example"}]}`
	renewBody := `{"source_certificate_id":"` + httpTestCertificateID + `","target_authority_id":"` + httpTestTargetAuthority + `","transition_id":"` + httpTestTransitionID + `"}`
	reissueBody := `{"source_certificate_id":"` + httpTestCertificateID + `","reason":"key_compromise","target_authority_id":"` + httpTestTargetAuthority + `"}`
	tests := []struct {
		name       string
		path       string
		body       string
		wantSeries domain.SeriesID
		callCount  func(*leafRoutesTestHarness) int
		wantCall   int
	}{
		{name: "issue", path: "/api/v1/leaf-series", body: issueBody, callCount: func(h *leafRoutesTestHarness) int { return h.issuance.issueCalls }, wantCall: 1},
		{name: "renew", path: "/api/v1/leaf-series/" + httpTestSeriesID + "/renewals", body: renewBody, wantSeries: domain.SeriesID(httpTestSeriesID), callCount: func(h *leafRoutesTestHarness) int { return h.issuance.renewCalls }, wantCall: 1},
		{name: "reissue", path: "/api/v1/leaf-series/" + httpTestSeriesID + "/reissues", body: reissueBody, wantSeries: domain.SeriesID(httpTestSeriesID), callCount: func(h *leafRoutesTestHarness) int { return h.issuance.reissueCalls }, wantCall: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newLeafRoutesTestHarness(t)
			headers := httpTestAdminHeaders(httpTestServiceURL)
			headers.Set("Idempotency-Key", httpTestIdempotencyKey)
			if tt.wantSeries != "" {
				headers.Set("If-Match", `"v7"`)
			}
			response := h.request(http.MethodPost, tt.path, tt.body, headers, httpTestSessionCookie())
			if response.Code != http.StatusCreated {
				t.Fatalf("new %s status=%d want=%d: %s", tt.name, response.Code, http.StatusCreated, response.Body.String())
			}
			if got := tt.callCount(h); got != tt.wantCall {
				t.Fatalf("%s application calls=%d want=%d", tt.name, got, tt.wantCall)
			}
			if response.Header().Get("ETag") != "" {
				t.Fatalf("issuance response fabricated resource version ETag %q", response.Header().Get("ETag"))
			}
			var payload struct {
				Data map[string]json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatalf("issuance response is not JSON: %v", err)
			}
			assertIssuanceDTOShape(t, payload.Data)
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("issuance response did not disable caching")
			}

			h.issuance.replayed = true
			replayed := h.request(http.MethodPost, tt.path, tt.body, headers, httpTestSessionCookie())
			if replayed.Code != http.StatusOK {
				t.Fatalf("replayed %s status=%d want=%d: %s", tt.name, replayed.Code, http.StatusOK, replayed.Body.String())
			}
			if strings.Contains(replayed.Body.String(), `"replayed"`) || strings.Contains(replayed.Body.String(), `"token"`) {
				t.Fatal("idempotent replay added an undocumented replay flag or exposed a delivery token")
			}
		})
	}
	for _, test := range []struct {
		name string
		path string
		body string
	}{
		{name: "issue", path: "/api/v1/leaf-series", body: issueBody},
		{name: "renew", path: "/api/v1/leaf-series/" + httpTestSeriesID + "/renewals", body: renewBody},
		{name: "reissue", path: "/api/v1/leaf-series/" + httpTestSeriesID + "/reissues", body: reissueBody},
	} {
		t.Run("rejects missing idempotency/CSRF/precondition/"+test.name, func(t *testing.T) {
			cases := []struct {
				name       string
				headers    http.Header
				cookies    bool
				wantStatus int
			}{
				{name: "unauthenticated", headers: httpTestAdminHeaders(httpTestServiceURL), wantStatus: http.StatusUnauthorized},
				{name: "csrf", headers: header("Origin", httpTestServiceURL), cookies: true, wantStatus: http.StatusForbidden},
				{name: "idempotency", headers: mutationHeadersForLeaf(test.name, false, false), cookies: true, wantStatus: http.StatusBadRequest},
			}
			if test.name != "issue" {
				cases = append(cases, struct {
					name       string
					headers    http.Header
					cookies    bool
					wantStatus int
				}{name: "version", headers: mutationHeadersForLeaf(test.name, true, false), cookies: true, wantStatus: http.StatusPreconditionRequired})
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					h := newLeafRoutesTestHarness(t)
					var cookies []*http.Cookie
					if tc.cookies {
						cookies = append(cookies, httpTestSessionCookie())
					}
					response := h.request(http.MethodPost, test.path, test.body, tc.headers, cookies...)
					if response.Code != tc.wantStatus {
						t.Fatalf("%s status=%d want=%d: %s", tc.name, response.Code, tc.wantStatus, response.Body.String())
					}
					if h.issuance.issueCalls+h.issuance.renewCalls+h.issuance.reissueCalls != 0 {
						t.Fatal("rejected issuance request reached application service")
					}
				})
			}
		})
	}
}

func TestLeafSeriesUpdateAndArchiveRequireIfMatchAndReturnFreshVersion(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
		body string
		call func(*leafRoutesTestHarness) int
	}{
		{name: "update", path: "/api/v1/leaf-series/" + httpTestSeriesID, body: `{"name":"renamed leaf","rotate_every":4}`, call: func(h *leafRoutesTestHarness) int { return h.issuance.updateCalls }},
		{name: "archive", path: "/api/v1/leaf-series/" + httpTestSeriesID + "/archive", body: `{}`, call: func(h *leafRoutesTestHarness) int { return h.issuance.archiveCalls }},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newLeafRoutesTestHarness(t)
			headers := httpTestAdminHeaders(httpTestServiceURL)
			withoutVersion := h.request(map[string]string{"update": http.MethodPatch, "archive": http.MethodPost}[test.name], test.path, test.body, headers, httpTestSessionCookie())
			if withoutVersion.Code != http.StatusPreconditionRequired {
				t.Fatalf("mutation without If-Match status=%d want=%d", withoutVersion.Code, http.StatusPreconditionRequired)
			}
			if test.call(h) != 0 {
				t.Fatal("mutation without If-Match reached issuance service")
			}
			headers.Set("If-Match", `"v7"`)
			response := h.request(map[string]string{"update": http.MethodPatch, "archive": http.MethodPost}[test.name], test.path, test.body, headers, httpTestSessionCookie())
			if response.Code != http.StatusOK {
				t.Fatalf("%s status=%d want=%d: %s", test.name, response.Code, http.StatusOK, response.Body.String())
			}
			if test.call(h) != 1 {
				t.Fatalf("%s application calls=%d want=1", test.name, test.call(h))
			}
			if h.issuance.lastMutationMeta.ExpectedVersion == nil || h.issuance.lastMutationMeta.ExpectedVersion.Int64() != 7 {
				t.Fatal("If-Match version was not forwarded")
			}
			if response.Header().Get("ETag") != `"v7"` {
				t.Fatalf("%s ETag=%q want=%q", test.name, response.Header().Get("ETag"), `"v7"`)
			}
			if h.queries.getSeriesCalls != 1 {
				t.Fatalf("%s response refresh calls=%d want=1", test.name, h.queries.getSeriesCalls)
			}
			var payload struct {
				Data map[string]json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatalf("%s response is not JSON: %v", test.name, err)
			}
			assertLeafSeriesDTOShape(t, payload.Data)
		})
	}
}

func TestLeafRoutesRejectInvalidPathQueryAndNestedInputBeforeService(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		status int
	}{
		{name: "bad series id", method: http.MethodGet, path: "/api/v1/leaf-series/not-a-uuid", status: http.StatusBadRequest},
		{name: "bad certificate id", method: http.MethodGet, path: "/api/v1/certificates/not-a-uuid", status: http.StatusBadRequest},
		{name: "unknown list query", method: http.MethodGet, path: "/api/v1/leaf-series?unexpected=1", status: http.StatusBadRequest},
		{name: "duplicate list query", method: http.MethodGet, path: "/api/v1/certificates?revoked=true&revoked=false", status: http.StatusBadRequest},
		{name: "invalid typed certificate filter", method: http.MethodGet, path: "/api/v1/certificates?revoked=yes", status: http.StatusBadRequest},
		{name: "unknown top-level create field", method: http.MethodPost, path: "/api/v1/leaf-series", body: `{"name":"web","authority_id":"` + httpTestAuthorityID + `","profile":"server_tls","subject":{"common_name":"web.example"},"sans":[{"type":"dns","value":"web.example"}],"private_key":"must-not-echo"}`, status: http.StatusUnprocessableEntity},
		{name: "unknown subject field", method: http.MethodPost, path: "/api/v1/leaf-series", body: `{"name":"web","authority_id":"` + httpTestAuthorityID + `","profile":"server_tls","subject":{"common_name":"web.example","extra":"x"},"sans":[{"type":"dns","value":"web.example"}]}`, status: http.StatusUnprocessableEntity},
		{name: "unknown san field", method: http.MethodPost, path: "/api/v1/leaf-series", body: `{"name":"web","authority_id":"` + httpTestAuthorityID + `","profile":"server_tls","subject":{"common_name":"web.example"},"sans":[{"type":"dns","value":"web.example","extra":"x"}]}`, status: http.StatusUnprocessableEntity},
		{name: "invalid issue profile sans", method: http.MethodPost, path: "/api/v1/leaf-series", body: `{"name":"web","authority_id":"` + httpTestAuthorityID + `","profile":"server_tls","subject":{"common_name":"web.example"},"sans":[{"type":"uri","value":"spiffe://example/web"}]}`, status: http.StatusUnprocessableEntity},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newLeafRoutesTestHarness(t)
			headers := make(http.Header)
			var cookies []*http.Cookie
			if tt.method != http.MethodGet {
				headers = httpTestAdminHeaders(httpTestServiceURL)
				headers.Set("Idempotency-Key", httpTestIdempotencyKey)
				cookies = append(cookies, httpTestSessionCookie())
			}
			response := h.request(tt.method, tt.path, tt.body, headers, cookies...)
			if response.Code != tt.status {
				t.Fatalf("status=%d want=%d: %s", response.Code, tt.status, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "must-not-echo") || strings.Contains(response.Body.String(), "private_key") {
				t.Fatal("request error echoed private input")
			}
			if h.issuance.issueCalls+h.issuance.renewCalls+h.issuance.reissueCalls+h.issuance.updateCalls+h.issuance.archiveCalls != 0 {
				t.Fatal("invalid request reached issuance service")
			}
			if h.queries.listSeriesCalls+h.queries.getSeriesCalls+h.queries.listCertificateCalls+h.queries.getCertificateCalls != 0 {
				t.Fatal("invalid path/query reached leaf query service")
			}
		})
	}
}

func mutationHeadersForLeaf(operation string, withVersion, withIdempotency bool) http.Header {
	headers := httpTestAdminHeaders(httpTestServiceURL)
	if withVersion {
		headers.Set("If-Match", `"v7"`)
	}
	if withIdempotency {
		headers.Set("Idempotency-Key", httpTestIdempotencyKey)
	}
	return headers
}

func assertLeafSeriesDTOShape(t *testing.T, value map[string]json.RawMessage) {
	t.Helper()
	required := []string{"id", "name", "purpose", "management_authority_id", "version", "created_at"}
	allowed := map[string]bool{
		"id": true, "name": true, "purpose": true, "management_authority_id": true,
		"current_certificate_id": true, "current_key_generation_id": true, "validity": true,
		"rotate_every": true, "renewal_count": true, "prior_history_unknown": true,
		"delivery": true, "archived_at": true, "version": true, "created_at": true,
	}
	assertJSONFieldSet(t, value, required, allowed)
}

func assertCertificateDTOShape(t *testing.T, value map[string]json.RawMessage) {
	t.Helper()
	required := []string{"id", "der_sha256", "key_material_id", "issuer_ca_key_generation_id", "serial_hex", "not_before", "not_after", "revoked", "affected", "expired", "created_at"}
	allowed := map[string]bool{
		"id": true, "der_sha256": true, "key_material_id": true, "issuer_ca_key_generation_id": true,
		"serial_hex": true, "not_before": true, "not_after": true, "subject": true, "sans": true,
		"origin": true, "series_id": true, "revoked": true, "affected": true, "expired": true,
		"delivery": true, "created_at": true,
	}
	assertJSONFieldSet(t, value, required, allowed)
}

func assertIssuanceDTOShape(t *testing.T, value map[string]json.RawMessage) {
	t.Helper()
	assertJSONFieldSet(t, value,
		[]string{"series_id", "certificate_id", "key_generation_id", "renewal_count", "key_rotated", "delivery"},
		map[string]bool{"series_id": true, "certificate_id": true, "key_generation_id": true, "renewal_count": true, "key_rotated": true, "delivery": true, "certificate_url": true, "series_url": true},
	)
}

func assertJSONFieldSet(t *testing.T, value map[string]json.RawMessage, required []string, allowed map[string]bool) {
	t.Helper()
	for _, field := range required {
		if _, ok := value[field]; !ok {
			t.Errorf("response omitted OpenAPI field %q", field)
		}
	}
	for field := range value {
		if !allowed[field] {
			t.Errorf("response included field %q outside OpenAPI schema", field)
		}
	}
}

func newLeafRoutesTestHarness(t *testing.T) *leafRoutesTestHarness {
	t.Helper()
	series, certificate := mustLeafTestViews(t)
	issuance := &leafTestIssuanceApplication{view: contract.IssuanceView{
		SeriesID: series.ID, CertificateID: certificate.ID, KeyGenerationID: domain.LeafKeyGenerationID(httpTestLeafKeyID),
		RenewalCount: 2, KeyRotated: true, Delivery: series.Delivery,
		CertificateURL: "/api/v1/certificates/" + httpTestCertificateID, SeriesURL: "/api/v1/leaf-series/" + httpTestSeriesID,
	}}
	queries := &leafTestQueryApplication{
		series: series, seriesPage: contract.Page[contract.LeafSeriesView]{Items: []contract.LeafSeriesView{series}, NextCursor: stringPtr("next-series")},
		certificate: certificate, certificatePage: contract.Page[contract.CertificateView]{Items: []contract.CertificateView{certificate}, NextCursor: stringPtr("next-certificate")},
	}
	handler, err := NewSetupHandler(SetupHandlerConfig{
		Service:  &httpTestSetupApplication{status: contract.SetupView{SetupStage: contract.SetupStageComplete}},
		Identity: &httpTestIdentityApplication{principal: mustHTTPTestAdminPrincipal(t)},
		Settings: &httpTestSettingsApplication{view: mustHTTPTestSettingsView(t, httpTestServiceURL, 1)},
		Issuance: issuance, LeafQueries: queries,
		ServiceURL: httpTestServiceURL, ServiceURLVersion: 1,
	})
	if err != nil {
		t.Fatalf("NewSetupHandler returned an error: %v", err)
	}
	return &leafRoutesTestHarness{handler: handler, issuance: issuance, queries: queries}
}

func (h *leafRoutesTestHarness) request(method, target, body string, headers http.Header, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var request *http.Request
	if body == "" {
		request = httptest.NewRequest(method, target, nil)
	} else {
		request = httptest.NewRequest(method, target, strings.NewReader(body))
		if headers.Get("Content-Type") == "" {
			request.Header.Set("Content-Type", "application/json")
		}
	}
	request.RemoteAddr = "192.0.2.10:1234"
	for name, values := range headers {
		request.Header.Del(name)
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	for _, cookie := range cookies {
		if cookie != nil {
			request.AddCookie(cookie)
		}
	}
	response := httptest.NewRecorder()
	h.handler.ServeHTTP(response, request)
	return response
}

type leafRoutesTestHarness struct {
	handler  http.Handler
	issuance *leafTestIssuanceApplication
	queries  *leafTestQueryApplication
}

type leafTestIssuanceApplication struct {
	view             contract.IssuanceView
	series           contract.LeafSeriesView
	issueCalls       int
	renewCalls       int
	reissueCalls     int
	updateCalls      int
	archiveCalls     int
	replayed         bool
	lastIssueMeta    contract.MutationMeta
	lastIssue        contract.IssuanceIssueCommand
	lastRenewMeta    contract.MutationMeta
	lastRenew        contract.IssuanceRenewCommand
	lastReissueMeta  contract.MutationMeta
	lastReissue      contract.IssuanceReissueCommand
	lastMutationMeta contract.MutationMeta
	lastUpdate       contract.IssuanceUpdateSeriesCommand
	lastArchive      contract.IssuanceArchiveSeriesCommand
}

func (f *leafTestIssuanceApplication) Issue(_ context.Context, meta contract.MutationMeta, command contract.IssuanceIssueCommand) (contract.IssuanceView, error) {
	f.issueCalls++
	f.lastIssueMeta, f.lastIssue = meta, command
	view := f.view
	view.Replayed = f.replayed
	return view, nil
}

func (f *leafTestIssuanceApplication) Renew(_ context.Context, meta contract.MutationMeta, command contract.IssuanceRenewCommand) (contract.IssuanceView, error) {
	f.renewCalls++
	f.lastRenewMeta, f.lastRenew = meta, command
	view := f.view
	view.Replayed = f.replayed
	return view, nil
}

func (f *leafTestIssuanceApplication) Reissue(_ context.Context, meta contract.MutationMeta, command contract.IssuanceReissueCommand) (contract.IssuanceView, error) {
	f.reissueCalls++
	f.lastReissueMeta, f.lastReissue = meta, command
	view := f.view
	view.Replayed = f.replayed
	return view, nil
}

func (f *leafTestIssuanceApplication) UpdateSeries(_ context.Context, meta contract.MutationMeta, command contract.IssuanceUpdateSeriesCommand) (contract.LeafSeriesView, error) {
	f.updateCalls++
	f.lastMutationMeta, f.lastUpdate = meta, command
	series := f.series
	series.Version = meta.ExpectedVersion.Next()
	return series, nil
}

func (f *leafTestIssuanceApplication) ArchiveSeries(_ context.Context, meta contract.MutationMeta, command contract.IssuanceArchiveSeriesCommand) (contract.LeafSeriesView, error) {
	f.archiveCalls++
	f.lastMutationMeta, f.lastArchive = meta, command
	series := f.series
	series.Version = meta.ExpectedVersion.Next()
	return series, nil
}

type leafTestQueryApplication struct {
	series               contract.LeafSeriesView
	seriesPage           contract.Page[contract.LeafSeriesView]
	certificate          contract.CertificateView
	certificatePage      contract.Page[contract.CertificateView]
	listSeriesCalls      int
	getSeriesCalls       int
	listCertificateCalls int
	getCertificateCalls  int
	lastSeriesList       contract.SeriesListQuery
	lastSeriesGet        contract.SeriesGetQuery
	lastCertificateList  contract.CertificateListQuery
	lastCertificateGet   contract.CertificateGetQuery
}

func (f *leafTestQueryApplication) ListSeries(_ context.Context, _ contract.RequestMeta, query contract.SeriesListQuery) (contract.Page[contract.LeafSeriesView], error) {
	f.listSeriesCalls++
	f.lastSeriesList = query
	return f.seriesPage, nil
}

func (f *leafTestQueryApplication) GetSeries(_ context.Context, _ contract.RequestMeta, query contract.SeriesGetQuery) (contract.LeafSeriesView, error) {
	f.getSeriesCalls++
	f.lastSeriesGet = query
	return f.series, nil
}

func (f *leafTestQueryApplication) ListCertificates(_ context.Context, _ contract.RequestMeta, query contract.CertificateListQuery) (contract.Page[contract.CertificateView], error) {
	f.listCertificateCalls++
	f.lastCertificateList = query
	return f.certificatePage, nil
}

func (f *leafTestQueryApplication) GetCertificate(_ context.Context, _ contract.RequestMeta, query contract.CertificateGetQuery) (contract.CertificateView, error) {
	f.getCertificateCalls++
	f.lastCertificateGet = query
	return f.certificate, nil
}

func mustLeafTestViews(t *testing.T) (contract.LeafSeriesView, contract.CertificateView) {
	t.Helper()
	validity, err := domain.NewCalendarValidity(1, domain.ValidityUnitYears)
	if err != nil {
		t.Fatalf("create test validity: %v", err)
	}
	version := mustHTTPTestVersion(t, 7)
	createdAt := domain.NewInstant(time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC))
	consumedAt := domain.NewInstant(time.Date(2026, time.January, 2, 3, 5, 0, 0, time.UTC))
	expiresAt := domain.NewInstant(time.Date(2026, time.January, 2, 4, 4, 5, 0, time.UTC))
	seriesID := domain.SeriesID(httpTestSeriesID)
	certificateID := domain.CertificateID(httpTestCertificateID)
	keyGenerationID := domain.LeafKeyGenerationID(httpTestLeafKeyID)
	delivery := &contract.DeliveryView{
		ID: domain.DeliveryID(httpTestDeliveryID), CertificateID: certificateID,
		State: domain.DeliveryStatePending, ExpiresAt: expiresAt, ConsumedAt: &consumedAt,
		FailureCode: "", Version: version,
	}
	series := contract.LeafSeriesView{
		ID: seriesID, Name: "web leaf", Purpose: domain.SeriesPurposeDistributed,
		ManagementAuthorityID: domain.AuthorityID(httpTestAuthorityID), CurrentCertificateID: &certificateID,
		CurrentKeyGenerationID: &keyGenerationID, Validity: validity, RotateEvery: 3,
		RenewalCount: 2, Delivery: delivery, Version: version, CreatedAt: createdAt,
	}
	fingerprint, err := domain.ParseFingerprint(strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("create test fingerprint: %v", err)
	}
	serial, err := domain.ParseSerialNumber("2a")
	if err != nil {
		t.Fatalf("create test serial: %v", err)
	}
	notBefore := createdAt
	notAfter := domain.NewInstant(time.Date(2027, time.January, 2, 3, 4, 5, 0, time.UTC))
	certificate := contract.CertificateView{
		ID: certificateID, DERSHA256: fingerprint, KeyMaterialID: domain.KeyMaterialID(httpTestKeyMaterialID),
		IssuerCAKeyGenerationID: domain.CAKeyGenerationID(httpTestIssuerKeyID), Serial: serial,
		NotBefore: notBefore, NotAfter: notAfter,
		Subject: contract.SubjectView{CommonName: "web.example", Organization: "Example"},
		SANs:    []contract.SANView{{Type: "dns", Value: "web.example"}},
		Origin:  contract.CertificateOriginGenerated, SeriesID: &seriesID, Affected: true,
		Delivery: delivery, CreatedAt: createdAt,
	}
	return series, certificate
}

func stringPtr(value string) *string { return &value }

func mustLeafTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatalf("parse test instant: %v", err)
	}
	return parsed
}
