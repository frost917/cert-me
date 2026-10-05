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

const httpTestAuthorityID = "00000000-0000-4000-8000-000000000011"
const httpTestAuthorityKeyID = "00000000-0000-4000-8000-000000000012"

func TestAuthorityListAndDetailRequireAdminAndMapOpenAPIShape(t *testing.T) {
	h := newAuthorityRoutesTestHarness(t)

	unauthorized := h.request(http.MethodGet, "/api/v1/authorities", "", make(http.Header))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list status = %d; want %d", unauthorized.Code, http.StatusUnauthorized)
	}
	if h.queries.listCalls != 0 {
		t.Fatalf("unauthenticated list reached query service %d times", h.queries.listCalls)
	}
	if unauthorized.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authority response did not disable caching")
	}

	list := h.request(http.MethodGet, "/api/v1/authorities?q=Root&cursor=next-page&limit=7", "", make(http.Header), httpTestSessionCookie())
	if list.Code != http.StatusOK {
		t.Fatalf("authority list status = %d; want %d: %s", list.Code, http.StatusOK, list.Body.String())
	}
	if h.queries.lastList.Search != "Root" || h.queries.lastList.Page.Cursor != "next-page" || h.queries.lastList.Page.Limit != 7 {
		t.Fatalf("authority list query = %#v; filters were not forwarded", h.queries.lastList)
	}
	var listPayload struct {
		Data       []map[string]json.RawMessage `json:"data"`
		NextCursor *string                      `json:"next_cursor"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &listPayload); err != nil {
		t.Fatalf("authority list response is not JSON: %v", err)
	}
	if len(listPayload.Data) != 1 || listPayload.NextCursor == nil || *listPayload.NextCursor != "next-page" {
		t.Fatalf("authority list envelope = %#v", listPayload)
	}
	assertAuthorityDTOShape(t, listPayload.Data[0])

	detail := h.request(http.MethodGet, "/api/v1/authorities/"+httpTestAuthorityID, "", make(http.Header), httpTestSessionCookie())
	if detail.Code != http.StatusOK {
		t.Fatalf("authority detail status = %d; want %d: %s", detail.Code, http.StatusOK, detail.Body.String())
	}
	if h.queries.lastGet.AuthorityID != domain.AuthorityID(httpTestAuthorityID) {
		t.Fatalf("authority detail query id = %q; want path id", h.queries.lastGet.AuthorityID)
	}
	if detail.Header().Get("ETag") != `"v7"` {
		t.Fatalf("authority detail ETag = %q; want %q", detail.Header().Get("ETag"), `"v7"`)
	}
	var detailPayload struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(detail.Body.Bytes(), &detailPayload); err != nil {
		t.Fatalf("authority detail response is not JSON: %v", err)
	}
	assertAuthorityDTOShape(t, detailPayload.Data)
	if _, ok := detailPayload.Data["crl"]; !ok {
		t.Fatal("authority detail omitted its available CRL status")
	}
	if strings.Contains(detail.Body.String(), "PRIVATE KEY") || strings.Contains(detail.Body.String(), "key_material") {
		t.Fatal("authority response exposed signing secret material")
	}
}

func TestAuthorityRoutesRejectInvalidPathAndQueryBeforeServiceCall(t *testing.T) {
	h := newAuthorityRoutesTestHarness(t)

	badID := h.request(http.MethodGet, "/api/v1/authorities/not-a-uuid", "", make(http.Header), httpTestSessionCookie())
	if badID.Code != http.StatusBadRequest {
		t.Fatalf("invalid authority id status = %d; want %d", badID.Code, http.StatusBadRequest)
	}
	if h.queries.getCalls != 0 {
		t.Fatalf("invalid authority id reached query service %d times", h.queries.getCalls)
	}

	badQuery := h.request(http.MethodGet, "/api/v1/authorities?limit=5&unexpected=1", "", make(http.Header), httpTestSessionCookie())
	if badQuery.Code != http.StatusBadRequest {
		t.Fatalf("unknown authority query parameter status = %d; want %d", badQuery.Code, http.StatusBadRequest)
	}
	if h.queries.listCalls != 0 {
		t.Fatalf("invalid authority query reached query service %d times", h.queries.listCalls)
	}
}

func TestCreateAuthorityUsesSessionCSRFAndIdempotencyStatus(t *testing.T) {
	h := newAuthorityRoutesTestHarness(t)
	body := `{"kind":"root","name":"Root CA","subject":{"common_name":"Root CA"},"validity":{"value":10,"unit":"years"}}`
	headers := httpTestAdminHeaders(httpTestServiceURL)
	headers.Set("Idempotency-Key", "00000000-0000-4000-8000-000000000013")

	created := h.request(http.MethodPost, "/api/v1/authorities", body, headers, httpTestSessionCookie())
	if created.Code != http.StatusCreated {
		t.Fatalf("new authority status = %d; want %d: %s", created.Code, http.StatusCreated, created.Body.String())
	}
	if h.authorities.createCalls != 1 {
		t.Fatalf("Create calls = %d; want 1", h.authorities.createCalls)
	}
	if h.authorities.lastCreateMeta.IdempotencyKey != headers.Get("Idempotency-Key") {
		t.Fatal("Idempotency-Key was not forwarded to Create")
	}
	if h.authorities.lastCreate.Kind != "root" || h.authorities.lastCreate.Name != "Root CA" || h.authorities.lastCreate.Subject.CommonName != "Root CA" {
		t.Fatalf("Create command = %#v; request fields were not forwarded", h.authorities.lastCreate)
	}
	if created.Header().Get("ETag") != `"v7"` || created.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authority creation omitted ETag or no-store response policy")
	}

	h.authorities.createView.Replayed = true
	replayed := h.request(http.MethodPost, "/api/v1/authorities", body, headers, httpTestSessionCookie())
	if replayed.Code != http.StatusOK {
		t.Fatalf("replayed authority status = %d; want %d: %s", replayed.Code, http.StatusOK, replayed.Body.String())
	}
	if h.authorities.createCalls != 2 {
		t.Fatalf("Create calls after replay = %d; want 2", h.authorities.createCalls)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(replayed.Body.Bytes(), &payload); err != nil {
		t.Fatalf("replay response is not JSON: %v", err)
	}
	if _, included := payload["replayed"]; included {
		t.Fatal("replay response added a field absent from the OpenAPI envelope")
	}
}

func TestCreateAuthorityRejectsCSRFIdempotencyAndUnknownFields(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		headers    func() http.Header
		wantStatus int
	}{
		{
			name:       "missing session CSRF",
			body:       `{"kind":"root","name":"Root CA","subject":{"common_name":"Root CA"},"validity":{"value":10,"unit":"years"}}`,
			headers:    func() http.Header { return header("Origin", httpTestServiceURL) },
			wantStatus: http.StatusForbidden,
		},
		{
			name: "unknown field",
			body: `{"kind":"root","name":"Root CA","subject":{"common_name":"Root CA"},"validity":{"value":10,"unit":"years"},"private_key":"never-echo"}`,
			headers: func() http.Header {
				headers := httpTestAdminHeaders(httpTestServiceURL)
				headers.Set("Idempotency-Key", "00000000-0000-4000-8000-000000000013")
				return headers
			},
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name: "missing idempotency key",
			body: `{"kind":"root","name":"Root CA","subject":{"common_name":"Root CA"},"validity":{"value":10,"unit":"years"}}`,
			headers: func() http.Header {
				return httpTestAdminHeaders(httpTestServiceURL)
			},
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newAuthorityRoutesTestHarness(t)
			response := h.request(http.MethodPost, "/api/v1/authorities", tt.body, tt.headers(), httpTestSessionCookie())
			if response.Code != tt.wantStatus {
				t.Fatalf("authority create status = %d; want %d: %s", response.Code, tt.wantStatus, response.Body.String())
			}
			if h.authorities.createCalls != 0 {
				t.Fatalf("invalid request reached Create %d times", h.authorities.createCalls)
			}
			if strings.Contains(response.Body.String(), "never-echo") {
				t.Fatal("request error exposed submitted data")
			}
		})
	}
}

func TestAuthorityMutationsRequireIfMatchAndForwardPathID(t *testing.T) {
	const path = "/api/v1/authorities/" + httpTestAuthorityID
	tests := []struct {
		name   string
		method string
		suffix string
		body   string
		invoke func(*authorityTestApplication) int
	}{
		{name: "rename", method: http.MethodPatch, body: `{"name":"Renamed Root"}`, invoke: func(a *authorityTestApplication) int { return a.renameCalls }},
		{name: "issuance state", method: http.MethodPost, suffix: "/issuance-state", body: `{"state":"stopped"}`, invoke: func(a *authorityTestApplication) int { return a.stateCalls }},
		{name: "key destruction", method: http.MethodPost, suffix: "/key-destruction", body: `{"key_generation_id":"` + httpTestAuthorityKeyID + `","justification":"retirement complete"}`, invoke: func(a *authorityTestApplication) int { return a.destroyCalls }},
		{name: "archive", method: http.MethodPost, suffix: "/archive", body: `{}`, invoke: func(a *authorityTestApplication) int { return a.archiveCalls }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newHarness := func() *authorityRoutesTestHarness { return newAuthorityRoutesTestHarness(t) }
			mutationHeaders := httpTestAdminHeaders(httpTestServiceURL)
			mutationHeaders.Set("If-Match", `"v7"`)

			unauthorizedHarness := newHarness()
			unauthorized := unauthorizedHarness.request(tt.method, path+tt.suffix, tt.body, mutationHeaders)
			if unauthorized.Code != http.StatusUnauthorized {
				t.Fatalf("mutation without session status = %d; want %d", unauthorized.Code, http.StatusUnauthorized)
			}
			if got := tt.invoke(unauthorizedHarness.authorities); got != 0 {
				t.Fatalf("mutation without session reached service %d times", got)
			}

			preconditionHarness := newHarness()
			withoutVersionHeaders := httpTestAdminHeaders(httpTestServiceURL)
			withoutVersion := preconditionHarness.request(tt.method, path+tt.suffix, tt.body, withoutVersionHeaders, httpTestSessionCookie())
			if withoutVersion.Code != http.StatusPreconditionRequired {
				t.Fatalf("mutation without If-Match status = %d; want %d", withoutVersion.Code, http.StatusPreconditionRequired)
			}
			if got := tt.invoke(preconditionHarness.authorities); got != 0 {
				t.Fatalf("mutation without If-Match reached service %d times", got)
			}

			h := newHarness()
			response := h.request(tt.method, path+tt.suffix, tt.body, mutationHeaders, httpTestSessionCookie())
			if response.Code != http.StatusOK {
				t.Fatalf("valid mutation status = %d; want %d: %s", response.Code, http.StatusOK, response.Body.String())
			}
			if got := tt.invoke(h.authorities); got != 1 {
				t.Fatalf("mutation service calls = %d; want 1", got)
			}
			if h.authorities.lastMutationMeta.ExpectedVersion == nil || h.authorities.lastMutationMeta.ExpectedVersion.Int64() != 7 {
				t.Fatal("If-Match version was not forwarded")
			}
			if h.authorities.lastAuthorityID != domain.AuthorityID(httpTestAuthorityID) {
				t.Fatalf("command authority id = %q; want path id", h.authorities.lastAuthorityID)
			}
			if response.Header().Get("ETag") != `"v7"` || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("authority mutation omitted ETag or no-store response policy")
			}
		})
	}
}

func TestAuthorityMutationRejectsBodyAuthorityOverride(t *testing.T) {
	h := newAuthorityRoutesTestHarness(t)
	headers := httpTestAdminHeaders(httpTestServiceURL)
	headers.Set("If-Match", `"v7"`)
	response := h.request(http.MethodPatch, "/api/v1/authorities/"+httpTestAuthorityID,
		`{"name":"Renamed Root","authority_id":"00000000-0000-4000-8000-000000000099"}`, headers, httpTestSessionCookie())
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("body path override status = %d; want %d", response.Code, http.StatusUnprocessableEntity)
	}
	if h.authorities.renameCalls != 0 {
		t.Fatalf("body path override reached Rename %d times", h.authorities.renameCalls)
	}
}

func assertAuthorityDTOShape(t *testing.T, value map[string]json.RawMessage) {
	t.Helper()
	required := []string{"id", "kind", "name", "issuance_state", "key_generation_id", "key_available", "affected", "version", "created_at"}
	for _, field := range required {
		if _, ok := value[field]; !ok {
			t.Errorf("authority response omitted OpenAPI field %q", field)
		}
	}
	allowed := map[string]bool{
		"id": true, "kind": true, "name": true, "management_parent_id": true, "issuance_state": true,
		"issuance_certificate_id": true, "key_generation_id": true, "key_available": true, "affected": true,
		"not_after": true, "archived_at": true, "crl": true, "version": true, "created_at": true,
	}
	for field := range value {
		if !allowed[field] {
			t.Errorf("authority response included field %q outside the OpenAPI schema", field)
		}
	}
}

type authorityRoutesTestHarness struct {
	handler     http.Handler
	authorities *authorityTestApplication
	queries     *authorityTestQueryApplication
}

func newAuthorityRoutesTestHarness(t *testing.T) *authorityRoutesTestHarness {
	t.Helper()
	setup := &httpTestSetupApplication{status: contract.SetupView{SetupStage: contract.SetupStageComplete}}
	identity := &httpTestIdentityApplication{principal: mustHTTPTestAdminPrincipal(t)}
	settings := &httpTestSettingsApplication{view: mustHTTPTestSettingsView(t, httpTestServiceURL, 1)}
	view := mustHTTPTestAuthorityView(t)
	authorities := &authorityTestApplication{view: view, createView: view}
	queries := &authorityTestQueryApplication{view: view, page: contract.Page[contract.AuthorityView]{Items: []contract.AuthorityView{view}}}
	handler, err := NewSetupHandler(SetupHandlerConfig{
		Service: setup, Identity: identity, Settings: settings,
		Authorities: authorities, PKIQueries: queries,
		ServiceURL: httpTestServiceURL, ServiceURLVersion: 1,
	})
	if err != nil {
		t.Fatalf("NewSetupHandler returned an error: %v", err)
	}
	return &authorityRoutesTestHarness{handler: handler, authorities: authorities, queries: queries}
}

func (h *authorityRoutesTestHarness) request(method, target, body string, headers http.Header, cookies ...*http.Cookie) *httptest.ResponseRecorder {
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

type authorityTestApplication struct {
	view             contract.AuthorityView
	createView       contract.AuthorityView
	createCalls      int
	renameCalls      int
	stateCalls       int
	destroyCalls     int
	archiveCalls     int
	lastCreate       contract.AuthorityCreateCommand
	lastCreateMeta   contract.MutationMeta
	lastRename       contract.AuthorityRenameCommand
	lastState        contract.AuthoritySetIssuanceStateCommand
	lastDestroy      contract.AuthorityDestroyKeyCommand
	lastArchive      contract.AuthorityArchiveCommand
	lastMutationMeta contract.MutationMeta
	lastAuthorityID  domain.AuthorityID
}

func (f *authorityTestApplication) Create(_ context.Context, meta contract.MutationMeta, command contract.AuthorityCreateCommand) (contract.AuthorityView, error) {
	f.createCalls++
	f.lastCreateMeta, f.lastCreate = meta, command
	return f.createView, nil
}

func (f *authorityTestApplication) Rename(_ context.Context, meta contract.MutationMeta, command contract.AuthorityRenameCommand) (contract.AuthorityView, error) {
	f.renameCalls++
	f.lastMutationMeta, f.lastRename = meta, command
	f.lastAuthorityID = command.AuthorityID
	return f.view, nil
}

func (f *authorityTestApplication) SetIssuanceState(_ context.Context, meta contract.MutationMeta, command contract.AuthoritySetIssuanceStateCommand) (contract.AuthorityView, error) {
	f.stateCalls++
	f.lastMutationMeta, f.lastState = meta, command
	f.lastAuthorityID = command.AuthorityID
	return f.view, nil
}

func (f *authorityTestApplication) DestroyKey(_ context.Context, meta contract.MutationMeta, command contract.AuthorityDestroyKeyCommand) (contract.AuthorityView, error) {
	f.destroyCalls++
	f.lastMutationMeta, f.lastDestroy = meta, command
	f.lastAuthorityID = command.AuthorityID
	return f.view, nil
}

func (f *authorityTestApplication) Archive(_ context.Context, meta contract.MutationMeta, command contract.AuthorityArchiveCommand) (contract.AuthorityView, error) {
	f.archiveCalls++
	f.lastMutationMeta, f.lastArchive = meta, command
	f.lastAuthorityID = command.AuthorityID
	return f.view, nil
}

type authorityTestQueryApplication struct {
	view      contract.AuthorityView
	page      contract.Page[contract.AuthorityView]
	listCalls int
	getCalls  int
	lastList  contract.AuthorityListQuery
	lastGet   contract.AuthorityGetQuery
}

func (f *authorityTestQueryApplication) ListAuthorities(_ context.Context, _ contract.RequestMeta, query contract.AuthorityListQuery) (contract.Page[contract.AuthorityView], error) {
	f.listCalls++
	f.lastList = query
	page := f.page
	if page.NextCursor == nil {
		next := "next-page"
		page.NextCursor = &next
	}
	return page, nil
}

func (f *authorityTestQueryApplication) GetAuthority(_ context.Context, _ contract.RequestMeta, query contract.AuthorityGetQuery) (contract.AuthorityView, error) {
	f.getCalls++
	f.lastGet = query
	return f.view, nil
}

func (f *authorityTestQueryApplication) GetCRLStatus(context.Context, contract.RequestMeta, contract.GetCRLStatusQuery) (contract.CRLStatusView, error) {
	return *f.view.CRL, nil
}

func mustHTTPTestAuthorityView(t *testing.T) contract.AuthorityView {
	t.Helper()
	id, err := domain.ParseAuthorityID(httpTestAuthorityID)
	if err != nil {
		t.Fatalf("parse test authority id: %v", err)
	}
	keyID, err := domain.ParseCAKeyGenerationID(httpTestAuthorityKeyID)
	if err != nil {
		t.Fatalf("parse test authority key id: %v", err)
	}
	version := mustHTTPTestVersion(t, 7)
	number, err := domain.ParseCRLNumber("1")
	if err != nil {
		t.Fatalf("parse test CRL number: %v", err)
	}
	coveredGeneration := int64(1)
	createdAt := domain.NewInstant(time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC))
	notAfter := domain.NewInstant(time.Date(2036, time.January, 2, 3, 4, 5, 0, time.UTC))
	crl := contract.CRLStatusView{
		Number: &number, CoveredGeneration: &coveredGeneration, RevocationGeneration: 1,
		PublicationState: domain.PublicationStateActive, Version: version,
	}
	return contract.AuthorityView{
		ID: id, Kind: domain.AuthorityKindRoot, Name: "Root CA", IssuanceState: domain.IssuanceStateInventory,
		KeyGenerationID: keyID, KeyAvailable: true, NotAfter: notAfter, Version: version, CreatedAt: createdAt, CRL: &crl,
	}
}
