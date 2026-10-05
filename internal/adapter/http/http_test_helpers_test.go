package httpadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

const (
	httpTestServiceURL  = "https://cert.example"
	httpTestSession     = "ssssssssssssssssssssssssssssssssssssssss"
	httpTestSessionCSRF = "cccccccccccccccccccccccccccccccccccccccc"
	httpTestIssuedCSRF  = "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
)

type httpTestHarness struct {
	handler  http.Handler
	setup    *httpTestSetupApplication
	identity *httpTestIdentityApplication
	settings *httpTestSettingsApplication
}

func newHTTPTestHarness(t *testing.T, serviceURL string) *httpTestHarness {
	t.Helper()
	setup := &httpTestSetupApplication{status: contract.SetupView{
		SetupStage:     contract.SetupStageAccountRequired,
		BootstrapHTTPS: true,
	}}
	identity := &httpTestIdentityApplication{principal: mustHTTPTestAdminPrincipal(t)}
	settings := &httpTestSettingsApplication{view: mustHTTPTestSettingsView(t, serviceURL, 1)}
	handler, err := NewSetupHandler(SetupHandlerConfig{
		Service:           setup,
		Identity:          identity,
		Settings:          settings,
		ServiceURL:        serviceURL,
		ServiceURLVersion: 1,
	})
	if err != nil {
		t.Fatalf("NewSetupHandler returned an error: %v", err)
	}
	return &httpTestHarness{handler: handler, setup: setup, identity: identity, settings: settings}
}

func (h *httpTestHarness) request(method, target, body string, headers http.Header, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var requestBody *strings.Reader
	if body != "" {
		requestBody = strings.NewReader(body)
	}
	var request *http.Request
	if requestBody == nil {
		request = httptest.NewRequest(method, target, nil)
	} else {
		request = httptest.NewRequest(method, target, requestBody)
	}
	request.RemoteAddr = "192.0.2.10:1234"
	if body != "" && headers.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/json")
	}
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

func (h *httpTestHarness) preauth(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	headers := make(http.Header)
	headers.Set("Origin", httpTestServiceURL)
	headers.Set("Sec-Fetch-Site", "same-origin")
	response := h.request(http.MethodGet, "/api/v1/auth/csrf?mode=preauth", "", headers, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("pre-auth CSRF route returned status %d", response.Code)
	}
	var payload struct {
		Data struct {
			CSRFToken string `json:"csrf_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("pre-auth CSRF response was not valid JSON: %v", err)
	}
	var nonce *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == preAuthCookieName {
			nonce = cookie
		}
	}
	if payload.Data.CSRFToken == "" || nonce == nil {
		t.Fatal("pre-auth CSRF response omitted its token or nonce cookie")
	}
	return payload.Data.CSRFToken, nonce
}

func httpTestSessionCookie() *http.Cookie {
	return &http.Cookie{Name: sessionCookieName, Value: httpTestSession}
}

func httpTestAdminHeaders(origin string) http.Header {
	headers := make(http.Header)
	headers.Set("Origin", origin)
	headers.Set("X-CSRF-Token", httpTestSessionCSRF)
	return headers
}

func mustHTTPTestAdminPrincipal(t *testing.T) contract.Principal {
	t.Helper()
	accountID, err := domain.ParseAccountID("00000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatalf("could not create test account id: %v", err)
	}
	sessionID, err := domain.ParseSessionID("00000000-0000-4000-8000-000000000002")
	if err != nil {
		t.Fatalf("could not create test session id: %v", err)
	}
	epoch, err := domain.ParseAuthEpoch(1)
	if err != nil {
		t.Fatalf("could not create test auth epoch: %v", err)
	}
	principal, err := contract.NewAdminPrincipal(contract.AdminPrincipalFacts{
		AccountID: accountID,
		SessionID: sessionID,
		AuthEpoch: epoch,
	})
	if err != nil {
		t.Fatalf("could not create test admin principal: %v", err)
	}
	return principal
}

func mustHTTPTestVersion(t *testing.T, value int64) domain.Version {
	t.Helper()
	version, err := domain.ParseVersion(value)
	if err != nil {
		t.Fatalf("could not create test version: %v", err)
	}
	return version
}

func mustHTTPTestSettingsView(t *testing.T, serviceURL string, version int64) contract.SettingsView {
	t.Helper()
	validity, err := domain.NewCalendarValidity(1, domain.ValidityUnitYears)
	if err != nil {
		t.Fatalf("could not create test validity: %v", err)
	}
	return contract.SettingsView{
		ServiceURL:              serviceURL,
		LeafValidity:            validity,
		RootValidity:            validity,
		IntermediateValidity:    validity,
		RotateEvery:             3,
		PrivateDeliveryLifetime: domain.NewDuration(3 * time.Hour),
		PublicLinkLifetime:      domain.NewDuration(10 * time.Minute),
		CRLInterval:             domain.NewDuration(12 * time.Hour),
		CRLValidity:             domain.NewDuration(48 * time.Hour),
		AuditRetentionDays:      365,
		Version:                 mustHTTPTestVersion(t, version),
	}
}

func mustHTTPTestAccount(t *testing.T) contract.AccountView {
	t.Helper()
	accountID, err := domain.ParseAccountID("00000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatalf("could not create test account id: %v", err)
	}
	return contract.AccountView{
		ID:            accountID,
		LoginName:     "operator",
		State:         domain.AccountStateActive,
		IsGlobalAdmin: true,
		Version:       mustHTTPTestVersion(t, 1),
	}
}

type httpTestSetupApplication struct {
	mu sync.Mutex

	status          contract.SetupView
	statusErr       error
	createAdminErr  error
	completeErr     error
	createAdminCall int
	createLoginName string
	passwordPresent bool
	completeCall    int
	completeVersion int64
}

func (f *httpTestSetupApplication) Status(context.Context, contract.RequestMeta, contract.EmptyCommand) (contract.SetupView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status, f.statusErr
}

func (f *httpTestSetupApplication) CreateAdmin(_ context.Context, _ contract.MutationMeta, command contract.SetupCreateAdminCommand) (contract.AccountView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createAdminCall++
	f.createLoginName = command.LoginName
	f.passwordPresent = command.Password != nil
	if f.createAdminErr != nil {
		return contract.AccountView{}, f.createAdminErr
	}
	return mustHTTPTestAccountForFake(), nil
}

func (f *httpTestSetupApplication) Complete(_ context.Context, meta contract.MutationMeta, _ contract.SetupCompleteCommand) (contract.SetupView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completeCall++
	if meta.ExpectedVersion != nil {
		f.completeVersion = meta.ExpectedVersion.Int64()
	}
	if f.completeErr != nil {
		return contract.SetupView{}, f.completeErr
	}
	return contract.SetupView{SetupStage: contract.SetupStageComplete, BootstrapHTTPS: false}, nil
}

func mustHTTPTestAccountForFake() contract.AccountView {
	accountID, _ := domain.ParseAccountID("00000000-0000-4000-8000-000000000001")
	version, _ := domain.ParseVersion(1)
	return contract.AccountView{ID: accountID, LoginName: "operator", State: domain.AccountStateActive, IsGlobalAdmin: true, Version: version}
}

func (f *httpTestSetupApplication) createAdminCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.createAdminCall
}

func (f *httpTestSetupApplication) completeResult() (int, int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.completeCall, f.completeVersion
}

type httpTestIdentityApplication struct {
	mu sync.Mutex

	principal contract.Principal
	loginFn   func(context.Context, contract.MutationMeta, contract.IdentityLoginCommand) (contract.LoginView, error)
	authFn    func(context.Context, contract.RequestMeta, contract.IdentityAuthenticateCommand) (contract.AuthenticateResult, error)
	logoutErr error
	issueErr  error

	loginCall        int
	authenticateCall int
	issueCSRFCall    int
	logoutCall       int
}

func (f *httpTestIdentityApplication) Login(ctx context.Context, meta contract.MutationMeta, command contract.IdentityLoginCommand) (contract.LoginView, error) {
	f.mu.Lock()
	f.loginCall++
	fn := f.loginFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, meta, command)
	}
	now := time.Now().UTC()
	return contract.LoginView{
		Account:           mustHTTPTestAccountForFake(),
		IdleExpiresAt:     domain.NewInstant(now.Add(time.Hour)),
		AbsoluteExpiresAt: domain.NewInstant(now.Add(24 * time.Hour)),
		SessionToken:      secret.FromString(httpTestSession),
		CSRFToken:         secret.FromString(httpTestIssuedCSRF),
	}, nil
}

func (f *httpTestIdentityApplication) Logout(context.Context, contract.MutationMeta, contract.IdentityLogoutCommand) (contract.LogoutResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logoutCall++
	return contract.LogoutResult{}, f.logoutErr
}

func (f *httpTestIdentityApplication) Authenticate(ctx context.Context, meta contract.RequestMeta, command contract.IdentityAuthenticateCommand) (contract.AuthenticateResult, error) {
	f.mu.Lock()
	f.authenticateCall++
	fn := f.authFn
	principal := f.principal
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, meta, command)
	}
	if !httpTestSecretEquals(command.SessionToken, httpTestSession) {
		return contract.AuthenticateResult{}, contract.NewAppError(contract.ErrorKindAuth, "authentication_required", "A valid session is required.")
	}
	if command.CSRFToken != nil && !httpTestSecretEquals(command.CSRFToken, httpTestSessionCSRF) {
		return contract.AuthenticateResult{}, contract.NewAppError(contract.ErrorKindForbidden, "csrf_failed", "The request could not be verified.")
	}
	return contract.AuthenticateResult{Principal: principal, Session: contract.SessionView{Account: mustHTTPTestAccountForFake()}}, nil
}

func httpTestSecretEquals(value *secret.Input, want string) bool {
	if value == nil {
		return false
	}
	matched := false
	if err := value.Use(func(raw []byte) error {
		matched = string(raw) == want
		return nil
	}); err != nil {
		return false
	}
	return matched
}

func (f *httpTestIdentityApplication) CompleteReset(context.Context, contract.MutationMeta, contract.IdentityCompleteResetCommand) (contract.CompleteResetResult, error) {
	return contract.CompleteResetResult{}, nil
}

func (f *httpTestIdentityApplication) IssueCSRF(context.Context, contract.RequestMeta, contract.IdentityIssueCSRFCommand) (contract.CSRFView, error) {
	f.mu.Lock()
	f.issueCSRFCall++
	err := f.issueErr
	f.mu.Unlock()
	if err != nil {
		return contract.CSRFView{}, err
	}
	return contract.CSRFView{CSRFToken: secret.FromString(httpTestIssuedCSRF)}, nil
}

func (f *httpTestIdentityApplication) callCounts() (login, authenticate, issueCSRF, logout int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loginCall, f.authenticateCall, f.issueCSRFCall, f.logoutCall
}

type httpTestSettingsApplication struct {
	mu sync.Mutex

	view     contract.SettingsView
	getErr   error
	getFn    func(context.Context, contract.RequestMeta, contract.SettingsGetCommand) (contract.SettingsView, error)
	updateFn func(context.Context, contract.MutationMeta, contract.SettingsUpdateCommand) (contract.SettingsView, error)

	getCall             int
	updateCall          int
	lastExpectedVersion int64
	lastCommand         contract.SettingsUpdateCommand
}

func (f *httpTestSettingsApplication) Get(ctx context.Context, meta contract.RequestMeta, command contract.SettingsGetCommand) (contract.SettingsView, error) {
	f.mu.Lock()
	f.getCall++
	fn := f.getFn
	view, getErr := f.view, f.getErr
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, meta, command)
	}
	return view, getErr
}

func (f *httpTestSettingsApplication) Update(ctx context.Context, meta contract.MutationMeta, command contract.SettingsUpdateCommand) (contract.SettingsView, error) {
	f.mu.Lock()
	f.updateCall++
	if meta.ExpectedVersion != nil {
		f.lastExpectedVersion = meta.ExpectedVersion.Int64()
	}
	f.lastCommand = command
	fn := f.updateFn
	view := f.view
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, meta, command)
	}
	if command.ServiceURL != nil {
		view.ServiceURL = *command.ServiceURL
	}
	if meta.ExpectedVersion != nil {
		view.Version, _ = domain.ParseVersion(meta.ExpectedVersion.Int64() + 1)
	}
	f.mu.Lock()
	f.view = view
	f.mu.Unlock()
	return view, nil
}

func (f *httpTestSettingsApplication) updateState() (calls int, expectedVersion int64, command contract.SettingsUpdateCommand) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.updateCall, f.lastExpectedVersion, f.lastCommand
}

func (f *httpTestSettingsApplication) getCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.getCall
}
