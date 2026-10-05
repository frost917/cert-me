package runtime

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/service"
	"cert-me/internal/authcrypto"
	"cert-me/internal/config"
	"cert-me/internal/cryptoformats"
	"cert-me/internal/secret"
	"cert-me/internal/storage/migrate"
)

const runtimeIntegrationSessionCookieName = "__Host-certme_session"

func TestRuntimeInitialHTTPSAdminFlow(t *testing.T) {
	for _, kind := range []config.DatabaseKind{config.SQLite, config.Postgres, config.MySQL, config.MariaDB} {
		t.Run(string(kind), func(t *testing.T) {
			database, configured := runtimeIntegrationDatabase(t, kind)
			if !configured {
				t.Skip("dedicated runtime test database not configured")
			}
			runRuntimeInitialHTTPSAdminFlow(t, database)
		})
	}
}

func runRuntimeInitialHTTPSAdminFlow(t *testing.T, database runtimeDBSpec) {
	t.Helper()
	app := openRuntimeIntegrationApp(t, database)

	if app.gate.IsAccepting() {
		t.Fatal("request admission opened before runtime recovery completed")
	}
	closedServer := httptest.NewServer(app.server.Handler)
	closedResponse, err := closedServer.Client().Get(closedServer.URL + "/api/v1/setup")
	if err != nil {
		closedServer.Close()
		t.Fatalf("request before admission: %v", err)
	}
	closeResponseBody(t, closedResponse)
	closedServer.Close()
	if closedResponse.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status before admission = %d, want %d", closedResponse.StatusCode, http.StatusServiceUnavailable)
	}

	if !app.gate.OpenAdmission() {
		t.Fatal("could not open runtime request admission")
	}
	server, client := startRuntimeIntegrationHTTPS(t, app)
	origin := server.URL

	setupResponse := mustRequest(t, client, http.MethodGet, origin+"/api/v1/setup", nil, nil, nil)
	if setupResponse.StatusCode != http.StatusOK {
		failWithAPIStatus(t, setupResponse, http.StatusOK)
	}
	if setupResponse.TLS == nil || len(setupResponse.TLS.PeerCertificates) == 0 {
		closeResponseBody(t, setupResponse)
		t.Fatal("HTTPS setup response has no peer certificate")
	}
	if got := setupResponse.TLS.PeerCertificates[0].Subject.CommonName; got != "cert-me" {
		closeResponseBody(t, setupResponse)
		t.Fatalf("bootstrap certificate common name = %q, want cert-me", got)
	}
	var setup struct {
		Data struct {
			SetupStage     string `json:"setup_stage"`
			BootstrapHTTPS bool   `json:"bootstrap_https"`
		} `json:"data"`
	}
	decodeResponse(t, setupResponse, &setup)
	if setup.Data.SetupStage != "account_required" {
		t.Fatalf("setup_stage = %q, want account_required", setup.Data.SetupStage)
	}
	if !setup.Data.BootstrapHTTPS {
		t.Fatal("setup response does not report bootstrap HTTPS")
	}

	preAuth := getPreAuthCSRF(t, client, origin)
	createResponse := mustRequest(t, client, http.MethodPost, origin+"/api/v1/setup/admin", map[string]string{
		"login_name": "runtime-admin",
		"password":   "runtime-test-password-123",
	}, preAuth.cookie, map[string]string{
		"Origin":         origin,
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   preAuth.token,
	})
	if createResponse.StatusCode != http.StatusCreated {
		failWithAPIStatus(t, createResponse, http.StatusCreated)
	}
	for _, cookie := range createResponse.Cookies() {
		if cookie.Name == runtimeIntegrationSessionCookieName {
			closeResponseBody(t, createResponse)
			t.Fatal("first administrator creation automatically issued a login session")
		}
	}
	var created struct {
		Data struct {
			LoginName     string `json:"login_name"`
			IsGlobalAdmin bool   `json:"is_global_admin"`
		} `json:"data"`
	}
	decodeResponse(t, createResponse, &created)
	if created.Data.LoginName != "runtime-admin" || !created.Data.IsGlobalAdmin {
		t.Fatal("first account response does not describe the requested administrator")
	}

	unauthenticated := mustRequest(t, client, http.MethodGet, origin+"/api/v1/auth/me", nil, nil, nil)
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		failWithAPIStatus(t, unauthenticated, http.StatusUnauthorized)
	}
	closeResponseBody(t, unauthenticated)

	loginCSRF := getPreAuthCSRF(t, client, origin)
	loginResponse := mustRequest(t, client, http.MethodPost, origin+"/api/v1/auth/login", map[string]string{
		"login_name": "runtime-admin",
		"password":   "runtime-test-password-123",
	}, loginCSRF.cookie, map[string]string{
		"Origin":         origin,
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   loginCSRF.token,
	})
	if loginResponse.StatusCode != http.StatusOK {
		failWithAPIStatus(t, loginResponse, http.StatusOK)
	}
	sessionCookie := responseCookie(t, loginResponse, runtimeIntegrationSessionCookieName)
	if !sessionCookie.Secure || !sessionCookie.HttpOnly || sessionCookie.Path != "/" || sessionCookie.SameSite != http.SameSiteStrictMode {
		closeResponseBody(t, loginResponse)
		t.Fatal("login session cookie does not have the required secure attributes")
	}
	var login struct {
		Data struct {
			CSRFToken string `json:"csrf_token"`
		} `json:"data"`
	}
	decodeResponse(t, loginResponse, &login)
	if login.Data.CSRFToken == "" {
		t.Fatal("login response omitted its session CSRF token")
	}

	meResponse := mustRequest(t, client, http.MethodGet, origin+"/api/v1/auth/me", nil, sessionCookie, nil)
	if meResponse.StatusCode != http.StatusOK {
		failWithAPIStatus(t, meResponse, http.StatusOK)
	}
	var me struct {
		Data struct {
			Account struct {
				LoginName     string `json:"login_name"`
				IsGlobalAdmin bool   `json:"is_global_admin"`
			} `json:"account"`
		} `json:"data"`
	}
	decodeResponse(t, meResponse, &me)
	if me.Data.Account.LoginName != "runtime-admin" || !me.Data.Account.IsGlobalAdmin {
		t.Fatal("authenticated session does not resolve to the first administrator")
	}

	settingsResponse := mustRequest(t, client, http.MethodGet, origin+"/api/v1/settings", nil, sessionCookie, nil)
	if got := apiErrorCode(t, settingsResponse); got != "settings_not_configured" {
		t.Fatalf("settings error code = %q, want settings_not_configured", got)
	}
	if settingsResponse.StatusCode != http.StatusConflict {
		t.Fatalf("settings status = %d, want %d", settingsResponse.StatusCode, http.StatusConflict)
	}

	completeHeaders := map[string]string{
		"Origin":         origin,
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   login.Data.CSRFToken,
		"If-Match":       `"v1"`,
	}
	completeResponse := mustRequest(t, client, http.MethodPost, origin+"/api/v1/setup/complete", nil, sessionCookie, completeHeaders)
	if got := apiErrorCode(t, completeResponse); got != "setup_settings_not_configured" {
		t.Fatalf("setup completion error code = %q, want setup_settings_not_configured", got)
	}
	if completeResponse.StatusCode != http.StatusConflict {
		t.Fatalf("setup completion status = %d, want %d", completeResponse.StatusCode, http.StatusConflict)
	}

	settingsSnapshot := map[string]any{
		"service_url":              origin,
		"leaf_validity":            map[string]any{"value": 2, "unit": "years"},
		"root_validity":            map[string]any{"value": 20, "unit": "years"},
		"intermediate_validity":    map[string]any{"value": 8, "unit": "years"},
		"rotate_every":             4,
		"private_delivery_seconds": 7200,
		"public_link_seconds":      900,
		"crl_interval_seconds":     3600,
		"crl_validity_seconds":     7200,
		"audit_retention_days":     180,
	}
	setupSettingsHeaders := map[string]string{
		"Origin":         origin,
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   login.Data.CSRFToken,
	}
	assertSettingsAuditFailureRollsBack(t, app, sessionCookie.Value, login.Data.CSRFToken, settingsSnapshot)
	initializeStart := make(chan struct{})
	initializeReady := make(chan struct{}, 2)
	initializeResults := make(chan runtimeHTTPResult, 2)
	for range 2 {
		go func() {
			initializeReady <- struct{}{}
			<-initializeStart
			response, err := runtimeRequest(client, http.MethodPost, origin+"/api/v1/setup/settings", settingsSnapshot, sessionCookie, setupSettingsHeaders)
			initializeResults <- runtimeHTTPResult{response: response, err: err}
		}()
	}
	for range 2 {
		<-initializeReady
	}
	close(initializeStart)
	var initializeResponse, concurrentLoser *http.Response
	for range 2 {
		result := <-initializeResults
		if result.err != nil {
			t.Fatalf("concurrent settings initialization request failed: %v", result.err)
		}
		switch result.response.StatusCode {
		case http.StatusCreated:
			if initializeResponse != nil {
				closeResponseBody(t, initializeResponse)
				closeResponseBody(t, result.response)
				t.Fatal("both concurrent settings initialization requests succeeded")
			}
			initializeResponse = result.response
		case http.StatusConflict:
			if concurrentLoser != nil {
				closeResponseBody(t, concurrentLoser)
				closeResponseBody(t, result.response)
				t.Fatal("both concurrent settings initialization requests conflicted")
			}
			concurrentLoser = result.response
		default:
			closeResponseBody(t, result.response)
			t.Fatalf("concurrent settings initialization status = %d, want one 201 and one 409", result.response.StatusCode)
		}
	}
	if initializeResponse == nil || concurrentLoser == nil {
		t.Fatal("concurrent settings initialization did not produce one winner and one conflict")
	}
	if got := concurrentLoser.StatusCode; got != http.StatusConflict {
		t.Fatalf("concurrent settings loser status = %d, want %d", got, http.StatusConflict)
	}
	if got := concurrentLoser.Header.Get("ETag"); got != "" {
		t.Fatalf("conflict response unexpectedly exposed settings ETag %q", got)
	}
	for _, response := range []*http.Response{initializeResponse, concurrentLoser} {
		body := captureResponseBody(t, response)
		assertResponseOmitsSessionSecrets(t, body, sessionCookie.Value, login.Data.CSRFToken)
		if len(response.Cookies()) != 0 {
			t.Fatal("settings initialization response unexpectedly changed authentication cookies")
		}
	}
	var duplicateEnvelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	loserBody := captureResponseBody(t, concurrentLoser)
	if err := json.Unmarshal(loserBody, &duplicateEnvelope); err != nil {
		t.Fatalf("decode concurrent settings conflict response: %v", err)
	}
	if duplicateEnvelope.Error.Code != "settings_already_configured" {
		t.Fatalf("concurrent settings conflict code = %q, want settings_already_configured", duplicateEnvelope.Error.Code)
	}
	var loserFields map[string]json.RawMessage
	if err := json.Unmarshal(loserBody, &loserFields); err != nil {
		t.Fatalf("decode concurrent settings conflict shape: %v", err)
	}
	if _, exposed := loserFields["data"]; exposed || bytes.Contains(loserBody, []byte(origin)) {
		t.Fatal("concurrent settings conflict response exposed the stored settings payload")
	}
	for field := range settingsSnapshot {
		if _, exposed := loserFields[field]; exposed {
			t.Fatal("concurrent settings conflict response echoed an initialization field")
		}
	}
	if initializeResponse.Header.Get("Location") != "/api/v1/settings" || initializeResponse.Header.Get("ETag") != `"v1"` {
		closeResponseBody(t, initializeResponse)
		t.Fatal("initial settings response omitted its canonical Location or version 1 ETag")
	}
	var initializedSettings struct {
		Data struct {
			ServiceURL  string `json:"service_url"`
			RotateEvery int    `json:"rotate_every"`
			Version     int64  `json:"version"`
		} `json:"data"`
	}
	decodeResponse(t, initializeResponse, &initializedSettings)
	if initializedSettings.Data.ServiceURL != origin || initializedSettings.Data.RotateEvery != 4 || initializedSettings.Data.Version != 1 {
		t.Fatal("initial settings response does not contain the explicitly supplied version 1 snapshot")
	}

	duplicateInitialize := mustRequest(t, client, http.MethodPost, origin+"/api/v1/setup/settings", settingsSnapshot, sessionCookie, setupSettingsHeaders)
	if got := apiErrorCode(t, duplicateInitialize); got != "settings_already_configured" {
		t.Fatalf("duplicate settings error code = %q, want settings_already_configured", got)
	}
	if duplicateInitialize.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate settings status = %d, want %d", duplicateInitialize.StatusCode, http.StatusConflict)
	}

	getSettings := mustRequest(t, client, http.MethodGet, origin+"/api/v1/settings", nil, sessionCookie, nil)
	if getSettings.StatusCode != http.StatusOK || getSettings.Header.Get("ETag") != `"v1"` {
		failWithAPIStatus(t, getSettings, http.StatusOK)
	}
	decodeResponse(t, getSettings, &initializedSettings)
	if initializedSettings.Data.ServiceURL != origin || initializedSettings.Data.Version != 1 {
		t.Fatal("settings GET does not return the stored initial snapshot")
	}

	patchResponse := mustRequest(t, client, http.MethodPatch, origin+"/api/v1/settings", map[string]int{"rotate_every": 5}, sessionCookie, map[string]string{
		"Origin":         origin,
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   login.Data.CSRFToken,
		"If-Match":       `"v1"`,
	})
	if patchResponse.StatusCode != http.StatusOK || patchResponse.Header.Get("ETag") != `"v2"` {
		failWithAPIStatus(t, patchResponse, http.StatusOK)
	}
	var patchedSettings struct {
		Data struct {
			ServiceURL  string `json:"service_url"`
			RotateEvery int    `json:"rotate_every"`
			Version     int64  `json:"version"`
		} `json:"data"`
	}
	decodeResponse(t, patchResponse, &patchedSettings)
	if patchedSettings.Data.ServiceURL != origin || patchedSettings.Data.RotateEvery != 5 || patchedSettings.Data.Version != 2 {
		t.Fatal("settings PATCH did not preserve the service URL and advance the requested versioned field")
	}

	rootlessCompletion := mustRequest(t, client, http.MethodPost, origin+"/api/v1/setup/complete", nil, sessionCookie, map[string]string{
		"Origin":         origin,
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   login.Data.CSRFToken,
		"If-Match":       `"v2"`,
	})
	if got := apiErrorCode(t, rootlessCompletion); got != "setup_root_required" {
		t.Fatalf("Root-less setup completion error code = %q, want setup_root_required", got)
	}
	if rootlessCompletion.StatusCode != http.StatusConflict {
		t.Fatalf("Root-less setup completion status = %d, want %d", rootlessCompletion.StatusCode, http.StatusConflict)
	}

	app.gate.FailClosed("runtime_integration_test")
	if got := app.gate.FailureCode(); got != "runtime_integration_test" {
		t.Fatalf("gate failure code = %q, want runtime_integration_test", got)
	}
	select {
	case <-app.gate.StopRequested():
	default:
		t.Fatal("fail-closed gate did not request process shutdown")
	}
	failClosedResponse := mustRequest(t, client, http.MethodGet, origin+"/api/v1/setup", nil, nil, nil)
	if failClosedResponse.StatusCode != http.StatusServiceUnavailable {
		failWithAPIStatus(t, failClosedResponse, http.StatusServiceUnavailable)
	}
	closeResponseBody(t, failClosedResponse)

	server.Close()
	if err := closeRuntimeIntegrationApp(app); err != nil {
		t.Fatalf("close runtime: %v", err)
	}
	if app.gate.IsAccepting() {
		t.Fatal("runtime admission remained open after Close")
	}
	if err := closeRuntimeIntegrationApp(app); err != nil {
		t.Fatalf("close runtime a second time: %v", err)
	}

	// Reopening the same database proves that the first administrator, session,
	// installation stage, and bootstrap TLS identity are persisted together.
	reopened := openRuntimeIntegrationApp(t, database)
	if !reopened.gate.OpenAdmission() {
		t.Fatal("could not open admission after runtime restart")
	}
	restartedServer, restartedClient := startRuntimeIntegrationHTTPS(t, reopened)
	restartedOrigin := restartedServer.URL
	restartedSetup := mustRequest(t, restartedClient, http.MethodGet, restartedOrigin+"/api/v1/setup", nil, nil, nil)
	if restartedSetup.StatusCode != http.StatusOK {
		failWithAPIStatus(t, restartedSetup, http.StatusOK)
	}
	var restartedStatus struct {
		Data struct {
			SetupStage     string `json:"setup_stage"`
			BootstrapHTTPS bool   `json:"bootstrap_https"`
		} `json:"data"`
	}
	decodeResponse(t, restartedSetup, &restartedStatus)
	if restartedStatus.Data.SetupStage != "pki_required" || !restartedStatus.Data.BootstrapHTTPS {
		t.Fatal("restart did not restore the administrator setup stage and bootstrap HTTPS state")
	}
	restartedMe := mustRequest(t, restartedClient, http.MethodGet, restartedOrigin+"/api/v1/auth/me", nil, sessionCookie, nil)
	if restartedMe.StatusCode != http.StatusOK {
		failWithAPIStatus(t, restartedMe, http.StatusOK)
	}
	decodeResponse(t, restartedMe, &me)
	if me.Data.Account.LoginName != "runtime-admin" || !me.Data.Account.IsGlobalAdmin {
		t.Fatal("runtime restart did not preserve the authenticated administrator session")
	}
	restartedSettings := mustRequest(t, restartedClient, http.MethodGet, restartedOrigin+"/api/v1/settings", nil, sessionCookie, nil)
	if restartedSettings.StatusCode != http.StatusOK || restartedSettings.Header.Get("ETag") != `"v2"` {
		failWithAPIStatus(t, restartedSettings, http.StatusOK)
	}
	decodeResponse(t, restartedSettings, &patchedSettings)
	if patchedSettings.Data.ServiceURL != origin || patchedSettings.Data.RotateEvery != 5 || patchedSettings.Data.Version != 2 {
		t.Fatal("runtime restart did not preserve the initial settings snapshot and its patched version")
	}
	restartedServer.Close()
	if err := closeRuntimeIntegrationApp(reopened); err != nil {
		t.Fatalf("close restarted runtime: %v", err)
	}
}

type preAuthCredential struct {
	cookie *http.Cookie
	token  string
}

type runtimeHTTPResult struct {
	response *http.Response
	err      error
}

type runtimeDBSpec struct {
	kind       config.DatabaseKind
	sqlitePath string
	envPrefix  string
}

// External database cases opt in through CERTME_RUNTIME_TEST_<KIND>_{HOST,
// PORT,DATABASE,USERNAME,PASSWORD}. Each database must be a dedicated empty
// disposable database distinct from CERTME_TEST_<KIND>_DSN, which is reserved
// for the migration schema tests.
func runtimeIntegrationDatabaseForKind(t *testing.T, kind config.DatabaseKind) (runtimeDBSpec, bool) {
	t.Helper()
	if kind == config.SQLite {
		return runtimeDBSpec{kind: kind, sqlitePath: filepath.Join(t.TempDir(), "runtime.db")}, true
	}
	prefix := "CERTME_RUNTIME_TEST_" + strings.ToUpper(string(kind)) + "_"
	fields := []string{"HOST", "PORT", "DATABASE", "USERNAME", "PASSWORD"}
	values := make(map[string]string, len(fields))
	present := 0
	for _, field := range fields {
		value, ok := os.LookupEnv(prefix + field)
		if ok {
			present++
		}
		values[field] = value
	}
	if present == 0 {
		return runtimeDBSpec{}, false
	}
	if present != len(fields) {
		t.Fatalf("%s test database configuration is incomplete", strings.ToLower(string(kind)))
	}
	port, err := strconv.ParseUint(values["PORT"], 10, 16)
	if err != nil || port == 0 {
		t.Fatalf("%s test database port is invalid", strings.ToLower(string(kind)))
	}
	return runtimeDBSpec{kind: kind, envPrefix: prefix}, true
}

func runtimeIntegrationDatabase(t *testing.T, kind config.DatabaseKind) (runtimeDBSpec, bool) {
	t.Helper()
	return runtimeIntegrationDatabaseForKind(t, kind)
}

func (database runtimeDBSpec) config(t *testing.T) config.Database {
	t.Helper()
	if database.kind == config.SQLite {
		return config.Database{Kind: config.SQLite, SQLitePath: database.sqlitePath}
	}
	prefix := database.envPrefix
	port, err := strconv.ParseUint(os.Getenv(prefix+"PORT"), 10, 16)
	if err != nil || port == 0 {
		t.Fatalf("%s test database port is invalid", strings.ToLower(string(database.kind)))
	}
	return config.Database{
		Kind:         database.kind,
		Host:         os.Getenv(prefix + "HOST"),
		Port:         uint16(port),
		DatabaseName: os.Getenv(prefix + "DATABASE"),
		Username:     os.Getenv(prefix + "USERNAME"),
		Password:     secret.FromString(os.Getenv(prefix + "PASSWORD")),
	}
}

func openRuntimeIntegrationApp(t *testing.T, database runtimeDBSpec) *App {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	storageKey := secret.New(bytes.Repeat([]byte{0x5a}, 32))
	defer storageKey.Close()
	dbConfig := database.config(t)
	if dbConfig.Password != nil {
		defer dbConfig.Password.Close()
	}
	app, err := Open(ctx, Options{
		Database:      dbConfig,
		StorageKey:    storageKey,
		ListenAddress: "127.0.0.1:0",
	})
	if err != nil {
		if appErr, ok := contract.AsAppError(err); ok {
			t.Fatalf("open runtime for %s: application %s (%s)", database.kind, appErr.Code(), appErr.Kind())
		}
		var migrationErr *migrate.MigrationError
		if errors.As(err, &migrationErr) {
			t.Fatalf("open runtime for %s: migration %s (%s)", database.kind, migrationErr.Code, migrationErr.Kind)
		}
		if database.kind == config.SQLite {
			t.Fatalf("open runtime for %s database: %v", database.kind, err)
		}
		stage := strings.SplitN(err.Error(), ":", 3)
		if len(stage) >= 2 {
			t.Fatalf("open runtime for %s failed at %s: %s", database.kind, stage[0], stage[1])
		}
		t.Fatalf("open runtime for %s database failed", database.kind)
	}
	t.Cleanup(func() {
		if err := closeRuntimeIntegrationApp(app); err != nil {
			t.Errorf("close runtime cleanup: %v", err)
		}
	})
	return app
}

func startRuntimeIntegrationHTTPS(t *testing.T, app *App) (*httptest.Server, *http.Client) {
	t.Helper()
	active, err := app.readActiveTLS(context.Background())
	if err != nil {
		t.Fatalf("read active runtime TLS snapshot: %v", err)
	}
	chain := active.ChainBundle()
	block, rest := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("bootstrap TLS snapshot has an invalid CA chain bundle")
	}
	bootstrapRoot, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse bootstrap trust anchor: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(bootstrapRoot)

	server := httptest.NewUnstartedServer(app.server.Handler)
	server.TLS = app.tlsManager.ServerConfig()
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		server.Close()
		t.Fatal("HTTPS test server returned an unexpected transport")
	}
	transport = transport.Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		RootCAs:    roots,
		ServerName: "cert-me",
	}
	client.Transport = transport
	return server, client
}

func getPreAuthCSRF(t *testing.T, client *http.Client, origin string) preAuthCredential {
	t.Helper()
	response := mustRequest(t, client, http.MethodGet, origin+"/api/v1/auth/csrf?mode=preauth", nil, nil, map[string]string{
		"Origin":         origin,
		"Sec-Fetch-Site": "same-origin",
	})
	if response.StatusCode != http.StatusOK {
		failWithAPIStatus(t, response, http.StatusOK)
	}
	cookie := responseCookie(t, response, "__Host-certme_preauth")
	var body struct {
		Data struct {
			CSRFToken string `json:"csrf_token"`
		} `json:"data"`
	}
	decodeResponse(t, response, &body)
	if body.Data.CSRFToken == "" {
		t.Fatal("pre-auth response omitted its CSRF token")
	}
	return preAuthCredential{cookie: cookie, token: body.Data.CSRFToken}
}

func mustRequest(t *testing.T, client *http.Client, method, target string, body any, cookie *http.Cookie, headers map[string]string) *http.Response {
	t.Helper()
	response, err := runtimeRequest(client, method, target, body, cookie, headers)
	if err != nil {
		t.Fatalf("send %s request: %v", method, err)
	}
	return response
}

func runtimeRequest(client *http.Client, method, target string, body any, cookie *http.Cookie, headers map[string]string) (*http.Response, error) {
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		requestBody = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, target, requestBody)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	return client.Do(request)
}

func captureResponseBody(t *testing.T, response *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return body
}

func assertResponseOmitsSessionSecrets(t *testing.T, body []byte, secrets ...string) {
	t.Helper()
	for _, value := range secrets {
		if value != "" && bytes.Contains(body, []byte(value)) {
			t.Fatal("HTTP response exposed an authentication secret")
		}
	}
}

func responseCookie(t *testing.T, response *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			copy := *cookie
			return &copy
		}
	}
	t.Fatalf("response omitted cookie %q", name)
	return nil
}

func decodeResponse(t *testing.T, response *http.Response, target any) {
	t.Helper()
	defer closeResponseBody(t, response)
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
}

func apiErrorCode(t *testing.T, response *http.Response) string {
	t.Helper()
	defer closeResponseBody(t, response)
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode API error response: %v", err)
	}
	return body.Error.Code
}

func failWithAPIStatus(t *testing.T, response *http.Response, want int) {
	t.Helper()
	code := apiErrorCode(t, response)
	t.Fatalf("HTTP status = %d (error code %q), want %d", response.StatusCode, code, want)
}

func closeResponseBody(t *testing.T, response *http.Response) {
	t.Helper()
	if response == nil || response.Body == nil {
		return
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Errorf("drain response body: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Errorf("close response body: %v", err)
	}
}

func closeRuntimeIntegrationApp(app *App) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return app.Close(ctx)
}

func assertSettingsAuditFailureRollsBack(t *testing.T, app *App, sessionToken, csrfToken string, payload map[string]any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	common := service.CommonDeps{
		UnitOfWork: app.store,
		ReadStore:  app.store,
		Authorizer: adminAuthorizer{},
		Clock:      systemClock{},
		IDs:        randomIDs{},
	}
	identity, err := service.NewIdentityService(service.IdentityDeps{
		CommonDeps:     common,
		PasswordHasher: authcrypto.PasswordHasher{},
		TokenCodec:     authcrypto.TokenCodec{},
	})
	if err != nil {
		t.Fatalf("create runtime identity service for rollback check: %v", err)
	}
	sessionInput := secret.FromString(sessionToken)
	csrfInput := secret.FromString(csrfToken)
	defer sessionInput.Close()
	defer csrfInput.Close()
	authenticated, err := identity.Authenticate(ctx, contract.RequestMeta{}, contract.IdentityAuthenticateCommand{
		SessionToken: sessionInput,
		CSRFToken:    csrfInput,
	})
	if err != nil {
		t.Fatalf("authenticate runtime session for rollback check: %v", err)
	}

	failingStore := failingAuditUnitOfWork{UnitOfWork: app.store}
	settings, err := service.NewSettingsService(service.SettingsDeps{
		CommonDeps: service.CommonDeps{
			UnitOfWork: failingStore,
			ReadStore:  app.store,
			Authorizer: adminAuthorizer{},
			Clock:      systemClock{},
			IDs:        randomIDs{},
		},
		URLValidator: cryptoformats.URLValidator{},
	})
	if err != nil {
		t.Fatalf("create runtime settings service for rollback check: %v", err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode rollback settings fixture: %v", err)
	}
	var command contract.SettingsInitializeCommand
	if err := json.Unmarshal(encoded, &command); err != nil {
		t.Fatalf("decode rollback settings fixture: %v", err)
	}
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: authenticated.Principal}}
	if _, err := settings.Initialize(ctx, meta, command); err == nil {
		t.Fatal("settings initialization succeeded when the audit append failed")
	} else if appErr, ok := contract.AsAppError(err); !ok || appErr.Code() != "settings_audit_failed" {
		t.Fatal("settings initialization did not report its audit append failure")
	}

	_, err = settings.Get(ctx, meta.RequestMeta, contract.SettingsGetCommand{})
	if appErr, ok := contract.AsAppError(err); !ok || appErr.Code() != "settings_not_configured" {
		t.Fatal("settings persisted even though its required audit append failed")
	}
}

type failingAuditUnitOfWork struct{ port.UnitOfWork }

func (store failingAuditUnitOfWork) Write(ctx context.Context, fn func(port.TxStores) error) error {
	return store.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		return fn(failingAuditTxStores{TxStores: tx})
	})
}

type failingAuditTxStores struct{ port.TxStores }

func (stores failingAuditTxStores) Audit() port.AuditRepository {
	return failingAuditRepository{AuditRepository: stores.TxStores.Audit()}
}

type failingAuditRepository struct{ port.AuditRepository }

func (failingAuditRepository) Append(context.Context, port.AuditEvent, port.AuditScope) error {
	return errors.New("test audit append failure")
}
