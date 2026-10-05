package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"cert-me/internal/app/port"
	"cert-me/internal/config"
	"cert-me/internal/domain"
)

// TestRuntimePKIIssuanceFlow exercises the stage 4 PKI endpoints through the
// real runtime, SQL repositories, and a TLS client that trusts the bootstrap
// CA and verifies the cert-me server name. External database cases are opt-in
// through the same dedicated-database environment variables as the stage 3
// runtime tests.
func TestRuntimePKIIssuanceFlow(t *testing.T) {
	for _, kind := range []config.DatabaseKind{config.SQLite, config.Postgres, config.MySQL, config.MariaDB} {
		t.Run(string(kind), func(t *testing.T) {
			database, configured := runtimeIntegrationDatabase(t, kind)
			if !configured {
				t.Skip("dedicated runtime test database not configured")
			}
			runRuntimePKIIssuanceFlow(t, database)
		})
	}
}

func runRuntimePKIIssuanceFlow(t *testing.T, database runtimeDBSpec) {
	t.Helper()
	app := openRuntimeIntegrationApp(t, database)
	if !app.gate.OpenAdmission() {
		t.Fatal("could not open runtime request admission")
	}
	server, client := startRuntimeIntegrationHTTPS(t, app)
	client.Timeout = 15 * time.Second
	origin := server.URL

	setupResponse := mustRequest(t, client, http.MethodGet, origin+"/api/v1/setup", nil, nil, nil)
	if setupResponse.StatusCode != http.StatusOK {
		failWithAPIStatus(t, setupResponse, http.StatusOK)
	}
	setup := stage4ResponseData(t, setupResponse)
	if got := stage4String(t, setup, "setup_stage"); got != "account_required" {
		t.Fatalf("fresh runtime setup stage = %q, want account_required", got)
	}

	sessionCookie, csrfToken := stage4CreateAdminSession(t, client, origin)
	settings := map[string]any{
		"service_url":              origin,
		"leaf_validity":            map[string]any{"value": 1, "unit": "years"},
		"root_validity":            map[string]any{"value": 20, "unit": "years"},
		"intermediate_validity":    map[string]any{"value": 10, "unit": "years"},
		"rotate_every":             3,
		"private_delivery_seconds": 7200,
		"public_link_seconds":      900,
		"crl_interval_seconds":     3600,
		"crl_validity_seconds":     7200,
		"audit_retention_days":     180,
	}
	settingsResponse := mustRequest(t, client, http.MethodPost, origin+"/api/v1/setup/settings", settings, sessionCookie, stage4MutationHeaders(origin, csrfToken, "", ""))
	stage4ExpectStatus(t, settingsResponse, http.StatusCreated)
	if settingsResponse.Header.Get("ETag") != `"v1"` {
		t.Fatal("initial settings response omitted the version 1 ETag")
	}
	settingsData := stage4ResponseData(t, settingsResponse)
	if stage4String(t, settingsData, "service_url") != origin {
		t.Fatal("initial settings did not preserve the explicitly supplied service URL")
	}

	rootBody := map[string]any{
		"kind":          "root",
		"name":          "Runtime Integration Root",
		"subject":       map[string]string{"common_name": "Runtime Integration Root"},
		"key_algorithm": "ecdsa_p256",
		"validity":      map[string]any{"value": 20, "unit": "years"},
	}
	rootKey := "00000000-0000-4000-8000-000000000101"
	rootResponse := mustRequest(t, client, http.MethodPost, origin+"/api/v1/authorities", rootBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, "", rootKey))
	stage4ExpectStatus(t, rootResponse, http.StatusCreated)
	rootData := stage4ResponseData(t, rootResponse)
	stage4AssertAuthority(t, rootData, true)
	rootID := stage4String(t, rootData, "id")
	if stage4String(t, rootData, "kind") != "root" || stage4String(t, rootData, "name") != "Runtime Integration Root" {
		t.Fatal("Root creation response does not describe the requested authority")
	}
	rootReplay := mustRequest(t, client, http.MethodPost, origin+"/api/v1/authorities", rootBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, "", rootKey))
	stage4ExpectStatus(t, rootReplay, http.StatusOK)
	rootReplayData := stage4ResponseData(t, rootReplay)
	if stage4String(t, rootReplayData, "id") != rootID {
		t.Fatal("Root idempotent replay returned a different authority")
	}
	rootConflictBody := map[string]any{
		"kind":          "root",
		"name":          "Different Root Name",
		"subject":       map[string]string{"common_name": "Different Root Name"},
		"key_algorithm": "ecdsa_p256",
		"validity":      map[string]any{"value": 20, "unit": "years"},
	}
	rootConflict := mustRequest(t, client, http.MethodPost, origin+"/api/v1/authorities", rootConflictBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, "", rootKey))
	stage4ExpectStatus(t, rootConflict, http.StatusConflict)
	if got := apiErrorCode(t, rootConflict); got != "idempotency_conflict" {
		t.Fatalf("Root idempotency conflict code = %q, want idempotency_conflict", got)
	}

	rootEnabled := mustRequest(t, client, http.MethodPost, origin+"/api/v1/authorities/"+rootID+"/issuance-state", map[string]string{"state": "enabled"}, sessionCookie, stage4MutationHeaders(origin, csrfToken, rootResponse.Header.Get("ETag"), ""))
	stage4ExpectStatus(t, rootEnabled, http.StatusOK)
	rootEnabledData := stage4ResponseData(t, rootEnabled)
	stage4AssertAuthority(t, rootEnabledData, true)

	intermediateBody := map[string]any{
		"kind":                "intermediate",
		"name":                "Runtime Integration Intermediate",
		"parent_authority_id": rootID,
		"subject":             map[string]string{"common_name": "Runtime Integration Intermediate"},
		"key_algorithm":       "ecdsa_p256",
		"validity":            map[string]any{"value": 10, "unit": "years"},
	}
	intermediateResponse := mustRequest(t, client, http.MethodPost, origin+"/api/v1/authorities", intermediateBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, "", "00000000-0000-4000-8000-000000000102"))
	stage4ExpectStatus(t, intermediateResponse, http.StatusCreated)
	intermediateData := stage4ResponseData(t, intermediateResponse)
	stage4AssertAuthority(t, intermediateData, true)
	intermediateID := stage4String(t, intermediateData, "id")
	if stage4String(t, intermediateData, "kind") != "intermediate" || stage4String(t, intermediateData, "management_parent_id") != rootID {
		t.Fatal("Intermediate creation response does not preserve its Root parent")
	}
	intermediateEnabled := mustRequest(t, client, http.MethodPost, origin+"/api/v1/authorities/"+intermediateID+"/issuance-state", map[string]string{"state": "enabled"}, sessionCookie, stage4MutationHeaders(origin, csrfToken, intermediateResponse.Header.Get("ETag"), ""))
	stage4ExpectStatus(t, intermediateEnabled, http.StatusOK)
	stage4AssertAuthority(t, stage4ResponseData(t, intermediateEnabled), true)

	complete := mustRequest(t, client, http.MethodPost, origin+"/api/v1/setup/complete", nil, sessionCookie, stage4MutationHeaders(origin, csrfToken, settingsResponse.Header.Get("ETag"), ""))
	stage4ExpectStatus(t, complete, http.StatusOK)
	completeData := stage4ResponseData(t, complete)
	if stage4String(t, completeData, "setup_stage") != "complete" {
		t.Fatal("setup completion did not advance the installation to complete")
	}

	issueBody := map[string]any{
		"name":          "runtime-node.internal",
		"authority_id":  intermediateID,
		"profile":       "server_tls",
		"subject":       map[string]string{"common_name": "runtime-node.internal"},
		"sans":          []map[string]string{{"type": "dns", "value": "runtime-node.internal"}},
		"key_algorithm": "ecdsa_p256",
		"validity":      map[string]any{"value": 1, "unit": "years"},
		"rotate_every":  3,
	}
	issueKey := "00000000-0000-4000-8000-000000000103"
	issueResponse := mustRequest(t, client, http.MethodPost, origin+"/api/v1/leaf-series", issueBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, "", issueKey))
	stage4ExpectStatus(t, issueResponse, http.StatusCreated)
	issueData := stage4ResponseData(t, issueResponse)
	stage4AssertIssuance(t, issueData, true)
	seriesID := stage4String(t, issueData, "series_id")
	initialCertificateID := stage4String(t, issueData, "certificate_id")
	if stage4String(t, issueData, "key_generation_id") == "" || stage4Int(t, issueData, "renewal_count") != 0 || stage4Bool(t, issueData, "key_rotated") {
		t.Fatal("initial Leaf issuance has an invalid key generation or renewal state")
	}
	delivery := stage4Object(t, issueData["delivery"])
	stage4AssertDelivery(t, delivery)
	if stage4String(t, delivery, "state") != string(domain.DeliveryStatePending) || stage4String(t, delivery, "certificate_id") != initialCertificateID {
		t.Fatal("initial Leaf issuance did not create its pending private-key delivery")
	}
	stage4AssertNoSecretFields(t, issueResponse)
	if len(issueResponse.Cookies()) != 0 {
		t.Fatal("Leaf issuance unexpectedly changed authentication cookies")
	}
	if stage4String(t, issueData, "certificate_url") == "" || stage4String(t, issueData, "series_url") == "" {
		t.Fatal("Leaf issuance omitted its certificate or series resource URL")
	}
	issueReplay := mustRequest(t, client, http.MethodPost, origin+"/api/v1/leaf-series", issueBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, "", issueKey))
	stage4ExpectStatus(t, issueReplay, http.StatusOK)
	issueReplayData := stage4ResponseData(t, issueReplay)
	stage4AssertIssuance(t, issueReplayData, true)
	if stage4String(t, issueReplayData, "series_id") != seriesID || stage4String(t, issueReplayData, "certificate_id") != initialCertificateID {
		t.Fatal("Leaf issue replay returned a different series or certificate")
	}
	stage4AssertNoSecretFields(t, issueReplay)

	seriesResponse := mustRequest(t, client, http.MethodGet, origin+"/api/v1/leaf-series/"+seriesID, nil, sessionCookie, nil)
	stage4ExpectStatus(t, seriesResponse, http.StatusOK)
	seriesData := stage4ResponseData(t, seriesResponse)
	stage4AssertSeries(t, seriesData, true)
	if stage4String(t, seriesData, "current_certificate_id") != initialCertificateID || stage4String(t, seriesData, "created_at") == "" {
		t.Fatal("Leaf series detail omitted its current certificate or creation time")
	}
	initialSeriesETag := seriesResponse.Header.Get("ETag")
	if initialSeriesETag == "" {
		t.Fatal("Leaf series detail omitted its version ETag")
	}

	pendingRenewal := mustRequest(t, client, http.MethodPost, origin+"/api/v1/leaf-series/"+seriesID+"/renewals", map[string]string{"source_certificate_id": initialCertificateID}, sessionCookie, stage4MutationHeaders(origin, csrfToken, initialSeriesETag, "00000000-0000-4000-8000-000000000104"))
	stage4ExpectStatus(t, pendingRenewal, http.StatusConflict)
	_ = apiErrorCode(t, pendingRenewal)

	if err := stage4CompleteInitialDelivery(t, app, seriesID); err != nil {
		t.Fatalf("record initial Leaf delivery through the runtime unit of work: %v", err)
	}

	renewalKey := "00000000-0000-4000-8000-000000000105"
	renewalBody := map[string]string{"source_certificate_id": initialCertificateID}
	renewalResponse := mustRequest(t, client, http.MethodPost, origin+"/api/v1/leaf-series/"+seriesID+"/renewals", renewalBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, initialSeriesETag, renewalKey))
	stage4ExpectStatus(t, renewalResponse, http.StatusCreated)
	renewalData := stage4ResponseData(t, renewalResponse)
	stage4AssertIssuance(t, renewalData, true)
	renewedCertificateID := stage4String(t, renewalData, "certificate_id")
	if renewedCertificateID == initialCertificateID || stage4Int(t, renewalData, "renewal_count") != 1 || stage4Bool(t, renewalData, "key_rotated") {
		t.Fatal("first ordinary renewal did not preserve the key while creating an immutable new certificate")
	}
	if string(bytes.TrimSpace(renewalData["delivery"])) != "null" {
		t.Fatal("key-reuse renewal unexpectedly created a new private delivery")
	}
	stage4AssertNoSecretFields(t, renewalResponse)
	renewalReplay := mustRequest(t, client, http.MethodPost, origin+"/api/v1/leaf-series/"+seriesID+"/renewals", renewalBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, initialSeriesETag, renewalKey))
	stage4ExpectStatus(t, renewalReplay, http.StatusOK)
	renewalReplayData := stage4ResponseData(t, renewalReplay)
	if stage4String(t, renewalReplayData, "certificate_id") != renewedCertificateID {
		t.Fatal("renewal replay with the prior series ETag returned a different certificate")
	}
	stage4AssertNoSecretFields(t, renewalReplay)

	seriesAfterRenewal := mustRequest(t, client, http.MethodGet, origin+"/api/v1/leaf-series/"+seriesID, nil, sessionCookie, nil)
	stage4ExpectStatus(t, seriesAfterRenewal, http.StatusOK)
	seriesAfterRenewalData := stage4ResponseData(t, seriesAfterRenewal)
	stage4AssertSeries(t, seriesAfterRenewalData, true)
	renewedSeriesETag := seriesAfterRenewal.Header.Get("ETag")
	if renewedSeriesETag == "" || stage4String(t, seriesAfterRenewalData, "current_certificate_id") != renewedCertificateID {
		t.Fatal("Leaf series did not advance to the renewed certificate")
	}

	reissueBody := map[string]string{"source_certificate_id": renewedCertificateID, "reason": "manual_rotation"}
	reissueKey := "00000000-0000-4000-8000-000000000106"
	reissueResponses := stage4ConcurrentSameKeyRequests(client, origin+"/api/v1/leaf-series/"+seriesID+"/reissues", reissueBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, renewedSeriesETag, reissueKey))
	var reissueData map[string]json.RawMessage
	var reissueStatus201, reissueStatus200 int
	for _, result := range reissueResponses {
		if result.err != nil {
			t.Fatal("concurrent reissue request failed")
		}
		switch result.response.StatusCode {
		case http.StatusCreated:
			reissueStatus201++
		case http.StatusOK:
			reissueStatus200++
		default:
			failWithAPIStatus(t, result.response, http.StatusCreated)
		}
		data := stage4ResponseData(t, result.response)
		stage4AssertIssuance(t, data, true)
		if reissueData == nil {
			reissueData = data
		} else if stage4String(t, reissueData, "certificate_id") != stage4String(t, data, "certificate_id") || stage4String(t, reissueData, "series_id") != stage4String(t, data, "series_id") {
			t.Fatal("concurrent reissue requests with one key created different certificates")
		}
		stage4AssertNoSecretFields(t, result.response)
	}
	if reissueStatus201 != 1 || reissueStatus200 != 1 {
		t.Fatalf("concurrent same-key reissue statuses = %d created, %d replayed; want one each", reissueStatus201, reissueStatus200)
	}
	reissuedCertificateID := stage4String(t, reissueData, "certificate_id")
	if reissuedCertificateID == renewedCertificateID || !stage4Bool(t, reissueData, "key_rotated") || stage4Int(t, reissueData, "renewal_count") != 0 {
		t.Fatal("manual reissue did not create a new key generation and certificate")
	}
	reissueDelivery := stage4Object(t, reissueData["delivery"])
	stage4AssertDelivery(t, reissueDelivery)
	if stage4String(t, reissueDelivery, "state") != string(domain.DeliveryStatePending) || stage4String(t, reissueDelivery, "certificate_id") != reissuedCertificateID {
		t.Fatal("manual reissue did not create a pending delivery for its new key")
	}
	if stage4String(t, reissueData, "certificate_url") == "" || stage4String(t, reissueData, "series_url") == "" {
		t.Fatal("manual reissue omitted its certificate or series resource URL")
	}

	// Replay after the concurrent operation using the old ETag proves a stored
	// idempotent result is resolved before a new-version mismatch is rejected.
	reissueReplay := mustRequest(t, client, http.MethodPost, origin+"/api/v1/leaf-series/"+seriesID+"/reissues", reissueBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, renewedSeriesETag, reissueKey))
	stage4ExpectStatus(t, reissueReplay, http.StatusOK)
	reissueReplayData := stage4ResponseData(t, reissueReplay)
	if stage4String(t, reissueReplayData, "certificate_id") != reissuedCertificateID {
		t.Fatal("manual reissue replay with the prior series ETag returned a different certificate")
	}
	stage4AssertNoSecretFields(t, reissueReplay)

	seriesAfterReissue := mustRequest(t, client, http.MethodGet, origin+"/api/v1/leaf-series/"+seriesID, nil, sessionCookie, nil)
	stage4ExpectStatus(t, seriesAfterReissue, http.StatusOK)
	seriesAfterReissueData := stage4ResponseData(t, seriesAfterReissue)
	stage4AssertSeries(t, seriesAfterReissueData, true)
	reissuedSeriesETag := seriesAfterReissue.Header.Get("ETag")
	if stage4String(t, seriesAfterReissueData, "current_certificate_id") != reissuedCertificateID || reissuedSeriesETag == "" {
		t.Fatal("Leaf series did not advance to the reissued certificate")
	}

	updatedName := "runtime-node-renamed.internal"
	updateResponse := mustRequest(t, client, http.MethodPatch, origin+"/api/v1/leaf-series/"+seriesID, map[string]string{"name": updatedName}, sessionCookie, stage4MutationHeaders(origin, csrfToken, reissuedSeriesETag, ""))
	stage4ExpectStatus(t, updateResponse, http.StatusOK)
	updateData := stage4ResponseData(t, updateResponse)
	stage4AssertSeries(t, updateData, true)
	if stage4String(t, updateData, "name") != updatedName {
		t.Fatal("Leaf series update did not apply the requested name")
	}
	updatedSeriesETag := updateResponse.Header.Get("ETag")
	if updatedSeriesETag == "" {
		t.Fatal("Leaf series update omitted the new version ETag")
	}

	archiveResponse := mustRequest(t, client, http.MethodPost, origin+"/api/v1/leaf-series/"+seriesID+"/archive", map[string]any{}, sessionCookie, stage4MutationHeaders(origin, csrfToken, updatedSeriesETag, ""))
	stage4ExpectStatus(t, archiveResponse, http.StatusOK)
	archivedData := stage4ResponseData(t, archiveResponse)
	stage4AssertSeries(t, archivedData, true)
	if stage4String(t, archivedData, "archived_at") == "" || stage4String(t, archivedData, "current_certificate_id") != reissuedCertificateID {
		t.Fatal("series archive did not retain the current certificate history")
	}

	stage4AssertAuthorityList(t, client, origin, sessionCookie, rootID, intermediateID)
	stage4AssertSeriesList(t, client, origin, sessionCookie, seriesID, reissuedCertificateID)
	stage4AssertCertificateList(t, client, origin, sessionCookie, seriesID, initialCertificateID, renewedCertificateID, reissuedCertificateID)
	for _, certificateID := range []string{initialCertificateID, renewedCertificateID, reissuedCertificateID} {
		certificateResponse := mustRequest(t, client, http.MethodGet, origin+"/api/v1/certificates/"+certificateID, nil, sessionCookie, nil)
		stage4ExpectStatus(t, certificateResponse, http.StatusOK)
		certificateData := stage4ResponseData(t, certificateResponse)
		stage4AssertCertificate(t, certificateData)
		stage4AssertNoSecretFields(t, certificateResponse)
		if stage4String(t, certificateData, "created_at") == "" {
			t.Fatal("certificate detail omitted its creation time")
		}
		if stage4String(t, certificateData, "series_id") != seriesID {
			t.Fatal("certificate detail lost its Leaf series lineage")
		}
	}
}

func stage4CreateAdminSession(t *testing.T, client *http.Client, origin string) (*http.Cookie, string) {
	t.Helper()
	preAuth := getPreAuthCSRF(t, client, origin)
	createAdmin := mustRequest(t, client, http.MethodPost, origin+"/api/v1/setup/admin", map[string]string{
		"login_name": "stage4-admin",
		"password":   "stage4-runtime-password-123",
	}, preAuth.cookie, map[string]string{
		"Origin":         origin,
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   preAuth.token,
	})
	stage4ExpectStatus(t, createAdmin, http.StatusCreated)
	closeResponseBody(t, createAdmin)
	loginCSRF := getPreAuthCSRF(t, client, origin)
	login := mustRequest(t, client, http.MethodPost, origin+"/api/v1/auth/login", map[string]string{
		"login_name": "stage4-admin",
		"password":   "stage4-runtime-password-123",
	}, loginCSRF.cookie, map[string]string{
		"Origin":         origin,
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   loginCSRF.token,
	})
	stage4ExpectStatus(t, login, http.StatusOK)
	var result struct {
		Data struct {
			CSRFToken string `json:"csrf_token"`
		} `json:"data"`
	}
	decodeResponse(t, login, &result)
	if result.Data.CSRFToken == "" {
		t.Fatal("administrator login omitted its session CSRF token")
	}
	return responseCookie(t, login, runtimeIntegrationSessionCookieName), result.Data.CSRFToken
}

func stage4MutationHeaders(origin, csrfToken, etag, idempotencyKey string) map[string]string {
	headers := map[string]string{
		"Origin":         origin,
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   csrfToken,
	}
	if etag != "" {
		headers["If-Match"] = etag
	}
	if idempotencyKey != "" {
		headers["Idempotency-Key"] = idempotencyKey
	}
	return headers
}

func stage4ExpectStatus(t *testing.T, response *http.Response, want int) {
	t.Helper()
	if response.StatusCode != want && response.Request != nil {
		t.Logf("failed stage4 request method=%s path=%s", response.Request.Method, response.Request.URL.Path)
	}
	if response.StatusCode != want {
		code := apiErrorCode(t, response)
		t.Fatalf("HTTP status = %d (error code %q), want %d", response.StatusCode, code, want)
	}
}

func stage4ResponseData(t *testing.T, response *http.Response) map[string]json.RawMessage {
	t.Helper()
	body := captureResponseBody(t, response)
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal("response did not contain a valid JSON envelope")
	}
	return stage4Object(t, envelope.Data)
}

func stage4Object(t *testing.T, raw json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	if len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null" || json.Unmarshal(raw, &object) != nil || object == nil {
		t.Fatal("response field was not a JSON object")
	}
	return object
}

func stage4String(t *testing.T, object map[string]json.RawMessage, key string) string {
	t.Helper()
	var value string
	if raw, ok := object[key]; !ok || json.Unmarshal(raw, &value) != nil {
		t.Fatalf("response field %q was missing or not a string", key)
	}
	return value
}

func stage4Int(t *testing.T, object map[string]json.RawMessage, key string) int64 {
	t.Helper()
	var value int64
	if raw, ok := object[key]; !ok || json.Unmarshal(raw, &value) != nil {
		t.Fatalf("response field %q was missing or not an integer", key)
	}
	return value
}

func stage4Bool(t *testing.T, object map[string]json.RawMessage, key string) bool {
	t.Helper()
	var value bool
	if raw, ok := object[key]; !ok || json.Unmarshal(raw, &value) != nil {
		t.Fatalf("response field %q was missing or not a boolean", key)
	}
	return value
}

func stage4AssertFields(t *testing.T, object map[string]json.RawMessage, allowed, required []string) {
	t.Helper()
	for _, field := range required {
		if _, ok := object[field]; !ok {
			t.Errorf("OpenAPI-required response field %q is missing", field)
		}
	}
	for field := range object {
		if !stage4Contains(allowed, field) {
			t.Errorf("response contains field %q outside the OpenAPI schema", field)
		}
	}
}

func stage4AssertAuthority(t *testing.T, object map[string]json.RawMessage, requireCRL bool) {
	t.Helper()
	stage4AssertFields(t, object,
		[]string{"id", "kind", "name", "management_parent_id", "issuance_state", "issuance_certificate_id", "key_generation_id", "key_available", "affected", "not_after", "archived_at", "crl", "version", "created_at"},
		[]string{"id", "kind", "name", "issuance_state", "key_generation_id", "key_available", "affected", "version", "created_at"})
	if _, err := time.Parse(time.RFC3339Nano, stage4String(t, object, "created_at")); err != nil {
		t.Error("authority created_at is not an RFC3339 timestamp")
	}
	if requireCRL {
		crlRaw, ok := object["crl"]
		if !ok {
			t.Fatal("authority response omitted its CRL status")
		}
		crl := stage4Object(t, crlRaw)
		stage4AssertFields(t, crl,
			[]string{"number_hex", "covered_generation", "revocation_generation", "next_publish_at", "next_update", "publication_state", "pending", "expired", "last_error_code", "version"},
			[]string{"revocation_generation", "publication_state", "pending", "expired", "version"})
	}
}

func stage4AssertDelivery(t *testing.T, object map[string]json.RawMessage) {
	t.Helper()
	stage4AssertFields(t, object,
		[]string{"id", "certificate_id", "state", "expires_at", "consumed_at", "finished_at", "failure_code", "version"},
		[]string{"id", "certificate_id", "state", "expires_at", "version"})
	if _, err := time.Parse(time.RFC3339Nano, stage4String(t, object, "expires_at")); err != nil {
		t.Error("delivery expires_at is not an RFC3339 timestamp")
	}
}

func stage4AssertSeries(t *testing.T, object map[string]json.RawMessage, requireDelivery bool) {
	t.Helper()
	stage4AssertFields(t, object,
		[]string{"id", "name", "purpose", "management_authority_id", "current_certificate_id", "current_key_generation_id", "validity", "rotate_every", "renewal_count", "prior_history_unknown", "delivery", "archived_at", "version", "created_at"},
		[]string{"id", "name", "purpose", "management_authority_id", "version", "created_at"})
	if _, err := time.Parse(time.RFC3339Nano, stage4String(t, object, "created_at")); err != nil {
		t.Error("series created_at is not an RFC3339 timestamp")
	}
	if requireDelivery {
		deliveryRaw, ok := object["delivery"]
		if !ok {
			t.Fatal("Leaf series detail omitted the current delivery state")
		}
		if string(bytes.TrimSpace(deliveryRaw)) != "null" {
			stage4AssertDelivery(t, stage4Object(t, deliveryRaw))
		}
	}
}

func stage4AssertCertificate(t *testing.T, object map[string]json.RawMessage) {
	t.Helper()
	stage4AssertFields(t, object,
		[]string{"id", "der_sha256", "key_material_id", "issuer_ca_key_generation_id", "serial_hex", "not_before", "not_after", "subject", "sans", "origin", "series_id", "revoked", "affected", "expired", "delivery", "created_at"},
		[]string{"id", "der_sha256", "key_material_id", "issuer_ca_key_generation_id", "serial_hex", "not_before", "not_after", "revoked", "affected", "expired", "created_at"})
	if _, err := time.Parse(time.RFC3339Nano, stage4String(t, object, "created_at")); err != nil {
		t.Error("certificate created_at is not an RFC3339 timestamp")
	}
	if deliveryRaw, ok := object["delivery"]; ok && string(bytes.TrimSpace(deliveryRaw)) != "null" {
		stage4AssertDelivery(t, stage4Object(t, deliveryRaw))
	}
}

func stage4AssertIssuance(t *testing.T, object map[string]json.RawMessage, requireURLs bool) {
	t.Helper()
	stage4AssertFields(t, object,
		[]string{"series_id", "certificate_id", "key_generation_id", "renewal_count", "key_rotated", "delivery", "certificate_url", "series_url"},
		[]string{"series_id", "certificate_id", "key_generation_id", "renewal_count", "key_rotated", "delivery"})
	if requireURLs {
		if stage4String(t, object, "certificate_url") == "" || stage4String(t, object, "series_url") == "" {
			t.Fatal("issuance response omitted its certificate or series URL")
		}
	}
	if deliveryRaw := object["delivery"]; len(deliveryRaw) != 0 && string(bytes.TrimSpace(deliveryRaw)) != "null" {
		stage4AssertDelivery(t, stage4Object(t, deliveryRaw))
	}
}

func stage4AssertAuthorityList(t *testing.T, client *http.Client, origin string, sessionCookie *http.Cookie, rootID, intermediateID string) {
	t.Helper()
	response := mustRequest(t, client, http.MethodGet, origin+"/api/v1/authorities?limit=50", nil, sessionCookie, nil)
	stage4ExpectStatus(t, response, http.StatusOK)
	body := captureResponseBody(t, response)
	var envelope struct {
		Data       []json.RawMessage `json:"data"`
		NextCursor *string           `json:"next_cursor"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		t.Fatal("authority list response was invalid JSON")
	}
	found := map[string]bool{}
	for _, raw := range envelope.Data {
		item := stage4Object(t, raw)
		stage4AssertAuthority(t, item, true)
		found[stage4String(t, item, "id")] = true
	}
	if !found[rootID] || !found[intermediateID] {
		t.Fatal("authority list omitted the created Root or Intermediate")
	}
	stage4AssertListEnvelope(t, body)
}

func stage4AssertSeriesList(t *testing.T, client *http.Client, origin string, sessionCookie *http.Cookie, seriesID, certificateID string) {
	t.Helper()
	response := mustRequest(t, client, http.MethodGet, origin+"/api/v1/leaf-series?limit=50", nil, sessionCookie, nil)
	stage4ExpectStatus(t, response, http.StatusOK)
	body := captureResponseBody(t, response)
	var envelope struct {
		Data []json.RawMessage `json:"data"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		t.Fatal("Leaf series list response was invalid JSON")
	}
	found := false
	for _, raw := range envelope.Data {
		item := stage4Object(t, raw)
		stage4AssertSeries(t, item, true)
		if stage4String(t, item, "id") == seriesID {
			found = stage4String(t, item, "current_certificate_id") == certificateID
		}
	}
	if !found {
		t.Fatal("Leaf series list omitted the archived series or its current certificate")
	}
	stage4AssertListEnvelope(t, body)
}

func stage4AssertCertificateList(t *testing.T, client *http.Client, origin string, sessionCookie *http.Cookie, seriesID string, certificateIDs ...string) {
	t.Helper()
	response := mustRequest(t, client, http.MethodGet, origin+"/api/v1/certificates?limit=50", nil, sessionCookie, nil)
	stage4ExpectStatus(t, response, http.StatusOK)
	body := captureResponseBody(t, response)
	var envelope struct {
		Data []json.RawMessage `json:"data"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		t.Fatal("certificate list response was invalid JSON")
	}
	found := make(map[string]bool)
	for _, raw := range envelope.Data {
		item := stage4Object(t, raw)
		stage4AssertCertificate(t, item)
		if series, ok := item["series_id"]; ok {
			var itemSeries string
			if json.Unmarshal(series, &itemSeries) == nil && itemSeries == seriesID {
				found[stage4String(t, item, "id")] = true
			}
		}
	}
	for _, certificateID := range certificateIDs {
		if !found[certificateID] {
			t.Fatalf("certificate list omitted a certificate in the requested series")
		}
	}
	stage4AssertListEnvelope(t, body)
}

func stage4AssertListEnvelope(t *testing.T, body []byte) {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal("list response was invalid JSON")
	}
	stage4AssertFields(t, fields, []string{"data", "next_cursor"}, []string{"data", "next_cursor"})
}

func stage4AssertNoSecretFields(t *testing.T, response *http.Response) {
	t.Helper()
	body := captureResponseBody(t, response)
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal("response body was invalid JSON")
	}
	if stage4ContainsSecretField(value) {
		t.Fatal("PKI API response exposed a private key, token, or secret field")
	}
}

func stage4ContainsSecretField(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
			if normalized == "token" || normalized == "token_value" || normalized == "csrf_token" || normalized == "private_key" || normalized == "private_key_pem" || normalized == "secret" || normalized == "secret_value" {
				return true
			}
			if stage4ContainsSecretField(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if stage4ContainsSecretField(child) {
				return true
			}
		}
	}
	return false
}

func stage4ConcurrentSameKeyRequests(client *http.Client, target string, body any, cookie *http.Cookie, headers map[string]string) []runtimeHTTPResult {
	start := make(chan struct{})
	ready := make(chan struct{}, 2)
	results := make(chan runtimeHTTPResult, 2)
	for range 2 {
		go func() {
			ready <- struct{}{}
			<-start
			response, err := runtimeRequest(client, http.MethodPost, target, body, cookie, headers)
			results <- runtimeHTTPResult{response: response, err: err}
		}()
	}
	for range 2 {
		<-ready
	}
	close(start)
	return []runtimeHTTPResult{<-results, <-results}
}

// stage4CompleteInitialDelivery models the documented successful handoff in
// the real runtime store. It uses the domain Consume/Complete transitions,
// persists through UoW repositories, removes the one-shot private ciphertext,
// and updates key custody as the successful delivery flow requires. No raw
// SQL or direct status-row mutation is used.
func stage4CompleteInitialDelivery(t *testing.T, app *App, rawSeriesID string) error {
	t.Helper()
	seriesID, err := domain.ParseSeriesID(rawSeriesID)
	if err != nil {
		return fmt.Errorf("parse series id: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var deliveryID domain.DeliveryID
	if err := app.store.Read(ctx, func(tx port.TxStores) error {
		snapshot, err := tx.PKI().GetSeriesForUpdate(ctx, seriesID)
		if err != nil {
			return err
		}
		delivery, err := tx.Delivery().GetDeliveryByLeafKeyGenerationForUpdate(ctx, snapshot.CurrentKeyGeneration.ID())
		if err != nil {
			return err
		}
		deliveryID = delivery.ID()
		return nil
	}); err != nil {
		return fmt.Errorf("read initial delivery: %w", err)
	}
	startedAt := domain.NewInstant(time.Now().UTC())
	if err := app.store.Write(ctx, func(tx port.TxStores) error {
		delivery, err := tx.Delivery().GetDeliveryForUpdate(ctx, deliveryID)
		if err != nil {
			return err
		}
		consumed, err := delivery.Consume(startedAt)
		if err != nil {
			return err
		}
		if err := tx.Delivery().SaveDelivery(ctx, consumed, delivery.Version()); err != nil {
			return err
		}
		if err := tx.Delivery().InvalidatePrivateGrants(ctx, delivery.ID(), startedAt); err != nil {
			return err
		}
		snapshot, err := tx.PKI().GetSeriesForUpdate(ctx, seriesID)
		if err != nil {
			return err
		}
		return tx.Secrets().Delete(ctx, snapshot.CurrentKeyGeneration.KeyMaterialID(), domain.SecretPurposeLeafDelivery)
	}); err != nil {
		return fmt.Errorf("record transfer start: %w", err)
	}
	finishedAt := domain.NewInstant(time.Now().UTC())
	return app.store.Write(ctx, func(tx port.TxStores) error {
		delivery, err := tx.Delivery().GetDeliveryForUpdate(ctx, deliveryID)
		if err != nil {
			return err
		}
		completed, err := delivery.Complete(finishedAt)
		if err != nil {
			return err
		}
		if err := tx.Delivery().SaveDelivery(ctx, completed, delivery.Version()); err != nil {
			return err
		}
		snapshot, err := tx.PKI().GetSeriesForUpdate(ctx, seriesID)
		if err != nil {
			return err
		}
		generation := snapshot.CurrentKeyGeneration
		clientHeld, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
			ID: generation.ID(), SeriesID: generation.SeriesID(), KeyMaterialID: generation.KeyMaterialID(),
			GenerationNo: generation.GenerationNo(), RenewalCount: generation.RenewalCount(),
			PriorHistoryUnknown: generation.PriorHistoryUnknown(), Custody: domain.KeyCustodyClientHeld,
		})
		if err != nil {
			return err
		}
		return tx.PKI().SaveLeafKeyGeneration(ctx, clientHeld)
	})
}

func stage4Contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
