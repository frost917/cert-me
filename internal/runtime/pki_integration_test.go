package runtime

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/service"
	"cert-me/internal/authcrypto"
	"cert-me/internal/config"
	"cert-me/internal/cryptoengine"
	"cert-me/internal/cryptoformats"
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
	t.Log("create Root authority")
	rootResponse := mustRequest(t, client, http.MethodPost, origin+"/api/v1/authorities", rootBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, "", rootKey))
	stage4ExpectStatus(t, rootResponse, http.StatusCreated)
	rootData := stage4ResponseData(t, rootResponse)
	stage4AssertAuthority(t, rootData, true)
	rootID := stage4String(t, rootData, "id")
	if stage4String(t, rootData, "kind") != "root" || stage4String(t, rootData, "name") != "Runtime Integration Root" {
		t.Fatal("Root creation response does not describe the requested authority")
	}
	t.Log("replay Root authority creation")
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
	t.Log("create Intermediate authority")
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
	if stage4String(t, issueData, "key_generation_id") == "" || stage4Int(t, issueData, "renewal_count") != 0 || !stage4Bool(t, issueData, "key_rotated") {
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

	t.Log("verify pending-delivery renewal rejection")
	pendingRenewal := mustRequest(t, client, http.MethodPost, origin+"/api/v1/leaf-series/"+seriesID+"/renewals", map[string]string{"source_certificate_id": initialCertificateID}, sessionCookie, stage4MutationHeaders(origin, csrfToken, initialSeriesETag, "00000000-0000-4000-8000-000000000104"))
	stage4ExpectStatus(t, pendingRenewal, http.StatusConflict)
	_ = apiErrorCode(t, pendingRenewal)

	if err := stage4CompleteInitialDelivery(t, app, seriesID); err != nil {
		t.Fatalf("record initial Leaf delivery through the runtime unit of work: %v", err)
	}

	renewalKey := "00000000-0000-4000-8000-000000000105"
	renewalBody := map[string]string{"source_certificate_id": initialCertificateID}
	renewalPath := "/api/v1/leaf-series/" + seriesID + "/renewals"
	t.Logf("renew after completed initial delivery: POST %s", renewalPath)
	renewalResponse := mustRequest(t, client, http.MethodPost, origin+renewalPath, renewalBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, initialSeriesETag, renewalKey))
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
	t.Logf("replay renewal with the original If-Match: POST %s", renewalPath)
	renewalReplay := mustRequest(t, client, http.MethodPost, origin+renewalPath, renewalBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, initialSeriesETag, renewalKey))
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

	reissuePath := "/api/v1/leaf-series/" + seriesID + "/reissues"
	reissueTarget := origin + reissuePath
	t.Logf("race concurrent same-key Reissue requests: POST %s", reissuePath)
	reissueBody := map[string]string{"source_certificate_id": renewedCertificateID, "reason": "manual_rotation"}
	reissueKey := "00000000-0000-4000-8000-000000000106"
	reissueResponses := stage4ConcurrentSameKeyRequests(client, reissueTarget, reissueBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, renewedSeriesETag, reissueKey))
	var reissueData map[string]json.RawMessage
	var reissueStatus201, reissueStatus200 int
	for _, result := range reissueResponses {
		if result.err != nil {
			t.Fatalf("concurrent Reissue transport failed: %v", result.err)
		}
		switch result.response.StatusCode {
		case http.StatusCreated:
			reissueStatus201++
		case http.StatusOK:
			reissueStatus200++
		default:
			method, path := http.MethodPost, reissuePath
			if result.response.Request != nil {
				method = result.response.Request.Method
				path = result.response.Request.URL.Path
			}
			code := apiErrorCode(t, result.response)
			t.Fatalf("concurrent Reissue request %s %s returned HTTP %d (error code %q), want 201 or 200", method, path, result.response.StatusCode, code)
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

	stage4ExerciseTransferReissueBoundary(t, app, client, origin, sessionCookie, csrfToken, intermediateID)
	stage4ExercisePublicCAAndAuthorityClosure(t, client, origin, sessionCookie, csrfToken, rootID, intermediateID, initialCertificateID)
}

func stage4ExercisePublicCAAndAuthorityClosure(t *testing.T, client *http.Client, origin string, sessionCookie *http.Cookie, csrfToken, rootID, intermediateID, leafCertificateID string) {
	t.Helper()

	rootResponse := mustRequest(t, client, http.MethodGet, origin+"/api/v1/authorities/"+rootID, nil, sessionCookie, nil)
	stage4ExpectStatus(t, rootResponse, http.StatusOK)
	rootAuthority := stage4ResponseData(t, rootResponse)
	stage4AssertAuthority(t, rootAuthority, true)
	rootCertificateID := stage4String(t, rootAuthority, "issuance_certificate_id")

	intermediateResponse := mustRequest(t, client, http.MethodGet, origin+"/api/v1/authorities/"+intermediateID, nil, sessionCookie, nil)
	stage4ExpectStatus(t, intermediateResponse, http.StatusOK)
	intermediateAuthority := stage4ResponseData(t, intermediateResponse)
	stage4AssertAuthority(t, intermediateAuthority, true)
	intermediateCertificateID := stage4String(t, intermediateAuthority, "issuance_certificate_id")
	intermediateKeyGenerationID := stage4String(t, intermediateAuthority, "key_generation_id")

	rootCertDER, rootChainDER, rootCertETag, rootChainETag := stage4ReadPublicCACertificateAndChain(t, client, origin, rootCertificateID)
	intermediateCertDER, intermediateChainDER, intermediateCertETag, intermediateChainETag := stage4ReadPublicCACertificateAndChain(t, client, origin, intermediateCertificateID)
	if len(rootChainDER) != 1 || !bytes.Equal(rootChainDER[0], rootCertDER) {
		t.Fatal("public Root chain did not contain only the Root certificate")
	}
	if len(intermediateChainDER) != 2 || !bytes.Equal(intermediateChainDER[0], intermediateCertDER) || !bytes.Equal(intermediateChainDER[1], rootCertDER) {
		t.Fatal("public Intermediate chain was not ordered Intermediate then Root")
	}
	intermediateCertificate, err := x509.ParseCertificate(intermediateCertDER)
	if err != nil {
		t.Fatal("parse public Intermediate certificate")
	}
	rootCertificate, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		t.Fatal("parse public Root certificate")
	}
	if err := intermediateCertificate.CheckSignatureFrom(rootCertificate); err != nil {
		t.Fatal("public Intermediate certificate was not signed by the public Root")
	}
	stage4AssertPublicCANotModified(t, client, origin, rootCertificateID, "certificate.pem", rootCertETag)
	stage4AssertPublicCANotModified(t, client, origin, rootCertificateID, "chain.pem", rootChainETag)
	stage4AssertPublicCANotModified(t, client, origin, intermediateCertificateID, "certificate.pem", intermediateCertETag)
	stage4AssertPublicCANotModified(t, client, origin, intermediateCertificateID, "chain.pem", intermediateChainETag)
	for _, filename := range []string{"certificate.pem", "chain.pem"} {
		leafResponse := mustRequest(t, client, http.MethodGet, origin+"/pki/ca-certificates/"+leafCertificateID+"/"+filename, nil, nil, nil)
		stage4ExpectStatus(t, leafResponse, http.StatusNotFound)
		closeResponseBody(t, leafResponse)
	}

	renamed := "Runtime Integration Intermediate Renamed"
	renameResponse := mustRequest(t, client, http.MethodPatch, origin+"/api/v1/authorities/"+intermediateID, map[string]string{"name": renamed}, sessionCookie, stage4MutationHeaders(origin, csrfToken, intermediateResponse.Header.Get("ETag"), ""))
	stage4ExpectStatus(t, renameResponse, http.StatusOK)
	renameData := stage4ResponseData(t, renameResponse)
	stage4AssertAuthority(t, renameData, true)
	if stage4String(t, renameData, "name") != renamed {
		t.Fatal("Intermediate rename response did not persist the requested name")
	}
	renamedAuthority := mustRequest(t, client, http.MethodGet, origin+"/api/v1/authorities/"+intermediateID, nil, sessionCookie, nil)
	stage4ExpectStatus(t, renamedAuthority, http.StatusOK)
	renamedData := stage4ResponseData(t, renamedAuthority)
	stage4AssertAuthority(t, renamedData, true)
	if stage4String(t, renamedData, "name") != renamed {
		t.Fatal("Intermediate rename was not persisted by the SQL repository")
	}
	renamedCertDER, renamedChainDER, _, _ := stage4ReadPublicCACertificateAndChain(t, client, origin, intermediateCertificateID)
	if !bytes.Equal(renamedCertDER, intermediateCertDER) || !stage4EqualCertificateChains(renamedChainDER, intermediateChainDER) {
		t.Fatal("renaming an Intermediate changed its immutable public certificate or chain")
	}

	stopResponse := mustRequest(t, client, http.MethodPost, origin+"/api/v1/authorities/"+intermediateID+"/issuance-state", map[string]string{"state": string(domain.IssuanceStateStopped)}, sessionCookie, stage4MutationHeaders(origin, csrfToken, renamedAuthority.Header.Get("ETag"), ""))
	stage4ExpectStatus(t, stopResponse, http.StatusOK)
	stopData := stage4ResponseData(t, stopResponse)
	stage4AssertAuthority(t, stopData, true)
	if stage4String(t, stopData, "issuance_state") != string(domain.IssuanceStateStopped) {
		t.Fatal("Intermediate issuance was not explicitly stopped")
	}
	stopETag := stopResponse.Header.Get("ETag")
	stoppedIssue := mustRequest(t, client, http.MethodPost, origin+"/api/v1/leaf-series", map[string]any{
		"name": "stopped-issuer.internal", "authority_id": intermediateID,
		"profile": "server_tls", "key_algorithm": "ecdsa_p256",
		"subject": map[string]string{"common_name": "stopped-issuer.internal"},
		"sans":    []map[string]string{{"type": "dns", "value": "stopped-issuer.internal"}},
	}, sessionCookie, stage4MutationHeaders(origin, csrfToken, "", "00000000-0000-4000-8000-000000000109"))
	stage4ExpectStatus(t, stoppedIssue, http.StatusConflict)
	if code := apiErrorCode(t, stoppedIssue); code != "issuer_stopped" {
		t.Fatalf("stopped issuer code = %q, want issuer_stopped", code)
	}
	if stopETag == "" {
		t.Fatal("stopping Intermediate issuance omitted the new authority ETag")
	}

	destroyResponse := mustRequest(t, client, http.MethodPost, origin+"/api/v1/authorities/"+intermediateID+"/key-destruction", map[string]string{
		"key_generation_id": intermediateKeyGenerationID,
		"justification":     "stage4 live-leaf closure guard",
	}, sessionCookie, stage4MutationHeaders(origin, csrfToken, stopETag, ""))
	destroyStatus, destroyCode := stage4StatusAndErrorCode(t, destroyResponse)
	stage4AssertAuthorityUnchangedAfterClosureRejection(t, client, origin, sessionCookie, intermediateID, stopETag, renamed, intermediateKeyGenerationID)

	archiveResponse := mustRequest(t, client, http.MethodPost, origin+"/api/v1/authorities/"+intermediateID+"/archive", map[string]any{}, sessionCookie, stage4MutationHeaders(origin, csrfToken, stopETag, ""))
	archiveStatus, archiveCode := stage4StatusAndErrorCode(t, archiveResponse)
	stage4AssertAuthorityUnchangedAfterClosureRejection(t, client, origin, sessionCookie, intermediateID, stopETag, renamed, intermediateKeyGenerationID)
	if destroyStatus != http.StatusConflict || archiveStatus != http.StatusConflict {
		t.Fatalf("live Leaf descendants should block Intermediate destruction/archive with HTTP 409; got destruction %d (%q), archive %d (%q)", destroyStatus, destroyCode, archiveStatus, archiveCode)
	}
}

func stage4ReadPublicCACertificateAndChain(t *testing.T, client *http.Client, origin, certificateID string) ([]byte, [][]byte, string, string) {
	t.Helper()
	basePath := origin + "/pki/ca-certificates/" + certificateID
	certificateResponse := mustRequest(t, client, http.MethodGet, basePath+"/certificate.pem", nil, nil, nil)
	stage4ExpectStatus(t, certificateResponse, http.StatusOK)
	certificateETag := certificateResponse.Header.Get("ETag")
	certificateDER := stage4ParseCertificatePEM(t, captureResponseBody(t, certificateResponse))
	if certificateETag == "" {
		t.Fatal("public CA certificate response omitted its ETag")
	}
	chainResponse := mustRequest(t, client, http.MethodGet, basePath+"/chain.pem", nil, nil, nil)
	stage4ExpectStatus(t, chainResponse, http.StatusOK)
	chainETag := chainResponse.Header.Get("ETag")
	chainDER := stage4ParseCertificateChainPEM(t, captureResponseBody(t, chainResponse))
	if chainETag == "" {
		t.Fatal("public CA chain response omitted its ETag")
	}
	return certificateDER, chainDER, certificateETag, chainETag
}

func stage4ParseCertificatePEM(t *testing.T, body []byte) []byte {
	t.Helper()
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("public CA certificate response was not one PEM certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatal("public CA certificate response contained invalid DER")
	}
	return append([]byte(nil), block.Bytes...)
}

func stage4ParseCertificateChainPEM(t *testing.T, body []byte) [][]byte {
	t.Helper()
	var certificates [][]byte
	for len(bytes.TrimSpace(body)) > 0 {
		block, rest := pem.Decode(body)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatal("public CA chain response contained an invalid PEM block")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			t.Fatal("public CA chain response contained invalid DER")
		}
		certificates = append(certificates, append([]byte(nil), block.Bytes...))
		body = rest
	}
	if len(certificates) == 0 {
		t.Fatal("public CA chain response contained no certificates")
	}
	return certificates
}

func stage4AssertPublicCANotModified(t *testing.T, client *http.Client, origin, certificateID, filename, etag string) {
	t.Helper()
	response := mustRequest(t, client, http.MethodGet, origin+"/pki/ca-certificates/"+certificateID+"/"+filename, nil, nil, map[string]string{"If-None-Match": etag})
	if response.StatusCode != http.StatusNotModified {
		stage4ExpectStatus(t, response, http.StatusNotModified)
	}
	if got := captureResponseBody(t, response); len(got) != 0 {
		t.Fatal("conditional public CA response included a body")
	}
	if response.Header.Get("ETag") != etag {
		t.Fatal("conditional public CA response changed its ETag")
	}
}

func stage4EqualCertificateChains(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

func stage4StatusAndErrorCode(t *testing.T, response *http.Response) (int, string) {
	t.Helper()
	if response.StatusCode >= http.StatusBadRequest {
		return response.StatusCode, apiErrorCode(t, response)
	}
	closeResponseBody(t, response)
	return response.StatusCode, ""
}

func stage4AssertAuthorityUnchangedAfterClosureRejection(t *testing.T, client *http.Client, origin string, sessionCookie *http.Cookie, authorityID, expectedETag, expectedName, expectedKeyGenerationID string) {
	t.Helper()
	response := mustRequest(t, client, http.MethodGet, origin+"/api/v1/authorities/"+authorityID, nil, sessionCookie, nil)
	stage4ExpectStatus(t, response, http.StatusOK)
	data := stage4ResponseData(t, response)
	stage4AssertAuthority(t, data, true)
	if response.Header.Get("ETag") != expectedETag ||
		stage4String(t, data, "name") != expectedName ||
		stage4String(t, data, "key_generation_id") != expectedKeyGenerationID ||
		stage4String(t, data, "issuance_state") != string(domain.IssuanceStateStopped) ||
		!stage4Bool(t, data, "key_available") {
		t.Fatal("rejected authority closure operation mutated the Intermediate")
	}
	if _, archived := data["archived_at"]; archived {
		t.Fatal("rejected authority closure operation archived the Intermediate")
	}
}

func stage4ExerciseTransferReissueBoundary(t *testing.T, app *App, client *http.Client, origin string, sessionCookie *http.Cookie, csrfToken, authorityID string) {
	t.Helper()

	issueBody := map[string]any{
		"name":          "runtime-transfer-race.internal",
		"authority_id":  authorityID,
		"profile":       "server_tls",
		"subject":       map[string]string{"common_name": "runtime-transfer-race.internal"},
		"sans":          []map[string]string{{"type": "dns", "value": "runtime-transfer-race.internal"}},
		"key_algorithm": "ecdsa_p256",
		"validity":      map[string]any{"value": 1, "unit": "years"},
		"rotate_every":  3,
	}
	issueResponse := mustRequest(t, client, http.MethodPost, origin+"/api/v1/leaf-series", issueBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, "", "00000000-0000-4000-8000-000000000107"))
	stage4ExpectStatus(t, issueResponse, http.StatusCreated)
	issueData := stage4ResponseData(t, issueResponse)
	stage4AssertIssuance(t, issueData, true)
	seriesID := stage4String(t, issueData, "series_id")
	certificateID := stage4String(t, issueData, "certificate_id")
	deliveryView := stage4Object(t, issueData["delivery"])
	deliveryID := stage4String(t, deliveryView, "id")
	if stage4String(t, deliveryView, "state") != string(domain.DeliveryStatePending) {
		t.Fatal("fresh Leaf issuance did not have a pending private-key delivery")
	}

	seriesResponse := mustRequest(t, client, http.MethodGet, origin+"/api/v1/leaf-series/"+seriesID, nil, sessionCookie, nil)
	stage4ExpectStatus(t, seriesResponse, http.StatusOK)
	seriesData := stage4ResponseData(t, seriesResponse)
	stage4AssertSeries(t, seriesData, true)
	seriesETag := seriesResponse.Header.Get("ETag")
	if seriesETag == "" || stage4String(t, seriesData, "current_certificate_id") != certificateID {
		t.Fatal("fresh Leaf series detail omitted its version or current certificate")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rawToken, tokenHash, err := (authcrypto.TokenCodec{}).NewToken(ctx)
	if err != nil {
		t.Fatal("create one-time private transfer token")
	}
	t.Cleanup(func() { _ = rawToken.Close() })
	seriesIDValue, err := domain.ParseSeriesID(seriesID)
	if err != nil {
		t.Fatal("parse transfer-race series identifier")
	}
	certificateIDValue, err := domain.ParseCertificateID(certificateID)
	if err != nil {
		t.Fatal("parse transfer-race certificate identifier")
	}
	deliveryIDValue, err := domain.ParseDeliveryID(deliveryID)
	if err != nil {
		t.Fatal("parse transfer-race delivery identifier")
	}
	var createdBy domain.AccountID
	if err := app.store.Read(ctx, func(tx port.TxStores) error {
		account, err := tx.Accounts().FindAccountByLoginName(ctx, domain.NormalizeLoginName("stage4-admin"))
		if err != nil {
			return err
		}
		createdBy = account.ID()
		return nil
	}); err != nil {
		t.Fatal("load administrator for typed private-grant fixture")
	}
	grantIDText, err := newUUID()
	if err != nil {
		t.Fatal("create private-grant identifier")
	}
	grantID, err := domain.ParseGrantID(grantIDText)
	if err != nil {
		t.Fatal("parse private-grant identifier")
	}
	grant, err := domain.NewDownloadGrant(domain.DownloadGrantFacts{
		ID:            grantID,
		TokenHash:     tokenHash,
		Purpose:       domain.GrantPurposeLeafPrivate,
		CertificateID: certificateIDValue,
		DeliveryID:    deliveryIDValue,
		CreatedBy:     createdBy,
		ExpiresAt:     domain.NewInstant(time.Now().UTC().Add(5 * time.Minute)),
		Version:       1,
	})
	if err != nil {
		t.Fatal("construct typed private download grant")
	}
	if err := app.store.Write(ctx, func(tx port.TxStores) error {
		return tx.Delivery().InsertGrant(ctx, grant)
	}); err != nil {
		t.Fatal("seed private download grant through runtime unit of work")
	}

	deliveryEncoder, err := cryptoengine.NewDeliveryEncoder(app.ring)
	if err != nil {
		t.Fatal("construct real delivery encoder")
	}
	distribution, err := service.NewDistributionService(service.DistributionDeps{
		CommonDeps: service.CommonDeps{
			UnitOfWork: app.store,
			ReadStore:  app.store,
			Authorizer: adminAuthorizer{},
			Clock:      systemClock{},
			IDs:        randomIDs{},
		},
		TokenCodec:               authcrypto.TokenCodec{},
		DeliveryEncoder:          deliveryEncoder,
		PublicCertificateEncoder: cryptoformats.NewPublicCertificateEncoder(),
		OperationalLogger:        operationalLogger{logger: app.logger},
		RuntimeGate:              app.gate,
	})
	if err != nil {
		t.Fatal("construct real DistributionService")
	}

	sink := &stage4BlockingDownloadSink{entered: make(chan int64, 1), release: make(chan struct{})}
	results := make(chan stage4DeliveryResult, 1)
	resultObserved := false
	t.Cleanup(func() {
		sink.releaseSend()
		if resultObserved {
			return
		}
		select {
		case <-results:
		case <-time.After(10 * time.Second):
			t.Error("private transfer did not finish during cleanup")
		}
	})
	go func() {
		summary, err := distribution.Deliver(ctx, contract.RequestMeta{
			Principal: contract.AnonymousPrincipal(),
			RequestID: "stage4-transfer-reissue-race",
		}, contract.DownloadCommand{RawToken: rawToken, Format: contract.DownloadFormatPEM}, sink)
		results <- stage4DeliveryResult{summary: summary, err: err}
	}()

	var payloadBytes int64
	select {
	case payloadBytes = <-sink.entered:
	case result := <-results:
		resultObserved = true
		if appErr, ok := contract.AsAppError(result.err); ok {
			t.Fatalf("private transfer failed before Send with code %q", appErr.Code())
		}
		t.Fatal("private transfer exited before Send")
	case <-ctx.Done():
		cancel()
		t.Fatal("private transfer did not reach the blocking Send")
	}
	if payloadBytes <= 0 {
		t.Fatal("real private delivery payload was empty")
	}

	reissuePath := origin + "/api/v1/leaf-series/" + seriesID + "/reissues"
	reissueBody := map[string]string{"source_certificate_id": certificateID, "reason": "manual_rotation"}
	reissueKey := "00000000-0000-4000-8000-000000000108"
	t.Log("verify reissue is rejected while the private payload is in Send")
	blockedReissue := mustRequest(t, client, http.MethodPost, reissuePath, reissueBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, seriesETag, reissueKey))
	stage4ExpectStatus(t, blockedReissue, http.StatusConflict)
	closeResponseBody(t, blockedReissue)
	if !app.gate.IsAccepting() {
		t.Fatal("a normal in-flight transfer unexpectedly closed runtime admission")
	}

	transferringResponse := mustRequest(t, client, http.MethodGet, origin+"/api/v1/leaf-series/"+seriesID, nil, sessionCookie, nil)
	stage4ExpectStatus(t, transferringResponse, http.StatusOK)
	transferringData := stage4ResponseData(t, transferringResponse)
	stage4AssertSeries(t, transferringData, true)
	if transferringResponse.Header.Get("ETag") != seriesETag ||
		stage4String(t, transferringData, "current_certificate_id") != certificateID ||
		stage4String(t, transferringData, "current_key_generation_id") != stage4String(t, seriesData, "current_key_generation_id") {
		t.Fatal("rejected reissue mutated the Leaf series while delivery was transferring")
	}
	transferringDelivery := stage4Object(t, transferringData["delivery"])
	if stage4String(t, transferringDelivery, "state") != string(domain.DeliveryStateTransferring) {
		t.Fatal("in-flight private delivery did not remain transferring")
	}

	sink.releaseSend()
	var deliveryResult stage4DeliveryResult
	select {
	case deliveryResult = <-results:
		resultObserved = true
	case <-ctx.Done():
		t.Fatal("private transfer did not complete after Send was released")
	}
	if deliveryResult.err != nil {
		if appErr, ok := contract.AsAppError(deliveryResult.err); ok {
			t.Fatalf("private transfer failed after Send with code %q", appErr.Code())
		}
		t.Fatal("private transfer failed after Send")
	}
	if !deliveryResult.summary.Completed || deliveryResult.summary.BytesWritten != payloadBytes || deliveryResult.summary.DeliveryID != deliveryIDValue {
		t.Fatal("private transfer summary did not report the completed payload and delivery")
	}
	if !app.gate.IsAccepting() {
		t.Fatal("successful private transfer closed runtime admission")
	}

	var finalDelivery domain.Delivery
	var finalCustody domain.KeyCustody
	if err := app.store.Read(ctx, func(tx port.TxStores) error {
		snapshot, err := tx.PKI().GetSeriesForUpdate(ctx, seriesIDValue)
		if err != nil {
			return err
		}
		finalCustody = snapshot.CurrentKeyGeneration.Custody()
		finalDelivery, err = tx.Delivery().GetDeliveryForUpdate(ctx, deliveryIDValue)
		return err
	}); err != nil {
		t.Fatal("read completed transfer state through runtime unit of work")
	}
	if finalDelivery.State() != domain.DeliveryStateServerCompleted || finalCustody != domain.KeyCustodyClientHeld {
		t.Fatal("successful transfer did not record server completion and client-held key custody")
	}

	completedResponse := mustRequest(t, client, http.MethodGet, origin+"/api/v1/leaf-series/"+seriesID, nil, sessionCookie, nil)
	stage4ExpectStatus(t, completedResponse, http.StatusOK)
	completedData := stage4ResponseData(t, completedResponse)
	completedDelivery := stage4Object(t, completedData["delivery"])
	if stage4String(t, completedDelivery, "state") != string(domain.DeliveryStateServerCompleted) {
		t.Fatal("Leaf series API did not expose the completed private delivery")
	}

	t.Log("retry manual reissue after server-observed transfer completion")
	retryReissue := mustRequest(t, client, http.MethodPost, reissuePath, reissueBody, sessionCookie, stage4MutationHeaders(origin, csrfToken, seriesETag, reissueKey))
	stage4ExpectStatus(t, retryReissue, http.StatusCreated)
	retryData := stage4ResponseData(t, retryReissue)
	stage4AssertIssuance(t, retryData, true)
	if stage4String(t, retryData, "certificate_id") == certificateID || !stage4Bool(t, retryData, "key_rotated") {
		t.Fatal("reissue retry after completed transfer did not create a fresh certificate and key")
	}
}

type stage4DeliveryResult struct {
	summary contract.TransferSummary
	err     error
}

type stage4BlockingDownloadSink struct {
	entered chan int64
	release chan struct{}
	once    sync.Once
}

func (s *stage4BlockingDownloadSink) Send(ctx context.Context, _ port.FileDescriptor, payload io.Reader) (port.TransferOutcome, error) {
	bytesWritten, err := io.Copy(io.Discard, payload)
	if err != nil {
		return port.TransferOutcome{}, err
	}
	s.entered <- bytesWritten
	select {
	case <-s.release:
		return port.TransferOutcome{BytesWritten: bytesWritten, FinishedAt: domain.NewInstant(time.Now().UTC()), Completed: true}, nil
	case <-ctx.Done():
		return port.TransferOutcome{}, ctx.Err()
	}
}

func (s *stage4BlockingDownloadSink) releaseSend() {
	s.once.Do(func() { close(s.release) })
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
		snapshot, err := tx.PKI().GetSeriesForUpdate(ctx, seriesID)
		if err != nil {
			return err
		}
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
		return tx.Secrets().Delete(ctx, snapshot.CurrentKeyGeneration.KeyMaterialID(), domain.SecretPurposeLeafDelivery)
	}); err != nil {
		return fmt.Errorf("record transfer start: %w", err)
	}
	finishedAt := domain.NewInstant(time.Now().UTC())
	return app.store.Write(ctx, func(tx port.TxStores) error {
		snapshot, err := tx.PKI().GetSeriesForUpdate(ctx, seriesID)
		if err != nil {
			return err
		}
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
		return tx.PKI().MarkLeafKeyGenerationClientHeld(ctx, snapshot.CurrentKeyGeneration.ID())
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
