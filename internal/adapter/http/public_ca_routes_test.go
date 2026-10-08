package httpadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

const publicCATestCertificateID = "00000000-0000-4000-8000-000000000041"

func TestPublicCARoutesServeFixedIDCertificateAndTargetInclusiveChainAnonymously(t *testing.T) {
	certificate := publicCARouteTestCertificate(t)
	rootDER := []byte("root-certificate-der")
	app := &publicCARouteTestApplication{view: contract.PublicCACertificateView{
		Certificate: certificate,
		ChainDER:    [][]byte{certificate.DER(), rootDER},
	}}
	handler := newPublicCARoutesTestHandler(app)

	certificateResponse := publicCARouteRequest(handler, "/pki/ca-certificates/"+publicCATestCertificateID+"/certificate.pem", "")
	if certificateResponse.Code != http.StatusOK {
		t.Fatalf("certificate response status = %d, want %d: %s", certificateResponse.Code, http.StatusOK, certificateResponse.Body.String())
	}
	if got := certificateResponse.Header().Get("Content-Type"); got != "application/x-pem-file" {
		t.Fatalf("certificate content type = %q, want application/x-pem-file", got)
	}
	if got := certificateResponse.Header().Get("Content-Disposition"); got != `attachment; filename="ca-certificate.pem"` {
		t.Fatalf("certificate disposition = %q, want fixed certificate filename", got)
	}
	wantCertificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.DER()})
	if !bytes.Equal(certificateResponse.Body.Bytes(), wantCertificatePEM) {
		t.Fatalf("certificate body = %q, want exact target certificate PEM %q", certificateResponse.Body.Bytes(), wantCertificatePEM)
	}
	if got, want := certificateResponse.Header().Get("ETag"), publicCADERETag(certificate.DER()); got != want {
		t.Fatalf("certificate ETag = %q, want DER SHA-256 %q", got, want)
	}
	if strings.Contains(certificateResponse.Body.String(), "PRIVATE KEY") {
		t.Fatal("public certificate response included private-key PEM")
	}
	if app.calls != 1 || app.lastQuery.CertificateID != domain.CertificateID(publicCATestCertificateID) || app.lastMeta.Principal.IsAdmin() {
		t.Fatalf("public route app calls=%d query=%#v admin=%t; want anonymous lookup by immutable certificate id", app.calls, app.lastQuery, app.lastMeta.Principal.IsAdmin())
	}

	chainResponse := publicCARouteRequest(handler, "/pki/ca-certificates/"+publicCATestCertificateID+"/chain.pem", "")
	if chainResponse.Code != http.StatusOK {
		t.Fatalf("chain response status = %d, want %d: %s", chainResponse.Code, http.StatusOK, chainResponse.Body.String())
	}
	if got := chainResponse.Header().Get("Content-Disposition"); got != `attachment; filename="chain.pem"` {
		t.Fatalf("chain disposition = %q, want fixed chain filename", got)
	}
	var wantChainPEM []byte
	for _, der := range app.view.ChainDER {
		wantChainPEM = append(wantChainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if !bytes.Equal(chainResponse.Body.Bytes(), wantChainPEM) {
		t.Fatalf("chain body = %q, want target-to-Root PEM %q", chainResponse.Body.Bytes(), wantChainPEM)
	}
	if got := chainResponse.Header().Get("ETag"); got != "" && got != publicCADERETag(wantChainPEM) {
		t.Fatalf("chain ETag = %q, want empty or a digest of the full chain representation", got)
	}
}

func TestPublicCARoutesUseIfNoneMatchForImmutableCertificate(t *testing.T) {
	certificate := publicCARouteTestCertificate(t)
	app := &publicCARouteTestApplication{view: contract.PublicCACertificateView{
		Certificate: certificate,
		ChainDER:    [][]byte{certificate.DER()},
	}}
	handler := newPublicCARoutesTestHandler(app)
	request := httptest.NewRequest(http.MethodGet, "/pki/ca-certificates/"+publicCATestCertificateID+"/certificate.pem", nil)
	request.Header.Set("If-None-Match", publicCADERETag(certificate.DER()))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotModified {
		t.Fatalf("matching If-None-Match status = %d, want %d: %s", response.Code, http.StatusNotModified, response.Body.String())
	}
	if response.Body.Len() != 0 {
		t.Fatalf("304 response body has %d bytes, want empty", response.Body.Len())
	}
}

func TestPublicCARoutesRejectMalformedIDAndKeepErrorsAsFixedJSON(t *testing.T) {
	app := &publicCARouteTestApplication{err: contract.NewAppError(contract.ErrorKindValidation, "not_found", "the certificate was not found")}
	handler := newPublicCARoutesTestHandler(app)
	badID := publicCARouteRequest(handler, "/pki/ca-certificates/not-a-uuid/certificate.pem", "")
	if badID.Code != http.StatusBadRequest {
		t.Fatalf("malformed certificate id status = %d, want %d", badID.Code, http.StatusBadRequest)
	}
	if app.calls != 0 {
		t.Fatalf("malformed certificate id reached application %d times", app.calls)
	}
	if !strings.HasPrefix(badID.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("malformed-id response content type = %q, want JSON error", badID.Header().Get("Content-Type"))
	}

	unknown := publicCARouteRequest(handler, "/pki/ca-certificates/"+publicCATestCertificateID+"/certificate.pem", "")
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown certificate status = %d, want %d", unknown.Code, http.StatusNotFound)
	}
	if !strings.HasPrefix(unknown.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("unknown-certificate response content type = %q, want JSON error", unknown.Header().Get("Content-Type"))
	}
	if strings.Contains(unknown.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("error response contains a partial public body: %s", unknown.Body.String())
	}
}

func TestPublicCARoutesDoNotLeakApplicationErrorDetailsOrPartialPEM(t *testing.T) {
	certificate := publicCARouteTestCertificate(t)
	app := &publicCARouteTestApplication{
		view: contract.PublicCACertificateView{Certificate: certificate, ChainDER: [][]byte{certificate.DER()}},
		err:  errors.New("private storage detail"),
	}
	handler := newPublicCARoutesTestHandler(app)
	response := publicCARouteRequest(handler, "/pki/ca-certificates/"+publicCATestCertificateID+"/certificate.pem", "")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("application failure status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
	if !strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("application failure content type = %q, want JSON error", response.Header().Get("Content-Type"))
	}
	if strings.Contains(response.Body.String(), "BEGIN CERTIFICATE") || strings.Contains(response.Body.String(), "private storage detail") {
		t.Fatalf("application error leaked PEM or internal detail: %s", response.Body.String())
	}
}

func newPublicCARoutesTestHandler(app PublicCAApplication) http.Handler {
	h := &setupHandler{publicCA: app}
	mux := http.NewServeMux()
	registerPublicCARoutes(mux, h)
	return mux
}

func publicCARouteRequest(handler http.Handler, target, ifNoneMatch string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	if ifNoneMatch != "" {
		request.Header.Set("If-None-Match", ifNoneMatch)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func publicCARouteTestCertificate(t *testing.T) domain.Certificate {
	t.Helper()
	id, err := domain.ParseCertificateID(publicCATestCertificateID)
	if err != nil {
		t.Fatalf("certificate id: %v", err)
	}
	keyMaterialID, err := domain.ParseKeyMaterialID("00000000-0000-4000-8000-000000000042")
	if err != nil {
		t.Fatalf("key material id: %v", err)
	}
	keyGenerationID, err := domain.ParseCAKeyGenerationID("00000000-0000-4000-8000-000000000043")
	if err != nil {
		t.Fatalf("key generation id: %v", err)
	}
	window, err := domain.NewValidityWindow(domain.NewInstant(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)), domain.NewInstant(time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatalf("certificate validity: %v", err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "Public Route Test CA"})
	if err != nil {
		t.Fatalf("certificate subject: %v", err)
	}
	serial, err := domain.ParseSerialNumber("aa41")
	if err != nil {
		t.Fatalf("certificate serial: %v", err)
	}
	certificate, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      id,
		DER:                     []byte("public-ca-certificate-der"),
		KeyMaterialID:           keyMaterialID,
		IssuerCAKeyGenerationID: keyGenerationID,
		Serial:                  serial,
		Validity:                window,
		Subject:                 subject,
		Kind:                    domain.CertificateKindCA,
		KeyAlgorithm:            domain.KeyAlgorithmECDSAP256,
		Origin:                  domain.CertificateOriginGenerated,
	})
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	return certificate
}

func publicCADERETag(der []byte) string {
	digest := sha256.Sum256(der)
	return `"` + hex.EncodeToString(digest[:]) + `"`
}

type publicCARouteTestApplication struct {
	view      contract.PublicCACertificateView
	err       error
	calls     int
	lastMeta  contract.RequestMeta
	lastQuery contract.PublicCACertificateQuery
}

func (a *publicCARouteTestApplication) ReadPublicCACertificate(_ context.Context, meta contract.RequestMeta, query contract.PublicCACertificateQuery) (contract.PublicCACertificateView, error) {
	a.calls++
	a.lastMeta = meta
	a.lastQuery = query
	if a.err != nil {
		return contract.PublicCACertificateView{}, a.err
	}
	return a.view, nil
}
