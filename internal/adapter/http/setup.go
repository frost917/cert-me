package httpadapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/secret"
)

const maxSetupJSONBytes = 1 << 20

// SetupApplication is the small application surface needed by first-run
// ingress. The adapter does not depend on the concrete service or its stores.
type SetupApplication interface {
	Status(context.Context, contract.RequestMeta, contract.EmptyCommand) (contract.SetupView, error)
	CreateAdmin(context.Context, contract.MutationMeta, contract.SetupCreateAdminCommand) (contract.AccountView, error)
	Complete(context.Context, contract.MutationMeta, contract.SetupCompleteCommand) (contract.SetupView, error)
}

// IdentityApplication is the authenticated credential and session boundary
// used by the HTTP adapter. The handler never reads account or session rows.
type IdentityApplication interface {
	Login(context.Context, contract.MutationMeta, contract.IdentityLoginCommand) (contract.LoginView, error)
	Logout(context.Context, contract.MutationMeta, contract.IdentityLogoutCommand) (contract.LogoutResult, error)
	Authenticate(context.Context, contract.RequestMeta, contract.IdentityAuthenticateCommand) (contract.AuthenticateResult, error)
	CompleteReset(context.Context, contract.MutationMeta, contract.IdentityCompleteResetCommand) (contract.CompleteResetResult, error)
	IssueCSRF(context.Context, contract.RequestMeta, contract.IdentityIssueCSRFCommand) (contract.CSRFView, error)
}

// SettingsApplication exposes only the settings use cases needed by HTTP.
type SettingsApplication interface {
	Get(context.Context, contract.RequestMeta, contract.SettingsGetCommand) (contract.SettingsView, error)
	Initialize(context.Context, contract.MutationMeta, contract.SettingsInitializeCommand) (contract.SettingsView, error)
	Update(context.Context, contract.MutationMeta, contract.SettingsUpdateCommand) (contract.SettingsView, error)
}

// SetupHandlerConfig contains only the dependencies needed by the public
// first-run routes. An empty ServiceURL means setup has not configured its
// canonical URL yet, so the security helpers require direct HTTPS authority.
type SetupHandlerConfig struct {
	Service           SetupApplication
	Identity          IdentityApplication
	Settings          SettingsApplication
	Authorities       AuthorityApplication
	PKIQueries        PKIQueryApplication
	Issuance          IssuanceApplication
	LeafQueries       LeafQueryApplication
	PublicCA          PublicCAApplication
	ServiceURL        string
	ServiceURLVersion int64
	TrustedProxies    []netip.Prefix
}

type serviceURLSnapshot struct {
	version int64
	url     string
}

type setupHandler struct {
	service        SetupApplication
	identity       IdentityApplication
	settings       SettingsApplication
	authorities    AuthorityApplication
	pkiQueries     PKIQueryApplication
	issuance       IssuanceApplication
	leafQueries    LeafQueryApplication
	publicCA       PublicCAApplication
	serviceURL     atomic.Pointer[serviceURLSnapshot]
	trustedProxies []netip.Prefix
	preAuthKey     [32]byte
}

func (h *setupHandler) currentServiceURL() string {
	value := h.serviceURL.Load()
	if value == nil {
		return ""
	}
	return value.url
}

func (h *setupHandler) setServiceURL(version int64, value string) {
	next := &serviceURLSnapshot{version: version, url: value}
	for {
		current := h.serviceURL.Load()
		if current != nil && version < current.version {
			return
		}
		if h.serviceURL.CompareAndSwap(current, next) {
			return
		}
	}
}

// NewSetupHandler creates the first-run and identity HTTP routes. Its pre-auth
// signing key is generated in memory and is intentionally lost when the
// process exits.
func NewSetupHandler(config SetupHandlerConfig) (http.Handler, error) {
	if config.Service == nil {
		return nil, fmt.Errorf("httpadapter: setup service is required")
	}
	if config.Identity == nil {
		return nil, fmt.Errorf("httpadapter: identity service is required")
	}
	if config.Settings == nil {
		return nil, fmt.Errorf("httpadapter: settings service is required")
	}

	h := &setupHandler{
		service:        config.Service,
		identity:       config.Identity,
		settings:       config.Settings,
		authorities:    config.Authorities,
		pkiQueries:     config.PKIQueries,
		issuance:       config.Issuance,
		leafQueries:    config.LeafQueries,
		publicCA:       config.PublicCA,
		trustedProxies: append([]netip.Prefix(nil), config.TrustedProxies...),
	}
	h.setServiceURL(config.ServiceURLVersion, config.ServiceURL)
	if _, err := rand.Read(h.preAuthKey[:]); err != nil {
		return nil, fmt.Errorf("httpadapter: initialize pre-auth signing key: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/setup", h.getSetup)
	mux.HandleFunc("GET /api/v1/auth/csrf", h.getCSRF)
	mux.HandleFunc("POST /api/v1/setup/admin", h.postCreateAdmin)
	mux.HandleFunc("POST /api/v1/auth/login", h.postLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", h.postLogout)
	mux.HandleFunc("GET /api/v1/auth/me", h.getSession)
	mux.HandleFunc("POST /api/v1/auth/password-reset", h.postCompleteReset)
	mux.HandleFunc("GET /api/v1/settings", h.getSettings)
	mux.HandleFunc("PATCH /api/v1/settings", h.patchSettings)
	mux.HandleFunc("POST /api/v1/setup/settings", h.postInitializeSettings)
	mux.HandleFunc("POST /api/v1/setup/complete", h.postCompleteSetup)
	registerAuthorityRoutes(mux, h)
	registerLeafRoutes(mux, h)
	registerPublicCARoutes(mux, h)
	if err := registerWebRoutes(mux, h); err != nil {
		return nil, err
	}
	return noStoreResponses(mux), nil
}

func noStoreResponses(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (h *setupHandler) getSetup(w http.ResponseWriter, r *http.Request) {
	requestID, ok := ensureRequestID(w)
	if !ok {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", "unavailable", nil)
		return
	}

	clientIP, err := ResolveClientIP(r, h.trustedProxies)
	if err != nil {
		writeSetupError(w, http.StatusBadRequest, "malformed_request", "The request is malformed.", requestID, nil)
		return
	}
	view, err := h.service.Status(r.Context(), contract.RequestMeta{
		Principal: contract.AnonymousPrincipal(),
		RequestID: requestID,
		ClientIP:  clientIP,
	}, contract.EmptyCommand{})
	if err != nil {
		writeApplicationError(w, err, requestID)
		return
	}
	if err := view.SetupStage.Validate(); err != nil {
		writeSetupError(w, http.StatusInternalServerError, "internal_error", "The request could not be processed.", requestID, nil)
		return
	}

	writeSetupJSON(w, http.StatusOK, struct {
		Data setupStatusResponse `json:"data"`
	}{Data: setupStatusResponse{SetupStage: string(view.SetupStage), BootstrapHTTPS: view.BootstrapHTTPS}})
}

type setupStatusResponse struct {
	SetupStage     string `json:"setup_stage"`
	BootstrapHTTPS bool   `json:"bootstrap_https"`
}

func (h *setupHandler) postCreateAdmin(w http.ResponseWriter, r *http.Request) {
	requestID, ok := ensureRequestID(w)
	if !ok {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", "unavailable", nil)
		return
	}
	serviceURL := h.currentServiceURL()
	if err := ValidateMutationOrigin(r, serviceURL); err != nil {
		writeSetupError(w, http.StatusForbidden, "csrf_failed", "The request could not be verified.", requestID, nil)
		return
	}
	origin, err := expectedOrigin(r, serviceURL)
	if err != nil || h.validatePreAuth(r, "https://"+origin) != nil {
		writeSetupError(w, http.StatusForbidden, "csrf_failed", "The request could not be verified.", requestID, nil)
		return
	}

	credentials, status, code, message := decodeSetupCredentials(w, r)
	if status != 0 {
		writeSetupError(w, status, code, message, requestID, nil)
		return
	}
	if credentials.Password != nil {
		defer credentials.Password.Close()
	}

	clientIP, err := ResolveClientIP(r, h.trustedProxies)
	if err != nil {
		writeSetupError(w, http.StatusBadRequest, "malformed_request", "The request is malformed.", requestID, nil)
		return
	}
	account, err := h.service.CreateAdmin(r.Context(), contract.MutationMeta{RequestMeta: contract.RequestMeta{
		Principal: contract.AnonymousPrincipal(),
		RequestID: requestID,
		ClientIP:  clientIP,
	}}, contract.SetupCreateAdminCommand{LoginName: credentials.LoginName, Password: credentials.Password})
	if err != nil {
		writeApplicationError(w, err, requestID)
		return
	}
	writeSetupJSON(w, http.StatusCreated, struct {
		Data setupAccountResponse `json:"data"`
	}{Data: setupAccountResponse{
		ID:            string(account.ID),
		LoginName:     account.LoginName,
		State:         string(account.State),
		IsGlobalAdmin: account.IsGlobalAdmin,
		Version:       account.Version.Int64(),
	}})
}

type setupAccountResponse struct {
	ID            string `json:"id"`
	LoginName     string `json:"login_name"`
	State         string `json:"state"`
	IsGlobalAdmin bool   `json:"is_global_admin"`
	Version       int64  `json:"version"`
}

func decodeSetupCredentials(w http.ResponseWriter, r *http.Request) (credentials setupCredentials, status int, code string, message string) {
	defer func() {
		if status != 0 && credentials.Password != nil {
			credentials.Password.Close()
		}
	}()
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return credentials, http.StatusBadRequest, "malformed_request", "The request is malformed."
	}
	mediaType, params, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" ||
		(params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		return credentials, http.StatusBadRequest, "malformed_request", "The request is malformed."
	}
	if r.ContentLength > maxSetupJSONBytes {
		return credentials, http.StatusRequestEntityTooLarge, "payload_too_large", "The request body is too large."
	}

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSetupJSONBytes))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		status, code, message := malformedBodyStatus(err)
		return credentials, status, code, message
	}
	seen := make(map[string]struct{}, 2)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			status, code, message := malformedBodyStatus(err)
			return credentials, status, code, message
		}
		key, ok := token.(string)
		if !ok {
			return credentials, http.StatusBadRequest, "malformed_request", "The request is malformed."
		}
		if _, duplicate := seen[key]; duplicate {
			return credentials, http.StatusBadRequest, "malformed_request", "The request is malformed."
		}
		seen[key] = struct{}{}
		if key != "login_name" && key != "password" {
			return credentials, http.StatusUnprocessableEntity, "unknown_field", "Unknown fields are not accepted."
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			status, code, message := malformedBodyStatus(err)
			return credentials, status, code, message
		}
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || trimmed[0] != '"' {
			zeroBytes(raw)
			return credentials, http.StatusBadRequest, "malformed_request", "The request is malformed."
		}
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil {
			zeroBytes(raw)
			return credentials, http.StatusBadRequest, "malformed_request", "The request is malformed."
		}
		zeroBytes(raw)
		switch key {
		case "login_name":
			credentials.LoginName = value
		case "password":
			credentials.Password = secret.FromString(value)
			value = ""
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		status, code, message := malformedBodyStatus(err)
		return credentials, status, code, message
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		zeroBytes(trailing)
		status, code, message := malformedBodyStatus(err)
		return credentials, status, code, message
	}
	return credentials, 0, "", ""
}

type setupCredentials struct {
	LoginName string
	Password  *secret.Input
}

func malformedBodyStatus(err error) (int, string, string) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return http.StatusRequestEntityTooLarge, "payload_too_large", "The request body is too large."
	}
	return http.StatusBadRequest, "malformed_request", "The request is malformed."
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

type setupErrorResponse struct {
	Error setupErrorDetail `json:"error"`
}

type setupErrorDetail struct {
	Code      string            `json:"code"`
	Message   string            `json:"message"`
	RequestID string            `json:"request_id"`
	Fields    map[string]string `json:"fields,omitempty"`
}

func writeApplicationError(w http.ResponseWriter, err error, requestID string) {
	appErr, ok := contract.AsAppError(err)
	if !ok {
		writeSetupError(w, http.StatusInternalServerError, "internal_error", "The request could not be processed.", requestID, nil)
		return
	}
	status := http.StatusInternalServerError
	fields := appErr.PublicFields()
	code := appErr.Code()
	if code == "idempotency_key_reused" {
		code = "idempotency_conflict"
	}
	switch appErr.Code() {
	case "rate_limited":
		status = http.StatusTooManyRequests
		w.Header().Set("Retry-After", retryAfterHeader(fields))
		delete(fields, "retry_after_unix_micro")
	case "settings_version_conflict", "setup_settings_version_mismatch", "authority_version_conflict", "series_version_conflict", "version_mismatch", "version_conflict":
		status = http.StatusPreconditionFailed
	case "not_found", "authority_not_found", "series_not_found", "leaf_series_not_found", "certificate_not_found", "source_certificate_not_found":
		status = http.StatusNotFound
	case "malformed_request", "idempotency_key_invalid":
		status = http.StatusBadRequest
	default:
		switch appErr.Kind() {
		case contract.ErrorKindValidation:
			status = http.StatusUnprocessableEntity
		case contract.ErrorKindAuth:
			status = http.StatusUnauthorized
		case contract.ErrorKindForbidden:
			status = http.StatusForbidden
		case contract.ErrorKindConflict:
			status = http.StatusConflict
		case contract.ErrorKindUnavailable, contract.ErrorKindCommitUnknown:
			status = http.StatusServiceUnavailable
		}
	}
	message := appErr.Detail()
	if message == "" {
		message = "The request could not be processed."
	}
	writeSetupError(w, status, code, message, requestID, fields)
}

func retryAfterHeader(fields map[string]string) string {
	seconds := int64(1)
	if raw := fields["retry_after_unix_micro"]; raw != "" {
		if untilMicros, err := strconv.ParseInt(raw, 10, 64); err == nil {
			delay := time.Until(time.UnixMicro(untilMicros))
			if delay > 0 {
				seconds = int64(delay / time.Second)
				if delay%time.Second != 0 {
					seconds++
				}
				if seconds < 1 {
					seconds = 1
				}
			}
		}
	}
	return strconv.FormatInt(seconds, 10)
}

func ensureRequestID(w http.ResponseWriter) (string, bool) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", false
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	requestID := fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
	w.Header().Set("X-Request-ID", requestID)
	return requestID, true
}

func writeSetupError(w http.ResponseWriter, status int, code, message, requestID string, fields map[string]string) {
	if fields == nil {
		fields = map[string]string{}
	}
	writeSetupJSON(w, status, setupErrorResponse{Error: setupErrorDetail{
		Code:      code,
		Message:   message,
		RequestID: requestID,
		Fields:    fields,
	}})
}

func writeSetupJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		// Response serialization for these fixed DTOs should not fail. Do not
		// append a second error body after headers have been committed.
		return
	}
}
