package httpadapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/secret"
)

const sessionCookieName = "__Host-certme_session"

func (h *setupHandler) getCSRF(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.requestMeta(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	if len(query) > 1 || (len(query) == 1 && len(query["mode"]) != 1) {
		writeSetupError(w, http.StatusBadRequest, "malformed_request", "The request is malformed.", meta.RequestID, nil)
		return
	}
	_, modePresent := query["mode"]
	mode := query.Get("mode")
	if modePresent && mode != "preauth" && mode != "session" {
		writeSetupError(w, http.StatusUnprocessableEntity, "invalid_mode", "The requested CSRF mode is not supported.", meta.RequestID, nil)
		return
	}
	if err := ValidateCSRFReadOrigin(r, h.currentServiceURL()); err != nil {
		writeSetupError(w, http.StatusForbidden, "csrf_failed", "The request could not be verified.", meta.RequestID, nil)
		return
	}
	if mode == "preauth" {
		h.getPreAuthCSRF(w, r)
		return
	}

	_, found, err := sessionCookie(r)
	if err != nil {
		writeSetupError(w, http.StatusForbidden, "csrf_failed", "The request could not be verified.", meta.RequestID, nil)
		return
	}
	if mode == "session" && !found {
		writeSetupError(w, http.StatusUnauthorized, "authentication_required", "A valid session is required.", meta.RequestID, nil)
		return
	}
	if found {
		result, authErr := h.authenticate(r, meta, nil)
		if authErr == nil {
			csrf, issueErr := h.identity.IssueCSRF(r.Context(), withPrincipal(meta, result.Principal), contract.IdentityIssueCSRFCommand{})
			if issueErr != nil {
				writeApplicationError(w, issueErr, meta.RequestID)
				return
			}
			defer csrf.CSRFToken.Close()
			if err := writeCSRFSecret(w, csrf.CSRFToken); err != nil {
				writeSetupError(w, http.StatusInternalServerError, "internal_error", "The request could not be processed.", meta.RequestID, nil)
			}
			return
		}
		if !isAuthenticationError(authErr) {
			writeApplicationError(w, authErr, meta.RequestID)
			return
		}
		clearSessionCookie(w)
		if mode == "session" {
			writeApplicationError(w, authErr, meta.RequestID)
			return
		}
	}
	h.getPreAuthCSRF(w, r)
}

func (h *setupHandler) postLogin(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.requestMeta(w, r)
	if !ok {
		return
	}
	if !h.validatePreAuthMutation(w, r, meta.RequestID) {
		return
	}
	credentials, status, code, message := decodeSetupCredentials(w, r)
	if status != 0 {
		writeSetupError(w, status, code, message, meta.RequestID, nil)
		return
	}
	defer credentials.Password.Close()
	login, err := h.identity.Login(r.Context(), contract.MutationMeta{RequestMeta: meta}, contract.IdentityLoginCommand{
		LoginName: credentials.LoginName,
		Password:  credentials.Password,
	})
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	defer login.SessionToken.Close()
	defer login.CSRFToken.Close()
	clearPreAuthCookie(w)
	if err := writeLoginResponse(w, login); err != nil {
		// Secret callbacks can fail only if their owner was closed unexpectedly;
		// no error detail or secret material is written to the response.
		writeSetupError(w, http.StatusInternalServerError, "internal_error", "The request could not be processed.", meta.RequestID, nil)
	}
}

func (h *setupHandler) postLogout(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.requestMeta(w, r)
	if !ok {
		return
	}
	authenticated, ok := h.authenticatedMutation(w, r, meta)
	if !ok {
		return
	}
	if _, err := h.identity.Logout(r.Context(), contract.MutationMeta{RequestMeta: authenticated.RequestMeta}, contract.IdentityLogoutCommand{}); err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *setupHandler) getSession(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.requestMeta(w, r)
	if !ok {
		return
	}
	result, err := h.authenticate(r, meta, nil)
	if err != nil {
		if isAuthenticationError(err) {
			clearSessionCookie(w)
		}
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	w.Header().Set("ETag", entityTag(result.Session.Account.Version.Int64()))
	writeSetupJSON(w, http.StatusOK, struct {
		Data sessionResponse `json:"data"`
	}{Data: toSessionResponse(result.Session)})
}

func (h *setupHandler) postCompleteReset(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.requestMeta(w, r)
	if !ok {
		return
	}
	if !h.validatePreAuthMutation(w, r, meta.RequestID) {
		return
	}
	fields, status, code, message := decodeJSONObject(w, r, []string{"reset_token", "new_password"})
	if status != 0 {
		writeSetupError(w, status, code, message, meta.RequestID, nil)
		return
	}
	defer clearJSONFields(fields)
	resetToken, ok := decodeSecretField(fields, "reset_token")
	if !ok {
		writeSetupError(w, http.StatusBadRequest, "malformed_request", "The request is malformed.", meta.RequestID, nil)
		return
	}
	defer resetToken.Close()
	newPassword, ok := decodeSecretField(fields, "new_password")
	if !ok {
		writeSetupError(w, http.StatusBadRequest, "malformed_request", "The request is malformed.", meta.RequestID, nil)
		return
	}
	defer newPassword.Close()
	command := contract.IdentityCompleteResetCommand{ResetToken: resetToken, NewPassword: newPassword}
	if _, err := h.identity.CompleteReset(r.Context(), contract.MutationMeta{RequestMeta: meta}, command); err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	clearSessionCookie(w)
	clearPreAuthCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *setupHandler) requestMeta(w http.ResponseWriter, r *http.Request) (contract.RequestMeta, bool) {
	requestID, ok := ensureRequestID(w)
	if !ok {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", "unavailable", nil)
		return contract.RequestMeta{}, false
	}
	clientIP, err := ResolveClientIP(r, h.trustedProxies)
	if err != nil {
		writeSetupError(w, http.StatusBadRequest, "malformed_request", "The request is malformed.", requestID, nil)
		return contract.RequestMeta{}, false
	}
	return contract.RequestMeta{Principal: contract.AnonymousPrincipal(), RequestID: requestID, ClientIP: clientIP}, true
}

func (h *setupHandler) authenticate(r *http.Request, meta contract.RequestMeta, csrfToken *secret.Input) (contract.AuthenticateResult, error) {
	cookie, found, err := sessionCookie(r)
	if err != nil {
		return contract.AuthenticateResult{}, contract.NewAppError(contract.ErrorKindAuth, "authentication_required", "a valid session is required")
	}
	if !found {
		return contract.AuthenticateResult{}, contract.NewAppError(contract.ErrorKindAuth, "authentication_required", "a valid session is required")
	}
	token := secret.FromString(cookie)
	defer token.Close()
	return h.identity.Authenticate(r.Context(), meta, contract.IdentityAuthenticateCommand{SessionToken: token, CSRFToken: csrfToken})
}

func (h *setupHandler) authenticatedMutation(w http.ResponseWriter, r *http.Request, meta contract.RequestMeta) (contract.MutationMeta, bool) {
	if err := ValidateMutationOrigin(r, h.currentServiceURL()); err != nil {
		writeSetupError(w, http.StatusForbidden, "csrf_failed", "The request could not be verified.", meta.RequestID, nil)
		return contract.MutationMeta{}, false
	}
	values := r.Header.Values("X-CSRF-Token")
	if len(values) != 1 || len(values[0]) < 32 || len(values[0]) > 256 {
		writeSetupError(w, http.StatusForbidden, "csrf_failed", "The request could not be verified.", meta.RequestID, nil)
		return contract.MutationMeta{}, false
	}
	csrf := secret.FromString(values[0])
	defer csrf.Close()
	result, err := h.authenticate(r, meta, csrf)
	if err != nil {
		if isAuthenticationError(err) {
			clearSessionCookie(w)
		}
		writeApplicationError(w, err, meta.RequestID)
		return contract.MutationMeta{}, false
	}
	return contract.MutationMeta{RequestMeta: withPrincipal(meta, result.Principal)}, true
}

func (h *setupHandler) validatePreAuthMutation(w http.ResponseWriter, r *http.Request, requestID string) bool {
	serviceURL := h.currentServiceURL()
	if err := ValidateMutationOrigin(r, serviceURL); err != nil {
		writeSetupError(w, http.StatusForbidden, "csrf_failed", "The request could not be verified.", requestID, nil)
		return false
	}
	origin, err := expectedOrigin(r, serviceURL)
	if err != nil || h.validatePreAuth(r, "https://"+origin) != nil {
		writeSetupError(w, http.StatusForbidden, "csrf_failed", "The request could not be verified.", requestID, nil)
		return false
	}
	return true
}

func withPrincipal(meta contract.RequestMeta, principal contract.Principal) contract.RequestMeta {
	meta.Principal = principal
	return meta
}

func sessionCookie(r *http.Request) (string, bool, error) {
	var value string
	found := false
	for _, cookie := range r.Cookies() {
		if cookie.Name != sessionCookieName {
			continue
		}
		if found || cookie.Value == "" {
			return "", false, errors.New("duplicate or empty session cookie")
		}
		found = true
		value = cookie.Value
	}
	return value, found, nil
}

func setSessionCookie(w http.ResponseWriter, raw *secret.Input, expiresAt time.Time) error {
	return raw.Use(func(value []byte) error {
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    string(value),
			Path:     "/",
			Expires:  expiresAt.UTC(),
			MaxAge:   max(0, int(time.Until(expiresAt).Seconds())),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		return nil
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0).UTC(), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func clearPreAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: preAuthCookieName, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0).UTC(), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func isAuthenticationError(err error) bool {
	appErr, ok := contract.AsAppError(err)
	return ok && appErr.Kind() == contract.ErrorKindAuth
}

func writeCSRFSecret(w http.ResponseWriter, token *secret.Input) error {
	return token.Use(func(value []byte) error {
		writeSetupJSON(w, http.StatusOK, struct {
			Data struct {
				CSRFToken string `json:"csrf_token"`
			} `json:"data"`
		}{Data: struct {
			CSRFToken string `json:"csrf_token"`
		}{CSRFToken: string(value)}})
		return nil
	})
}

func writeLoginResponse(w http.ResponseWriter, login contract.LoginView) error {
	return login.CSRFToken.Use(func(csrf []byte) error {
		if err := setSessionCookie(w, login.SessionToken, login.AbsoluteExpiresAt.Time()); err != nil {
			return err
		}
		writeLoginPayload(w, login, csrf)
		return nil
	})
}

type accountResponse struct {
	ID            string `json:"id"`
	LoginName     string `json:"login_name"`
	State         string `json:"state"`
	IsGlobalAdmin bool   `json:"is_global_admin"`
	Version       int64  `json:"version"`
}

type sessionResponse struct {
	Account           accountResponse `json:"account"`
	IdleExpiresAt     string          `json:"idle_expires_at"`
	AbsoluteExpiresAt string          `json:"absolute_expires_at"`
}

func toAccountResponse(account contract.AccountView) accountResponse {
	return accountResponse{ID: string(account.ID), LoginName: account.LoginName, State: string(account.State), IsGlobalAdmin: account.IsGlobalAdmin, Version: account.Version.Int64()}
}

func toSessionResponse(session contract.SessionView) sessionResponse {
	return sessionResponse{Account: toAccountResponse(session.Account), IdleExpiresAt: session.IdleExpiresAt.String(), AbsoluteExpiresAt: session.AbsoluteExpiresAt.String()}
}

func entityTag(version int64) string { return fmt.Sprintf("\"v%d\"", version) }

func writeLoginPayload(w http.ResponseWriter, login contract.LoginView, csrf []byte) {
	writeSetupJSON(w, http.StatusOK, struct {
		Data struct {
			Account           accountResponse `json:"account"`
			IdleExpiresAt     string          `json:"idle_expires_at"`
			AbsoluteExpiresAt string          `json:"absolute_expires_at"`
			CSRFToken         string          `json:"csrf_token"`
		} `json:"data"`
	}{Data: struct {
		Account           accountResponse `json:"account"`
		IdleExpiresAt     string          `json:"idle_expires_at"`
		AbsoluteExpiresAt string          `json:"absolute_expires_at"`
		CSRFToken         string          `json:"csrf_token"`
	}{Account: toAccountResponse(login.Account), IdleExpiresAt: login.IdleExpiresAt.String(), AbsoluteExpiresAt: login.AbsoluteExpiresAt.String(), CSRFToken: string(csrf)}})
}

func decodeSecretField(fields map[string]json.RawMessage, name string) (*secret.Input, bool) {
	raw, ok := fields[name]
	if !ok || len(strings.TrimSpace(string(raw))) == 0 || strings.TrimSpace(string(raw))[0] != '"' {
		return nil, false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, false
	}
	input := secret.FromString(value)
	value = ""
	return input, true
}

func decodeJSONObject(w http.ResponseWriter, r *http.Request, allowed []string) (map[string]json.RawMessage, int, string, string) {
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return nil, http.StatusBadRequest, "malformed_request", "The request is malformed."
	}
	mediaType, params, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		return nil, http.StatusBadRequest, "malformed_request", "The request is malformed."
	}
	if r.ContentLength > maxSetupJSONBytes {
		return nil, http.StatusRequestEntityTooLarge, "payload_too_large", "The request body is too large."
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSetupJSONBytes))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		status, code, message := malformedBodyStatus(err)
		return nil, status, code, message
	}
	accepted := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		accepted[name] = struct{}{}
	}
	fields := make(map[string]json.RawMessage, len(allowed))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			status, code, message := malformedBodyStatus(err)
			clearJSONFields(fields)
			return nil, status, code, message
		}
		name, ok := token.(string)
		if !ok {
			clearJSONFields(fields)
			return nil, http.StatusBadRequest, "malformed_request", "The request is malformed."
		}
		if _, duplicate := fields[name]; duplicate {
			clearJSONFields(fields)
			return nil, http.StatusBadRequest, "malformed_request", "The request is malformed."
		}
		if _, known := accepted[name]; !known {
			clearJSONFields(fields)
			return nil, http.StatusUnprocessableEntity, "unknown_field", "Unknown fields are not accepted."
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			status, code, message := malformedBodyStatus(err)
			clearJSONFields(fields)
			return nil, status, code, message
		}
		fields[name] = raw
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		clearJSONFields(fields)
		status, code, message := malformedBodyStatus(err)
		return nil, status, code, message
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		zeroBytes(trailing)
		clearJSONFields(fields)
		status, code, message := malformedBodyStatus(err)
		return nil, status, code, message
	}
	return fields, 0, "", ""
}

func clearJSONFields(fields map[string]json.RawMessage) {
	for _, raw := range fields {
		zeroBytes(raw)
	}
}
