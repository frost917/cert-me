package httpadapter

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

var errInvalidJSONShape = errors.New("httpadapter: invalid JSON object shape")

func (h *setupHandler) getSettings(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.requestMeta(w, r)
	if !ok {
		return
	}
	authenticated, err := h.authenticate(r, meta, nil)
	if err != nil {
		if isAuthenticationError(err) {
			clearSessionCookie(w)
		}
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	view, err := h.settings.Get(r.Context(), withPrincipal(meta, authenticated.Principal), contract.SettingsGetCommand{})
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	w.Header().Set("ETag", entityTag(view.Version.Int64()))
	writeSetupJSON(w, http.StatusOK, struct {
		Data settingsResponse `json:"data"`
	}{Data: toSettingsResponse(view)})
}

func (h *setupHandler) patchSettings(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.requestMeta(w, r)
	if !ok {
		return
	}
	authenticated, ok := h.authenticatedMutation(w, r, meta)
	if !ok {
		return
	}
	version, status, code, message := expectedVersion(r)
	if status != 0 {
		writeSetupError(w, status, code, message, meta.RequestID, nil)
		return
	}
	fields, status, code, message := decodeJSONObject(w, r, []string{
		"service_url", "leaf_validity", "root_validity", "intermediate_validity", "rotate_every",
		"private_delivery_seconds", "public_link_seconds", "crl_interval_seconds", "crl_validity_seconds", "audit_retention_days",
	})
	if status != 0 {
		writeSetupError(w, status, code, message, meta.RequestID, nil)
		return
	}
	defer clearJSONFields(fields)
	for _, raw := range fields {
		if strings.TrimSpace(string(raw)) == "null" {
			writeSetupError(w, http.StatusUnprocessableEntity, "invalid_settings", "Settings fields cannot be null.", meta.RequestID, nil)
			return
		}
	}
	for _, name := range []string{"leaf_validity", "root_validity", "intermediate_validity"} {
		if raw, present := fields[name]; present {
			if err := validateJSONObjectRaw(raw, []string{"value", "unit"}); err != nil {
				writeSetupError(w, http.StatusUnprocessableEntity, "invalid_validity", "The validity value is invalid.", meta.RequestID, nil)
				return
			}
		}
	}
	body, err := json.Marshal(fields)
	if err != nil {
		writeSetupError(w, http.StatusBadRequest, "malformed_request", "The request is malformed.", meta.RequestID, nil)
		return
	}
	var command contract.SettingsUpdateCommand
	if err := json.Unmarshal(body, &command); err != nil {
		zeroBytes(body)
		writeSetupError(w, http.StatusBadRequest, "malformed_request", "The request is malformed.", meta.RequestID, nil)
		return
	}
	zeroBytes(body)
	authenticated.ExpectedVersion = &version
	view, err := h.settings.Update(r.Context(), authenticated, command)
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	h.setServiceURL(view.Version.Int64(), view.ServiceURL)
	w.Header().Set("ETag", entityTag(view.Version.Int64()))
	writeSetupJSON(w, http.StatusOK, struct {
		Data settingsResponse `json:"data"`
	}{Data: toSettingsResponse(view)})
}

func (h *setupHandler) postCompleteSetup(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.requestMeta(w, r)
	if !ok {
		return
	}
	authenticated, ok := h.authenticatedMutation(w, r, meta)
	if !ok {
		return
	}
	version, status, code, message := expectedVersion(r)
	if status != 0 {
		writeSetupError(w, status, code, message, meta.RequestID, nil)
		return
	}
	authenticated.ExpectedVersion = &version
	view, err := h.service.Complete(r.Context(), authenticated, contract.SetupCompleteCommand{})
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	writeSetupJSON(w, http.StatusOK, struct {
		Data setupStatusResponse `json:"data"`
	}{Data: setupStatusResponse{SetupStage: string(view.SetupStage), BootstrapHTTPS: view.BootstrapHTTPS}})
}

func expectedVersion(r *http.Request) (domain.Version, int, string, string) {
	values := r.Header.Values("If-Match")
	if len(values) == 0 {
		return 0, http.StatusPreconditionRequired, "precondition_required", "If-Match is required."
	}
	if len(values) != 1 {
		return 0, http.StatusBadRequest, "malformed_request", "If-Match is malformed."
	}
	value := values[0]
	if len(value) < 4 || value[0] != '"' || value[len(value)-1] != '"' || !strings.HasPrefix(value[1:len(value)-1], "v") {
		return 0, http.StatusBadRequest, "malformed_request", "If-Match is malformed."
	}
	raw := value[2 : len(value)-1]
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || strconv.FormatInt(n, 10) != raw {
		return 0, http.StatusBadRequest, "malformed_request", "If-Match is malformed."
	}
	version, err := domain.ParseVersion(n)
	if err != nil {
		return 0, http.StatusBadRequest, "malformed_request", "If-Match is malformed."
	}
	return version, 0, "", ""
}

type validityResponse struct {
	Value int    `json:"value"`
	Unit  string `json:"unit"`
}

type settingsResponse struct {
	ServiceURL             string           `json:"service_url"`
	LeafValidity           validityResponse `json:"leaf_validity"`
	RootValidity           validityResponse `json:"root_validity"`
	IntermediateValidity   validityResponse `json:"intermediate_validity"`
	RotateEvery            int              `json:"rotate_every"`
	PrivateDeliverySeconds int64            `json:"private_delivery_seconds"`
	PublicLinkSeconds      int64            `json:"public_link_seconds"`
	CRLIntervalSeconds     int64            `json:"crl_interval_seconds"`
	CRLValiditySeconds     int64            `json:"crl_validity_seconds"`
	AuditRetentionDays     int              `json:"audit_retention_days"`
	Version                int64            `json:"version"`
}

func toSettingsResponse(view contract.SettingsView) settingsResponse {
	seconds := func(microseconds int64) int64 { return microseconds / 1_000_000 }
	return settingsResponse{
		ServiceURL:             view.ServiceURL,
		LeafValidity:           validityResponse{Value: view.LeafValidity.Value(), Unit: string(view.LeafValidity.Unit())},
		RootValidity:           validityResponse{Value: view.RootValidity.Value(), Unit: string(view.RootValidity.Unit())},
		IntermediateValidity:   validityResponse{Value: view.IntermediateValidity.Value(), Unit: string(view.IntermediateValidity.Unit())},
		RotateEvery:            view.RotateEvery,
		PrivateDeliverySeconds: seconds(view.PrivateDeliveryLifetime.Microseconds()),
		PublicLinkSeconds:      seconds(view.PublicLinkLifetime.Microseconds()),
		CRLIntervalSeconds:     seconds(view.CRLInterval.Microseconds()),
		CRLValiditySeconds:     seconds(view.CRLValidity.Microseconds()),
		AuditRetentionDays:     view.AuditRetentionDays,
		Version:                view.Version.Int64(),
	}
}

func validateJSONObjectRaw(raw json.RawMessage, allowed []string) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return errInvalidJSONShape
	}
	accepted := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		accepted[field] = struct{}{}
	}
	seen := make(map[string]struct{}, len(allowed))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		field, ok := token.(string)
		if !ok {
			return errInvalidJSONShape
		}
		if _, duplicate := seen[field]; duplicate {
			return errInvalidJSONShape
		}
		if _, known := accepted[field]; !known {
			return errInvalidJSONShape
		}
		seen[field] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		zeroBytes(value)
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || len(seen) != 2 {
		return errInvalidJSONShape
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		zeroBytes(trailing)
		return errInvalidJSONShape
	}
	return nil
}
