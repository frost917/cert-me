package httpadapter

import (
	"encoding/json"
	"net/http"
	"strings"

	"cert-me/internal/app/contract"
)

func (h *setupHandler) postInitializeSettings(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.requestMeta(w, r)
	if !ok {
		return
	}
	authenticated, ok := h.authenticatedMutation(w, r, meta)
	if !ok {
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
	defer zeroBytes(body)
	var command contract.SettingsInitializeCommand
	if err := json.Unmarshal(body, &command); err != nil {
		writeSetupError(w, http.StatusBadRequest, "malformed_request", "The request is malformed.", meta.RequestID, nil)
		return
	}
	if err := command.Validate(); err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	view, err := h.settings.Initialize(r.Context(), authenticated, command)
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	h.setServiceURL(view.Version.Int64(), view.ServiceURL)
	w.Header().Set("Location", "/api/v1/settings")
	w.Header().Set("ETag", entityTag(view.Version.Int64()))
	writeSetupJSON(w, http.StatusCreated, struct {
		Data settingsResponse `json:"data"`
	}{Data: toSettingsResponse(view)})
}
