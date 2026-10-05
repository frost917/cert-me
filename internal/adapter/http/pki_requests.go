package httpadapter

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"cert-me/internal/app/contract"
)

func (h *setupHandler) pkiReadMeta(w http.ResponseWriter, r *http.Request) (contract.RequestMeta, bool) {
	meta, ok := h.requestMeta(w, r)
	if !ok {
		return contract.RequestMeta{}, false
	}
	result, err := h.authenticate(r, meta, nil)
	if err != nil {
		if isAuthenticationError(err) {
			clearSessionCookie(w)
		}
		writeApplicationError(w, err, meta.RequestID)
		return contract.RequestMeta{}, false
	}
	return withPrincipal(meta, result.Principal), true
}

func (h *setupHandler) pkiMutationMeta(w http.ResponseWriter, r *http.Request, version, idempotent bool) (contract.MutationMeta, bool) {
	meta, ok := h.requestMeta(w, r)
	if !ok {
		return contract.MutationMeta{}, false
	}
	mutation, ok := h.authenticatedMutation(w, r, meta)
	if !ok {
		return contract.MutationMeta{}, false
	}
	if version {
		v, status, code, message := expectedVersion(r)
		if status != 0 {
			writeSetupError(w, status, code, message, meta.RequestID, nil)
			return contract.MutationMeta{}, false
		}
		mutation.ExpectedVersion = &v
	}
	if idempotent {
		values := r.Header.Values("Idempotency-Key")
		if len(values) != 1 {
			writeSetupError(w, http.StatusBadRequest, "idempotency_key_invalid", "A single UUID idempotency key is required.", meta.RequestID, nil)
			return contract.MutationMeta{}, false
		}
		mutation.IdempotencyKey = values[0]
		if _, err := mutation.RequireIdempotencyKey(); err != nil {
			writeSetupError(w, http.StatusBadRequest, "idempotency_key_invalid", "A single UUID idempotency key is required.", meta.RequestID, nil)
			return contract.MutationMeta{}, false
		}
	}
	return mutation, true
}

func decodePKICommand(w http.ResponseWriter, r *http.Request, dest any, allowed []string, nested map[string][]string, nullableFields []string) bool {
	requestID := w.Header().Get("X-Request-ID")
	fields, status, code, message := decodeJSONObject(w, r, allowed)
	if status != 0 {
		writeSetupError(w, status, code, message, requestID, nil)
		return false
	}
	defer clearJSONFields(fields)
	for name, raw := range fields {
		if strings.TrimSpace(string(raw)) == "null" && !stringInList(nullableFields, name) {
			writeSetupError(w, http.StatusUnprocessableEntity, "invalid_request", "Request fields cannot be null.", requestID, nil)
			return false
		}
		if children, exists := nested[name]; exists && strings.TrimSpace(string(raw)) != "null" {
			if err := validateJSONObjectRaw(raw, children); err != nil {
				writeSetupError(w, http.StatusUnprocessableEntity, "invalid_request", "The nested object is invalid.", requestID, nil)
				return false
			}
		}
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		writeSetupError(w, http.StatusBadRequest, "malformed_request", "The request is malformed.", requestID, nil)
		return false
	}
	defer zeroBytes(encoded)
	if err := json.Unmarshal(encoded, dest); err != nil {
		writeSetupError(w, http.StatusBadRequest, "malformed_request", "The request is malformed.", requestID, nil)
		return false
	}
	return true
}

func stringInList(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func pkiListValues(r *http.Request, extra []string) (url.Values, contract.PageRequest, string, error) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, contract.PageRequest{}, "", invalidPKIQuery()
	}
	for name, entries := range values {
		if len(entries) != 1 || (name != "q" && name != "cursor" && name != "limit" && !stringInList(extra, name)) {
			return nil, contract.PageRequest{}, "", invalidPKIQuery()
		}
	}
	page := contract.PageRequest{Limit: 50, Cursor: values.Get("cursor")}
	if limit, present := values["limit"]; present {
		page.Limit, err = strconv.Atoi(limit[0])
		if err != nil || page.Limit < 1 || page.Limit > 200 {
			return nil, page, "", invalidPKIQuery()
		}
	}
	if len(page.Cursor) > 4096 || len(values.Get("q")) > 255 {
		return nil, page, "", invalidPKIQuery()
	}
	return values, page, values.Get("q"), nil
}

func invalidPKIQuery() error {
	return contract.NewAppError(contract.ErrorKindValidation, "malformed_request", "The query parameters are invalid.")
}
