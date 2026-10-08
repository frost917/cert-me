package httpadapter

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

func registerLeafRoutes(mux *http.ServeMux, h *setupHandler) {
	mux.HandleFunc("GET /api/v1/leaf-series", h.listLeafSeries)
	mux.HandleFunc("POST /api/v1/leaf-series", h.postIssueLeaf)
	mux.HandleFunc("GET /api/v1/leaf-series/{id}", h.getLeafSeries)
	mux.HandleFunc("PATCH /api/v1/leaf-series/{id}", h.patchLeafSeries)
	mux.HandleFunc("POST /api/v1/leaf-series/{id}/renewals", h.postRenewLeaf)
	mux.HandleFunc("POST /api/v1/leaf-series/{id}/reissues", h.postReissueLeaf)
	mux.HandleFunc("POST /api/v1/leaf-series/{id}/archive", h.postArchiveLeafSeries)
	mux.HandleFunc("GET /api/v1/certificates", h.listCertificates)
	mux.HandleFunc("GET /api/v1/certificates/{id}", h.getCertificate)
}

func (h *setupHandler) listLeafSeries(w http.ResponseWriter, r *http.Request) {
	values, page, search, err := pkiListValues(r, []string{"authority_id"})
	if err != nil {
		writeLeafBadRequest(w, "The query parameters are invalid.", "")
		return
	}
	var authorityID *domain.AuthorityID
	if raw, present := values["authority_id"]; present {
		parsed, err := domain.ParseAuthorityID(raw[0])
		if err != nil {
			writeLeafBadRequest(w, "The query parameters are invalid.", "")
			return
		}
		authorityID = &parsed
	}
	meta, ok := h.pkiReadMeta(w, r)
	if !ok {
		return
	}
	if h.leafQueries == nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", meta.RequestID, nil)
		return
	}
	result, err := h.leafQueries.ListSeries(r.Context(), meta, contract.SeriesListQuery{
		Search: search, AuthorityID: authorityID, Page: page,
	})
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	items := make([]leafSeriesResponse, 0, len(result.Items))
	for _, view := range result.Items {
		item, err := toLeafSeriesResponse(view)
		if err != nil {
			writeSetupError(w, http.StatusInternalServerError, "internal_error", "The request could not be processed.", meta.RequestID, nil)
			return
		}
		items = append(items, item)
	}
	writeSetupJSON(w, http.StatusOK, struct {
		Data       []leafSeriesResponse `json:"data"`
		NextCursor *string              `json:"next_cursor"`
	}{Data: items, NextCursor: result.NextCursor})
}

func (h *setupHandler) getLeafSeries(w http.ResponseWriter, r *http.Request) {
	seriesID, ok := parseLeafSeriesPathID(w, r, "")
	if !ok {
		return
	}
	meta, ok := h.pkiReadMeta(w, r)
	if !ok {
		return
	}
	if h.leafQueries == nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", meta.RequestID, nil)
		return
	}
	view, err := h.leafQueries.GetSeries(r.Context(), meta, contract.SeriesGetQuery{SeriesID: seriesID})
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	h.writeLeafSeries(w, http.StatusOK, meta.RequestID, view)
}

func (h *setupHandler) postIssueLeaf(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.pkiMutationMeta(w, r, false, true)
	if !ok {
		return
	}
	if h.issuance == nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", meta.RequestID, nil)
		return
	}
	var command contract.IssuanceIssueCommand
	if !decodeLeafIssueCommand(w, r, &command) {
		return
	}
	if err := command.Validate(); err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	view, err := h.issuance.Issue(r.Context(), meta, command)
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	status := http.StatusCreated
	if view.Replayed {
		status = http.StatusOK
	}
	h.writeIssuance(w, status, toIssuanceResponse(view))
}

func (h *setupHandler) postRenewLeaf(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.pkiMutationMeta(w, r, true, true)
	if !ok {
		return
	}
	if h.issuance == nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", meta.RequestID, nil)
		return
	}
	seriesID, ok := parseLeafSeriesPathID(w, r, meta.RequestID)
	if !ok {
		return
	}
	var command contract.IssuanceRenewCommand
	if !decodePKICommand(w, r, &command, []string{"source_certificate_id", "target_authority_id", "transition_id"}, nil, nil) {
		return
	}
	command.SeriesID = seriesID
	if err := command.Validate(); err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	view, err := h.issuance.Renew(r.Context(), meta, command)
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	status := http.StatusCreated
	if view.Replayed {
		status = http.StatusOK
	}
	h.writeIssuance(w, status, toIssuanceResponse(view))
}

func (h *setupHandler) postReissueLeaf(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.pkiMutationMeta(w, r, true, true)
	if !ok {
		return
	}
	if h.issuance == nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", meta.RequestID, nil)
		return
	}
	seriesID, ok := parseLeafSeriesPathID(w, r, meta.RequestID)
	if !ok {
		return
	}
	var command contract.IssuanceReissueCommand
	if !decodePKICommand(w, r, &command, []string{"source_certificate_id", "reason", "target_authority_id", "transition_id"}, nil, nil) {
		return
	}
	command.SeriesID = seriesID
	if err := command.Validate(); err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	view, err := h.issuance.Reissue(r.Context(), meta, command)
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	status := http.StatusCreated
	if view.Replayed {
		status = http.StatusOK
	}
	h.writeIssuance(w, status, toIssuanceResponse(view))
}

func (h *setupHandler) patchLeafSeries(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.pkiMutationMeta(w, r, true, false)
	if !ok {
		return
	}
	if h.issuance == nil || h.leafQueries == nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", meta.RequestID, nil)
		return
	}
	seriesID, ok := parseLeafSeriesPathID(w, r, meta.RequestID)
	if !ok {
		return
	}
	var command contract.IssuanceUpdateSeriesCommand
	if !decodePKICommand(w, r, &command, []string{"name", "validity", "rotate_every"}, map[string][]string{
		"validity": {"value", "unit"},
	}, nil) {
		return
	}
	command.SeriesID = seriesID
	if err := command.Validate(); err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	view, err := h.issuance.UpdateSeries(r.Context(), meta, command)
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	h.writeLeafSeriesMutation(w, r, meta, view.ID)
}

func (h *setupHandler) postArchiveLeafSeries(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.pkiMutationMeta(w, r, true, false)
	if !ok {
		return
	}
	if h.issuance == nil || h.leafQueries == nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", meta.RequestID, nil)
		return
	}
	seriesID, ok := parseLeafSeriesPathID(w, r, meta.RequestID)
	if !ok {
		return
	}
	fields, status, code, message := decodeOptionalEmptyJSONObject(w, r)
	if status != 0 {
		writeSetupError(w, status, code, message, meta.RequestID, nil)
		return
	}
	clearJSONFields(fields)
	command := contract.IssuanceArchiveSeriesCommand{SeriesID: seriesID}
	if err := command.Validate(); err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	view, err := h.issuance.ArchiveSeries(r.Context(), meta, command)
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	h.writeLeafSeriesMutation(w, r, meta, view.ID)
}

func (h *setupHandler) listCertificates(w http.ResponseWriter, r *http.Request) {
	values, page, search, err := pkiListValues(r, []string{"authority_id", "expires_before", "revoked", "affected"})
	if err != nil {
		writeLeafBadRequest(w, "The query parameters are invalid.", "")
		return
	}
	query := contract.CertificateListQuery{Search: search, Page: page}
	if raw, present := values["authority_id"]; present {
		parsed, err := domain.ParseAuthorityID(raw[0])
		if err != nil {
			writeLeafBadRequest(w, "The query parameters are invalid.", "")
			return
		}
		query.AuthorityID = &parsed
	}
	if raw, present := values["expires_before"]; present {
		parsed, err := time.Parse(time.RFC3339Nano, raw[0])
		if err != nil {
			writeLeafBadRequest(w, "The query parameters are invalid.", "")
			return
		}
		instant := domain.NewInstant(parsed)
		query.ExpiresBefore = &instant
	}
	if query.Revoked, err = parseLeafBoolFilter(values, "revoked"); err != nil {
		writeLeafBadRequest(w, "The query parameters are invalid.", "")
		return
	}
	if query.Affected, err = parseLeafBoolFilter(values, "affected"); err != nil {
		writeLeafBadRequest(w, "The query parameters are invalid.", "")
		return
	}
	meta, ok := h.pkiReadMeta(w, r)
	if !ok {
		return
	}
	if h.leafQueries == nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", meta.RequestID, nil)
		return
	}
	result, err := h.leafQueries.ListCertificates(r.Context(), meta, query)
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	items := make([]certificateResponse, 0, len(result.Items))
	for _, view := range result.Items {
		item, err := toCertificateResponse(view)
		if err != nil {
			writeSetupError(w, http.StatusInternalServerError, "internal_error", "The request could not be processed.", meta.RequestID, nil)
			return
		}
		items = append(items, item)
	}
	writeSetupJSON(w, http.StatusOK, struct {
		Data       []certificateResponse `json:"data"`
		NextCursor *string               `json:"next_cursor"`
	}{Data: items, NextCursor: result.NextCursor})
}

func (h *setupHandler) getCertificate(w http.ResponseWriter, r *http.Request) {
	certificateID, err := domain.ParseCertificateID(r.PathValue("id"))
	if err != nil {
		writeLeafBadRequest(w, "The request is malformed.", "")
		return
	}
	meta, ok := h.pkiReadMeta(w, r)
	if !ok {
		return
	}
	if h.leafQueries == nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", meta.RequestID, nil)
		return
	}
	view, err := h.leafQueries.GetCertificate(r.Context(), meta, contract.CertificateGetQuery{CertificateID: certificateID})
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	response, err := toCertificateResponse(view)
	if err != nil {
		writeSetupError(w, http.StatusInternalServerError, "internal_error", "The request could not be processed.", meta.RequestID, nil)
		return
	}
	writeSetupJSON(w, http.StatusOK, struct {
		Data certificateResponse `json:"data"`
	}{Data: response})
}

func parseLeafSeriesPathID(w http.ResponseWriter, r *http.Request, requestID string) (domain.SeriesID, bool) {
	id, err := leafSeriesID(r.PathValue("id"))
	if err != nil {
		writeLeafBadRequest(w, "The request is malformed.", requestID)
		return "", false
	}
	return id, true
}

func writeLeafBadRequest(w http.ResponseWriter, message, requestID string) {
	if requestID == "" {
		var ok bool
		requestID, ok = ensureRequestID(w)
		if !ok {
			writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", "unavailable", nil)
			return
		}
	}
	writeSetupError(w, http.StatusBadRequest, "malformed_request", message, requestID, nil)
}

func (h *setupHandler) writeLeafSeriesMutation(w http.ResponseWriter, r *http.Request, meta contract.MutationMeta, id domain.SeriesID) {
	view, err := h.leafQueries.GetSeries(r.Context(), meta.RequestMeta, contract.SeriesGetQuery{SeriesID: id})
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	h.writeLeafSeries(w, http.StatusOK, meta.RequestID, view)
}

func (h *setupHandler) writeLeafSeries(w http.ResponseWriter, status int, requestID string, view contract.LeafSeriesView) {
	response, err := toLeafSeriesResponse(view)
	if err != nil {
		writeSetupError(w, http.StatusInternalServerError, "internal_error", "The request could not be processed.", requestID, nil)
		return
	}
	w.Header().Set("ETag", entityTag(response.Version))
	writeSetupJSON(w, status, struct {
		Data leafSeriesResponse `json:"data"`
	}{Data: response})
}

func (h *setupHandler) writeIssuance(w http.ResponseWriter, status int, response issuanceResponse) {
	writeSetupJSON(w, status, struct {
		Data issuanceResponse `json:"data"`
	}{Data: response})
}

func parseLeafBoolFilter(values url.Values, key string) (*bool, error) {
	raw, present := values[key]
	if !present {
		return nil, nil
	}
	var parsed bool
	switch raw[0] {
	case "true":
		parsed = true
	case "false":
		parsed = false
	default:
		return nil, contract.NewAppError(contract.ErrorKindValidation, "malformed_request", "the query parameters are invalid")
	}
	return &parsed, nil
}

func decodeLeafIssueCommand(w http.ResponseWriter, r *http.Request, dest *contract.IssuanceIssueCommand) bool {
	requestID := w.Header().Get("X-Request-ID")
	allowed := []string{"name", "authority_id", "profile", "subject", "sans", "key_algorithm", "validity", "rotate_every"}
	fields, status, code, message := decodeJSONObject(w, r, allowed)
	if status != 0 {
		writeSetupError(w, status, code, message, requestID, nil)
		return false
	}
	defer clearJSONFields(fields)
	for name, raw := range fields {
		if strings.TrimSpace(string(raw)) == "null" {
			writeSetupError(w, http.StatusUnprocessableEntity, "invalid_request", "Request fields cannot be null.", requestID, nil)
			return false
		}
		switch name {
		case "subject":
			if err := validateLeafSubject(raw); err != nil {
				writeSetupError(w, http.StatusUnprocessableEntity, "invalid_subject", "The subject is invalid.", requestID, nil)
				return false
			}
		case "sans":
			if err := validateLeafSANArray(raw); err != nil {
				writeSetupError(w, http.StatusUnprocessableEntity, "invalid_sans", "The SAN list is invalid.", requestID, nil)
				return false
			}
		case "validity":
			if err := validateJSONObjectRawRequired(raw, []string{"value", "unit"}, []string{"value", "unit"}); err != nil {
				writeSetupError(w, http.StatusUnprocessableEntity, "invalid_validity", "The validity value is invalid.", requestID, nil)
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

func validateLeafSubject(raw json.RawMessage) error {
	allowed := []string{"common_name", "organization", "organizational_unit", "country"}
	if err := validateJSONObjectRawRequired(raw, allowed, []string{"common_name"}); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	defer clearJSONFields(fields)
	for name, value := range fields {
		var text string
		if err := json.Unmarshal(value, &text); err != nil || utf8.RuneCountInString(text) < 1 || utf8.RuneCountInString(text) > 255 {
			return contract.NewAppError(contract.ErrorKindValidation, "invalid_subject", "the subject is invalid")
		}
		if name == "country" && (len(text) != 2 || text[0] < 'A' || text[0] > 'Z' || text[1] < 'A' || text[1] > 'Z') {
			return contract.NewAppError(contract.ErrorKindValidation, "invalid_subject", "the subject is invalid")
		}
	}
	return nil
}

func validateLeafSANArray(raw json.RawMessage) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('[') {
		return contract.NewAppError(contract.ErrorKindValidation, "invalid_sans", "the SAN list is invalid")
	}
	for decoder.More() {
		var item json.RawMessage
		if err := decoder.Decode(&item); err != nil {
			return err
		}
		if err := validateJSONObjectRawRequired(item, []string{"type", "value"}, []string{"type", "value"}); err != nil {
			zeroBytes(item)
			return err
		}
		zeroBytes(item)
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim(']') {
		return contract.NewAppError(contract.ErrorKindValidation, "invalid_sans", "the SAN list is invalid")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		zeroBytes(trailing)
		return contract.NewAppError(contract.ErrorKindValidation, "invalid_sans", "the SAN list is invalid")
	}
	return nil
}
