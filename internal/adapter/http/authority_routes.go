package httpadapter

import (
	"net/http"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

func registerAuthorityRoutes(mux *http.ServeMux, h *setupHandler) {
	mux.HandleFunc("GET /api/v1/authorities", h.listAuthorities)
	mux.HandleFunc("POST /api/v1/authorities", h.postCreateAuthority)
	mux.HandleFunc("GET /api/v1/authorities/{id}", h.getAuthority)
	mux.HandleFunc("PATCH /api/v1/authorities/{id}", h.patchAuthority)
	mux.HandleFunc("POST /api/v1/authorities/{id}/issuance-state", h.postAuthorityIssuanceState)
	mux.HandleFunc("POST /api/v1/authorities/{id}/key-destruction", h.postAuthorityKeyDestruction)
	mux.HandleFunc("POST /api/v1/authorities/{id}/archive", h.postArchiveAuthority)
}

func (h *setupHandler) listAuthorities(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.pkiReadMeta(w, r)
	if !ok {
		return
	}
	if h.pkiQueries == nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", meta.RequestID, nil)
		return
	}

	_, page, search, err := pkiListValues(r, nil)
	if err != nil {
		writeSetupError(w, http.StatusBadRequest, "malformed_request", "The request is malformed.", meta.RequestID, nil)
		return
	}
	result, err := h.pkiQueries.ListAuthorities(r.Context(), meta, contract.AuthorityListQuery{Search: search, Page: page})
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	items := make([]authorityResponse, 0, len(result.Items))
	for _, view := range result.Items {
		item, err := toAuthorityResponse(view)
		if err != nil {
			writeSetupError(w, http.StatusInternalServerError, "internal_error", "The request could not be processed.", meta.RequestID, nil)
			return
		}
		items = append(items, item)
	}
	writeSetupJSON(w, http.StatusOK, struct {
		Data       []authorityResponse `json:"data"`
		NextCursor *string             `json:"next_cursor"`
	}{Data: items, NextCursor: result.NextCursor})
}

func (h *setupHandler) getAuthority(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.pkiReadMeta(w, r)
	if !ok {
		return
	}
	if h.pkiQueries == nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", meta.RequestID, nil)
		return
	}
	authorityID, ok := parseAuthorityPathID(w, r, meta.RequestID)
	if !ok {
		return
	}
	view, err := h.pkiQueries.GetAuthority(r.Context(), meta, contract.AuthorityGetQuery{AuthorityID: authorityID})
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	h.writeAuthority(w, http.StatusOK, meta.RequestID, view)
}

func (h *setupHandler) postCreateAuthority(w http.ResponseWriter, r *http.Request) {
	meta, ok := h.pkiMutationMeta(w, r, false, true)
	if !ok {
		return
	}
	if h.authorities == nil || h.pkiQueries == nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", meta.RequestID, nil)
		return
	}
	var command contract.AuthorityCreateCommand
	if !decodePKICommand(w, r, &command,
		[]string{"kind", "name", "parent_authority_id", "subject", "key_algorithm", "validity"},
		map[string][]string{"subject": {"common_name", "organization", "organizational_unit", "country"}, "validity": {"value", "unit"}},
		nil) {
		return
	}
	view, err := h.authorities.Create(r.Context(), meta, command)
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	status := http.StatusCreated
	if view.Replayed {
		status = http.StatusOK
	}
	h.writeAuthorityMutation(w, r, meta, status, view)
}

func (h *setupHandler) patchAuthority(w http.ResponseWriter, r *http.Request) {
	meta, authorityID, ok := h.authorityMutationMeta(w, r, true)
	if !ok {
		return
	}
	var command contract.AuthorityRenameCommand
	if !decodePKICommand(w, r, &command, []string{"name"}, nil, nil) {
		return
	}
	command.AuthorityID = authorityID
	view, err := h.authorities.Rename(r.Context(), meta, command)
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	h.writeAuthorityMutation(w, r, meta, http.StatusOK, view)
}

func (h *setupHandler) postAuthorityIssuanceState(w http.ResponseWriter, r *http.Request) {
	meta, authorityID, ok := h.authorityMutationMeta(w, r, true)
	if !ok {
		return
	}
	var command contract.AuthoritySetIssuanceStateCommand
	if !decodePKICommand(w, r, &command, []string{"state"}, nil, nil) {
		return
	}
	command.AuthorityID = authorityID
	view, err := h.authorities.SetIssuanceState(r.Context(), meta, command)
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	h.writeAuthorityMutation(w, r, meta, http.StatusOK, view)
}

func (h *setupHandler) postAuthorityKeyDestruction(w http.ResponseWriter, r *http.Request) {
	meta, authorityID, ok := h.authorityMutationMeta(w, r, true)
	if !ok {
		return
	}
	var command contract.AuthorityDestroyKeyCommand
	if !decodePKICommand(w, r, &command, []string{"key_generation_id", "justification"}, nil, nil) {
		return
	}
	command.AuthorityID = authorityID
	view, err := h.authorities.DestroyKey(r.Context(), meta, command)
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	h.writeAuthorityMutation(w, r, meta, http.StatusOK, view)
}

func (h *setupHandler) postArchiveAuthority(w http.ResponseWriter, r *http.Request) {
	meta, authorityID, ok := h.authorityMutationMeta(w, r, true)
	if !ok {
		return
	}
	var command contract.AuthorityArchiveCommand
	if !decodePKICommand(w, r, &command, nil, nil, nil) {
		return
	}
	command.AuthorityID = authorityID
	view, err := h.authorities.Archive(r.Context(), meta, command)
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	h.writeAuthorityMutation(w, r, meta, http.StatusOK, view)
}

func (h *setupHandler) authorityMutationMeta(w http.ResponseWriter, r *http.Request, requireVersion bool) (contract.MutationMeta, domain.AuthorityID, bool) {
	meta, ok := h.pkiMutationMeta(w, r, requireVersion, false)
	if !ok {
		return contract.MutationMeta{}, "", false
	}
	if h.authorities == nil || h.pkiQueries == nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", meta.RequestID, nil)
		return contract.MutationMeta{}, "", false
	}
	authorityID, ok := parseAuthorityPathID(w, r, meta.RequestID)
	if !ok {
		return contract.MutationMeta{}, "", false
	}
	return meta, authorityID, true
}

func parseAuthorityPathID(w http.ResponseWriter, r *http.Request, requestID string) (domain.AuthorityID, bool) {
	id, err := domain.ParseAuthorityID(r.PathValue("id"))
	if err != nil {
		writeSetupError(w, http.StatusBadRequest, "malformed_request", "The request is malformed.", requestID, nil)
		return "", false
	}
	return id, true
}

func (h *setupHandler) writeAuthorityMutation(w http.ResponseWriter, r *http.Request, meta contract.MutationMeta, status int, view contract.AuthorityView) {
	// Mutation views do not always include read-side fields. Refresh the
	// committed row through QueryService so the response carries its durable
	// creation time and current CRL status; preserve the service's replay bit.
	replayed := view.Replayed
	view, err := h.pkiQueries.GetAuthority(r.Context(), meta.RequestMeta, contract.AuthorityGetQuery{AuthorityID: view.ID})
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}
	view.Replayed = replayed
	if replayed {
		status = http.StatusOK
	}
	h.writeAuthority(w, status, meta.RequestID, view)
}

func (h *setupHandler) writeAuthority(w http.ResponseWriter, status int, requestID string, view contract.AuthorityView) {
	response, err := toAuthorityResponse(view)
	if err != nil {
		writeSetupError(w, http.StatusInternalServerError, "internal_error", "The request could not be processed.", requestID, nil)
		return
	}
	w.Header().Set("ETag", entityTag(response.Version))
	writeSetupJSON(w, status, struct {
		Data authorityResponse `json:"data"`
	}{Data: response})
}
