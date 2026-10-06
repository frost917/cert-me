package httpadapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"strings"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

const publicCACacheControl = "public, max-age=31536000, immutable"

func registerPublicCARoutes(mux *http.ServeMux, h *setupHandler) {
	mux.HandleFunc("GET /pki/ca-certificates/{id}/certificate.pem", h.getPublicCACertificate)
	mux.HandleFunc("GET /pki/ca-certificates/{id}/chain.pem", h.getPublicCAChain)
}

func (h *setupHandler) getPublicCACertificate(w http.ResponseWriter, r *http.Request) {
	h.servePublicCAFile(w, r, false)
}

func (h *setupHandler) getPublicCAChain(w http.ResponseWriter, r *http.Request) {
	h.servePublicCAFile(w, r, true)
}

func (h *setupHandler) servePublicCAFile(w http.ResponseWriter, r *http.Request, includeChain bool) {
	meta, ok := h.requestMeta(w, r)
	if !ok {
		return
	}
	certificateID, err := domain.ParseCertificateID(r.PathValue("id"))
	if err != nil {
		writeSetupError(w, http.StatusBadRequest, "malformed_request", "The request is malformed.", meta.RequestID, nil)
		return
	}
	if h.publicCA == nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", meta.RequestID, nil)
		return
	}
	view, err := h.publicCA.ReadPublicCACertificate(r.Context(), meta, contract.PublicCACertificateQuery{CertificateID: certificateID})
	if err != nil {
		writeApplicationError(w, err, meta.RequestID)
		return
	}

	certificateDER := view.Certificate.DER()
	if view.Certificate.ID() != certificateID || view.Certificate.Kind() != domain.CertificateKindCA || len(certificateDER) == 0 {
		writeSetupError(w, http.StatusInternalServerError, "internal_error", "The request could not be processed.", meta.RequestID, nil)
		return
	}

	filename := "ca-certificate.pem"
	var body []byte
	var etag string
	if includeChain {
		if len(view.ChainDER) == 0 || !bytes.Equal(view.ChainDER[0], certificateDER) {
			writeSetupError(w, http.StatusInternalServerError, "internal_error", "The request could not be processed.", meta.RequestID, nil)
			return
		}
		filename = "chain.pem"
		for _, der := range view.ChainDER {
			if len(der) == 0 {
				writeSetupError(w, http.StatusInternalServerError, "internal_error", "The request could not be processed.", meta.RequestID, nil)
				return
			}
			body = append(body, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		etag = publicCAETag(body)
	} else {
		body = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
		etag = publicCAETag(certificateDER)
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", publicCACacheControl)
	w.Header().Set("ETag", etag)
	if publicCAIfNoneMatch(r.Header.Values("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		// The status and headers are already committed; stopping the write is
		// the only safe response to a client disconnect at this point.
		return
	}
}

func publicCAETag(value []byte) string {
	digest := sha256.Sum256(value)
	return `"` + hex.EncodeToString(digest[:]) + `"`
}

func publicCAIfNoneMatch(values []string, etag string) bool {
	for _, value := range values {
		for _, candidate := range strings.Split(value, ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "*" {
				return true
			}
			if strings.HasPrefix(candidate, "W/") {
				candidate = strings.TrimSpace(strings.TrimPrefix(candidate, "W/"))
			}
			if candidate == etag {
				return true
			}
		}
	}
	return false
}
