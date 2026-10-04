package httpadapter

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"

	"cert-me/internal/app/contract"
)

//go:embed web
var webFiles embed.FS

func registerWebRoutes(mux *http.ServeMux, h *setupHandler) error {
	templates, err := template.ParseFS(webFiles, "web/index.html", "web/setup-status.html")
	if err != nil {
		return fmt.Errorf("httpadapter: parse embedded web templates: %w", err)
	}
	assets, err := fs.Sub(webFiles, "web")
	if err != nil {
		return fmt.Errorf("httpadapter: open embedded web assets: %w", err)
	}
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := templates.ExecuteTemplate(w, "index.html", struct{ Page string }{Page: "app"}); err != nil {
			return
		}
	})
	mux.HandleFunc("GET /reset-password/{token}", func(w http.ResponseWriter, r *http.Request) {
		// Do not bind the token into template data, markup, or an application log.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := templates.ExecuteTemplate(w, "index.html", struct{ Page string }{Page: "reset"}); err != nil {
			return
		}
	})
	mux.Handle("GET /assets/{path...}", http.StripPrefix("/assets/", http.FileServer(http.FS(assets))))
	mux.HandleFunc("GET /ui/setup-status", func(w http.ResponseWriter, r *http.Request) {
		meta, ok := h.requestMeta(w, r)
		if !ok {
			return
		}
		view, err := h.service.Status(r.Context(), meta, contract.EmptyCommand{})
		if err != nil {
			writeApplicationError(w, err, meta.RequestID)
			return
		}
		if err := view.SetupStage.Validate(); err != nil {
			writeSetupError(w, http.StatusInternalServerError, "internal_error", "The request could not be processed.", meta.RequestID, nil)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := templates.ExecuteTemplate(w, "setup-status.html", struct {
			SetupStage     string
			BootstrapHTTPS bool
		}{SetupStage: string(view.SetupStage), BootstrapHTTPS: view.BootstrapHTTPS}); err != nil {
			return
		}
	})
	return nil
}
