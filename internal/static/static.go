package static

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/ab/emudhra-fourgery/internal/issuer"
)

type Handler struct {
	root    *os.Root
	Headers map[string]string
	Types   map[string]string
}

func New(dir string) (*Handler, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	types, err := loadContentTypes(root)
	if err != nil {
		root.Close()
		return nil, err
	}
	return &Handler{root: root, Headers: map[string]string{}, Types: types}, nil
}
func (h *Handler) Close() error { return h.root.Close() }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authority := r.Host
	if strings.Contains(authority, ":") {
		var err error
		authority, _, err = net.SplitHostPort(authority)
		if err != nil {
			http.Error(w, "invalid host", 400)
			return
		}
	}
	host, err := issuer.Host(authority)
	if err != nil {
		http.Error(w, "invalid host", 400)
		return
	}
	if r.TLS == nil {
		http.Error(w, "TLS required", 400)
		return
	}
	sni, err := issuer.Host(r.TLS.ServerName)
	if err != nil || sni != host {
		http.Error(w, "SNI and Host must match", http.StatusMisdirectedRequest)
		return
	}
	site, err := h.root.OpenRoot("domains/" + host)
	if os.IsNotExist(err) {
		site, err = h.root.OpenRoot("default")
	}
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("content root unavailable", "host", host, "error", err)
		}
		http.NotFound(w, r)
		return
	}
	defer site.Close()
	for k, v := range h.Headers {
		w.Header().Set(k, v)
	}
	if t := h.Types[r.URL.Path]; t != "" {
		w.Header().Set("Content-Type", t)
	} else if t := h.Types[path.Ext(r.URL.Path)]; t != "" {
		w.Header().Set("Content-Type", t)
	}
	// FileServerFS handles URL cleaning and redirects; os.Root confines symlinks.
	rw := &response{ResponseWriter: w, status: 200}
	http.FileServerFS(site.FS()).ServeHTTP(rw, r)
	slog.Info("http request",
		"client", r.RemoteAddr,
		"sni", sni,
		"method", r.Method,
		"path", r.URL.Path,
		"status", rw.status,
	)
}

type response struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *response) WriteHeader(code int) {
	if !w.written {
		w.status = code
		w.written = true
		w.ResponseWriter.WriteHeader(code)
	}
}
func (w *response) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}
