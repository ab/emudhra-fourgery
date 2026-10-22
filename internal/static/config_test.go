package static

import (
	"crypto/tls"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestContentTypeConfig(t *testing.T) {
	root := t.TempDir()
	for name, data := range map[string]string{
		"config.json":        `{"content_types":{"/document":"application/json",".data":"text/plain","/exact.data":"application/octet-stream"}}`,
		"default/document":   `{}`,
		"default/file.data":  "extension match",
		"default/exact.data": "path match",
	} {
		file := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	h, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	for _, tc := range []struct {
		path, contentType string
		status            int
	}{
		{"/document?anything=1", "application/json", 200},
		{"/file.data", "text/plain", 200},
		{"/exact.data", "application/octet-stream", 200},
		{"/config.json", "", 404},
	} {
		r := httptest.NewRequest("GET", "https://example.test"+tc.path, nil)
		r.TLS = &tls.ConnectionState{ServerName: "example.test"}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status || tc.contentType != "" && w.Header().Get("Content-Type") != tc.contentType {
			t.Fatalf("%s: status=%d headers=%v", tc.path, w.Code, w.Header())
		}
	}
	// The CLI merges explicit entries into Types after construction.
	h.Types["/document"] = "text/plain"
	r := httptest.NewRequest("GET", "https://example.test/document", nil)
	r.TLS = &tls.ConnectionState{ServerName: "example.test"}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Content-Type") != "text/plain" {
		t.Fatal(w.Header())
	}
}

func TestInvalidContentConfig(t *testing.T) {
	for _, data := range []string{
		``, `null`, `[]`, `{`, `{} {}`,
		`{"headers":{}}`,
		`{"content_types":{"info/refs":"text/plain"}}`,
		`{"content_types":{"/file":""}}`,
		`{"content_types":{"/file":"invalid"}}`,
		`{"content_types":{"/file":"text/plain\r\nX-Header: bad"}}`,
	} {
		t.Run(data, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			h, err := New(root)
			if err == nil {
				h.Close()
				t.Fatal("invalid config accepted")
			}
		})
	}
}
