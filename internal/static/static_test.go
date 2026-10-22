package static

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ab/emudhra-fourgery/internal/testca"
)

func TestSites(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"default/index.html":                                    "default",
		"domains/example.test/index.html":                       "domain",
		"domains/example.test/.well-known/openid-configuration": "{}",
	} {
		file := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "domains/example.test/escape")); err != nil {
		t.Fatal(err)
	}
	h, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	h.Types["/.well-known/openid-configuration"] = "application/json"
	for _, tc := range []struct {
		host, sni, path, body string
		status                int
	}{
		{"example.test", "example.test", "/", "domain", 200},
		{"other.test", "other.test", "/", "default", 200},
		{"example.test", "example.test", "/missing", "", 404},
		{"example.test", "other.test", "/", "", 421},
		{"example.test", "example.test", "/.well-known/openid-configuration", "{}", 200},
		{"example.test", "example.test", "/escape", "", 500},
	} {
		r := httptest.NewRequest("GET", "https://"+tc.host+tc.path, nil)
		r.TLS = &tls.ConnectionState{ServerName: tc.sni}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status || tc.body != "" && w.Body.String() != tc.body {
			t.Errorf("%+v: status=%d body=%q", tc, w.Code, w.Body.String())
		}
		if tc.path == "/.well-known/openid-configuration" && w.Header().Get("Content-Type") != "application/json" {
			t.Fatal(w.Header())
		}
	}
}

func TestGitDiagnostic(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	h, err := New("../../examples/content")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	r := httptest.NewRequest("GET", "https://other.test/info/refs?service=git-upload-pack", nil)
	r.TLS = &tls.ConnectionState{ServerName: "other.test"}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("Git diagnostic should not be served for other hostnames: %d", w.Code)
	}
	m, _ := testca.New(t)
	cert, err := m.Certificate("git.example.com")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(h)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
	server.StartTLS()
	defer server.Close()
	root := t.TempDir()
	ca := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: m.CA.Raw,
	}), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	url := strings.Replace(server.URL, "127.0.0.1", "git.example.com", 1) + "/"
	cmd := exec.CommandContext(ctx, git,
		"-c", "http.proxy=",
		"-c", "http.sslVerify=true",
		"-c", "http.sslCAInfo="+ca,
		"-c", "http.curloptResolve=git.example.com:"+port+":127.0.0.1",
		"clone", url, filepath.Join(root, "clone"),
	)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_COUNT=0",
		"GIT_SSL_NO_VERIFY=false",
		"GIT_SSL_CAINFO="+ca,
		"GIT_TERMINAL_PROMPT=0",
	)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal(ctx.Err())
	}
	if err == nil || !strings.Contains(string(out), "remote error: You are vulnerable:") {
		t.Fatalf("expected diagnostic clone failure, got %v\n%s", err, out)
	}
}
