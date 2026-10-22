package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ab/emudhra-fourgery/internal/testca"
	"golang.org/x/net/dns/dnsmessage"
)

func TestPlainHTTPDetection(t *testing.T) {
	for _, tc := range []struct {
		header string
		http   bool
	}{
		{"GET /", true},
		{"POST ", true},
		{"HEAD ", true},
		{"PUT /", true},
		{"DELET", true},
		{"CONNE", true},
		{"OPTIO", true},
		{"TRACE", true},
		{"PATCH", true},
		{"PRI *", true},
		{"\x16\x03\x01\x00\x20", false},
		{"SSH-2", false},
		{"hello", false},
	} {
		var header [5]byte
		copy(header[:], tc.header)
		err := fmt.Errorf("handshake: %w", tls.RecordHeaderError{RecordHeader: header})
		if got := isPlainHTTP(err); got != tc.http {
			t.Errorf("header %q: got %v, want %v", tc.header, got, tc.http)
		}
	}
	if isPlainHTTP(errors.New("GET /")) || isPlainHTTP(nil) {
		t.Fatal("classified an unrelated error as HTTP")
	}
}

func TestRelay(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, alpn := range []string{"http/1.1", "h2"} {
			t.Run(alpn+"/"+tls.VersionName(version), func(t *testing.T) {
				m, roots := testca.New(t)
				cert, err := m.Certificate("example.test")
				if err != nil {
					t.Fatal(err)
				}
				up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.TLS.NegotiatedProtocol != alpn {
						t.Errorf("ALPN %q", r.TLS.NegotiatedProtocol)
					}
					io.Copy(w, r.Body)
				}))
				up.EnableHTTP2 = alpn == "h2"
				up.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
				up.StartTLS()
				defer up.Close()
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var keys bytes.Buffer
				p := &Proxy{
					Issuer:       m,
					Roots:        roots,
					Port:         "443",
					Mappings:     map[string]string{"example.test": up.Listener.Addr().String()},
					Idle:         time.Second,
					KeyLogWriter: &keys,
				}
				done := make(chan error, 1)
				go func() { done <- p.Run(ctx, ln) }()
				tr := &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:    roots,
						NextProtos: []string{alpn},
						MaxVersion: version,
					},
					ForceAttemptHTTP2: alpn == "h2",
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
					},
				}
				client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
				req, err := http.NewRequest("POST", "https://example.test/", strings.NewReader("relay test"))
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || string(body) != "relay test" {
					t.Fatalf("%q %v", body, err)
				}
				if alpn == "h2" && resp.ProtoMajor != 2 {
					t.Fatal("HTTP/2 not preserved")
				}
				tr.CloseIdleConnections()
				// A client without the test CA must reject the minted certificate.
				c, err := tls.DialWithDialer(
					&net.Dialer{Timeout: 3 * time.Second},
					"tcp", ln.Addr().String(),
					&tls.Config{ServerName: "example.test"},
				)
				if c != nil {
					c.Close()
				}
				if err == nil {
					t.Fatal("untrusted client accepted certificate")
				}
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("shutdown stalled")
				}
				labels := []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"}
				if version == tls.VersionTLS12 {
					labels = []string{"CLIENT_RANDOM"}
				}
				for _, label := range labels {
					if !strings.Contains(keys.String(), label+" ") {
						t.Fatalf("missing %s in TLS keylog", label)
					}
				}
			})
		}
	}
}

func TestUpstreamVerification(t *testing.T) {
	m, _ := testca.New(t)
	up := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer up.Close()
	p := &Proxy{
		Issuer:   m,
		Port:     "443",
		Mappings: map[string]string{"example.test": up.Listener.Addr().String()},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := p.connect(ctx, "example.test", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	if c != nil {
		c.Close()
	}
	if err == nil {
		t.Fatal("invalid upstream accepted")
	}
	var failure *upstreamError
	if !errors.As(err, &failure) || failure.stage != "tls" {
		t.Fatalf("expected upstream TLS failure, got %v", err)
	}
}

func TestUpstreamFailureLogs(t *testing.T) {
	r := dnsServer(t, func(q dnsmessage.Message) *dnsmessage.Message {
		a := reply(q)
		a.RCode = dnsmessage.RCodeNameError
		return a
	})
	m, roots := testca.New(t)
	p := &Proxy{Issuer: m, Resolver: r, Port: "443"}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(old)
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			p.handle(context.Background(), conn, ln.Addr(), 1)
		}
		done <- err
	}()
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", ln.Addr().String(), &tls.Config{
		ServerName: "missing.test",
		RootCAs:    roots,
	})
	if c != nil {
		c.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "internal error") {
		t.Fatalf("expected internal_error alert, got %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var failed, aborted bool
	decoder := json.NewDecoder(&logs)
	for decoder.More() {
		var event map[string]any
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		switch event["msg"] {
		case "upstream failed":
			failed = true
			if event["stage"] != "dns" || event["error"] == nil {
				t.Fatal(event)
			}
		case "client handshake aborted":
			aborted = true
			if event["stage"] != "dns" || event["reason"] != "upstream_failure" || event["certificate_presented"] != false {
				t.Fatal(event)
			}
		case "client handshake failed":
			t.Fatalf("upstream failure mislabeled as client failure: %v", event)
		}
	}
	if !failed || !aborted {
		t.Fatalf("missing upstream failure or handshake abort event")
	}
}

func TestDNSFallback(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	answer := func(query []byte, truncated bool) []byte {
		var q dnsmessage.Message
		if q.Unpack(query) != nil {
			return nil
		}
		a := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:        q.ID,
				Response:  true,
				Truncated: truncated,
			},
			Questions: q.Questions,
		}
		if !truncated && len(q.Questions) > 0 && q.Questions[0].Type == dnsmessage.TypeA {
			a.Answers = []dnsmessage.Resource{
				{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Questions[0].Name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   60,
					},
					Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 123}},
				},
			}
		}
		b, _ := a.Pack()
		return b
	}
	go func() {
		b := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			udp.WriteTo(answer(b[:n], true), addr)
		}
	}()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				var size [2]byte
				if _, err := io.ReadFull(c, size[:]); err != nil {
					return
				}
				b := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(c, b); err != nil {
					return
				}
				a := answer(b, false)
				binary.BigEndian.PutUint16(size[:], uint16(len(a)))
				c.Write(append(size[:], a...))
			}()
		}
	}()
	resolver, err := Resolver(tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// localhost is present in the host's local name service. The explicit DNS
	// answer must win anyway, on macOS as well as Linux, without editing /etc/hosts.
	local, err := net.DefaultResolver.LookupIPAddr(ctx, "localhost")
	if err != nil || len(local) == 0 {
		t.Fatalf("localhost regression precondition: %v %v", local, err)
	}
	for _, ip := range local {
		if !ip.IP.IsLoopback() {
			t.Fatalf("expected localhost to resolve locally to loopback, got %v", local)
		}
	}
	ips, err := resolver.LookupIPAddr(ctx, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0].IP.String() != "192.0.2.123" {
		t.Fatal(ips)
	}
	if !loops(net.IPv4(127, 0, 0, 1), "443", &net.TCPAddr{IP: net.IPv4zero, Port: 443}) {
		t.Fatal("loop not detected")
	}
}
