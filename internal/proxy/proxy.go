package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ab/emudhra-fourgery/internal/issuer"
)

type Proxy struct {
	Issuer         *issuer.Manager
	Resolver       *DNSResolver
	Port           string
	Mappings       map[string]string
	Roots          *x509.CertPool
	Insecure       bool
	Idle           time.Duration
	MaxConnections int
	KeyLogWriter   io.Writer // Client-facing secrets; the writer must be concurrency-safe.
}

type upstreamError struct {
	stage string
	err   error
}

func (e *upstreamError) Error() string { return e.err.Error() }
func (e *upstreamError) Unwrap() error { return e.err }

func (p *Proxy) Run(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	limit := p.MaxConnections
	if limit <= 0 {
		limit = 256
	}
	slots := make(chan struct{}, limit)
	var seq atomic.Uint64
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			slog.Warn("connection limit reached")
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); defer func() { <-slots }(); p.handle(ctx, c, ln.Addr(), seq.Add(1)) }()
	}
}

func (p *Proxy) handle(ctx context.Context, raw net.Conn, listen net.Addr, id uint64) {
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	log := slog.With("connection", id, "client", raw.RemoteAddr().String())
	var upstream *tls.Conn
	defer func() {
		if upstream != nil {
			upstream.Close()
		}
	}()
	var host string
	var upstreamFailure *upstreamError
	raw.SetDeadline(time.Now().Add(15 * time.Second))
	configForClient := func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		var err error
		host, err = issuer.Host(hello.ServerName)
		if err != nil {
			return nil, err
		}
		log = log.With("sni", host)
		cert, err := p.Issuer.Certificate(host)
		if err != nil {
			return nil, err
		}
		hctx, cancel := context.WithTimeout(hello.Context(), 10*time.Second)
		defer cancel()
		upstream, err = p.connect(hctx, host, hello.SupportedProtos, listen)
		if err != nil {
			errors.As(err, &upstreamFailure)
			log.Warn("upstream failed", "stage", upstreamFailure.stage, "error", err)
			return nil, err
		}
		selected := upstream.ConnectionState().NegotiatedProtocol
		cfg := &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*cert},
			KeyLogWriter: p.KeyLogWriter,
		}
		if selected != "" {
			cfg.NextProtos = []string{selected}
		}
		return cfg, nil
	}
	downstream := tls.Server(raw, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		GetConfigForClient: configForClient,
	})
	if err := downstream.HandshakeContext(ctx); err != nil {
		if upstreamFailure != nil {
			log.Info("client handshake aborted",
				"reason", "upstream_failure",
				"stage", upstreamFailure.stage,
				"certificate_presented", false,
			)
		} else if isPlainHTTP(err) {
			log.Info("plain HTTP received on TLS listener")
		} else {
			log.Info("client handshake failed", "error", err)
		}
		return
	}
	if upstream == nil {
		log.Error("missing upstream")
		return
	}
	stopUp := context.AfterFunc(ctx, func() { upstream.Close() })
	defer stopUp()
	raw.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})
	state := downstream.ConnectionState()
	log.Info("client handshake completed",
		"tls_version", tls.VersionName(state.Version),
		"alpn", state.NegotiatedProtocol,
		"upstream", upstream.RemoteAddr().String(),
	)
	idle := p.Idle
	if idle <= 0 {
		idle = 2 * time.Minute
	}
	// Any traffic refreshes both legs' deadlines, including long unidirectional streams.
	touch := func() {
		deadline := time.Now().Add(idle)
		downstream.SetDeadline(deadline)
		upstream.SetDeadline(deadline)
	}
	touch()
	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := io.Copy(activity{upstream, touch}, activity{downstream, touch})
		upstream.CloseWrite()
		done <- result{n, err}
	}()
	n, err := io.Copy(activity{downstream, touch}, activity{upstream, touch})
	downstream.CloseWrite()
	if err != nil {
		downstream.Close()
		upstream.Close()
	}
	other := <-done
	attrs := []any{"client_bytes", other.n, "upstream_bytes", n}
	if other.err != nil {
		attrs = append(attrs, "client_error", other.err)
	}
	if err != nil {
		attrs = append(attrs, "upstream_error", err)
	}
	log.Info("relay closed", attrs...)
}

func isPlainHTTP(err error) bool {
	var header tls.RecordHeaderError
	if !errors.As(err, &header) {
		return false
	}
	prefix := string(header.RecordHeader[:])
	for _, method := range []string{
		"GET ",
		"HEAD ",
		"POST ",
		"PUT ",
		"DELETE ",
		"CONNECT ",
		"OPTIONS ",
		"TRACE ",
		"PATCH ",
		"PRI *",
	} {
		// Only five bytes are available; longer methods can only be identified
		// by their prefix. PRI * identifies the cleartext HTTP/2 preface.
		if len(method) > len(prefix) {
			method = method[:len(prefix)]
		}
		if strings.HasPrefix(prefix, method) {
			return true
		}
	}
	return false
}

type activity struct {
	net.Conn
	touch func()
}

func (a activity) Read(b []byte) (int, error) {
	n, e := a.Conn.Read(b)
	if n > 0 {
		a.touch()
	}
	return n, e
}
func (a activity) Write(b []byte) (int, error) {
	n, e := a.Conn.Write(b)
	if n > 0 {
		a.touch()
	}
	return n, e
}

func (p *Proxy) connect(ctx context.Context, host string, protos []string, listen net.Addr) (*tls.Conn, error) {
	address := net.JoinHostPort(host, p.Port)
	if mapped := p.Mappings[host]; mapped != "" {
		address = mapped
	}
	h, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &upstreamError{"connect", err}
	}
	var ips []net.IPAddr
	if ip := net.ParseIP(h); ip != nil {
		ips = []net.IPAddr{{IP: ip}}
	} else {
		if p.Resolver == nil {
			return nil, &upstreamError{"dns", fmt.Errorf("upstream DNS resolver required")}
		}
		ips, err = p.Resolver.LookupIPAddr(ctx, h)
		if err != nil {
			return nil, &upstreamError{"dns", err}
		}
	}
	if len(ips) == 0 {
		return nil, &upstreamError{"dns", fmt.Errorf("no upstream addresses")}
	}
	var last error
	for _, ip := range ips {
		if loops(ip.IP, port, listen) {
			last = &upstreamError{"connect", fmt.Errorf("upstream points back to listener: %s", ip.IP)}
			continue
		}
		dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		raw, e := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(ip.String(), port))
		if e != nil {
			cancel()
			last = &upstreamError{"connect", e}
			continue
		}
		up := tls.Client(raw, &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         host,
			RootCAs:            p.Roots,
			InsecureSkipVerify: p.Insecure,
			NextProtos:         protos,
		})
		e = up.HandshakeContext(dialCtx)
		cancel()
		if e == nil {
			return up, nil
		}
		raw.Close()
		last = &upstreamError{"tls", e}
	}
	return nil, last
}

func loops(ip net.IP, port string, listen net.Addr) bool {
	addr, ok := listen.(*net.TCPAddr)
	if !ok || strconv.Itoa(addr.Port) != port {
		return false
	}
	if addr.IP.Equal(ip) {
		return true
	}
	if !addr.IP.IsUnspecified() {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	addresses, _ := net.InterfaceAddrs()
	for _, a := range addresses {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}
