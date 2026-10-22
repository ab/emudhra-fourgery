package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/ab/emudhra-fourgery/internal/issuer"
	"github.com/ab/emudhra-fourgery/internal/proxy"
)

type proxyOptions struct {
	dns        string
	port       string
	roots      string
	insecure   bool
	idle       time.Duration
	max        int
	keyLogPath string
	mappings   pairs
}

func proxyFlags(flags *flag.FlagSet) *proxyOptions {
	opts := &proxyOptions{mappings: pairs{}}
	flags.StringVar(&opts.dns, "upstream-dns", "", "required upstream resolver literal IP:port")
	flags.StringVar(&opts.port, "upstream-port", "443", "upstream TLS port")
	flags.StringVar(&opts.roots, "upstream-ca", "", "optional PEM CA bundle added to system trust")
	flags.BoolVar(&opts.insecure, "upstream-insecure", false, "disable upstream TLS host verification")
	flags.DurationVar(&opts.idle, "idle-timeout", 2*time.Minute, "relay idle timeout")
	flags.IntVar(&opts.max, "max-connections", 256, "maximum simultaneous proxy connections")
	flags.StringVar(&opts.keyLogPath, "tls-keylog", "",
		"append client-facing TLS session secrets to a Wireshark-compatible keylog file",
	)
	flags.Var(opts.mappings, "upstream", "hostname=IP:port override (repeatable)")
	return opts
}

func runProxy(ctx context.Context, m *issuer.Manager, listen string, opts *proxyOptions) error {
	resolver, err := proxy.Resolver(opts.dns)
	if err != nil {
		return err
	}
	n, err := strconv.Atoi(opts.port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid upstream port")
	}
	if opts.idle <= 0 || opts.max < 1 {
		return fmt.Errorf("idle-timeout and max-connections must be positive")
	}
	normalized := map[string]string{}
	for k, v := range opts.mappings {
		h, err := issuer.Host(k)
		if err != nil {
			return err
		}
		ip, p, err := net.SplitHostPort(v)
		if err != nil || net.ParseIP(ip) == nil {
			return fmt.Errorf("upstream mapping requires IP:port")
		}
		pn, e := strconv.Atoi(p)
		if e != nil || pn < 1 || pn > 65535 {
			return fmt.Errorf("invalid mapping port")
		}
		normalized[h] = v
	}
	var pool *x509.CertPool
	if opts.roots != "" {
		pool, err = x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		data, e := os.ReadFile(opts.roots)
		if e != nil {
			return e
		}
		if !pool.AppendCertsFromPEM(data) {
			return fmt.Errorf("no CA certificates in upstream-ca")
		}
	}
	p := &proxy.Proxy{
		Issuer:         m,
		Resolver:       resolver,
		Port:           opts.port,
		Mappings:       normalized,
		Roots:          pool,
		Insecure:       opts.insecure,
		Idle:           opts.idle,
		MaxConnections: opts.max,
	}
	if opts.keyLogPath != "" {
		writer, err := openKeyLog(opts.keyLogPath)
		if err != nil {
			return fmt.Errorf("TLS keylog: %w", err)
		}
		defer writer.Close()
		p.KeyLogWriter = writer
		slog.Info("TLS key logging enabled", "path", opts.keyLogPath, "leg", "client")
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	slog.Info("proxy listening",
		"address", ln.Addr().String(),
		"upstream_dns", opts.dns,
		"upstream_insecure", opts.insecure,
	)
	return p.Run(ctx, ln)
}
