package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net/http"
	"time"

	"github.com/ab/emudhra-fourgery/internal/issuer"
	"github.com/ab/emudhra-fourgery/internal/static"
)

type serveOptions struct {
	content string
	headers pairs
	types   pairs
}

func serveFlags(flags *flag.FlagSet) *serveOptions {
	opts := &serveOptions{
		headers: pairs{},
		types:   pairs{},
	}
	flags.StringVar(&opts.content, "content", "./content", "directory containing domains/ and default/")
	flags.Var(opts.headers, "header", "response header Name=value (repeatable)")
	flags.Var(opts.types, "content-type", "URL-path or extension=MIME-type (repeatable)")
	return opts
}

func runServe(ctx context.Context, m *issuer.Manager, listen string, opts *serveOptions) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	h, err := static.New(opts.content)
	if err != nil {
		return err
	}
	defer h.Close()
	h.Headers = opts.headers
	for key, value := range opts.types {
		h.Types[key] = value
	}
	certificateForClient := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return m.Certificate(hello.ServerName)
	}
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: certificateForClient,
	}
	server := &http.Server{
		Addr:              listen,
		Handler:           h,
		TLSConfig:         cfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		<-ctx.Done()
		shutdown, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		if server.Shutdown(shutdown) != nil {
			server.Close()
		}
	}()
	slog.Info("static server listening", "address", listen, "content", opts.content)
	err = server.ListenAndServeTLS("", "")
	cancel()
	<-finished
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
