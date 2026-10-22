package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ab/emudhra-fourgery/internal/issuer"
	"golang.org/x/term"
)

type pairs map[string]string

func (p pairs) String() string { return fmt.Sprint(map[string]string(p)) }
func (p pairs) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok || k == "" {
		return fmt.Errorf("expected key=value")
	}
	p[k] = v
	return nil
}

func main() {
	logger, _ := newLogger(os.Stderr, "auto", term.IsTerminal(int(os.Stderr.Fd())))
	slog.SetDefault(logger)
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) == 2 && (os.Args[1] == "-help" || os.Args[1] == "--help" || os.Args[1] == "-h" || os.Args[1] == "help") {
		fmt.Fprintln(os.Stdout, `Usage: fourgery <command> [flags]

Commands:
  proxy  Intercept TLS and relay to an independently resolved upstream
  serve  Serve static content by hostname with a default site

Examples:
  fourgery proxy --listen :8443 --upstream-dns 1.1.1.1:53
  fourgery serve --listen :8443 --content ./examples/content

Run fourgery <command> --help for command-specific flags.`)
		return nil
	}
	if len(os.Args) < 2 || (os.Args[1] != "proxy" && os.Args[1] != "serve") {
		return fmt.Errorf("usage: fourgery {proxy|serve} [flags]; use subcommand -help")
	}
	mode := os.Args[1]
	flags := flag.NewFlagSet(mode, flag.ExitOnError)
	listen := flags.String("listen", ":8443", "TCP TLS listen address")
	cache := flags.Int("cert-cache", 1024, "maximum cached leaf certificates")
	logFormat := flags.String("log-format", "auto",
		"log format: auto (text on terminal, JSON otherwise), text, or json",
	)
	var proxyArgs *proxyOptions
	var serveArgs *serveOptions
	if mode == "proxy" {
		proxyArgs = proxyFlags(flags)
	} else {
		serveArgs = serveFlags(flags)
	}
	flags.Parse(os.Args[2:])
	logger, err := newLogger(os.Stderr, *logFormat, term.IsTerminal(int(os.Stderr.Fd())))
	if err != nil {
		return err
	}
	slog.SetDefault(logger)
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *cache < 1 {
		return fmt.Errorf("cert-cache must be positive")
	}
	m, err := issuer.New()
	if err != nil {
		return err
	}
	m.Limit = *cache
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if mode == "proxy" {
		return runProxy(ctx, m, *listen, proxyArgs)
	}
	return runServe(ctx, m, *listen, serveArgs)
}
