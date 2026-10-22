package main

import (
	"fmt"
	"io"
	"log/slog"
)

func newLogger(w io.Writer, format string, terminal bool) (*slog.Logger, error) {
	if format == "auto" {
		format = "json"
		if terminal {
			format = "text"
		}
	}
	switch format {
	case "json":
		return slog.New(slog.NewJSONHandler(w, nil)), nil
	case "text":
		opts := &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.String(slog.TimeKey, a.Value.Time().Format("15:04:05.000"))
			}
			return a
		}}
		return slog.New(slog.NewTextHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("invalid log format %q: expected auto, text, or json", format)
	}
}
