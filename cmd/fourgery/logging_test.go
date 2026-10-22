package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestLogFormats(t *testing.T) {
	for _, tc := range []struct {
		format   string
		terminal bool
		json     bool
	}{
		{"auto", true, false},
		{"auto", false, true},
		{"text", false, false},
		{"json", true, true},
	} {
		t.Run(tc.format+"/terminal="+map[bool]string{true: "yes", false: "no"}[tc.terminal], func(t *testing.T) {
			var buf bytes.Buffer
			logger, err := newLogger(&buf, tc.format, tc.terminal)
			if err != nil {
				t.Fatal(err)
			}
			logger.With("connection", 7).Info("handshake completed", "tls_version", "TLS1.3")
			if tc.json {
				var event map[string]any
				if err := json.Unmarshal(buf.Bytes(), &event); err != nil {
					t.Fatal(err)
				}
				if event["connection"] != float64(7) || event["tls_version"] != "TLS1.3" || event["time"] == nil {
					t.Fatal(event)
				}
			} else {
				text := buf.String()
				for _, field := range []string{"level=INFO", "connection=7", "tls_version=TLS1.3"} {
					if !strings.Contains(text, field) {
						t.Fatalf("missing %s: %s", field, text)
					}
				}
				stamp := strings.Fields(text)[0]
				if len(stamp) != len("time=15:04:05.000") {
					t.Fatalf("expected short text timestamp, got %s", stamp)
				}
			}
		})
	}
	if _, err := newLogger(&bytes.Buffer{}, "invalid", false); err == nil {
		t.Fatal("invalid format accepted")
	}
}
