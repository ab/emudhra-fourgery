package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestKeyLogAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.keys")
	for _, line := range []string{"first session\n", "second session\n"} {
		writer, err := openKeyLog(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(line)); err != nil {
			writer.Close()
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first session\nsecond session\n" {
		t.Fatalf("keylog was not preserved across opens: %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		t.Fatalf("keylog permissions too broad: %v", info.Mode())
	}
}
