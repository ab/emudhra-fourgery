package main

import (
	"os"
	"sync"
)

type keyLogWriter struct {
	mu   sync.Mutex
	file *os.File
}

func openKeyLog(path string) (*keyLogWriter, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return &keyLogWriter{file: file}, nil
}

func (w *keyLogWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Write(data)
}

func (w *keyLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}
