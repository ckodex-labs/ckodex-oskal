//go:build darwin || linux

package main

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReceiptKeyRejectsFIFOWithoutOpening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pipe")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readReceiptPublicKey(path); err == nil {
		t.Fatal("FIFO accepted as key file")
	}
}
