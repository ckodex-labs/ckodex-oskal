package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestReceiptPublicKeyFileBounds(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := []byte(hex.EncodeToString(public))
	directory := t.TempDir()
	path := filepath.Join(directory, "trusted.pub")
	maximum := append(append([]byte(nil), encoded...), bytes.Repeat([]byte("\n"), 4096-len(encoded))...)
	if err := os.WriteFile(path, maximum, 0600); err != nil {
		t.Fatal(err)
	}
	key, err := readReceiptPublicKey(path)
	if err != nil || !bytes.Equal(key, public) {
		t.Fatalf("4 KiB boundary changed key: %x %v", key, err)
	}
	for _, value := range []string{"", directory} {
		if _, err := readReceiptPublicKey(value); err == nil {
			t.Fatalf("invalid key source %q accepted", value)
		}
	}
	for _, raw := range [][]byte{nil, append(maximum, '\n')} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readReceiptPublicKey(path); err == nil {
			t.Fatal("empty/oversized key accepted")
		}
	}
}
