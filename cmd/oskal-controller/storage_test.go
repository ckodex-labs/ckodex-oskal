package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDurableEvidenceStorageRejectsUnavailablePath(t *testing.T) {
	if repo, err := openEvidenceRepository(""); err == nil || repo != nil {
		t.Fatal("empty storage path must refuse startup")
	}
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("preserve this file"), 0600); err != nil {
		t.Fatal(err)
	}
	if repo, err := openEvidenceRepository(path); err == nil || repo != nil {
		t.Fatal("an unusable durable store must not fall back to memory")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "preserve this file" {
		t.Fatalf("failed startup changed existing bytes: %q, %v", raw, err)
	}
	if _, err := openEvidenceRepository(t.TempDir()); err != nil {
		t.Fatalf("real writable storage failed: %v", err)
	}
}
