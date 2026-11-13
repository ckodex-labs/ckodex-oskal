package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadOnlyOpenDoesNotCreateMissingEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent-store")
	if _, err := OpenFilesystemEvidenceRepository(path); err == nil {
		t.Fatal("opening an absent store must report absence")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("read-only request changed the filesystem: %v", err)
	}
	if _, err := NewFilesystemEvidenceRepository(path); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFilesystemEvidenceRepository(path); err != nil {
		t.Fatalf("opening the real existing store failed: %v", err)
	}
}
