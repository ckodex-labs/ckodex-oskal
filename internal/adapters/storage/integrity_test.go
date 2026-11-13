package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestFilesystemRestoreFailsClosedAndPreservesCorruption(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		data       []byte
	}{
		{"wrong-payload-digest", "blobs/sha256/" + strings.Repeat("0", 64) + ".bin", []byte("corrupt binary payload")},
		{"invalid-blob-name", "blobs/sha256/not-a-digest.json", []byte(`{}`)},
		{"malformed-envelope", "blobs/sha256/" + assurance.ComputeDigest([]byte(`{}`))[7:] + ".json", []byte(`{}`)},
		{"malformed-legacy", "admission.json", []byte(`{"id":`)},
		{"malformed-receipt", "receipts/rcpt-damaged.json", []byte(`{}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := NewFilesystemEvidenceRepository(dir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, tc.path)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			repo, err := NewFilesystemEvidenceRepository(dir)
			var failure *IntegrityError
			if repo != nil || !errors.As(err, &failure) || failure.Path != path {
				t.Fatalf("expected no repository and affected path: repo=%v err=%v", repo, err)
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, tc.data) {
				t.Fatalf("forensic bytes changed: err=%v", err)
			}
		})
	}
}

func TestFilesystemRestoreDoesNotFollowBlobSymlinks(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewFilesystemEvidenceRepository(dir); err != nil {
		t.Fatal(err)
	}
	data := []byte("external evidence bytes")
	source := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "blobs", "sha256", assurance.ComputeDigest(data)[7:]+".bin")
	if err := os.Symlink(source, path); err != nil {
		t.Fatal(err)
	}
	repo, err := NewFilesystemEvidenceRepository(dir)
	var failure *IntegrityError
	if repo != nil || !errors.As(err, &failure) {
		t.Fatalf("symlink admitted: repo=%v err=%v", repo, err)
	}
}

func TestLegacyEnvelopeUsesSerializedByteDigest(t *testing.T) {
	dir := t.TempDir()
	env := createTestEnvelope("legacy", "default/Pod/legacy", "legacy.file")
	raw := []byte(`[]`)
	// Preserve unrelated export JSON alongside a legacy observation.
	if err := os.WriteFile(filepath.Join(dir, "empty-export.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	// Real repository serialization supplies an envelope, not a mocked backend.
	source := NewMemoryEvidenceRepository()
	ref, err := source.Put(context.Background(), env, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := source.blobs[ref.Digest]
	if err := os.WriteFile(filepath.Join(dir, "admission.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	repo, err := NewFilesystemEvidenceRepository(dir)
	if err != nil {
		t.Fatal(err)
	}
	count, err := repo.VerifyIntegrity(context.Background())
	if err != nil || count != 1 {
		t.Fatalf("legacy serialized bytes not recoverable: count=%d err=%v", count, err)
	}
}
