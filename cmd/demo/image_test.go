package main

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExportedIdentityRejectsChangedContent(t *testing.T) {
	layer := []byte("image layer bytes")
	config, err := json.Marshal(map[string]any{"architecture": "arm64", "os": "linux", "rootfs": map[string]any{"diff_ids": []string{bytesDigest(layer)}}})
	if err != nil {
		t.Fatal(err)
	}
	configDescriptor := imageDescriptor{Digest: bytesDigest(config), Size: int64(len(config))}
	layerDescriptor := imageDescriptor{Digest: bytesDigest(layer), Size: int64(len(layer))}
	manifest, err := json.Marshal(map[string]any{"schemaVersion": 2, "config": configDescriptor, "layers": []imageDescriptor{layerDescriptor}})
	if err != nil {
		t.Fatal(err)
	}
	manifestDescriptor := imageDescriptor{Digest: bytesDigest(manifest), Size: int64(len(manifest))}
	index, err := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []imageDescriptor{manifestDescriptor}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, change, sourceID, architecture string
		wantError                            bool
	}{
		{name: "manifest identity", sourceID: manifestDescriptor.Digest, architecture: "arm64"},
		{name: "configuration identity", sourceID: configDescriptor.Digest, architecture: "arm64"},
		{name: "changed manifest", change: "manifest", sourceID: manifestDescriptor.Digest, architecture: "arm64", wantError: true},
		{name: "changed configuration", change: "config", sourceID: manifestDescriptor.Digest, architecture: "arm64", wantError: true},
		{name: "changed layer", change: "layer", sourceID: manifestDescriptor.Digest, architecture: "arm64", wantError: true},
		{name: "unrelated source image", sourceID: bytesDigest([]byte("another image")), architecture: "arm64", wantError: true},
		{name: "different node architecture", sourceID: manifestDescriptor.Digest, architecture: "amd64", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			entries := map[string][]byte{"index.json": index, blobPath(manifestDescriptor.Digest): manifest, blobPath(configDescriptor.Digest): config, blobPath(layerDescriptor.Digest): layer}
			for name, descriptor := range map[string]imageDescriptor{"manifest": manifestDescriptor, "config": configDescriptor, "layer": layerDescriptor} {
				if test.change == name {
					changed := append([]byte(nil), entries[blobPath(descriptor.Digest)]...)
					changed[len(changed)-1] ^= 1
					entries[blobPath(descriptor.Digest)] = changed
				}
			}
			archive := filepath.Join(t.TempDir(), "image.tar")
			writeArchive(t, archive, entries)
			identity, err := exportedIdentity(t.Context(), archive, test.sourceID, test.architecture)
			if test.wantError {
				if err == nil {
					t.Fatal("changed image content or platform was admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if identity.Manifest != manifestDescriptor.Digest || identity.Config != configDescriptor.Digest || identity.Index != bytesDigest(index) {
				t.Fatal("verified image association lost its typed digests")
			}
		})
	}
}

func TestExportedIdentityHonorsCancellation(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "image.tar")
	writeArchive(t, archive, map[string][]byte{"index.json": []byte(`{}`)})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := exportedIdentity(ctx, archive, "", "arm64"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled image verification returned %v", err)
	}
}

func writeArchive(t *testing.T, path string, entries map[string][]byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	writer := tar.NewWriter(file)
	for name, raw := range entries {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(raw)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}
