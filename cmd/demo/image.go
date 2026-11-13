package main

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type imageDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type archiveIdentity struct {
	Index, Manifest, Config string
	Layers                  []imageDescriptor
	DiffIDs                 []string
}

// exportedIdentity verifies the actual exported bytes before Kind imports them.
// Docker's image ID may identify an OCI manifest or an image configuration.
func exportedIdentity(ctx context.Context, archive, sourceID, architecture string) (archiveIdentity, error) {
	var identity archiveIdentity
	indexRaw, err := archiveJSON(ctx, archive, "index.json")
	if err != nil {
		return identity, err
	}
	var index struct {
		SchemaVersion int               `json:"schemaVersion"`
		Manifests     []imageDescriptor `json:"manifests"`
	}
	if err := json.Unmarshal(indexRaw, &index); err != nil {
		return identity, err
	}
	if index.SchemaVersion != 2 || len(index.Manifests) != 1 || !digestReference.MatchString(index.Manifests[0].Digest) {
		return identity, fmt.Errorf("exported image must contain one explicit OCI platform manifest; inspect the retained archive")
	}
	identity.Index = bytesDigest(indexRaw)
	identity.Manifest = index.Manifests[0].Digest
	manifestRaw, err := archiveJSON(ctx, archive, blobPath(identity.Manifest))
	if err != nil {
		return identity, err
	}
	if bytesDigest(manifestRaw) != identity.Manifest || int64(len(manifestRaw)) != index.Manifests[0].Size {
		return identity, fmt.Errorf("exported manifest bytes do not match their OCI descriptor")
	}
	var manifest struct {
		SchemaVersion int               `json:"schemaVersion"`
		Config        imageDescriptor   `json:"config"`
		Layers        []imageDescriptor `json:"layers"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return identity, err
	}
	if manifest.SchemaVersion != 2 || !digestReference.MatchString(manifest.Config.Digest) || len(manifest.Layers) == 0 || len(manifest.Layers) > 128 {
		return identity, fmt.Errorf("exported manifest lacks a bounded configuration/layer identity")
	}
	identity.Config, identity.Layers = manifest.Config.Digest, manifest.Layers
	configRaw, err := archiveJSON(ctx, archive, blobPath(identity.Config))
	if err != nil {
		return identity, err
	}
	if bytesDigest(configRaw) != identity.Config || int64(len(configRaw)) != manifest.Config.Size {
		return identity, fmt.Errorf("exported configuration bytes do not match their OCI descriptor")
	}
	if sourceID != identity.Manifest && sourceID != identity.Config {
		return identity, fmt.Errorf("docker's built identity is absent from the actual exported manifest/configuration")
	}
	var config struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
		RootFS       struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := json.Unmarshal(configRaw, &config); err != nil {
		return identity, err
	}
	if config.Architecture != architecture || config.OS != "linux" || len(config.RootFS.DiffIDs) != len(manifest.Layers) {
		return identity, fmt.Errorf("exported configuration does not match the actual Linux node and layer count")
	}
	identity.DiffIDs = config.RootFS.DiffIDs
	for _, digest := range identity.DiffIDs {
		if !digestReference.MatchString(digest) {
			return identity, fmt.Errorf("exported configuration contains a malformed layer identity")
		}
	}
	pending := make(map[string]imageDescriptor, len(identity.Layers))
	for _, layer := range identity.Layers {
		if !digestReference.MatchString(layer.Digest) || layer.Size <= 0 || layer.Size > 512<<20 {
			return identity, fmt.Errorf("exported image layer exceeds its identity/size bound")
		}
		pending[blobPath(layer.Digest)] = layer
	}
	err = walkArchive(ctx, archive, func(header *tar.Header, body io.Reader) error {
		layer, found := pending[header.Name]
		if !found {
			return nil
		}
		if header.Size != layer.Size {
			return fmt.Errorf("exported layer size differs from its descriptor")
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, body); err != nil {
			return err
		}
		if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != layer.Digest {
			return fmt.Errorf("exported layer bytes differ from their descriptor")
		}
		delete(pending, header.Name)
		return nil
	})
	if err != nil {
		return identity, err
	}
	if len(pending) != 0 {
		return identity, fmt.Errorf("exported archive is missing %d declared image layers", len(pending))
	}
	return identity, nil
}

func blobPath(digest string) string { return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:") }

func bytesDigest(raw []byte) string {
	hash := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func archiveJSON(ctx context.Context, archive, name string) ([]byte, error) {
	var raw []byte
	err := walkArchive(ctx, archive, func(header *tar.Header, body io.Reader) error {
		if header.Name != name {
			return nil
		}
		if raw != nil || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > 1<<20 {
			return fmt.Errorf("image metadata %s is duplicated or exceeds its file/size bound", name)
		}
		var err error
		raw, err = io.ReadAll(body)
		return err
	})
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf("exported OCI image lacks %s; inspect the retained archive before changing runtime assumptions", name)
	}
	return raw, nil
}

func walkArchive(ctx context.Context, path string, visit func(*tar.Header, io.Reader) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 2<<30 {
		return fmt.Errorf("exported image archive exceeds the 2 GiB demo bound")
	}
	reader := tar.NewReader(file)
	for count := 0; count < 4096; count++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := visit(header, reader); err != nil {
			return err
		}
	}
	return fmt.Errorf("exported image archive exceeds the 4096-entry demo bound")
}
