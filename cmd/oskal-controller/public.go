package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// writePublicFact publishes a complete public trust snapshot atomically. Private
// keys and bearer credentials must never be passed to this helper.
func writePublicFact(path string, data []byte) error {
	if len(data) == 0 || len(data) > 1<<20 {
		return fmt.Errorf("public trust fact must contain 1..1048576 bytes")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".public-fact-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0644); err != nil {
		return err
	}
	// Link a synced temporary inode into the digest namespace without replacing
	// an existing historical proof. The latest alias is published only afterward.
	sum := sha256.Sum256(data)
	history := path + ".d"
	if err := os.MkdirAll(history, 0755); err != nil {
		return err
	}
	immutable := filepath.Join(history, hex.EncodeToString(sum[:])+".json")
	if err := os.Link(name, immutable); err != nil {
		if !os.IsExist(err) {
			return err
		}
		existing, readErr := os.ReadFile(immutable)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("public trust snapshot digest collision or corrupt history")
		}
	}
	if err := syncDirectory(history); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
