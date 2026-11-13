package main

import (
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
	return os.Rename(name, path)
}
