package storage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
)

// publishBlob is create-only. Digest identities never overwrite existing bytes,
// including corrupt bytes that must survive for explicit operator recovery.
func publishBlob(path string, data []byte) error {
	compare := func() error {
		existing, err := readEvidenceFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, data) {
			return &IntegrityError{Path: path, Reason: "immutable blob identity already contains different bytes"}
		}
		return nil
	}
	if _, err := os.Lstat(path); err == nil {
		return compare()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".oskal-cas-tmp-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
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
	if err := os.Chmod(temporary, 0644); err != nil {
		return err
	}
	if err := os.Link(temporary, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return compare()
		}
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
