package storage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// Receipt lookup keys are single bounded filename components on all platforms.
func safeReceiptKey(key string) bool {
	if key == "" || len(key) > 200 || strings.Contains(key, "..") {
		return false
	}
	for _, c := range key {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.()", c) {
			continue
		}
		return false
	}
	return key != "."
}

// Both legacy 48-bit references and current full SHA-256 references reserve their
// namespace. A control alias may never masquerade as either kind of digest.
func receiptDigestSuffix(key string) (string, bool) {
	if !strings.HasPrefix(strings.ToLower(key), "rcpt-") {
		return "", false
	}
	suffix := key[5:]
	if len(suffix) != 12 && len(suffix) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(suffix); err != nil {
		return "", false
	}
	return strings.ToLower(suffix), true
}
func receiptAliases(receipt assurance.ControlReceipt) ([]string, error) {
	control := "rcpt-" + receipt.Control.ID
	if !safeReceiptKey(receipt.Control.ID) || !safeReceiptKey(control) {
		return nil, errors.New("receipt control ID cannot form a safe alias")
	}
	if _, reserved := receiptDigestSuffix(control); reserved {
		return nil, errors.New("receipt control alias occupies a reserved digest namespace")
	}
	aliases := []string{control}
	_, _, leaf := extractSubjectNamespaceKindAndLeaf(receipt.Subject)
	if leaf != "" {
		for _, alias := range []string{leaf + "-" + receipt.Control.ID, "rcpt-" + leaf + "-" + receipt.Control.ID} {
			_, reserved := receiptDigestSuffix(alias)
			if safeReceiptKey(leaf) && safeReceiptKey(alias) && !reserved {
				aliases = append(aliases, alias)
			}
		}
	}
	return aliases, nil
}
func validReceiptEncoding(receipt assurance.ControlReceipt) bool {
	signature, err := hex.DecodeString(receipt.Signature)
	return err == nil && len(signature) == ed25519.SignatureSize && receipt.Subject.Validate() == nil && receipt.Control.Validate() == nil
}
func latestReceipt(candidate, current assurance.ControlReceipt) bool {
	if !candidate.EvaluatedAt.Equal(current.EvaluatedAt) {
		return candidate.EvaluatedAt.After(current.EvaluatedAt)
	}
	return candidate.Digest() > current.Digest()
}
func (r *ContentAddressedEvidenceRepository) indexReceipt(receipt assurance.ControlReceipt, hash, key string) {
	r.receipts["rcpt-"+hash] = receipt
	r.receipts[hash] = receipt
	if _, digestKey := receiptDigestSuffix(key); digestKey {
		r.receipts[key] = receipt
	}
	aliases, err := receiptAliases(receipt)
	if err != nil {
		return
	} // Preserve immutable legacy history without unsafe aliases.
	for _, alias := range aliases {
		if previous, exists := r.receipts[alias]; !exists || latestReceipt(receipt, previous) {
			r.receipts[alias] = receipt
		}
	}
}

func readReceiptFile(root *os.Root, name string) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("receipt must be a regular file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, MaxPayloadBytes+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	if len(data) > MaxPayloadBytes {
		return nil, errors.New("receipt exceeds storage read bound")
	}
	return data, nil
}
func readLegacyReceipt(baseDir, name string) ([]byte, error) {
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return readReceiptFile(root, name)
}
func (r *ContentAddressedEvidenceRepository) loadReceipts() error {
	base, err := os.OpenRoot(r.baseDir)
	if err != nil {
		return err
	}
	defer func() { _ = base.Close() }()
	root, err := base.OpenRoot("receipts")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return &IntegrityError{Path: filepath.Join(r.baseDir, "receipts"), Reason: "cannot open confined receipt directory: " + err.Error()}
	}
	defer func() { _ = root.Close() }()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(r.baseDir, "receipts", entry.Name())
		data, err := readReceiptFile(root, entry.Name())
		if err != nil {
			return &IntegrityError{Path: path, Reason: "cannot read confined receipt: " + err.Error()}
		}
		if err := r.restoreReceipt(path, data); err != nil {
			return err
		}
	}
	return nil
}

// publishReceipt uses a confined temporary file. Immutable objects are published
// with Link (create only), so an existing digest object is never replaced.
func publishReceipt(root *os.Root, name string, data []byte, immutable bool) error {
	if info, err := root.Lstat(name); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("existing receipt target is not a regular file")
		}
		if immutable {
			return compareReceipt(root, name, data)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	temporary := ".oskal-receipt-" + rand.Text()
	file, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(temporary) }()
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
	if !immutable {
		return root.Rename(temporary, name)
	}
	if err := root.Link(temporary, name); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return compareReceipt(root, name, data)
		}
		return err
	}
	return nil
}
func compareReceipt(root *os.Root, name string, expected []byte) error {
	actual, err := readReceiptFile(root, name)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return &IntegrityError{Path: name, Reason: "immutable receipt identity already contains different bytes"}
	}
	return nil
}
func (r *ContentAddressedEvidenceRepository) persistReceipt(id string, data []byte, aliases []string) error {
	base, err := os.OpenRoot(r.baseDir)
	if err != nil {
		return err
	}
	defer func() { _ = base.Close() }()
	if err := base.MkdirAll("receipts", 0755); err != nil {
		return err
	}
	root, err := base.OpenRoot("receipts")
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := publishReceipt(root, id+".json", data, true); err != nil {
		return fmt.Errorf("persist immutable receipt: %w", err)
	}
	for _, alias := range aliases {
		if !strings.HasPrefix(alias, "rcpt-") {
			continue
		}
		if err := publishReceipt(root, alias+".json", data, false); err != nil {
			return fmt.Errorf("persist receipt compatibility alias: %w", err)
		}
		if err := publishReceipt(base, alias+".json", data, false); err != nil {
			return fmt.Errorf("persist legacy receipt compatibility alias: %w", err)
		}
	}
	return nil
}

func validateStoredReceiptName(key, hash string, receipt assurance.ControlReceipt) error {
	if !safeReceiptKey(key) {
		return errors.New("unsafe receipt filename")
	}
	if suffix, digestKey := receiptDigestSuffix(key); digestKey {
		if suffix != hash[:len(suffix)] {
			return errors.New("receipt content does not match its digest filename")
		}
		return nil
	}
	aliases, err := receiptAliases(receipt)
	if err != nil {
		return err
	}
	for _, alias := range aliases {
		if key == alias {
			return nil
		}
	}
	return errors.New("receipt filename is neither its digest nor its declared compatibility alias")
}

// canonicalReceiptKey accepts complete digests and safe compatibility IDs. It
// never accepts paths or adds arbitrary strings to a filesystem location.
func canonicalReceiptKey(value string) (string, error) {
	if strings.HasPrefix(value, "sha256:") {
		hash := strings.TrimPrefix(value, "sha256:")
		if !isValidHexDigest(hash) {
			return "", errors.New("receipt digest must contain 64 lowercase hexadecimal characters")
		}
		return "rcpt-" + hash, nil
	}
	if !safeReceiptKey(value) {
		return "", errors.New("unsafe receipt lookup ID")
	}
	if isValidHexDigest(value) {
		return "rcpt-" + value, nil
	}
	return value, nil
}
