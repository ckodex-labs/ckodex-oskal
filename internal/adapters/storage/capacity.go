package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

const (
	DefaultArchiveBytes   int64 = 64 << 20
	DefaultArchiveEntries       = 8192
	MaxMetadataBytes            = 64 << 10
	maxMetadataItems            = 256
)

// ArchiveLimits bound accounted disk objects and canonical resident objects
// separately. They are storage budgets, not a claim about exact Go heap/RSS.
type ArchiveLimits struct {
	MaxBytes   int64
	MaxEntries int
}

func DefaultArchiveLimits() ArchiveLimits {
	return ArchiveLimits{MaxBytes: DefaultArchiveBytes, MaxEntries: DefaultArchiveEntries}
}

// Validate rejects invalid budgets before constructors create any files.
func (l ArchiveLimits) Validate() error {
	if l.MaxBytes <= 0 || l.MaxBytes > 1<<40 || l.MaxEntries <= 0 || l.MaxEntries > 1_000_000 {
		return fmt.Errorf("archive limits require 1..1099511627776 bytes and 1..1000000 entries")
	}
	return nil
}

// CapacityError retains the exhausted dimension without deleting historical data.
type CapacityError struct {
	Dimension              string
	Used, Requested, Limit int64
}

func (e *CapacityError) Error() string {
	return fmt.Sprintf("%s: %s used=%d requested=%d limit=%d; preserve history and review archive limits before resuming", ports.ErrEvidenceCapacity, e.Dimension, e.Used, e.Requested, e.Limit)
}
func (e *CapacityError) Unwrap() error { return ports.ErrEvidenceCapacity }

// ArchiveUsage is conservative: failed writes may retain reservations until reopen.
type ArchiveUsage struct {
	DiskBytes, ResidentBytes     int64
	DiskEntries, ResidentEntries int
	Limits                       ArchiveLimits
}

func (r *ContentAddressedEvidenceRepository) Usage() ArchiveUsage {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return ArchiveUsage{DiskBytes: r.diskBytes, ResidentBytes: r.residentBytes, DiskEntries: len(r.diskObjects), ResidentEntries: len(r.residentObjects), Limits: r.limits}
}

func checkCapacity(objects map[string]int64, used int64, changes map[string]int64, limits ArchiveLimits, dimension string) error {
	entries := len(objects)
	for key, size := range changes {
		old, exists := objects[key]
		if !exists {
			entries++
			if entries > limits.MaxEntries {
				return &CapacityError{Dimension: dimension + " entries", Used: int64(len(objects)), Requested: int64(entries - len(objects)), Limit: int64(limits.MaxEntries)}
			}
		}
		if size > old {
			delta := size - old
			if delta > limits.MaxBytes-used {
				return &CapacityError{Dimension: dimension + " bytes", Used: used, Requested: delta, Limit: limits.MaxBytes}
			}
			used += delta
		}
	}
	return nil
}
func reserveCapacity(objects map[string]int64, used *int64, changes map[string]int64) {
	for key, size := range changes {
		old, exists := objects[key]
		if !exists || size > old {
			objects[key] = size
			*used += size - old
		}
	}
}

// Called under the write mutex (or during constructor-only restore). All budgets
// are checked before any reservation or persistent write; failures are conservative.
func (r *ContentAddressedEvidenceRepository) admit(disk, resident map[string]int64) error {
	if err := checkCapacity(r.diskObjects, r.diskBytes, disk, r.limits, "archive"); err != nil {
		return err
	}
	if err := checkCapacity(r.residentObjects, r.residentBytes, resident, r.limits, "resident"); err != nil {
		return err
	}
	reserveCapacity(r.diskObjects, &r.diskBytes, disk)
	reserveCapacity(r.residentObjects, &r.residentBytes, resident)
	return nil
}

func boundedDirectory(file *os.File, max int) ([]os.DirEntry, error) {
	var result []os.DirEntry
	for {
		entries, err := file.ReadDir(min(128, max+1-len(result)))
		result = append(result, entries...)
		if len(result) > max {
			return nil, &CapacityError{Dimension: "directory entries", Requested: int64(len(result)), Limit: int64(max)}
		}
		if err == io.EOF {
			return result, nil
		}
		if err != nil {
			return nil, err
		}
	}
}
func boundedReadDir(path string, max int) ([]os.DirEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return boundedDirectory(file, max)
}

// Preflight inspects sizes before restore allocates file contents or decoded
// object indexes. Legacy and compatibility files count against disk budgets too.
func (r *ContentAddressedEvidenceRepository) preflightArchive() error {
	for _, directory := range []string{"blobs/sha256", ".", "receipts"} {
		path := filepath.Join(r.baseDir, directory)
		if directory != "." {
			info, err := os.Lstat(path)
			if os.IsNotExist(err) && directory == "receipts" {
				continue
			}
			if err != nil {
				return err
			}
			if !info.IsDir() {
				return &IntegrityError{Path: path, Reason: "archive directory must not be a symlink or other non-directory"}
			}
		}
		entries, err := boundedReadDir(path, r.limits.MaxEntries+16)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			ext := filepath.Ext(name)
			if ext != ".json" && (directory != "blobs/sha256" || ext != ".bin") {
				continue
			}
			full := filepath.Join(path, name)
			info, err := os.Lstat(full)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return &IntegrityError{Path: full, Reason: "expected regular archive object"}
			}
			bound := int64(MaxPayloadBytes)
			if directory == "receipts" || directory == "blobs/sha256" && ext == ".json" || directory == "." && strings.HasPrefix(name, "rcpt-") {
				bound = MaxMetadataBytes
			}
			if info.Size() > bound {
				return &CapacityError{Dimension: "restore object bytes", Requested: info.Size(), Limit: bound}
			}
			if err := r.admit(map[string]int64{filepath.Join(directory, name): info.Size()}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}
func (r *ContentAddressedEvidenceRepository) accountRestoreFile(path string, size int) error {
	relative, err := filepath.Rel(r.baseDir, path)
	if err != nil {
		return err
	}
	return r.admit(map[string]int64{relative: int64(size)}, nil)
}

func metadataStrings(subject assurance.SubjectRef, values ...string) error {
	if len(subject.Attributes) > maxMetadataItems {
		return &CapacityError{Dimension: "subject metadata entries", Requested: int64(len(subject.Attributes)), Limit: maxMetadataItems}
	}
	size := len(subject.Scheme) + len(subject.ID)
	for _, value := range values {
		if len(value) > MaxMetadataBytes-size {
			return &CapacityError{Dimension: "metadata string bytes", Used: int64(size), Requested: int64(len(value)), Limit: MaxMetadataBytes}
		}
		size += len(value)
	}
	for key, value := range subject.Attributes {
		if len(key) > MaxMetadataBytes-size || len(value) > MaxMetadataBytes-size-len(key) {
			return &CapacityError{Dimension: "subject metadata bytes", Requested: int64(len(key)) + int64(len(value)) + int64(size), Limit: MaxMetadataBytes}
		}
		size += len(key) + len(value)
	}
	if size > MaxMetadataBytes {
		return &CapacityError{Dimension: "subject bytes", Requested: int64(size), Limit: MaxMetadataBytes}
	}
	return nil
}
func envelopeBounds(e assurance.EvidenceEnvelope) error {
	if len(e.ControlRefs) > maxMetadataItems {
		return &CapacityError{Dimension: "envelope controls", Requested: int64(len(e.ControlRefs)), Limit: maxMetadataItems}
	}
	values := []string{e.Schema, e.ID, e.ObservationType, e.Producer.Scheme, e.Producer.Subject, e.Producer.TrustDomain, e.Artifact.URI, e.Artifact.Digest, e.Artifact.MediaType, e.IntegrityDigest, e.SignatureRef, e.Epoch.SubjectDigest, e.Epoch.ImplementationDigest, e.Epoch.PolicyDigest, e.Epoch.AuthorityDigest, e.Epoch.EnvironmentDigest}
	for _, c := range e.ControlRefs {
		values = append(values, c.Namespace, c.ID, c.Version)
	}
	return metadataStrings(e.Subject, values...)
}
func receiptBounds(r assurance.ControlReceipt) error {
	return metadataStrings(r.Subject, r.Control.Namespace, r.Control.ID, r.Control.Version, r.EvidenceRoot, r.Signature, r.Evaluator.Scheme, r.Evaluator.Subject, r.Evaluator.TrustDomain, r.Epoch.SubjectDigest, r.Epoch.ImplementationDigest, r.Epoch.PolicyDigest, r.Epoch.AuthorityDigest, r.Epoch.EnvironmentDigest)
}

func (r *ContentAddressedEvidenceRepository) restoreLegacy(path string, data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		decoder := json.NewDecoder(bytes.NewReader(data))
		if _, err := decoder.Token(); err != nil {
			return err
		}
		count := 0
		for decoder.More() {
			count++
			if count > r.limits.MaxEntries {
				return &CapacityError{Dimension: "legacy array entries", Requested: int64(count), Limit: int64(r.limits.MaxEntries)}
			}
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				return &IntegrityError{Path: path, Reason: "invalid legacy envelope array"}
			}
			if err := r.restoreLegacyObject(path, raw, true); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return err
		}
		if len(bytes.TrimSpace(data[decoder.InputOffset():])) != 0 {
			return &IntegrityError{Path: path, Reason: "legacy array has trailing JSON"}
		}
		return nil
	}
	return r.restoreLegacyObject(path, data, false)
}
func (r *ContentAddressedEvidenceRepository) restoreLegacyObject(path string, raw []byte, canonicalize bool) error {
	var identity struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(raw, &identity); err != nil {
		return &IntegrityError{Path: path, Reason: "invalid legacy JSON"}
	}
	if identity.ID == nil {
		return nil
	}
	if len(identity.ID) > MaxMetadataBytes {
		return &CapacityError{Dimension: "legacy identity bytes", Requested: int64(len(identity.ID)), Limit: MaxMetadataBytes}
	}
	var id string
	if err := json.Unmarshal(identity.ID, &id); err != nil {
		return &IntegrityError{Path: path, Reason: "invalid legacy identity"}
	}
	if id == "" {
		return nil
	}
	if len(raw) > MaxMetadataBytes {
		return &CapacityError{Dimension: "legacy envelope bytes", Requested: int64(len(raw)), Limit: MaxMetadataBytes}
	}
	var envelope assurance.EvidenceEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil || !validStoredEnvelope(envelope) {
		return &IntegrityError{Path: path, Reason: "malformed legacy evidence envelope"}
	}
	if err := envelopeBounds(envelope); err != nil {
		return err
	}
	if canonicalize {
		var err error
		raw, err = json.Marshal(envelope)
		if err != nil {
			return err
		}
	}
	return r.indexEnvelope(envelope, raw)
}
