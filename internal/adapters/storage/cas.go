package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

// MaxPayloadBytes bounds secondary raw evidence payload ingestion (32 MiB) per Constitution Section 30.
const MaxPayloadBytes = 32 << 20

var _ ports.EvidenceRepository = (*ContentAddressedEvidenceRepository)(nil)

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".oskal-cas-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func appendUniqueDigest(slice []string, digest string) []string {
	for _, existing := range slice {
		if existing == digest {
			return slice
		}
	}
	return append(slice, digest)
}

// ContentAddressedEvidenceRepository implements ports.EvidenceRepository
// supporting both in-memory and durable content-addressed filesystem storage (ADR-002).
type ContentAddressedEvidenceRepository struct {
	baseDir      string
	mu           sync.RWMutex
	blobs        map[string][]byte
	envelopes    map[string]assurance.EvidenceEnvelope
	subjectIndex map[string][]string // subjectURI -> []envelopeDigest
	receipts     map[string]assurance.ControlReceipt
}

// NewMemoryEvidenceRepository creates an in-memory evidence repository.
func NewMemoryEvidenceRepository() *ContentAddressedEvidenceRepository {
	return &ContentAddressedEvidenceRepository{
		baseDir:      "",
		blobs:        make(map[string][]byte),
		envelopes:    make(map[string]assurance.EvidenceEnvelope),
		subjectIndex: make(map[string][]string),
		receipts:     make(map[string]assurance.ControlReceipt),
	}
}

// NewFilesystemEvidenceRepository creates a durable filesystem-backed evidence repository.
func NewFilesystemEvidenceRepository(baseDir string) (*ContentAddressedEvidenceRepository, error) {
	if err := os.MkdirAll(filepath.Join(baseDir, "blobs", "sha256"), 0755); err != nil {
		return nil, fmt.Errorf("failed to initialize evidence storage directory: %w", err)
	}

	repo := &ContentAddressedEvidenceRepository{
		baseDir:      baseDir,
		blobs:        make(map[string][]byte),
		envelopes:    make(map[string]assurance.EvidenceEnvelope),
		subjectIndex: make(map[string][]string),
		receipts:     make(map[string]assurance.ControlReceipt),
	}

	if err := repo.loadFromDisk(); err != nil {
		return nil, fmt.Errorf("failed to recover existing evidence index: %w", err)
	}

	return repo, nil
}

func isValidHexDigest(hexHash string) bool {
	if len(hexHash) != 64 {
		return false
	}
	for i := 0; i < len(hexHash); i++ {
		c := hexHash[i]
		isDigit := c >= '0' && c <= '9'
		isHexLower := c >= 'a' && c <= 'f'
		if !isDigit && !isHexLower {
			return false
		}
	}
	return true
}

func (r *ContentAddressedEvidenceRepository) loadFromDisk() error {
	blobsDir := filepath.Join(r.baseDir, "blobs", "sha256")
	dirsToScan := []string{
		blobsDir,
		r.baseDir,
	}

	for _, dir := range dirsToScan {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if dir == blobsDir && strings.HasSuffix(name, ".bin") {
				expectedHex := strings.TrimSuffix(name, ".bin")
				if !isValidHexDigest(expectedHex) {
					continue
				}
				path := filepath.Join(dir, name)
				data, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				h := sha256.Sum256(data)
				actualHex := hex.EncodeToString(h[:])
				if actualHex != expectedHex {
					continue
				}
				r.blobs["sha256:"+actualHex] = data
				continue
			}
			if !strings.HasSuffix(name, ".json") {
				continue
			}
			path := filepath.Join(dir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			if dir == blobsDir {
				expectedHex := strings.TrimSuffix(name, ".json")
				if !isValidHexDigest(expectedHex) {
					continue
				}
				h := sha256.Sum256(data)
				actualHex := hex.EncodeToString(h[:])
				if actualHex != expectedHex {
					// Tampered blob in content-addressed store: reject on startup
					continue
				}
				var env assurance.EvidenceEnvelope
				if err := json.Unmarshal(data, &env); err == nil && env.ID != "" {
					digest := "sha256:" + actualHex
					if _, exists := r.envelopes[digest]; !exists {
						r.envelopes[digest] = env
						r.blobs[digest] = data
						subURI := env.Subject.URI()
						r.subjectIndex[subURI] = append(r.subjectIndex[subURI], digest)
					}
				}
				continue
			}

			// Try list of envelopes
			var envList []assurance.EvidenceEnvelope
			if err := json.Unmarshal(data, &envList); err == nil && len(envList) > 0 {
				for _, env := range envList {
					if env.ID != "" {
						digest := env.Digest()
						if _, exists := r.envelopes[digest]; !exists {
							r.envelopes[digest] = env
							raw, _ := json.Marshal(env)
							r.blobs[digest] = raw
							subURI := env.Subject.URI()
							r.subjectIndex[subURI] = append(r.subjectIndex[subURI], digest)
						}
					}
				}
				continue
			}

			// Try single envelope
			var env assurance.EvidenceEnvelope
			if err := json.Unmarshal(data, &env); err == nil && env.ID != "" {
				digest := env.Digest()
				if _, exists := r.envelopes[digest]; !exists {
					r.envelopes[digest] = env
					r.blobs[digest] = data
					subURI := env.Subject.URI()
					r.subjectIndex[subURI] = append(r.subjectIndex[subURI], digest)
				}
			}
		}
	}

	receiptsDir := filepath.Join(r.baseDir, "receipts")
	if entries, err := os.ReadDir(receiptsDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(receiptsDir, entry.Name()))
			if err != nil {
				continue
			}
			var rcpt assurance.ControlReceipt
			if err := json.Unmarshal(data, &rcpt); err == nil && rcpt.Signature != "" {
				key := strings.TrimSuffix(entry.Name(), ".json")
				r.receipts[key] = rcpt
				h := sha256.Sum256(data)
				r.receipts[hex.EncodeToString(h[:])] = rcpt
				_, _, subLeaf := extractSubjectNamespaceKindAndLeaf(rcpt.Subject)
				if subLeaf != "" && rcpt.Control.ID != "" {
					r.receipts[fmt.Sprintf("%s-%s", subLeaf, rcpt.Control.ID)] = rcpt
					r.receipts[fmt.Sprintf("rcpt-%s-%s", subLeaf, rcpt.Control.ID)] = rcpt
				}
			}
		}
	}

	return nil
}

// Put stores an immutable EvidenceEnvelope and optional raw payload into the content-addressed store.
func (r *ContentAddressedEvidenceRepository) Put(
	ctx context.Context,
	envelope assurance.EvidenceEnvelope,
	payload io.Reader,
) (assurance.EvidenceRef, error) {
	if ctx != nil && ctx.Err() != nil {
		return assurance.EvidenceRef{}, ctx.Err()
	}
	envelopeData, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return assurance.EvidenceRef{}, fmt.Errorf("failed to serialize evidence envelope: %w", err)
	}

	var rawPayload []byte
	var rawHexHash string
	if payload != nil {
		limited := io.LimitReader(payload, MaxPayloadBytes+1)
		rawPayload, err = io.ReadAll(limited)
		if err != nil {
			return assurance.EvidenceRef{}, fmt.Errorf("failed to read raw evidence payload: %w", err)
		}
		if len(rawPayload) > MaxPayloadBytes {
			return assurance.EvidenceRef{}, fmt.Errorf("raw evidence payload exceeds maximum bound (%d bytes)", MaxPayloadBytes)
		}
		rawHash := sha256.Sum256(rawPayload)
		rawHexHash = hex.EncodeToString(rawHash[:])
	}

	h := sha256.Sum256(envelopeData)
	hexHash := hex.EncodeToString(h[:])
	digest := "sha256:" + hexHash

	r.mu.Lock()
	defer r.mu.Unlock()

	// Persist to disk atomically BEFORE mutating in-memory index so disk failures never leave decoherent memory state.
	if r.baseDir != "" {
		filePath := filepath.Join(r.baseDir, "blobs", "sha256", fmt.Sprintf("%s.json", hexHash))
		if err := writeFileAtomic(filePath, envelopeData, 0644); err != nil {
			return assurance.EvidenceRef{}, fmt.Errorf("failed to write evidence blob to disk: %w", err)
		}
		if payload != nil {
			rawPath := filepath.Join(r.baseDir, "blobs", "sha256", fmt.Sprintf("%s.bin", rawHexHash))
			if err := writeFileAtomic(rawPath, rawPayload, 0644); err != nil {
				return assurance.EvidenceRef{}, fmt.Errorf("failed to write secondary evidence payload to disk: %w", err)
			}
		}
	}

	r.blobs[digest] = envelopeData
	r.envelopes[digest] = envelope

	subURI := envelope.Subject.URI()
	r.subjectIndex[subURI] = appendUniqueDigest(r.subjectIndex[subURI], digest)

	if payload != nil {
		rawDigest := "sha256:" + rawHexHash
		r.blobs[rawDigest] = rawPayload
	}

	ref := assurance.EvidenceRef{
		URI:       fmt.Sprintf("cas://sha256/%s", hexHash),
		Digest:    digest,
		MediaType: "application/vnd.ckodex.evidence+json",
	}

	return ref, nil
}

// Get retrieves raw evidence data by content-addressed reference.
func (r *ContentAddressedEvidenceRepository) Get(ctx context.Context, ref assurance.EvidenceRef) (io.ReadCloser, error) {
	if !strings.HasPrefix(ref.Digest, "sha256:") {
		return nil, fmt.Errorf("invalid digest format (must start with sha256:): %s", ref.Digest)
	}
	hexHash := strings.TrimPrefix(ref.Digest, "sha256:")
	if !isValidHexDigest(hexHash) {
		return nil, fmt.Errorf("invalid sha256 hex digest: %s", ref.Digest)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	data, exists := r.blobs[ref.Digest]
	if !exists {
		// Attempt reading from disk
		if r.baseDir != "" {
			path := filepath.Join(r.baseDir, "blobs", "sha256", fmt.Sprintf("%s.json", hexHash))
			diskData, err := os.ReadFile(path)
			if err != nil {
				binPath := filepath.Join(r.baseDir, "blobs", "sha256", fmt.Sprintf("%s.bin", hexHash))
				diskData, err = os.ReadFile(binPath)
			}
			if err == nil {
				h := sha256.Sum256(diskData)
				computed := "sha256:" + hex.EncodeToString(h[:])
				if computed != ref.Digest {
					return nil, fmt.Errorf("digest mismatch on read: expected %s, computed %s", ref.Digest, computed)
				}
				return io.NopCloser(bytes.NewReader(diskData)), nil
			}
		}
		return nil, fmt.Errorf("evidence blob not found for digest: %s", ref.Digest)
	}

	return io.NopCloser(bytes.NewReader(data)), nil
}

// Verify validates that the stored content matches the cryptographic digest in the reference.
func (r *ContentAddressedEvidenceRepository) Verify(ctx context.Context, ref assurance.EvidenceRef) (bool, error) {
	rc, err := r.Get(ctx, ref)
	if err != nil {
		return false, err
	}
	defer func() { _ = rc.Close() }()

	data, err := io.ReadAll(rc)
	if err != nil {
		return false, err
	}

	h := sha256.Sum256(data)
	computedDigest := "sha256:" + hex.EncodeToString(h[:])
	if computedDigest != ref.Digest {
		return false, fmt.Errorf("digest mismatch: expected %s, computed %s", ref.Digest, computedDigest)
	}

	return true, nil
}

// ListBySubject retrieves all verified evidence envelopes associated with a subject.
func (r *ContentAddressedEvidenceRepository) ListBySubject(
	ctx context.Context,
	subject assurance.SubjectRef,
) ([]assurance.EvidenceEnvelope, error) {
	if subject.ID == "" && subject.Scheme == "" {
		return nil, errors.New("subject reference cannot be empty")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []assurance.EvidenceEnvelope
	seen := make(map[string]bool)

	// 1. Direct index lookup by exact URI
	if digests, ok := r.subjectIndex[subject.URI()]; ok {
		for _, d := range digests {
			if env, found := r.envelopes[d]; found && !seen[env.ID] {
				results = append(results, env)
				seen[env.ID] = true
			}
		}
	}

	// 2. Fuzzy / hierarchical matching across all envelopes
	// (e.g. subject is "payments/Deployment/payments-api" or "payments-api", envelope subject is "k8s://payments/Pod/payments-api-xxxx")
	targetParts := strings.Split(strings.Trim(subject.ID, "/"), "/")
	targetLeaf := targetParts[len(targetParts)-1]

	for _, env := range r.envelopes {
		if seen[env.ID] {
			continue
		}
		if matchSubject(env.Subject, subject, targetLeaf) {
			results = append(results, env)
			seen[env.ID] = true
		}
	}

	return results, nil
}

func extractSubjectNamespaceKindAndLeaf(sub assurance.SubjectRef) (string, string, string) {
	trimmed := strings.Trim(sub.ID, "/")
	if trimmed == "" {
		return sub.Attributes["namespace"], sub.Attributes["kind"], ""
	}
	parts := strings.Split(trimmed, "/")
	leaf := parts[len(parts)-1]
	kind := sub.Attributes["kind"]
	if ns := sub.Attributes["namespace"]; ns != "" {
		if kind == "" && len(parts) >= 3 {
			kind = parts[len(parts)-2]
		}
		return ns, kind, leaf
	}
	switch len(parts) {
	case 4:
		// <cluster>/<namespace>/<Kind>/<name>
		if kind == "" {
			kind = parts[2]
		}
		return parts[1], kind, leaf
	case 3:
		// <namespace>/<Kind>/<name>
		if kind == "" {
			kind = parts[1]
		}
		return parts[0], kind, leaf
	case 2:
		// <namespace>/<name> unless synthetic prefix like components/<name> or system/<name>
		if parts[0] != "components" && parts[0] != "system" && parts[0] != "cluster" {
			return parts[0], kind, leaf
		}
	}
	return "", kind, leaf
}

func isAllowedWorkloadSuffix(suffix string) bool {
	if suffix == "" {
		return false
	}
	if suffix == "binding" || suffix == "contract" || suffix == "state" {
		return true
	}
	segments := strings.Split(suffix, "-")
	for _, seg := range segments {
		if seg == "" {
			return false
		}
		if seg == "pod" || seg == "uid" {
			if len(segments) < 2 {
				return false
			}
			continue
		}
		hasDigit := false
		allDigits := true
		allHex := true
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			isLower := c >= 'a' && c <= 'z'
			isDigit := c >= '0' && c <= '9'
			if !isLower && !isDigit {
				return false
			}
			if isDigit {
				hasDigit = true
			} else {
				allDigits = false
			}
			if !isDigit && (c < 'a' || c > 'f') {
				allHex = false
			}
		}
		if allDigits {
			continue
		}
		if len(seg) < 4 || (!hasDigit && !allHex) {
			return false
		}
	}
	return true
}

func isWorkloadControllerKind(kind string) bool {
	switch strings.ToLower(kind) {
	case "deployment", "statefulset", "daemonset":
		return true
	default:
		return false
	}
}

func matchSubject(envSub assurance.SubjectRef, targetSub assurance.SubjectRef, targetLeaf string) bool {
	if envSub.URI() == targetSub.URI() || envSub.ID == targetSub.ID {
		return true
	}
	envNS, envKind, envLeaf := extractSubjectNamespaceKindAndLeaf(envSub)
	targetNS, targetKind, extractedTargetLeaf := extractSubjectNamespaceKindAndLeaf(targetSub)
	if targetLeaf == "" {
		targetLeaf = extractedTargetLeaf
	}
	if envNS != "" && targetNS != "" && envNS != targetNS {
		return false
	}

	cleanTarget := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(targetLeaf, "-binding"), "-contract"), "-state")
	cleanEnv := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(envLeaf, "-binding"), "-contract"), "-state")

	if envLeaf == targetLeaf || (cleanTarget != "" && cleanEnv == cleanTarget) {
		return true
	}
	// Do not prefix-match two distinct workload controllers (e.g. Deployment/payments-api-2 vs Deployment/payments-api).
	if isWorkloadControllerKind(envKind) && isWorkloadControllerKind(targetKind) {
		return false
	}
	if strings.HasPrefix(envLeaf, targetLeaf+"-") && isAllowedWorkloadSuffix(strings.TrimPrefix(envLeaf, targetLeaf+"-")) {
		return true
	}
	if cleanTarget != "" && strings.HasPrefix(envLeaf, cleanTarget+"-") && isAllowedWorkloadSuffix(strings.TrimPrefix(envLeaf, cleanTarget+"-")) {
		return true
	}
	return false
}

// PruneReport contains statistics from a CAS storage prune operation.
type PruneReport struct {
	PrunedCount   int           `json:"pruned_count"`
	PrunedBytes   int64         `json:"pruned_bytes"`
	RetainedCount int           `json:"retained_count"`
	Duration      time.Duration `json:"duration_ns"`
}

// Prune removes evidence envelopes older than the specified maxAge threshold.
// If dryRun is true, it calculates what would be removed without modifying disk or memory.
func (r *ContentAddressedEvidenceRepository) Prune(maxAge time.Duration, dryRun bool) (*PruneReport, error) {
	start := time.Now()
	cutoff := start.Add(-maxAge)

	r.mu.Lock()
	defer r.mu.Unlock()

	report := &PruneReport{}
	var toDelete []string
	deletedEnvs := make(map[string]assurance.EvidenceEnvelope)
	survivingArtifacts := make(map[string]bool)

	for digest, env := range r.envelopes {
		if env.CapturedAt.Before(cutoff) {
			toDelete = append(toDelete, digest)
			deletedEnvs[digest] = env
			report.PrunedCount++
			if b, ok := r.blobs[digest]; ok {
				report.PrunedBytes += int64(len(b))
			}
		} else {
			if env.Artifact.Digest != "" {
				survivingArtifacts[env.Artifact.Digest] = true
			}
		}
	}

	if !dryRun {
		prunedArtifacts := make(map[string]bool)
		for _, digest := range toDelete {
			env := deletedEnvs[digest]
			delete(r.envelopes, digest)
			delete(r.blobs, digest)

			if r.baseDir != "" {
				hexHash := strings.TrimPrefix(digest, "sha256:")
				if isValidHexDigest(hexHash) {
					filePath := filepath.Join(r.baseDir, "blobs", "sha256", fmt.Sprintf("%s.json", hexHash))
					_ = os.Remove(filePath)
					binPath := filepath.Join(r.baseDir, "blobs", "sha256", fmt.Sprintf("%s.bin", hexHash))
					_ = os.Remove(binPath)
				}
			}

			artDigest := env.Artifact.Digest
			if artDigest != "" && artDigest != digest && !survivingArtifacts[artDigest] && !prunedArtifacts[artDigest] {
				prunedArtifacts[artDigest] = true
				delete(r.blobs, artDigest)
				if r.baseDir != "" {
					artHex := strings.TrimPrefix(artDigest, "sha256:")
					if isValidHexDigest(artHex) {
						artBinPath := filepath.Join(r.baseDir, "blobs", "sha256", fmt.Sprintf("%s.bin", artHex))
						_ = os.Remove(artBinPath)
					}
				}
			}

			if r.baseDir != "" && env.ID != "" && !strings.Contains(env.ID, "/") && !strings.Contains(env.ID, "\\") && !strings.Contains(env.ID, "..") {
				_ = os.Remove(filepath.Join(r.baseDir, env.ID+".json"))
			}
		}

		if r.baseDir != "" {
			if entries, err := os.ReadDir(r.baseDir); err == nil {
				for _, e := range entries {
					if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
						continue
					}
					flatPath := filepath.Join(r.baseDir, e.Name())
					data, err := os.ReadFile(flatPath)
					if err != nil {
						continue
					}
					var env assurance.EvidenceEnvelope
					if err := json.Unmarshal(data, &env); err == nil && env.ID != "" && !env.CapturedAt.IsZero() && env.CapturedAt.Before(cutoff) {
						_ = os.Remove(flatPath)
					}
				}
			}
		}

		// Rebuild subjectIndex
		r.subjectIndex = make(map[string][]string)
		for digest, env := range r.envelopes {
			subURI := env.Subject.URI()
			r.subjectIndex[subURI] = append(r.subjectIndex[subURI], digest)
		}
	}

	report.RetainedCount = len(r.envelopes)
	if dryRun {
		report.RetainedCount = len(r.envelopes) - report.PrunedCount
	}
	report.Duration = time.Since(start)
	return report, nil
}

// ListAll returns all stored evidence envelopes sorted by ID.
func (r *ContentAddressedEvidenceRepository) ListAll(ctx context.Context) ([]assurance.EvidenceEnvelope, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	results := make([]assurance.EvidenceEnvelope, 0, len(r.envelopes))
	seen := make(map[string]bool)
	for _, env := range r.envelopes {
		if seen[env.ID] {
			continue
		}
		seen[env.ID] = true
		results = append(results, env)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].ID < results[j].ID
	})
	return results, nil
}

// PutReceipt stores a signed ControlReceipt in memory and on disk (if baseDir is configured).
// It returns the receipt ID (rcpt-<controlID> or rcpt-<shortHash>).
func (r *ContentAddressedEvidenceRepository) PutReceipt(ctx context.Context, receipt assurance.ControlReceipt) (string, error) {
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialize control receipt: %w", err)
	}

	h := sha256.Sum256(data)
	hexHash := hex.EncodeToString(h[:])
	rcptID := fmt.Sprintf("rcpt-%s", hexHash[:12])
	if receipt.Control.ID != "" {
		rcptID = fmt.Sprintf("rcpt-%s", receipt.Control.ID)
	}

	_, _, subLeaf := extractSubjectNamespaceKindAndLeaf(receipt.Subject)
	subControlKey := ""
	subControlRcptKey := ""
	if subLeaf != "" && receipt.Control.ID != "" {
		subControlKey = fmt.Sprintf("%s-%s", subLeaf, receipt.Control.ID)
		subControlRcptKey = fmt.Sprintf("rcpt-%s-%s", subLeaf, receipt.Control.ID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.baseDir != "" {
		receiptsDir := filepath.Join(r.baseDir, "receipts")
		if err := os.MkdirAll(receiptsDir, 0755); err != nil {
			return "", fmt.Errorf("failed to create receipts directory: %w", err)
		}
		byIDPath := filepath.Join(receiptsDir, fmt.Sprintf("%s.json", rcptID))
		if err := writeFileAtomic(byIDPath, data, 0644); err != nil {
			return "", fmt.Errorf("failed to write receipt by ID: %w", err)
		}
		byHashPath := filepath.Join(receiptsDir, fmt.Sprintf("rcpt-%s.json", hexHash[:12]))
		if byHashPath != byIDPath {
			_ = writeFileAtomic(byHashPath, data, 0644)
		}
		if subControlRcptKey != "" {
			bySubControlPath := filepath.Join(receiptsDir, fmt.Sprintf("%s.json", subControlRcptKey))
			_ = writeFileAtomic(bySubControlPath, data, 0644)
		}
		topPath := filepath.Join(r.baseDir, fmt.Sprintf("%s.json", rcptID))
		_ = writeFileAtomic(topPath, data, 0644)
	}

	r.receipts[rcptID] = receipt
	r.receipts[hexHash] = receipt
	r.receipts[fmt.Sprintf("rcpt-%s", hexHash[:12])] = receipt
	if subControlKey != "" {
		r.receipts[subControlKey] = receipt
		r.receipts[subControlRcptKey] = receipt
	}

	return rcptID, nil
}

// VerifyIntegrity scans all content-addressed blobs on disk and in memory to detect bit-rot or tampering.
func (r *ContentAddressedEvidenceRepository) VerifyIntegrity(ctx context.Context) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	verified := 0
	for digest, data := range r.blobs {
		if ctx != nil && ctx.Err() != nil {
			return verified, ctx.Err()
		}
		h := sha256.Sum256(data)
		computed := "sha256:" + hex.EncodeToString(h[:])
		if computed != digest {
			return verified, fmt.Errorf("in-memory CAS integrity failure: expected %s, got %s", digest, computed)
		}
		verified++
	}

	if r.baseDir != "" {
		blobsDir := filepath.Join(r.baseDir, "blobs", "sha256")
		entries, err := os.ReadDir(blobsDir)
		if err == nil {
			for _, entry := range entries {
				if ctx != nil && ctx.Err() != nil {
					return verified, ctx.Err()
				}
				if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
					continue
				}
				ext := filepath.Ext(entry.Name())
				if ext != ".json" && ext != ".bin" {
					continue
				}
				expectedHex := strings.TrimSuffix(entry.Name(), ext)
				data, err := os.ReadFile(filepath.Join(blobsDir, entry.Name()))
				if err != nil {
					return verified, fmt.Errorf("failed reading CAS blob %s: %w", entry.Name(), err)
				}
				h := sha256.Sum256(data)
				actualHex := hex.EncodeToString(h[:])
				if actualHex != expectedHex {
					return verified, fmt.Errorf("on-disk CAS integrity tampering detected in %s: expected sha256:%s, computed sha256:%s", entry.Name(), expectedHex, actualHex)
				}
			}
		}
	}
	return verified, nil
}

// GetReceipt retrieves a stored ControlReceipt by receipt ID or digest prefix.
func (r *ContentAddressedEvidenceRepository) GetReceipt(ctx context.Context, idOrDigest string) (assurance.ControlReceipt, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if rcpt, ok := r.receipts[idOrDigest]; ok {
		return rcpt, nil
	}
	trimmed := strings.TrimPrefix(idOrDigest, "sha256:")
	if rcpt, ok := r.receipts[trimmed]; ok {
		return rcpt, nil
	}
	if !strings.HasPrefix(idOrDigest, "rcpt-") {
		if rcpt, ok := r.receipts["rcpt-"+idOrDigest]; ok {
			return rcpt, nil
		}
	}
	return assurance.ControlReceipt{}, fmt.Errorf("receipt not found: %s", idOrDigest)
}
