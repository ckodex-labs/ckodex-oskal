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
	"strings"
	"sync"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

var _ ports.EvidenceRepository = (*ContentAddressedEvidenceRepository)(nil)

// ContentAddressedEvidenceRepository implements ports.EvidenceRepository
// supporting both in-memory and durable content-addressed filesystem storage (ADR-002).
type ContentAddressedEvidenceRepository struct {
	baseDir      string
	mu           sync.RWMutex
	blobs        map[string][]byte
	envelopes    map[string]assurance.EvidenceEnvelope
	subjectIndex map[string][]string // subjectURI -> []envelopeDigest
}

// NewMemoryEvidenceRepository creates an in-memory evidence repository.
func NewMemoryEvidenceRepository() *ContentAddressedEvidenceRepository {
	return &ContentAddressedEvidenceRepository{
		baseDir:      "",
		blobs:        make(map[string][]byte),
		envelopes:    make(map[string]assurance.EvidenceEnvelope),
		subjectIndex: make(map[string][]string),
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
	}

	if err := repo.loadFromDisk(); err != nil {
		return nil, fmt.Errorf("failed to recover existing evidence index: %w", err)
	}

	return repo, nil
}

func (r *ContentAddressedEvidenceRepository) loadFromDisk() error {
	dirsToScan := []string{
		filepath.Join(r.baseDir, "blobs", "sha256"),
		r.baseDir,
	}

	for _, dir := range dirsToScan {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
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
	return nil
}

// Put stores an immutable EvidenceEnvelope and optional raw payload into the content-addressed store.
func (r *ContentAddressedEvidenceRepository) Put(
	ctx context.Context,
	envelope assurance.EvidenceEnvelope,
	payload io.Reader,
) (assurance.EvidenceRef, error) {
	envelopeData, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return assurance.EvidenceRef{}, fmt.Errorf("failed to serialize evidence envelope: %w", err)
	}

	h := sha256.Sum256(envelopeData)
	hexHash := hex.EncodeToString(h[:])
	digest := "sha256:" + hexHash

	r.mu.Lock()
	defer r.mu.Unlock()

	r.blobs[digest] = envelopeData
	r.envelopes[digest] = envelope

	subURI := envelope.Subject.URI()
	r.subjectIndex[subURI] = append(r.subjectIndex[subURI], digest)

	// Persist to disk if baseDir configured
	if r.baseDir != "" {
		filePath := filepath.Join(r.baseDir, "blobs", "sha256", fmt.Sprintf("%s.json", hexHash))
		if err := os.WriteFile(filePath, envelopeData, 0644); err != nil {
			return assurance.EvidenceRef{}, fmt.Errorf("failed to write evidence blob to disk: %w", err)
		}
	}

	// Store optional secondary raw payload if provided
	if payload != nil {
		rawPayload, err := io.ReadAll(payload)
		if err != nil {
			return assurance.EvidenceRef{}, fmt.Errorf("failed to read raw evidence payload: %w", err)
		}
		rawHash := sha256.Sum256(rawPayload)
		rawDigest := "sha256:" + hex.EncodeToString(rawHash[:])
		r.blobs[rawDigest] = rawPayload
		if r.baseDir != "" {
			rawPath := filepath.Join(r.baseDir, "blobs", "sha256", fmt.Sprintf("%s.bin", hex.EncodeToString(rawHash[:])))
			_ = os.WriteFile(rawPath, rawPayload, 0644)
		}
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
	r.mu.RLock()
	defer r.mu.RUnlock()

	data, exists := r.blobs[ref.Digest]
	if !exists {
		// Attempt reading from disk
		if r.baseDir != "" {
			hexHash := strings.TrimPrefix(ref.Digest, "sha256:")
			path := filepath.Join(r.baseDir, "blobs", "sha256", fmt.Sprintf("%s.json", hexHash))
			diskData, err := os.ReadFile(path)
			if err == nil {
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

func matchSubject(envSub assurance.SubjectRef, targetSub assurance.SubjectRef, targetLeaf string) bool {
	if envSub.URI() == targetSub.URI() || envSub.ID == targetSub.ID {
		return true
	}
	cleanTarget := strings.TrimSuffix(strings.TrimSuffix(targetLeaf, "-binding"), "-contract")
	// Match leaf workload name (e.g. Pod name prefixed with Deployment name)
	envParts := strings.Split(strings.Trim(envSub.ID, "/"), "/")
	envLeaf := envParts[len(envParts)-1]
	if envLeaf == targetLeaf || strings.HasPrefix(envLeaf, targetLeaf+"-") {
		return true
	}
	if cleanTarget != "" && (envLeaf == cleanTarget || strings.HasPrefix(envLeaf, cleanTarget+"-")) {
		return true
	}
	return false
}
