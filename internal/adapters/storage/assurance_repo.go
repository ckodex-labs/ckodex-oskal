package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

var _ ports.AssuranceRepository = (*AssuranceStateRepository)(nil)

type stateRecord struct {
	Subject      assurance.SubjectRef     `json:"subject"`
	State        assurance.AssuranceState `json:"state"`
	Epoch        assurance.AssuranceEpoch `json:"epoch"`
	EvidenceRoot string                   `json:"evidence_root"`
}

// AssuranceStateRepository implements ports.AssuranceRepository
// with in-memory caching and optional filesystem persistence.
type AssuranceStateRepository struct {
	baseDir string
	mu      sync.RWMutex
	states  map[string]stateRecord
}

// NewAssuranceStateRepository creates a new AssuranceStateRepository.
func NewAssuranceStateRepository(baseDir string) *AssuranceStateRepository {
	repo := &AssuranceStateRepository{
		baseDir: baseDir,
		states:  make(map[string]stateRecord),
	}
	if baseDir != "" {
		_ = repo.loadFromDisk()
	}
	return repo
}

func (r *AssuranceStateRepository) loadFromDisk() error {
	filePath := filepath.Join(r.baseDir, "assurance_states.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	var loaded map[string]stateRecord
	if err := json.Unmarshal(data, &loaded); err == nil {
		r.states = loaded
	}
	return nil
}

func (r *AssuranceStateRepository) persistToDisk() error {
	if r.baseDir == "" {
		return nil
	}
	filePath := filepath.Join(r.baseDir, "assurance_states.json")
	data, err := json.MarshalIndent(r.states, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0600)
}

// GetState retrieves the latest assurance state and epoch for a subject.
func (r *AssuranceStateRepository) GetState(ctx context.Context, subject assurance.SubjectRef) (assurance.AssuranceState, assurance.AssuranceEpoch, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := subject.URI()
	rec, exists := r.states[key]
	if !exists {
		return assurance.AssuranceStateUnknown, assurance.AssuranceEpoch{}, fmt.Errorf("no state recorded for subject: %s", key)
	}

	return rec.State, rec.Epoch, nil
}

// SaveState records the latest assurance state, epoch, and evidence root for a subject.
func (r *AssuranceStateRepository) SaveState(ctx context.Context, subject assurance.SubjectRef, state assurance.AssuranceState, epoch assurance.AssuranceEpoch, root string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := subject.URI()
	r.states[key] = stateRecord{
		Subject:      subject,
		State:        state,
		Epoch:        epoch,
		EvidenceRoot: root,
	}

	return r.persistToDisk()
}
