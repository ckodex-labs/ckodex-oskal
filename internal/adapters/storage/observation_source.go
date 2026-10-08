package storage

import (
	"context"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

var _ ports.ObservationSource = (*RepositoryObservationSource)(nil)

// RepositoryObservationSource extracts and maps observations from an EvidenceRepository.
type RepositoryObservationSource struct {
	repo ports.EvidenceRepository
}

// NewRepositoryObservationSource creates a new observation source backed by an evidence repository.
func NewRepositoryObservationSource(repo ports.EvidenceRepository) *RepositoryObservationSource {
	return &RepositoryObservationSource{repo: repo}
}

// ListObservations returns all observations recorded for the subject since the given timestamp.
func (s *RepositoryObservationSource) ListObservations(ctx context.Context, subject assurance.SubjectRef, since time.Time) ([]assurance.Observation, error) {
	if s.repo == nil {
		return nil, nil
	}

	envelopes, err := s.repo.ListBySubject(ctx, subject)
	if err != nil {
		return nil, err
	}

	var observations []assurance.Observation
	for _, env := range envelopes {
		if !since.IsZero() && env.CapturedAt.Before(since) {
			continue
		}

		obs := assurance.Observation{
			ID:         "obs-" + env.ID,
			Subject:    env.Subject,
			Type:       env.ObservationType,
			ObservedAt: env.CapturedAt,
			Observer:   env.Producer,
			Evidence: []assurance.EvidenceRef{
				env.Artifact,
			},
			Attributes: map[string]string{
				"epochComposite": env.Epoch.CompositeDigest(),
				"producer":       env.Producer.Canonical(),
			},
		}
		observations = append(observations, obs)
	}

	return observations, nil
}
