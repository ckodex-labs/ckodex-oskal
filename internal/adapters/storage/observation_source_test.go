package storage

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestRepositoryObservationSource(t *testing.T) {
	repo := NewMemoryEvidenceRepository()
	obsSource := NewRepositoryObservationSource(repo)
	ctx := context.Background()

	sub := assurance.SubjectRef{
		Scheme: "k8s",
		ID:     "payments/payments-api",
	}

	now := time.Now().UTC()
	env := assurance.EvidenceEnvelope{
		ID:              "env-1",
		ObservationType: "kubernetes.admission",
		Subject:         sub,
		CapturedAt:      now,
		Producer: assurance.AuthorityRef{
			Scheme:  "spiffe",
			Subject: "prod/ns/oskal/sa/observer",
		},
		Artifact: assurance.EvidenceRef{
			URI:    "blob://1",
			Digest: "sha256:abc",
		},
		Epoch: assurance.AssuranceEpoch{
			SubjectDigest: "sha256:sub",
		},
	}

	_, err := repo.Put(ctx, env, bytes.NewReader([]byte(`{"admitted":true}`)))
	if err != nil {
		t.Fatalf("failed to put evidence: %v", err)
	}

	// 1. List observations
	obsList, err := obsSource.ListObservations(ctx, sub, now.Add(-1*time.Minute))
	if err != nil {
		t.Fatalf("ListObservations failed: %v", err)
	}
	if len(obsList) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obsList))
	}
	if obsList[0].Type != "kubernetes.admission" {
		t.Fatalf("expected kubernetes.admission type, got %s", obsList[0].Type)
	}

	// 2. Filter since in future returns 0
	futureObs, err := obsSource.ListObservations(ctx, sub, now.Add(1*time.Hour))
	if err != nil {
		t.Fatalf("ListObservations failed: %v", err)
	}
	if len(futureObs) != 0 {
		t.Fatalf("expected 0 observations in future, got %d", len(futureObs))
	}
}
