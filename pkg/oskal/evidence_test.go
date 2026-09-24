package oskal

import (
	"testing"
	"time"
)

func TestEvidenceEnvelopeBuilder(t *testing.T) {
	sub := SubjectRef{Scheme: "k8s", ID: "default/app"}
	auth := AuthorityRef{Scheme: "spiffe", Subject: "prod/sa/tester"}
	epoch := AssuranceEpoch{
		SubjectDigest: "sha256:sub",
	}

	// 1. Valid envelope construction
	builder := NewEvidenceEnvelope("https://assurance.ckodex.io/schemas/v1", "env-001", sub, "admission").
		WithProducer(auth).
		WithArtifact("evidence://cel/01", "sha256:art123", "application/json").
		WithEpoch(epoch).
		WithControlRefs(ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}).
		WithCapturedAt(time.Now().UTC())

	env, err := builder.Build()
	if err != nil {
		t.Fatalf("unexpected error building envelope: %v", err)
	}
	if env.ID != "env-001" || env.ObservationType != "admission" {
		t.Fatalf("unexpected envelope fields: %+v", env)
	}
	if env.IntegrityDigest == "" {
		t.Fatal("expected auto-computed integrity digest")
	}

	// 2. Validation failures on missing required fields
	_, err = NewEvidenceEnvelope("", "", sub, "admission").Build()
	if err == nil {
		t.Fatal("expected error on empty ID")
	}

	_, err = NewEvidenceEnvelope("", "env-02", SubjectRef{}, "admission").Build()
	if err == nil {
		t.Fatal("expected error on empty subject")
	}
}

func TestObservationBuilder(t *testing.T) {
	sub := SubjectRef{Scheme: "k8s", ID: "default/app"}
	auth := AuthorityRef{Scheme: "spiffe", Subject: "prod/sa/tester"}

	obs, err := NewObservation("obs-001", "admission", sub).
		WithProducer(auth).
		WithEvidenceRef("evidence://cel/01", "sha256:art123", "application/json").
		Build()
	if err != nil {
		t.Fatalf("unexpected error building observation: %v", err)
	}

	if obs.Id != "obs-001" || obs.Type != "admission" {
		t.Fatalf("unexpected observation fields: %+v", obs)
	}
	if len(obs.Evidence) != 1 || obs.Evidence[0].Digest != "sha256:art123" {
		t.Fatalf("unexpected evidence list: %+v", obs.Evidence)
	}

	// Validation error on empty ID
	_, err = NewObservation("", "admission", sub).Build()
	if err == nil {
		t.Fatal("expected error on empty observation ID")
	}
}

func TestComputeEvidenceRoot(t *testing.T) {
	rootEmpty := ComputeEvidenceRoot(nil)
	if rootEmpty != "none" {
		t.Fatalf("expected 'none' for empty digests, got %s", rootEmpty)
	}

	root1 := ComputeEvidenceRoot([]string{"sha256:aaa", "sha256:bbb"})
	root2 := ComputeEvidenceRoot([]string{"sha256:aaa", "sha256:bbb"})
	if root1 != root2 {
		t.Fatalf("expected deterministic root, got %s != %s", root1, root2)
	}

	rootDiff := ComputeEvidenceRoot([]string{"sha256:aaa", "sha256:ccc"})
	if root1 == rootDiff {
		t.Fatal("expected different roots for different digests")
	}
}
