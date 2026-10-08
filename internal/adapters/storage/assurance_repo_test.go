package storage

import (
	"context"
	"os"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestAssuranceStateRepository(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "oskal-state-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(tempDir)
	})

	repo := NewAssuranceStateRepository(tempDir)
	ctx := context.Background()

	sub := assurance.SubjectRef{
		Scheme: "k8s",
		ID:     "payments/payments-api",
	}

	epoch := assurance.AssuranceEpoch{
		SubjectDigest: "sha256:sub",
	}

	// 1. Initial get returns error
	_, _, err = repo.GetState(ctx, sub)
	if err == nil {
		t.Fatal("expected error on non-existent state")
	}

	// 2. SaveState
	err = repo.SaveState(ctx, sub, assurance.AssuranceStateAssured, epoch, "sha256:root")
	if err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// 3. GetState retrieves saved state
	state, recEpoch, err := repo.GetState(ctx, sub)
	if err != nil {
		t.Fatalf("GetState failed: %v", err)
	}
	if state != assurance.AssuranceStateAssured {
		t.Fatalf("expected ASSURED, got %s", state)
	}
	if recEpoch.SubjectDigest != "sha256:sub" {
		t.Fatalf("unexpected epoch digest: %s", recEpoch.SubjectDigest)
	}

	// 4. Recovery from disk in new instance
	recoveredRepo := NewAssuranceStateRepository(tempDir)
	recState, _, err := recoveredRepo.GetState(ctx, sub)
	if err != nil {
		t.Fatalf("failed to recover state from disk: %v", err)
	}
	if recState != assurance.AssuranceStateAssured {
		t.Fatalf("expected recovered state ASSURED, got %s", recState)
	}
}
