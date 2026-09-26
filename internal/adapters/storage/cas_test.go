package storage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func createTestEnvelope(id, subjectID, obsType string) assurance.EvidenceEnvelope {
	now := time.Now().UTC()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: subjectID}
	raw := "test-payload-" + id
	digest := assurance.ComputeStringDigest(raw)

	return assurance.EvidenceEnvelope{
		Schema:          "assurance.ckodex.io/evidence/v1alpha1",
		ID:              id,
		Subject:         sub,
		ObservationType: obsType,
		CapturedAt:      now,
		Producer: assurance.AuthorityRef{
			Scheme:  "spiffe",
			Subject: "prod/ns/security/sa/observer",
		},
		Artifact: assurance.EvidenceRef{
			URI:       "evidence://" + id,
			Digest:    digest,
			MediaType: "application/vnd.ckodex.evidence+json",
		},
		IntegrityDigest: digest,
		Epoch: assurance.AssuranceEpoch{
			SubjectDigest: sub.Digest(),
		},
		ControlRefs: []assurance.ControlRef{
			{Namespace: "ckodex", ID: "least-privilege"},
		},
	}
}

func TestMemoryEvidenceRepository(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryEvidenceRepository()

	env := createTestEnvelope("ev-01", "payments/Pod/payments-api-1234", "kubernetes.admission")
	payload := bytes.NewReader([]byte("extra-payload"))

	ref, err := repo.Put(ctx, env, payload)
	if err != nil {
		t.Fatalf("unexpected put error: %v", err)
	}

	if ref.Digest == "" || ref.URI == "" {
		t.Fatalf("expected non-empty ref fields, got: %+v", ref)
	}

	// Verify
	ok, err := repo.Verify(ctx, ref)
	if err != nil || !ok {
		t.Fatalf("expected verification success, got ok=%v, err=%v", ok, err)
	}

	// Get
	rc, err := repo.Get(ctx, ref)
	if err != nil {
		t.Fatalf("unexpected get error: %v", err)
	}
	defer func() { _ = rc.Close() }()

	// ListBySubject exact
	envs, err := repo.ListBySubject(ctx, assurance.SubjectRef{Scheme: "k8s", ID: "payments/Pod/payments-api-1234"})
	if err != nil {
		t.Fatalf("unexpected list error: %v", err)
	}
	if len(envs) != 1 || envs[0].ID != "ev-01" {
		t.Fatalf("expected 1 envelope ev-01, got: %v", envs)
	}

	// ListBySubject fuzzy deployment leaf
	envsFuzzy, err := repo.ListBySubject(ctx, assurance.SubjectRef{Scheme: "k8s", ID: "payments/Deployment/payments-api"})
	if err != nil {
		t.Fatalf("unexpected fuzzy list error: %v", err)
	}
	if len(envsFuzzy) != 1 || envsFuzzy[0].ID != "ev-01" {
		t.Fatalf("expected 1 envelope ev-01 via fuzzy match, got: %v", envsFuzzy)
	}
}

func TestFilesystemEvidenceRepository_PersistenceAndRecovery(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp("", "oskal-cas-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	repo1, err := NewFilesystemEvidenceRepository(tmpDir)
	if err != nil {
		t.Fatalf("failed to create fs repo: %v", err)
	}

	env1 := createTestEnvelope("ev-persisted-01", "default/Pod/web-app-abcd", "kubernetes.admission")
	ref1, err := repo1.Put(ctx, env1, nil)
	if err != nil {
		t.Fatalf("failed to put envelope: %v", err)
	}

	// Verify file exists on disk
	hexHash := ref1.Digest[len("sha256:"):]
	diskPath := filepath.Join(tmpDir, "blobs", "sha256", hexHash+".json")
	if _, err := os.Stat(diskPath); err != nil {
		t.Fatalf("expected file on disk at %s, got: %v", diskPath, err)
	}

	// Create second repo instance pointing to same directory to verify recovery
	repo2, err := NewFilesystemEvidenceRepository(tmpDir)
	if err != nil {
		t.Fatalf("failed to create second fs repo: %v", err)
	}

	recovered, err := repo2.ListBySubject(ctx, assurance.SubjectRef{Scheme: "k8s", ID: "default/Deployment/web-app"})
	if err != nil {
		t.Fatalf("failed to list from recovered repo: %v", err)
	}
	if len(recovered) != 1 || recovered[0].ID != "ev-persisted-01" {
		t.Fatalf("expected recovered envelope ev-persisted-01, got: %v", recovered)
	}

	// Verify recovered
	ok, err := repo2.Verify(ctx, ref1)
	if err != nil || !ok {
		t.Fatalf("expected verification success on recovered repo, got: %v, err=%v", ok, err)
	}
}

func TestEvidenceRepository_TamperDetection(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryEvidenceRepository()

	env := createTestEnvelope("ev-tamper", "ns/Pod/victim", "test.obs")
	ref, err := repo.Put(ctx, env, nil)
	if err != nil {
		t.Fatalf("unexpected put error: %v", err)
	}

	// Modify underlying blob
	repo.mu.Lock()
	repo.blobs[ref.Digest] = []byte("tampered content")
	repo.mu.Unlock()

	ok, err := repo.Verify(ctx, ref)
	if ok || err == nil {
		t.Fatalf("expected verification failure on tampered content, got ok=%v, err=%v", ok, err)
	}
}

func TestEvidenceRepository_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryEvidenceRepository()

	var wg sync.WaitGroup
	workers := 10
	iterations := 20

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				envID := "ev-worker"
				subID := "ns/Pod/worker-pod-1"
				env := createTestEnvelope(envID, subID, "concurrent.test")

				ref, err := repo.Put(ctx, env, nil)
				if err != nil {
					t.Errorf("worker %d put error: %v", workerID, err)
					return
				}

				if _, err := repo.Verify(ctx, ref); err != nil {
					t.Errorf("worker %d verify error: %v", workerID, err)
					return
				}

				if _, err := repo.ListBySubject(ctx, assurance.SubjectRef{Scheme: "k8s", ID: "ns/Deployment/worker-pod"}); err != nil {
					t.Errorf("worker %d list error: %v", workerID, err)
					return
				}
			}
		}(i)
	}

	wg.Wait()
}
