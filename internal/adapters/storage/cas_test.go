package storage

import (
	"bytes"
	"context"
	"errors"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func signStoredTestReceipt(t *testing.T, receipt assurance.ControlReceipt) assurance.ControlReceipt {
	t.Helper()
	signer, err := receipts.NewReceiptManager(assurance.AuthorityRef{Scheme: "local", Subject: "storage-test"})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignReceipt(context.Background(), receipt)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

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

func TestEvidenceRepository_Prune(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp("", "oskal-prune-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	repo, err := NewFilesystemEvidenceRepository(tmpDir)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	// 1. Insert fresh envelope (now)
	envFresh := createTestEnvelope("ev-fresh", "ns/Pod/fresh-pod", "test")
	envFresh.CapturedAt = time.Now().UTC()
	if _, err := repo.Put(ctx, envFresh, nil); err != nil {
		t.Fatalf("put fresh failed: %v", err)
	}

	// 2. Insert old envelope (2 hours ago)
	envOld := createTestEnvelope("ev-old", "ns/Pod/old-pod", "test")
	envOld.CapturedAt = time.Now().UTC().Add(-2 * time.Hour)
	if _, err := repo.Put(ctx, envOld, nil); err != nil {
		t.Fatalf("put old failed: %v", err)
	}

	// Dry run prune with 1h cutoff
	dryReport, err := repo.Prune(1*time.Hour, true)
	if err != nil {
		t.Fatalf("dry run prune failed: %v", err)
	}
	if dryReport.PrunedCount != 1 {
		t.Fatalf("expected 1 pruned in dry-run, got %d", dryReport.PrunedCount)
	}
	if dryReport.RetainedCount != 1 {
		t.Fatalf("expected 1 retained in dry-run, got %d", dryReport.RetainedCount)
	}

	// Actual prune with 1h cutoff
	actReport, err := repo.Prune(1*time.Hour, false)
	if err != nil {
		t.Fatalf("actual prune failed: %v", err)
	}
	if actReport.PrunedCount != 1 {
		t.Fatalf("expected 1 pruned, got %d", actReport.PrunedCount)
	}
	if actReport.RetainedCount != 1 {
		t.Fatalf("expected 1 retained, got %d", actReport.RetainedCount)
	}

	// Verify only fresh remains
	envelopes, err := repo.ListBySubject(ctx, assurance.SubjectRef{Scheme: "k8s", ID: "ns/Pod/fresh-pod"})
	if err != nil || len(envelopes) != 1 {
		t.Fatalf("expected fresh envelope to remain, got: %v, err: %v", envelopes, err)
	}
	oldEnvelopes, err := repo.ListBySubject(ctx, assurance.SubjectRef{Scheme: "k8s", ID: "ns/Pod/old-pod"})
	if err != nil || len(oldEnvelopes) != 0 {
		t.Fatalf("expected old envelope to be deleted, got: %v", oldEnvelopes)
	}
}

func TestEvidenceRepository_ListAllAndReceipts(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	repo, err := NewFilesystemEvidenceRepository(tmpDir)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	envA := createTestEnvelope("ev-a", "ns/Pod/pod-a", "test")
	envB := createTestEnvelope("ev-b", "ns/Pod/pod-b", "test")
	if _, err := repo.Put(ctx, envB, nil); err != nil {
		t.Fatalf("put B failed: %v", err)
	}
	if _, err := repo.Put(ctx, envA, nil); err != nil {
		t.Fatalf("put A failed: %v", err)
	}

	all, err := repo.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}
	if len(all) != 2 || all[0].ID != "ev-a" || all[1].ID != "ev-b" {
		t.Fatalf("expected sorted envelopes [ev-a, ev-b], got: %+v", all)
	}

	rcpt := assurance.ControlReceipt{
		Subject:      assurance.SubjectRef{Scheme: "k8s", ID: "ns/Deployment/pod-a"},
		Control:      assurance.ControlRef{Namespace: "ckodex", ID: "AC-6"},
		State:        assurance.AssuranceStateAssured,
		EvidenceRoot: "sha256:1234",
	}
	rcpt = signStoredTestReceipt(t, rcpt)
	rcptID, err := repo.PutReceipt(ctx, rcpt)
	if err != nil {
		t.Fatalf("PutReceipt failed: %v", err)
	}
	if rcptID != "rcpt-AC-6" {
		t.Fatalf("expected receipt ID rcpt-AC-6, got %s", rcptID)
	}

	repoReloaded, err := NewFilesystemEvidenceRepository(tmpDir)
	if err != nil {
		t.Fatalf("failed to reload repo: %v", err)
	}
	gotRcpt, err := repoReloaded.GetReceipt(ctx, "rcpt-AC-6")
	if err != nil {
		t.Fatalf("GetReceipt after reload failed: %v", err)
	}
	if gotRcpt.Signature != rcpt.Signature {
		t.Fatalf("receipt signature changed after reload")
	}
}

func TestEvidenceRepository_NamespacePrefixAndDiskTamper(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	repo, err := NewFilesystemEvidenceRepository(tmpDir)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	// 1. Cross-namespace, version-suffix, and prefix boundary isolation
	envPayments := createTestEnvelope("ev-pay", "payments/Pod/payments-api-7f8b9-x1234", "kubernetes.admission")
	envAdmin := createTestEnvelope("ev-admin", "payments/Pod/payments-api-admin-7f8b9-x1234", "kubernetes.admission")
	envV2 := createTestEnvelope("ev-v2", "payments/Pod/payments-api-v2-7f8b9-x1234", "kubernetes.admission")
	envDeploy2 := createTestEnvelope("ev-deploy2", "payments/Deployment/payments-api-2", "kubernetes.admission")
	envOtherNS := createTestEnvelope("ev-other-ns", "staging/Pod/payments-api-7f8b9-x1234", "kubernetes.admission")
	envStsPod := createTestEnvelope("ev-sts-0", "payments/Pod/payments-db-0", "kubernetes.admission")

	_, _ = repo.Put(ctx, envPayments, nil)
	_, _ = repo.Put(ctx, envAdmin, nil)
	_, _ = repo.Put(ctx, envV2, nil)
	_, _ = repo.Put(ctx, envDeploy2, nil)
	_, _ = repo.Put(ctx, envOtherNS, nil)
	_, _ = repo.Put(ctx, envStsPod, nil)

	matches, err := repo.ListBySubject(ctx, assurance.SubjectRef{Scheme: "k8s", ID: "payments/Deployment/payments-api"})
	if err != nil {
		t.Fatalf("ListBySubject failed: %v", err)
	}
	if len(matches) != 1 || matches[0].ID != "ev-pay" {
		t.Fatalf("expected only ev-pay to match payments/Deployment/payments-api, got: %+v", matches)
	}

	// StatefulSet ordinal pod (payments-db-0) should match StatefulSet/payments-db
	stsMatches, err := repo.ListBySubject(ctx, assurance.SubjectRef{Scheme: "k8s", ID: "payments/StatefulSet/payments-db"})
	if err != nil || len(stsMatches) != 1 || stsMatches[0].ID != "ev-sts-0" {
		t.Fatalf("expected StatefulSet ordinal pod to match payments/StatefulSet/payments-db, got: %+v, err: %v", stsMatches, err)
	}

	// Cluster-prefixed query (prod/payments/Deployment/payments-api) should still match payments/Pod/payments-api-...
	clusterMatches, err := repo.ListBySubject(ctx, assurance.SubjectRef{Scheme: "k8s", ID: "prod/payments/Deployment/payments-api"})
	if err != nil || len(clusterMatches) != 1 || clusterMatches[0].ID != "ev-pay" {
		t.Fatalf("expected cluster-prefixed query to match ev-pay, got: %+v, err: %v", clusterMatches, err)
	}

	// 2. Multi-subject receipt indexing without clobbering subject-scoped keys
	rcptA := assurance.ControlReceipt{
		Subject:      assurance.SubjectRef{Scheme: "k8s", ID: "payments/Deployment/payments-api"},
		Control:      assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"},
		State:        assurance.AssuranceStateAssured,
		EvidenceRoot: "sha256:aaaa",
	}
	rcptB := assurance.ControlReceipt{
		Subject:      assurance.SubjectRef{Scheme: "k8s", ID: "payments/Deployment/billing-api"},
		Control:      assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"},
		State:        assurance.AssuranceStateAssured,
		EvidenceRoot: "sha256:bbbb",
	}
	rcptA = signStoredTestReceipt(t, rcptA)
	rcptB = signStoredTestReceipt(t, rcptB)
	_, _ = repo.PutReceipt(ctx, rcptA)
	_, _ = repo.PutReceipt(ctx, rcptB)

	gotA, err := repo.GetReceipt(ctx, "rcpt-payments-api-AC-6")
	if err != nil || gotA.Signature != rcptA.Signature {
		t.Fatalf("expected rcpt-payments-api-AC-6 with sig-a, got %+v, err=%v", gotA, err)
	}
	gotB, err := repo.GetReceipt(ctx, "rcpt-billing-api-AC-6")
	if err != nil || gotB.Signature != rcptB.Signature {
		t.Fatalf("expected rcpt-billing-api-AC-6 with sig-b, got %+v, err=%v", gotB, err)
	}

	// Corrupt real durable bytes, reject the entire restore, preserve them, and
	// recover only after explicitly restoring the original digest-verified bytes.
	ref, err := repo.Put(ctx, envPayments, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(tmpDir, "blobs", "sha256", ref.Digest[len("sha256:"):]+".json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	corrupted := append([]byte(nil), original...)
	corrupted[0] = '!'
	if err := os.WriteFile(path, corrupted, 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewFilesystemEvidenceRepository(tmpDir)
	var integrityErr *IntegrityError
	if reloaded != nil || !errors.As(err, &integrityErr) || integrityErr.Path != path {
		t.Fatalf("expected fail-closed typed integrity error; repo=%v err=%v", reloaded, err)
	}
	preserved, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(preserved, corrupted) {
		t.Fatalf("corrupt bytes were not preserved: %v", err)
	}
	if _, err := repo.VerifyIntegrity(ctx); err == nil {
		t.Fatal("live integrity check accepted corrupt disk bytes")
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, err = NewFilesystemEvidenceRepository(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	verifiedBlobs, err := reloaded.VerifyIntegrity(ctx)
	if err != nil || verifiedBlobs == 0 {
		t.Fatalf("recovery verification failed: count=%d err=%v", verifiedBlobs, err)
	}

	// 5. Idempotent Put deduplicates subjectIndex and rejects oversized payloads
	for i := 0; i < 10; i++ {
		if _, err := reloaded.Put(ctx, envPayments, nil); err != nil {
			t.Fatalf("idempotent Put failed: %v", err)
		}
	}
	subURI := envPayments.Subject.URI()
	if len(reloaded.subjectIndex[subURI]) != 1 {
		t.Fatalf("expected subjectIndex[%s] to have 1 deduplicated digest, got %d", subURI, len(reloaded.subjectIndex[subURI]))
	}

	oversized := bytes.NewReader(make([]byte, MaxPayloadBytes+10))
	if _, err := reloaded.Put(ctx, envPayments, oversized); err == nil {
		t.Fatal("expected oversized payload (> MaxPayloadBytes) to be rejected")
	}
}

func TestEvidenceRepository_PathTraversalAndBinaryBlobLifecycle(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	repo, err := NewFilesystemEvidenceRepository(tmpDir)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	// 1. Path traversal and malformed digest rejection in Get
	traversalRefs := []assurance.EvidenceRef{
		{Digest: "sha256:../../../../etc/passwd"},
		{Digest: "sha256:../secret"},
		{Digest: "md5:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{Digest: "sha256:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"},
	}
	for _, badRef := range traversalRefs {
		if _, err := repo.Get(ctx, badRef); err == nil {
			t.Fatalf("expected Get to reject invalid/traversal digest %q", badRef.Digest)
		}
	}

	// 2. Secondary .bin payload reachable after restart and disk fallback
	rawPayload := []byte("secondary-binary-evidence-artifact-payload")
	rawDigest := assurance.ComputeDigest(rawPayload)
	envOld := createTestEnvelope("ev-bin-old", "payments/Pod/old-bin-pod", "kubernetes.admission")
	envOld.CapturedAt = time.Now().UTC().Add(-3 * time.Hour)
	envOld.Artifact.Digest = rawDigest

	if _, err := repo.Put(ctx, envOld, bytes.NewReader(rawPayload)); err != nil {
		t.Fatalf("Put with binary payload failed: %v", err)
	}

	// Reload repo from disk and verify secondary .bin blob is loaded and readable via Get
	reloaded, err := NewFilesystemEvidenceRepository(tmpDir)
	if err != nil {
		t.Fatalf("failed to reload repo: %v", err)
	}
	rc, err := reloaded.Get(ctx, assurance.EvidenceRef{Digest: rawDigest})
	if err != nil {
		t.Fatalf("expected secondary .bin blob to be readable after restart, got: %v", err)
	}
	_ = rc.Close()

	// Also verify disk fallback when in-memory r.blobs entry is cleared
	reloaded.mu.Lock()
	delete(reloaded.blobs, rawDigest)
	reloaded.mu.Unlock()
	rcFallback, err := reloaded.Get(ctx, assurance.EvidenceRef{Digest: rawDigest})
	if err != nil {
		t.Fatalf("expected Get fallback to .bin on disk to succeed, got: %v", err)
	}
	_ = rcFallback.Close()

	// Reload again so r.blobs has rawDigest, and write an expired flat ev-bin-old.json in baseDir
	reloaded2, err := NewFilesystemEvidenceRepository(tmpDir)
	if err != nil {
		t.Fatalf("failed to reload repo2: %v", err)
	}
	flatFile := filepath.Join(tmpDir, "ev-bin-old.json")
	if err := os.WriteFile(flatFile, []byte(`{"id":"ev-bin-old","capturedAt":"2020-01-01T00:00:00Z"}`), 0600); err != nil {
		t.Fatalf("failed to write flat file: %v", err)
	}

	// 3. Prune removes expired envelope, its unreferenced .bin artifact, and expired flat file
	if _, err := reloaded2.Prune(1*time.Hour, false); err != nil {
		t.Fatalf("Prune failed: %v", err)
	}
	if _, err := reloaded2.Get(ctx, assurance.EvidenceRef{Digest: rawDigest}); err == nil {
		t.Fatal("expected pruned secondary .bin blob to be removed from memory and disk")
	}
	if _, err := os.Stat(flatFile); !os.IsNotExist(err) {
		t.Fatalf("expected expired flat file %s to be removed by Prune", flatFile)
	}
}
