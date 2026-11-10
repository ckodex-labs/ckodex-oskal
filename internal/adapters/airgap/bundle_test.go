package airgap

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

func TestAirgapBundleExportAndImport(t *testing.T) {
	ctx := context.Background()
	sourceRepo := storage.NewMemoryEvidenceRepository()
	targetRepo := storage.NewMemoryEvidenceRepository()

	sub := assurance.SubjectRef{
		Scheme: "k8s",
		ID:     "isolated-zone/secure-workload",
	}

	auth := assurance.AuthorityRef{
		Scheme:  "spiffe",
		Subject: "airgap/sa/signer",
	}

	receiptMgr, err := receipts.NewReceiptManager(auth)
	if err != nil {
		t.Fatalf("failed to create receipt manager: %v", err)
	}

	now := time.Now().UTC()
	epoch := assurance.AssuranceEpoch{
		SubjectDigest: assurance.ComputeStringDigest(sub.URI()),
	}

	blobData := []byte(`{"admission":"enforced","policy":"strict"}`)
	blobDigest := assurance.ComputeStringDigest(string(blobData))

	env := assurance.EvidenceEnvelope{
		ID:              "env-airgap-1",
		ObservationType: "kubernetes.admission",
		Subject:         sub,
		CapturedAt:      now,
		Producer:        auth,
		Artifact: assurance.EvidenceRef{
			URI:       "blob://" + blobDigest,
			Digest:    blobDigest,
			MediaType: "application/json",
		},
		Epoch: epoch,
	}

	_, err = sourceRepo.Put(ctx, env, bytes.NewReader(blobData))
	if err != nil {
		t.Fatalf("failed to store evidence in source repo: %v", err)
	}

	ctrl := assurance.ControlRef{Namespace: "ckodex", ID: "least-privilege"}
	receipt, err := receiptMgr.IssueReceipt(sub, ctrl, assurance.AssuranceStateAssured, epoch, []assurance.EvidenceRef{env.Artifact}, now)
	if err != nil {
		t.Fatalf("failed to issue receipt: %v", err)
	}

	eval := assurance.ClaimEvaluation{
		ID:           "eval-1",
		Subject:      sub,
		Control:      ctrl,
		State:        assurance.AssuranceStateAssured,
		Epoch:        epoch,
		EvidenceRoot: receipt.EvidenceRoot,
		EvaluatedAt:  now,
	}

	// 1. Export Bundle
	bundle, bundleData, err := ExportBundle(ctx, sub, []assurance.ClaimEvaluation{eval}, []assurance.ControlReceipt{receipt}, []assurance.EvidenceEnvelope{env}, sourceRepo)
	if err != nil {
		t.Fatalf("ExportBundle failed: %v", err)
	}
	if bundle.ManifestDigest == "" {
		t.Fatal("expected non-empty manifest digest")
	}

	// 2. Import Bundle into target repository
	importedBundle, err := ImportBundle(ctx, bundleData, targetRepo, receiptMgr)
	if err != nil {
		t.Fatalf("ImportBundle failed: %v", err)
	}
	if len(importedBundle.Evaluations) != 1 {
		t.Fatalf("expected 1 imported evaluation, got %d", len(importedBundle.Evaluations))
	}

	// 3. Verify evidence blob and receipts were ingested into targetRepo
	verifiedEnvelopes, err := targetRepo.ListBySubject(ctx, sub)
	if err != nil || len(verifiedEnvelopes) != 1 {
		t.Fatalf("expected 1 envelope in targetRepo, got %d (err: %v)", len(verifiedEnvelopes), err)
	}
	verifiedReceipt, err := targetRepo.GetReceipt(ctx, ctrl.ID)
	if err != nil || verifiedReceipt.Signature != receipt.Signature {
		t.Fatalf("expected receipt %s in targetRepo, got err=%v", ctrl.ID, err)
	}

	// 3b. Verify non-sha256 blob key is rejected
	nonShaBundle := *bundle
	nonShaBundle.Blobs = map[string]string{
		"md5:abcd": "invalid-scheme",
	}
	nonShaBundle.ManifestDigest = nonShaBundle.ComputeManifestDigest()
	nonShaBytes, _ := json.Marshal(nonShaBundle)
	if _, err := ImportBundle(ctx, nonShaBytes, storage.NewMemoryEvidenceRepository(), receiptMgr); err == nil {
		t.Fatal("expected ImportBundle to reject blob key without sha256: prefix")
	}

	// 4. Verify tampering with bundle manifest is rejected
	tamperedData := bytes.Replace(bundleData, []byte("strict"), []byte("permissive"), 1)
	_, err = ImportBundle(ctx, tamperedData, targetRepo, receiptMgr)
	if err == nil {
		t.Fatal("expected error when importing tampered bundle, got nil")
	}

	// 5. Verify self-consistent manifest with forged blob content (digest != sha256(content)) is rejected before mutating targetRepo
	forgedBundle := *bundle
	forgedBundle.Blobs = map[string]string{
		blobDigest: `{"admission":"forged-with-recomputed-manifest"}`,
	}
	forgedBundle.ManifestDigest = forgedBundle.ComputeManifestDigest()
	forgedBytes, _ := json.Marshal(forgedBundle)

	cleanTarget := storage.NewMemoryEvidenceRepository()
	if _, err := ImportBundle(ctx, forgedBytes, cleanTarget, receiptMgr); err == nil {
		t.Fatal("expected ImportBundle to reject self-consistent manifest when blob content does not match its SHA-256 key")
	}
	afterForged, _ := cleanTarget.ListAll(ctx)
	if len(afterForged) != 0 {
		t.Fatalf("expected cleanTarget to remain untouched after preflight rejection, got %d envelopes", len(afterForged))
	}
}
