package airgap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/evaluation"
	"github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

// This offline test covers actual file/CAS bytes, receipt cryptography and
// projection. It does not establish Kubernetes admission or workload identity.
func TestAirGapAcceptanceWithoutPublicNetwork(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "material.json")
	payload := []byte(`{"scope":"local untrusted material"}`)
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sub := assurance.SubjectRef{Scheme: "file", ID: path}
	authority := assurance.AuthorityRef{Scheme: "local", Subject: "airgap-material-observer"}
	hash := assurance.ComputeDigest(actual)
	evidence := assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/material/v1", ID: "local-material", Subject: sub, ObservationType: "local.file.read", CapturedAt: now, Producer: authority, Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(hash, "sha256:"), Digest: hash, MediaType: "application/json"}, IntegrityDigest: hash}
	repo, err := storage.NewFilesystemEvidenceRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Put(t.Context(), evidence, bytes.NewReader(actual)); err != nil {
		t.Fatal(err)
	}
	reader, err := repo.Get(t.Context(), evidence.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, actual) {
		t.Fatal("offline artifact bytes changed")
	}
	control := assurance.ControlRef{Namespace: "example", ID: "local-material"}
	evaluated := evaluation.UnverifiedEvaluation(sub, control, []assurance.EvidenceEnvelope{evidence}, now)
	if evaluated.State != assurance.AssuranceStateUnknown || evaluated.Completeness.Verified != 0 {
		t.Fatal("local material became live assurance")
	}
	signer, err := receipts.NewReceiptManager(authority)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := signer.IssueReceipt(sub, control, evaluated.State, evaluated.Epoch, []assurance.EvidenceRef{evidence.Artifact}, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := receipts.VerifyIndependentReceipt(receipt, signer.PublicKey())
	if err != nil || !verified {
		t.Fatalf("offline signature: %v", err)
	}
	projector := oscal.NewProjectorWithContext(oscal.ProjectionContext{AssessmentPlanHref: "example-assessment-plan.json", ControlNamespace: control.Namespace})
	projected, err := projector.ProjectAssessmentResults(t.Context(), sub, []assurance.ClaimEvaluation{evaluated}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(projected) == 0 {
		t.Fatal("empty projection")
	}
	t.Log("actual local file/CAS bytes and receipt signature verified offline; control standing remains UNKNOWN")
}

func TestAirgapBundleTampering(t *testing.T) {
	now := time.Now().UTC()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "ns/app"}
	ctrl := assurance.ControlRef{Namespace: "ckodex", ID: "AC-6"}
	epoch := assurance.AssuranceEpoch{SubjectDigest: "sha256:test"}
	eval := assurance.ClaimEvaluation{
		ID:          "eval-1",
		Subject:     sub,
		Control:     ctrl,
		State:       assurance.AssuranceStateAssured,
		Epoch:       epoch,
		EvaluatedAt: now,
		ValidUntil:  now.Add(time.Hour),
	}

	bundle, data, err := ExportBundle(context.Background(), sub, []assurance.ClaimEvaluation{eval}, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to export bundle: %v", err)
	}

	// Valid import succeeds
	_, err = ImportBundle(context.Background(), data, nil, nil)
	if err != nil {
		t.Fatalf("expected valid bundle import to succeed, got: %v", err)
	}

	// Tamper with evaluation state
	bundle.Evaluations[0].State = assurance.AssuranceStateFailed
	tamperedData, _ := json.Marshal(bundle)

	_, err = ImportBundle(context.Background(), tamperedData, nil, nil)
	if err == nil {
		t.Fatal("expected tampered evaluation in bundle to fail manifest verification")
	}
}
