package diagnostics

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestRunDoctor(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "oskal-doctor-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	report := RunDoctor(context.Background(), tmpDir)
	if report == nil {
		t.Fatal("expected non-nil DoctorReport")
	}

	if len(report.Checks) == 0 {
		t.Fatal("expected at least 1 diagnostic check")
	}

	// Verify pure ASCII in check names and messages
	for _, c := range report.Checks {
		for _, b := range []byte(c.Name + c.Message + c.Remediation) {
			if b > 127 {
				t.Fatalf("non-ASCII character detected in check %s: %d", c.Name, b)
			}
		}
	}

	t.Logf("Doctor Overall State: %s (%d checks evaluated in %s)", report.OverallState, len(report.Checks), report.Duration)
}

func TestInspectSubjectFourTruthChannels(t *testing.T) {
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "prod/payments/Deployment/payments-api"}
	ctrl := assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
	now := time.Now().UTC()

	eval := assurance.ClaimEvaluation{
		ID:      "eval-01",
		Subject: sub,
		Control: ctrl,
		State:   assurance.AssuranceStateAssured,
		Epoch: assurance.AssuranceEpoch{
			SubjectDigest:        assurance.ComputeStringDigest(sub.URI()),
			ImplementationDigest: assurance.ComputeStringDigest("kubernetes:admission"),
			PolicyDigest:         assurance.ComputeStringDigest("cel:policy:ac-6"),
			AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
			EnvironmentDigest:    assurance.ComputeStringDigest("cluster:local"),
		},
		EvidenceRoot: "root-hash-123",
		EvaluatedAt:  now,
		ValidUntil:   now.Add(15 * time.Minute),
	}

	envelopes := []assurance.EvidenceEnvelope{
		{
			ID:              "env-01",
			ObservationType: "k8s:admission:review",
			Producer: assurance.AuthorityRef{
				Scheme:  "spiffe",
				Subject: "spiffe://assurance.ckodex.io/ns/ckodex-system/sa/oskal-webhook",
			},
			CapturedAt: now,
			Artifact: assurance.EvidenceRef{
				URI:       "file:///evidence/env-01.json",
				Digest:    "sha256:abc123def456",
				MediaType: "application/json",
			},
		},
	}

	report := InspectSubject(context.Background(), sub, eval, envelopes)
	if report == nil {
		t.Fatal("expected non-nil InspectionReport")
	}

	// 1. Verify Channel 1: Telemetry
	if report.Telemetry.EvaluationDuration == "" {
		t.Fatal("missing telemetry evaluation duration")
	}

	// 2. Verify Channel 2: Execution
	for _, step := range report.Execution.Steps {
		if step.Stage == "HistoricalExecution" && step.Outcome != "UNKNOWN" {
			t.Fatalf("invented historical execution: %+v", step)
		}
		if step.Stage == "ReceiptVerification" && step.Outcome != "UNKNOWN" {
			t.Fatalf("invented receipt proof: %+v", step)
		}
	}
	if report.Evidence.ReceiptVerification != StatusUnknown || report.Evidence.LineageVerification != StatusUnknown || report.Evidence.ProducerIdentityVerification != StatusUnknown || report.Evidence.MerkleValid || report.Evidence.LineageVerified {
		t.Fatalf("invented cryptographic proof: %+v", report.Evidence)
	}

	// 3. Verify Channel 3: Decision
	if report.Decision.ControlID != "AC-6" || report.Decision.Disposition != "ADMIT" {
		t.Fatalf("unexpected decision trace: %+v", report.Decision)
	}

	// 4. Verify Channel 4: Evidence
	if len(report.Evidence.Artifacts) != 1 {
		t.Fatalf("expected 1 evidence artifact, got %d", len(report.Evidence.Artifacts))
	}
	if report.Evidence.SignerIdentity == "" {
		t.Fatal("missing evidence signer identity")
	}
	if !strings.HasPrefix(report.Evidence.EvidenceRoot, "root-hash") {
		t.Fatalf("unexpected evidence root: %s", report.Evidence.EvidenceRoot)
	}
}

func TestInspectSubjectHonestUnknownAndFutureDated(t *testing.T) {
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "prod/payments/Deployment/unverified-app"}
	ctrl := assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
	now := time.Now().UTC()

	evalUnknown := assurance.ClaimEvaluation{
		ID:          "eval-unknown",
		Subject:     sub,
		Control:     ctrl,
		State:       assurance.AssuranceStateUnknown,
		EvaluatedAt: now,
	}

	report := InspectSubject(context.Background(), sub, evalUnknown, nil)
	if report.Decision.Disposition != "SAFE_HOLD" {
		t.Fatalf("expected SAFE_HOLD disposition for UNKNOWN state, got %s", report.Decision.Disposition)
	}
	for _, step := range report.Execution.Steps {
		if step.Order >= 3 && (step.Outcome == "VERIFIED" || step.Outcome == "EMITTED") {
			t.Fatalf("expected unverified/skipped outcome on step %d when no evidence exists, got %s", step.Order, step.Outcome)
		}
	}

	// Future-dated evidence envelope should downgrade disposition to SAFE_HOLD
	futureEnv := assurance.EvidenceEnvelope{
		ID:              "env-future",
		Subject:         sub,
		ObservationType: "kubernetes.admission",
		CapturedAt:      now.Add(10 * time.Minute),
		Artifact:        assurance.EvidenceRef{URI: "file:///future.json", Digest: "sha256:1111"},
	}
	evalAssured := evalUnknown
	evalAssured.State = assurance.AssuranceStateAssured
	futureReport := InspectSubject(context.Background(), sub, evalAssured, []assurance.EvidenceEnvelope{futureEnv})
	if futureReport.Decision.Disposition != "SAFE_HOLD" {
		t.Fatalf("expected future-dated evidence to downgrade disposition to SAFE_HOLD, got %s", futureReport.Decision.Disposition)
	}
}

func TestRunDoctorEnvChecks(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Non-existent TUF_ROOT fails checkSigstoreInfrastructure
	t.Setenv("TUF_ROOT", tmpDir+"/missing-tuf-root.json")
	emptyKube := tmpDir + "/empty-kubeconfig"
	_ = os.WriteFile(emptyKube, []byte("   "), 0600)
	t.Setenv("KUBECONFIG", emptyKube)

	report := RunDoctor(context.Background(), tmpDir)
	if report.OverallState != StatusFail {
		t.Fatalf("expected OverallState StatusFail when TUF_ROOT is missing, got %s", report.OverallState)
	}

	foundTufFail := false
	foundKubeWarn := false
	for _, c := range report.Checks {
		if strings.Contains(c.Name, "Sigstore") && c.Status == StatusFail {
			foundTufFail = true
		}
		if strings.Contains(c.Name, "Kubernetes") && c.Status == StatusWarn && strings.Contains(c.Message, "empty or missing") {
			foundKubeWarn = true
		}
	}
	if !foundTufFail {
		t.Fatal("expected Sigstore check to FAIL for non-existent TUF_ROOT")
	}
	if !foundKubeWarn {
		t.Fatal("expected Kubernetes check to WARN for empty kubeconfig file")
	}
}
