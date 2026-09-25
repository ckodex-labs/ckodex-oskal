package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestCLIHonestStateReporting(t *testing.T) {
	// 1. Build binary to ensure current code is under test
	binPath := filepath.Join(t.TempDir(), "oskal-test")
	cmdBuild := exec.Command("go", "build", "-o", binPath, "../../cmd/oskal/main.go")
	if out, err := cmdBuild.CombinedOutput(); err != nil {
		t.Fatalf("failed to build oskal binary: %v, output: %s", err, string(out))
	}

	subjectURI := "k8s://prod/payments/Deployment/payments-api"

	// 2. Test without flags: absence of evidence must report UNKNOWN (Invariant I-02)
	cmdState := exec.Command(binPath, "assurance", "state", subjectURI)
	outState, err := cmdState.CombinedOutput()
	if err != nil {
		t.Fatalf("oskal assurance state failed: %v", err)
	}
	stateStr := string(outState)
	if !strings.Contains(stateStr, "STATE:           UNKNOWN") {
		t.Errorf("expected STATE: UNKNOWN without evidence, got:\n%s", stateStr)
	}
	if !strings.Contains(stateStr, "EVIDENCE ROOT:   none") {
		t.Errorf("expected EVIDENCE ROOT: none, got:\n%s", stateStr)
	}

	// 3. Test explain without flags: atomic requirements and state must be UNKNOWN / [FAIL]
	cmdExplain := exec.Command(binPath, "assurance", "explain", subjectURI)
	outExplain, err := cmdExplain.CombinedOutput()
	if err != nil {
		t.Fatalf("oskal assurance explain failed: %v", err)
	}
	explainStr := string(outExplain)
	if !strings.Contains(explainStr, "ASSURANCE\nUNKNOWN") {
		t.Errorf("expected ASSURANCE UNKNOWN in explain, got:\n%s", explainStr)
	}
	if !strings.Contains(explainStr, "[FAIL] non-root execution") {
		t.Errorf("expected [FAIL] non-root execution without evidence, got:\n%s", explainStr)
	}

	// 4. Test evidence command without flags
	cmdEvidence := exec.Command(binPath, "assurance", "evidence", subjectURI)
	outEvidence, err := cmdEvidence.CombinedOutput()
	if err != nil {
		t.Fatalf("oskal assurance evidence failed: %v", err)
	}
	if !strings.Contains(string(outEvidence), "No verified evidence envelopes available") {
		t.Errorf("expected no evidence available message, got:\n%s", string(outEvidence))
	}

	// 5. Create genuine local evidence directory
	evidenceDir := t.TempDir()
	env1 := assurance.EvidenceEnvelope{
		Schema:          "https://assurance.ckodex.io/schemas/evidence/v1",
		ID:              "ev-admission-01",
		Subject:         assurance.SubjectRef{Scheme: "k8s", ID: "payments/payments-api"},
		ObservationType: "admission",
		CapturedAt:      time.Now().UTC(),
		Producer:        assurance.AuthorityRef{Scheme: "spiffe", Subject: "prod/ns/ckodex/sa/cel"},
		Artifact:        assurance.EvidenceRef{URI: "evidence://cel/admission", Digest: assurance.ComputeStringDigest("admission-digest"), MediaType: "application/json"},
		IntegrityDigest: assurance.ComputeStringDigest("ev-admission-01-integrity"),
		Epoch: assurance.AssuranceEpoch{
			SubjectDigest:        assurance.ComputeStringDigest("payments/payments-api"),
			ImplementationDigest: assurance.ComputeStringDigest("kubernetes:workload"),
			PolicyDigest:         assurance.ComputeStringDigest("cel:policy:restricted-containers"),
			AuthorityDigest:      assurance.ComputeStringDigest("spiffe://cluster.local/ns/ckodex/sa/cel"),
			EnvironmentDigest:    assurance.ComputeStringDigest("cluster:local"),
		},
	}
	envData, err := json.MarshalIndent(env1, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}
	if err := os.WriteFile(filepath.Join(evidenceDir, "admission.json"), envData, 0644); err != nil {
		t.Fatalf("failed to write evidence file: %v", err)
	}

	// 6. Test with --evidence-dir: should report ASSURED with computed Merkle root
	cmdStateEv := exec.Command(binPath, "--evidence-dir", evidenceDir, "assurance", "state", subjectURI)
	outStateEv, err := cmdStateEv.CombinedOutput()
	if err != nil {
		t.Fatalf("oskal assurance state with evidence-dir failed: %v", err)
	}
	stateEvStr := string(outStateEv)
	if !strings.Contains(stateEvStr, "STATE:           ASSURED") {
		t.Errorf("expected STATE: ASSURED with evidence-dir, got:\n%s", stateEvStr)
	}
	if strings.Contains(stateEvStr, "EVIDENCE ROOT:   none") {
		t.Errorf("expected valid EVIDENCE ROOT, got none:\n%s", stateEvStr)
	}

	// 7. Test explain with --evidence-dir
	cmdExplainEv := exec.Command(binPath, "--evidence-dir", evidenceDir, "assurance", "explain", subjectURI)
	outExplainEv, err := cmdExplainEv.CombinedOutput()
	if err != nil {
		t.Fatalf("oskal assurance explain with evidence-dir failed: %v", err)
	}
	explainEvStr := string(outExplainEv)
	if !strings.Contains(explainEvStr, "ASSURANCE\nASSURED") {
		t.Errorf("expected ASSURANCE ASSURED in explain with evidence, got:\n%s", explainEvStr)
	}

	// 8. Test evidence with --evidence-dir
	cmdListEv := exec.Command(binPath, "--evidence-dir", evidenceDir, "assurance", "evidence", subjectURI)
	outListEv, err := cmdListEv.CombinedOutput()
	if err != nil {
		t.Fatalf("oskal assurance evidence with evidence-dir failed: %v", err)
	}
	listEvStr := string(outListEv)
	if !strings.Contains(listEvStr, "VERIFIED EVIDENCE ENVELOPES") || !strings.Contains(listEvStr, "ev-admission-01") {
		t.Errorf("expected envelope listing, got:\n%s", listEvStr)
	}

	// 9. Verify zero non-ASCII characters across all outputs
	allOutputs := []string{stateStr, explainStr, string(outEvidence), stateEvStr, explainEvStr, listEvStr}
	for i, out := range allOutputs {
		for _, r := range out {
			if r > 127 {
				t.Fatalf("output %d contains non-ASCII character: %c (code %d)", i, r, r)
			}
		}
	}
}
