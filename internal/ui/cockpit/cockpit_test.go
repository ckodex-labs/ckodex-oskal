package cockpit

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestCockpitRenderSnapshot(t *testing.T) {
	emptyDir := t.TempDir()
	buf := new(bytes.Buffer)
	cockpit := NewCockpit(CockpitConfig{
		Once:        true,
		EvidenceDir: emptyDir,
		Writer:      buf,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := cockpit.Run(ctx); err != nil {
		t.Fatalf("cockpit.Run failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "OSKAL ASSURANCE COCKPIT") {
		t.Fatalf("expected title in cockpit output:\n%s", out)
	}
	if !strings.Contains(out, "payments-api") {
		t.Fatalf("expected payments-api in workload list:\n%s", out)
	}
	if !strings.Contains(out, "UNKNOWN") {
		t.Fatalf("expected UNKNOWN state without evidence (Invariant I-02):\n%s", out)
	}
	if !strings.Contains(out, "CRYPTOGRAPHIC MERKLE LINEAGE") {
		t.Fatalf("expected Merkle lineage section:\n%s", out)
	}

	// Verify 100% pure ASCII (0x00 - 0x7F)
	for idx, b := range buf.Bytes() {
		if b > 127 {
			t.Fatalf("non-ASCII character detected at offset %d: %d", idx, b)
		}
	}

	// Now test with populated evidence directory
	evDir := t.TempDir()
	env := assurance.EvidenceEnvelope{
		Schema:          "assurance.ckodex.io/evidence/v1alpha1",
		ID:              "ev-cockpit-1",
		Subject:         assurance.SubjectRef{Scheme: "k8s", ID: "prod/payments/Deployment/payments-api"},
		ObservationType: "admission",
		CapturedAt:      time.Now().UTC(),
		Producer:        assurance.AuthorityRef{Scheme: "spiffe", Subject: "prod/ns/system/sa/observer"},
		Artifact:        assurance.EvidenceRef{URI: "cas://sha256/1234", Digest: assurance.ComputeStringDigest("cockpit-ev"), MediaType: "application/json"},
		IntegrityDigest: assurance.ComputeStringDigest("cockpit-ev"),
	}
	raw, _ := json.Marshal(env)
	if err := os.WriteFile(filepath.Join(evDir, "ev.json"), raw, 0644); err != nil {
		t.Fatalf("failed to write evidence file: %v", err)
	}

	bufAssured := new(bytes.Buffer)
	cockpitAssured := NewCockpit(CockpitConfig{
		Once:        true,
		EvidenceDir: evDir,
		Writer:      bufAssured,
	})
	if err := cockpitAssured.Run(ctx); err != nil {
		t.Fatalf("cockpitAssured.Run failed: %v", err)
	}
	if !strings.Contains(bufAssured.String(), "ASSURED") {
		t.Fatalf("expected ASSURED state when evidence exists:\n%s", bufAssured.String())
	}

	// Verify violation envelope transitions cockpit display to FAILED / NEGATIVE / DECOHERENT
	violDir := t.TempDir()
	violEnv := env
	violEnv.ID = "ev-cockpit-viol"
	violEnv.ObservationType = "kubernetes.admission.violation"
	violRaw, _ := json.Marshal(violEnv)
	if err := os.WriteFile(filepath.Join(violDir, "viol.json"), violRaw, 0644); err != nil {
		t.Fatalf("failed to write violation evidence: %v", err)
	}
	bufViol := new(bytes.Buffer)
	cockpitViol := NewCockpit(CockpitConfig{
		Once:        true,
		EvidenceDir: violDir,
		Writer:      bufViol,
	})
	if err := cockpitViol.Run(ctx); err != nil {
		t.Fatalf("cockpitViol.Run failed: %v", err)
	}
	violOut := bufViol.String()
	if !strings.Contains(violOut, "FAILED") || !strings.Contains(violOut, "NEGATIVE") || !strings.Contains(violOut, "DECOHERENT") {
		t.Fatalf("expected FAILED / NEGATIVE / DECOHERENT in cockpit output on violation:\n%s", violOut)
	}
}
