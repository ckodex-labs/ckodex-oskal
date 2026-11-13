package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
)

func TestCLIHonestStateReporting(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "oskal-test")
	if output, err := exec.Command("go", "build", "-o", binary, "../../cmd/oskal").CombinedOutput(); err != nil {
		t.Fatalf("build whole CLI package: %v\n%s", err, output)
	}
	subject := "k8s://example/Pod/material"
	command := func(args ...string) string {
		t.Helper()
		output, err := exec.Command(binary, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("CLI %v failed: %v\n%s", args, err, output)
		}
		return string(output)
	}
	state := command("assurance", "state", subject)
	if !strings.Contains(state, "STATE:           UNKNOWN") || !strings.Contains(state, "EVIDENCE ROOT:   none") {
		t.Fatalf("missing evidence fabricated assurance: %s", state)
	}
	explanation := command("assurance", "explain", subject, "--control", "example:observed")
	if !strings.Contains(explanation, "ASSURANCE\nUNKNOWN") || strings.Contains(explanation, "[FAIL]") || strings.Contains(explanation, "spiffe://prod") {
		t.Fatalf("offline explanation invented adverse facts or producer authority: %s", explanation)
	}
	payload := []byte("actual untrusted test material")
	digest := assurance.ComputeDigest(payload)
	envelope := assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/material/v1", ID: "untrusted-material", Subject: assurance.SubjectRef{Scheme: "k8s", ID: "example/Pod/material"}, ObservationType: "manifest.observed", CapturedAt: time.Now().UTC(), Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(digest, "sha256:"), Digest: digest, MediaType: "text/plain"}, IntegrityDigest: digest}
	// The repository's actual persistent path is explicit; no signer or producer
	// trust is supplied, so the CLI must continue to report UNKNOWN.
	evidenceDirectory := filepath.Join(t.TempDir(), "material-store")
	persisted, err := storage.NewFilesystemEvidenceRepository(evidenceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persisted.Put(t.Context(), envelope, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	state = command("--evidence-dir", evidenceDirectory, "assurance", "state", subject)
	if !strings.Contains(state, "STATE:           UNKNOWN") || strings.Contains(state, "ASSURED") {
		t.Fatalf("material presence became assurance: %s", state)
	}
	listing := command("--evidence-dir", evidenceDirectory, "assurance", "evidence", subject)
	if !strings.Contains(listing, "SUPPLIED EVIDENCE REFERENCES") || !strings.Contains(listing, envelope.ID) || strings.Contains(listing, "VERIFIED EVIDENCE") {
		t.Fatalf("listing misrepresented trust: %s", listing)
	}
	manifest := filepath.Join(t.TempDir(), "workload.yaml")
	if err := os.WriteFile(manifest, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: material\n  namespace: example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	materialDirectory := filepath.Join(t.TempDir(), "material")
	recorded := command("record", "manifest", "--file", manifest, "--evidence-dir", materialDirectory)
	var result map[string]any
	if err := json.Unmarshal([]byte(recorded), &result); err != nil || result["status"] != "RECORDED_UNTRUSTED" {
		t.Fatalf("manifest fabricated admission: %s %v", recorded, err)
	}
	if _, err := os.Stat(filepath.Join(materialDirectory, "receipts")); !os.IsNotExist(err) {
		t.Fatalf("manifest recording manufactured receipts: %v", err)
	}
	for _, args := range [][]string{{"record", "admission", "--file", manifest, "--evidence-dir", filepath.Join(t.TempDir(), "retired")}, {"export", "ssp", "--subject", subject}, {"assurance", "receipt", "verify", "--receipt-id", "untrusted"}} {
		if output, err := exec.Command(binary, args...).CombinedOutput(); err == nil {
			t.Fatalf("missing authoritative inputs unexpectedly succeeded: %v\n%s", args, output)
		}
	}
}
