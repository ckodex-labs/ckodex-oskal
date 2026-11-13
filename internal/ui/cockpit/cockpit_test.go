package cockpit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

func TestArchiveInventoryDoesNotInferStanding(t *testing.T) {
	directory := t.TempDir()
	repo, err := storage.NewFilesystemEvidenceRepository(directory)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	view := NewCockpit(CockpitConfig{Once: true, EvidenceDir: directory, Writer: &output})
	if err := view.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "payments") || !strings.Contains(output.String(), "No archived subjects") {
		t.Fatal(output.String())
	}
	producer := assurance.AuthorityRef{Scheme: "local", Subject: "cockpit-archive-test"}
	signer, err := receipts.NewReceiptManager(producer)
	if err != nil {
		t.Fatal(err)
	}
	subject := assurance.SubjectRef{Scheme: "k8s", ID: "fixture/Pod/archive-only"}
	payload := []byte(`{"stored":"material"}`)
	digest := assurance.ComputeDigest(payload)
	for _, kind := range []string{"admission", "kubernetes.admission.violation"} {
		envelope := assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/evidence/v1alpha1", ID: kind, Subject: subject, ObservationType: kind, CapturedAt: time.Now().Add(-time.Hour), Producer: producer, Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(digest, "sha256:"), Digest: digest, MediaType: "application/json"}, IntegrityDigest: digest}
		signed, err := signer.SignEvidence(t.Context(), envelope)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Put(t.Context(), signed, bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
	}
	output.Reset()
	if err := view.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	rows, err := view.gatherWorkloads(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].State != "UNKNOWN" || rows[0].Archived != 2 || rows[0].Verified != 0 || rows[0].Presence != "PRESENT" || rows[0].Coherence != "UNKNOWN" || rows[0].EvidenceRoot != "" || rows[0].Controls != "" {
		t.Fatalf("archive invented assessment: %+v", rows)
	}
	for _, invented := range []string{"ASSURED", "FAILED", "DECOHERENT", "SPIRE verified", "In Sync", "NIST SP 800-53", "Mode: NORMAL", "AC-6"} {
		if strings.Contains(output.String(), invented) {
			t.Fatalf("invented %s: %s", invented, output.String())
		}
	}
	if !strings.Contains(output.String(), "VERIFIED") || !strings.Contains(output.String(), "Live assessment: NOT CONFIGURED") {
		t.Fatal(output.String())
	}
}

func TestArchiveFailuresRemainErrorsAndDoNotCreateStores(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	view := NewCockpit(CockpitConfig{Once: true, EvidenceDir: missing, Writer: &bytes.Buffer{}})
	if err := view.Run(t.Context()); err == nil {
		t.Fatal("missing archive silently became empty")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("read-only cockpit created archive: %v", err)
	}
	directory := t.TempDir()
	repo, err := storage.NewFilesystemEvidenceRepository(directory)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("actual stored fixture")
	digest := assurance.ComputeDigest(payload)
	envelope := assurance.EvidenceEnvelope{ID: "corruption-case", Subject: assurance.SubjectRef{Scheme: "k8s", ID: "fixture/Pod/material"}, ObservationType: "material", CapturedAt: time.Now(), Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(digest, "sha256:"), Digest: digest, MediaType: "text/plain"}, IntegrityDigest: digest}
	if _, err := repo.Put(t.Context(), envelope, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(directory, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:")+".bin")
	if err := os.WriteFile(blob, []byte("corrupted test fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	view = NewCockpit(CockpitConfig{Once: true, EvidenceDir: directory, Writer: &output})
	if err := view.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("corruption not surfaced: %v", err)
	}
	if output.Len() != 0 {
		t.Fatal("failed archive published a dashboard frame")
	}
	if data, err := os.ReadFile(blob); err != nil || string(data) != "corrupted test fixture" {
		t.Fatal("cockpit changed forensic bytes")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := view.Run(canceled); err == nil {
		t.Fatal("cancellation ignored")
	}
}
