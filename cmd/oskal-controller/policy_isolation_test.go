package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

func TestPolicyBatchesCannotInvalidateBoundRuntimeEvidence(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "observed-bytes")
	if err := os.WriteFile(path, []byte("actual local observation\n"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := storage.NewFilesystemEvidenceRepository(filepath.Join(directory, "archive"))
	if err != nil {
		t.Fatal(err)
	}
	producer := assurance.AuthorityRef{Scheme: "local", Subject: "isolation-test"}
	signer, err := receipts.NewReceiptManager(producer)
	if err != nil {
		t.Fatal(err)
	}
	makeRegistry := func(id string) *collection.Candidates {
		t.Helper()
		registry, err := collection.NewCandidates(archive, []collection.SourceConfig{{ID: id, Producer: producer, Signer: signer}}, 1)
		if err != nil {
			t.Fatal(err)
		}
		return registry
	}
	runtime, capture := makeRegistry("runtime"), makeRegistry("policy")
	session, err := runtime.BeginSession("runtime")
	if err != nil {
		t.Fatal(err)
	}
	digest := assurance.ComputeDigest(data)
	subject := assurance.SubjectRef{Scheme: "file", ID: path}
	envelope := assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/evidence/v1alpha1", ID: "actual-file-read", Subject: subject, ObservationType: "local.file.read", CapturedAt: time.Now().UTC(), Producer: producer, Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(digest, "sha256:"), Digest: digest, MediaType: "text/plain"}, IntegrityDigest: digest, Epoch: assurance.AssuranceEpoch{SubjectDigest: digest}}
	if _, err := session.Repository().Put(t.Context(), envelope, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	group := &sourceGroup{candidates: runtime, captureCandidates: capture, window: time.Second}
	revision := runtime.Revision()
	batches := &policyBatches{group: group, source: preparedSource{spec: sourceSpec{ID: "policy"}, policy: &preparedPolicySource{}}}
	for _, failure := range []error{nil, errors.New("actual policy batch ended without eligibility")} {
		_, end, err := batches.begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		end(failure)
		if runtime.Revision() != revision {
			t.Fatal("capture-only batch changed bound runtime revision")
		}
		eligible, err := runtime.ListBySubject(t.Context(), subject)
		if err != nil || len(eligible) != 1 {
			t.Fatalf("bound local evidence was invalidated: %d %v", len(eligible), err)
		}
		if err := group.Ready(nil); err != nil {
			t.Fatalf("policy source changed runtime readiness: %v", err)
		}
	}
	statuses := group.Snapshot()
	if len(statuses) != 2 || statuses[0].Mode != "CAPTURE" || statuses[1].Mode != "BOUND_RUNTIME" {
		t.Fatalf("operational truth hid source mode: %+v", statuses)
	}
	if statuses[0].Lifecycle == collection.SourceRunning {
		t.Fatal("empty policy batch acquired live capture standing")
	}
}

func TestCaptureOnlySourcesRequireExplicitReadOnlyMode(t *testing.T) {
	config := sourceConfiguration{Sources: []sourceSpec{{ID: "policy", Kind: "policy-report", PolicyMode: "CAPTURE"}}}
	if err := validateAdmissionSources(config, true); err == nil {
		t.Fatal("policy capture enabled admission without runtime authority")
	}
	if err := validateAdmissionSources(config, false); err != nil {
		t.Fatal(err)
	}
	config.Sources = append(config.Sources, sourceSpec{ID: "runtime", Kind: "tetragon"})
	if err := validateAdmissionSources(config, true); err != nil {
		t.Fatal(err)
	}
}
