package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

func TestControllerInvalidArchiveLimitsCreateNoArchive(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "controller")
	if output, err := exec.CommandContext(t.Context(), "go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("actual controller build: %v %s", err, output)
	}
	for _, flags := range [][]string{{"--archive-max-bytes=0"}, {"--archive-max-entries=0"}, {"--archive-max-bytes=1099511627777"}, {"--archive-max-entries=1000001"}} {
		path := filepath.Join(t.TempDir(), "never-created")
		args := append([]string{"--evidence-dir", path, "--enable-webhook=false"}, flags...)
		command := exec.CommandContext(t.Context(), binary, args...)
		command.Env = append(os.Environ(), "KUBECONFIG="+filepath.Join(t.TempDir(), "missing"))
		output, err := command.CombinedOutput()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || !bytes.Contains(output, []byte("archive limits require")) {
			t.Fatalf("actual invalid budget did not fail before API/files: %v %s", err, output)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("invalid budget created archive: %v", err)
		}
	}
}

func TestActualQuotaFaultPreservesHistoryAndRuntimeSafeHold(t *testing.T) {
	directory := t.TempDir()
	archivePath := filepath.Join(directory, "archive")
	archive, err := storage.NewFilesystemEvidenceRepositoryWithLimits(archivePath, storage.ArchiveLimits{MaxBytes: 4096, MaxEntries: 16})
	if err != nil {
		t.Fatal(err)
	}
	producer := assurance.AuthorityRef{Scheme: "local", Subject: "quota-observer"}
	signer, err := receipts.NewReceiptManager(producer)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := collection.NewCandidates(archive, []collection.SourceConfig{{ID: "runtime", Producer: producer, Signer: signer}}, 8)
	if err != nil {
		t.Fatal(err)
	}
	session, err := sources.BeginSession("runtime")
	if err != nil {
		t.Fatal(err)
	}
	observe := func(name string, data []byte) error {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		actual, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		hash := assurance.ComputeDigest(actual)
		envelope := assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/evidence/v1alpha1", ID: name, Subject: assurance.SubjectRef{Scheme: "file", ID: path}, ObservationType: "local.file.read", CapturedAt: time.Now().UTC(), Producer: producer, Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(hash, "sha256:"), Digest: hash, MediaType: "application/octet-stream"}, IntegrityDigest: hash, Epoch: assurance.AssuranceEpoch{SubjectDigest: hash}}
		_, err = session.Repository().Put(t.Context(), envelope, bytes.NewReader(actual))
		return err
	}
	if err := observe("first", []byte("actual retained file observation")); err != nil {
		t.Fatal(err)
	}
	err = observe("over-budget", bytes.Repeat([]byte("x"), 8192))
	if !errors.Is(err, ports.ErrEvidenceCapacity) {
		t.Fatalf("actual quota did not refuse new bytes: %v", err)
	}
	if !finishRuntimeSession(session, err) {
		t.Fatal("runtime quota fault would retry")
	}
	before := sources.Snapshot()[0]
	if before.Lifecycle != collection.SourceSafeHold || before.Eligible != 0 || before.Generation != 1 {
		t.Fatalf("actual capacity source state: %+v", before)
	}
	if err := session.End("source shutdown"); err != nil {
		t.Fatal(err)
	}
	after := sources.Snapshot()[0]
	if after.Lifecycle != collection.SourceSafeHold || after.Reason != before.Reason || after.Generation != before.Generation {
		t.Fatalf("quota containment lineage changed: %+v", after)
	}
	restored, err := storage.OpenFilesystemEvidenceRepositoryWithLimits(archivePath, storage.DefaultArchiveLimits())
	if err != nil {
		t.Fatal(err)
	}
	envelopes, err := restored.ListAll(t.Context())
	if err != nil || len(envelopes) != 1 || envelopes[0].ID != "first" || envelopes[0].SignatureRef == "" {
		t.Fatalf("quota refusal lost retained signed history: %+v %v", envelopes, err)
	}
	if _, err := restored.VerifyIntegrity(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Log("actual quota refused admission, runtime generation stayed SAFE_HOLD without retry, retained signed history reopened under reviewed limits")
}

func TestRuntimeConflictHoldStopsAutomaticNextGeneration(t *testing.T) {
	directory := t.TempDir()
	archive, err := storage.NewFilesystemEvidenceRepository(filepath.Join(directory, "archive"))
	if err != nil {
		t.Fatal(err)
	}
	producer := assurance.AuthorityRef{Scheme: "local", Subject: "conflict-observer"}
	signer, err := receipts.NewReceiptManager(producer)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := collection.NewCandidates(archive, []collection.SourceConfig{{ID: "runtime", Producer: producer, Signer: signer}}, 8)
	if err != nil {
		t.Fatal(err)
	}
	session, err := sources.BeginSession("runtime")
	if err != nil {
		t.Fatal(err)
	}
	var refs []assurance.EvidenceRef
	observe := func(text string) error {
		t.Helper()
		path := filepath.Join(directory, "observed-file")
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		hash := assurance.ComputeDigest(data)
		envelope := assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/evidence/v1alpha1", ID: "same-observation-identity", Subject: assurance.SubjectRef{Scheme: "file", ID: path}, ObservationType: "local.file.read", CapturedAt: time.Now().UTC(), Producer: producer, Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(hash, "sha256:"), Digest: hash, MediaType: "text/plain"}, IntegrityDigest: hash, Epoch: assurance.AssuranceEpoch{SubjectDigest: hash}}
		ref, putErr := session.Repository().Put(t.Context(), envelope, bytes.NewReader(data))
		if ref.Digest != "" {
			refs = append(refs, ref)
		}
		return putErr
	}
	if err := observe("first actual file version"); err != nil {
		t.Fatal(err)
	}
	err = observe("second actual file version")
	if err == nil || errors.Is(err, ports.ErrEvidenceCapacity) {
		t.Fatalf("expected actual identity conflict: %v", err)
	}
	before := sources.Snapshot()[0]
	if before.Lifecycle != collection.SourceSafeHold || !runtimeSourceOnHold(sources, "runtime") {
		t.Fatalf("runtime guard missed actual conflict hold: %+v", before)
	}
	finishRuntimeSession(session, err)
	if !runtimeSourceOnHold(sources, "runtime") {
		t.Fatal("ordinary stream end reset conflict containment")
	}
	after := sources.Snapshot()[0]
	if after.Generation != before.Generation || after.Reason != before.Reason || after.Eligible != 0 {
		t.Fatalf("automatic retry guard changed held generation: %+v", after)
	}
	restored, err := storage.OpenFilesystemEvidenceRepository(filepath.Join(directory, "archive"))
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 || refs[0].Digest == refs[1].Digest {
		t.Fatalf("actual conflict did not retain two content identities: %+v", refs)
	}
	for _, ref := range refs {
		reader, err := restored.Get(t.Context(), ref)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(reader)
		if err := errors.Join(readErr, reader.Close()); err != nil {
			t.Fatal(err)
		}
		var envelope assurance.EvidenceEnvelope
		if err := json.Unmarshal(data, &envelope); err != nil {
			t.Fatal(err)
		}
		if assurance.ComputeDigest(data) != ref.Digest || envelope.SignatureRef == "" {
			t.Fatal("historical signed version failed digest binding")
		}
	}
	t.Log("actual conflicting observation caused stable visible SAFE_HOLD; guard prohibits automatic BeginSession while preserving both signed versions")
}
