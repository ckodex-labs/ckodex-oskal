package diagnostics

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

func TestDoctorConfigurationIsNotTrustProof(t *testing.T) {
	t.Setenv("TUF_ROOT", "")
	if check := checkSigstoreInfrastructure(t.Context()); check.Status != StatusUnknown {
		t.Fatalf("absent trust root was not UNKNOWN: %+v", check)
	}
	root := filepath.Join(t.TempDir(), "unverified-root.json")
	if err := os.WriteFile(root, []byte(`{"arbitrary":"configuration"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TUF_ROOT", root)
	if check := checkSigstoreInfrastructure(t.Context()); check.Status != StatusUnknown {
		t.Fatalf("path existence was treated as trusted metadata: %+v", check)
	}
	socketDir, err := os.MkdirTemp("/tmp", "oskal-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", socket)
	if check := checkSPIFFEWorkloadAPI(t.Context()); check.Status != StatusUnknown {
		t.Fatalf("socket connectivity was treated as identity proof: %+v", check)
	}
}

func TestInspectPersistedReceiptRequiresTrustAndBinding(t *testing.T) {
	ctx := context.Background()
	subject := assurance.SubjectRef{Scheme: "local", ID: "receipt-inspection"}
	control := assurance.ControlRef{Namespace: "test", ID: "stored-proof"}
	epoch := assurance.AssuranceEpoch{SubjectDigest: subject.Digest()}
	payload := []byte("actual stored evidence bytes")
	digest := assurance.ComputeDigest(payload)
	env := assurance.EvidenceEnvelope{ID: "stored-observation", Schema: "assurance.ckodex.io/evidence/v1alpha1", Subject: subject, ObservationType: "test.file", CapturedAt: time.Now().UTC(), Producer: assurance.AuthorityRef{Scheme: "local", Subject: "file-observer"}, Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + digest[7:], Digest: digest}, IntegrityDigest: digest, Epoch: epoch, ControlRefs: []assurance.ControlRef{control}}
	dir := t.TempDir()
	repo, err := storage.NewFilesystemEvidenceRepository(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Put(ctx, env, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	signer, err := receipts.NewReceiptManager(assurance.AuthorityRef{Scheme: "local", Subject: "trusted-evaluator"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	receipt, err := signer.IssueReceipt(subject, control, assurance.AssuranceStateAssured, epoch, []assurance.EvidenceRef{env.Artifact}, now)
	if err != nil {
		t.Fatal(err)
	}
	receiptID, err := repo.PutReceipt(ctx, receipt)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := storage.NewFilesystemEvidenceRepository(dir)
	if err != nil {
		t.Fatal(err)
	}
	envelopes, err := restored.ListBySubject(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	eval := assurance.ClaimEvaluation{ID: "stored-evaluation", Subject: subject, Control: control, State: receipt.State, Epoch: epoch, Evidence: []assurance.EvidenceRef{env.Artifact}, EvidenceRoot: receipt.EvidenceRoot, EvaluatedAt: now}
	report, err := InspectStoredSubject(ctx, subject, eval, envelopes, restored, receiptID, signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if report.Evidence.ReceiptVerification != StatusPass || report.Evidence.ReceiptBinding != StatusPass || report.Evidence.RootConsistency != StatusPass {
		t.Fatalf("stored proof not verified: %+v", report.Evidence)
	}
	if report.Evidence.ProducerIdentityVerification != StatusUnknown || report.Evidence.LineageVerification != StatusUnknown || report.Evidence.MerkleValid || report.Evidence.LineageVerified {
		t.Fatalf("receipt was promoted into observation proof: %+v", report.Evidence)
	}
	withoutKey, err := InspectStoredSubject(ctx, subject, eval, envelopes, restored, receiptID, "")
	if err == nil || withoutKey.Evidence.ReceiptVerification != StatusUnknown {
		t.Fatalf("verification without trust anchor: %+v err=%v", withoutKey, err)
	}
	other, err := receipts.NewReceiptManager(assurance.AuthorityRef{Scheme: "local", Subject: "other-key"})
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := InspectStoredSubject(ctx, subject, eval, envelopes, restored, receiptID, other.PublicKey())
	if err == nil || wrongKey.Evidence.ReceiptVerification != StatusFail {
		t.Fatalf("wrong trust anchor accepted: %+v err=%v", wrongKey, err)
	}
	wrongEval := eval
	wrongEval.Epoch.PolicyDigest = assurance.ComputeStringDigest("different policy")
	mismatched, err := InspectStoredSubject(ctx, subject, wrongEval, envelopes, restored, receiptID, signer.PublicKey())
	if err == nil || mismatched.Evidence.ReceiptBinding != StatusFail || mismatched.Evidence.ReceiptVerification != StatusPass {
		t.Fatalf("unbound receipt accepted: %+v err=%v", mismatched, err)
	}
	// Persist genuinely tampered signed bytes, then verify under the original key.
	receipt.EvidenceRoot = assurance.ComputeStringDigest("tampered root")
	if _, err := restored.PutReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	tamperedStore, err := storage.NewFilesystemEvidenceRepository(dir)
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := InspectStoredSubject(ctx, subject, eval, envelopes, tamperedStore, receiptID, signer.PublicKey())
	if err == nil || tampered.Evidence.ReceiptVerification != StatusFail {
		t.Fatalf("tampered persisted receipt accepted: %+v err=%v", tampered, err)
	}
}

func TestInspectContradictoryEvidenceRootRequiresSafeHold(t *testing.T) {
	now := time.Now().UTC()
	sub := assurance.SubjectRef{Scheme: "local", ID: "contradiction"}
	env := assurance.EvidenceEnvelope{ID: "actual-reference", Subject: sub, CapturedAt: now, Artifact: assurance.EvidenceRef{Digest: assurance.ComputeStringDigest("observed bytes")}}
	eval := assurance.ClaimEvaluation{Subject: sub, State: assurance.AssuranceStateAssured, Evidence: []assurance.EvidenceRef{env.Artifact}, EvidenceRoot: assurance.ComputeStringDigest("contradictory root")}
	report := InspectSubject(t.Context(), sub, eval, []assurance.EvidenceEnvelope{env})
	if report.Evidence.RootConsistency != StatusFail || report.AssuranceState != "UNKNOWN" || report.Decision.Disposition != "SAFE_HOLD" {
		t.Fatalf("root contradiction did not restrict the result: %+v", report)
	}
}
