package receipts

import (
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestCryptographicReceiptIssueAndIndependentVerification(t *testing.T) {
	evaluatorID := assurance.AuthorityRef{
		Scheme:      "spiffe",
		Subject:     "prod/ns/ckodex-assurance/sa/evaluator",
		TrustDomain: "prod",
	}

	mgr, err := NewReceiptManager(evaluatorID)
	if err != nil {
		t.Fatalf("failed to create receipt manager: %v", err)
	}

	sub := assurance.SubjectRef{Scheme: "k8s", ID: "payments/payments-api/Deployment/payments-api"}
	ctrl := assurance.ControlRef{Namespace: "ckodex", ID: "container.least-privilege"}
	epoch := assurance.AssuranceEpoch{
		SubjectDigest:        "sha256:sub123",
		ImplementationDigest: "sha256:imp123",
		PolicyDigest:         "sha256:pol123",
		AuthorityDigest:      "sha256:auth123",
		EnvironmentDigest:    "sha256:env123",
	}

	evidences := []assurance.EvidenceRef{
		{URI: "evidence://cel/1", Digest: "sha256:aaa", MediaType: "application/json"},
		{URI: "evidence://tetragon/2", Digest: "sha256:bbb", MediaType: "application/json"},
	}

	now := time.Now().UTC()

	// 1. Issue signed receipt
	receipt, err := mgr.IssueReceipt(sub, ctrl, assurance.AssuranceStateAssured, epoch, evidences, now)
	if err != nil {
		t.Fatalf("failed to issue receipt: %v", err)
	}

	if receipt.Signature == "" {
		t.Fatalf("expected non-empty signature on receipt")
	}

	// 2. Milestone 12 Exit Criteria:
	// Another process with only the public key can independently verify the receipt.
	pubKeyHex := mgr.PublicKey()

	valid, err := VerifyIndependentReceipt(receipt, pubKeyHex)
	if err != nil || !valid {
		t.Fatalf("M12 Exit Failure: Independent process failed to verify valid receipt: %v", err)
	}

	// 3. Tampering with any field invalidates signature
	// Tamper subject
	tamperedReceiptSub := receipt
	tamperedReceiptSub.Subject = assurance.SubjectRef{Scheme: "k8s", ID: "attacker/fake-deployment"}
	validTamperedSub, _ := VerifyIndependentReceipt(tamperedReceiptSub, pubKeyHex)
	if validTamperedSub {
		t.Fatalf("Security failure: Tampered subject was verified!")
	}

	// Tamper state (e.g. FAILED -> ASSURED)
	tamperedReceiptState := receipt
	tamperedReceiptState.State = assurance.AssuranceStateFailed
	validTamperedState, _ := VerifyIndependentReceipt(tamperedReceiptState, pubKeyHex)
	if validTamperedState {
		t.Fatalf("Security failure: Tampered state was verified!")
	}

	// Tamper evidence root
	tamperedReceiptRoot := receipt
	tamperedReceiptRoot.EvidenceRoot = "sha256:fakeEvidenceRoot"
	validTamperedRoot, _ := VerifyIndependentReceipt(tamperedReceiptRoot, pubKeyHex)
	if validTamperedRoot {
		t.Fatalf("Security failure: Tampered evidence root was verified!")
	}
}

func TestDeterministicEvidenceRoot(t *testing.T) {
	ev1 := []assurance.EvidenceRef{
		{Digest: "sha256:zzz"},
		{Digest: "sha256:aaa"},
		{Digest: "sha256:mmm"},
	}
	ev2 := []assurance.EvidenceRef{
		{Digest: "sha256:aaa"},
		{Digest: "sha256:mmm"},
		{Digest: "sha256:zzz"},
	}

	root1 := ComputeEvidenceRoot(ev1)
	root2 := ComputeEvidenceRoot(ev2)

	if root1 != root2 {
		t.Fatalf("expected deterministic root regardless of input slice order: %s vs %s", root1, root2)
	}
}
