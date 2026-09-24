package oskal

import (
	"testing"
	"time"
)

func TestReceiptManagerLifecycle(t *testing.T) {
	evaluatorAuth := AuthorityRef{
		Scheme:  "spiffe",
		Subject: "prod/ns/ckodex/sa/evaluator",
	}

	mgr, err := NewReceiptManager(evaluatorAuth)
	if err != nil {
		t.Fatalf("failed to create receipt manager: %v", err)
	}

	if len(mgr.PublicKey()) == 0 {
		t.Fatal("expected non-empty public key")
	}

	sub := SubjectRef{Scheme: "k8s", ID: "prod/api"}
	ctrl := ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
	epoch := AssuranceEpoch{
		SubjectDigest:        "sha256:sub",
		ImplementationDigest: "sha256:imp",
		PolicyDigest:         "sha256:pol",
		AuthorityDigest:      "sha256:auth",
		EnvironmentDigest:    "sha256:env",
	}
	evidences := []EvidenceRef{
		{Digest: "sha256:ev01"},
		{Digest: "sha256:ev02"},
	}
	now := time.Now().UTC()

	// 1. Issue genuine receipt
	rcpt, err := mgr.IssueReceipt(sub, ctrl, StateAssured, epoch, evidences, now)
	if err != nil {
		t.Fatalf("failed to issue receipt: %v", err)
	}

	// 2. Verify genuine receipt
	if !mgr.VerifyReceipt(rcpt) {
		t.Fatal("expected genuine receipt verification to succeed, got false")
	}

	// 3. Tamper with receipt subject
	tamperedRcpt := rcpt
	tamperedRcpt.Subject.ID = "prod/hacked-api"
	if mgr.VerifyReceipt(tamperedRcpt) {
		t.Fatal("expected tampered receipt verification to fail, got true")
	}

	// 4. Tamper with evidence root
	tamperedRoot := rcpt
	tamperedRoot.EvidenceRoot = "sha256:tamperedRoot"
	if mgr.VerifyReceipt(tamperedRoot) {
		t.Fatal("expected tampered root receipt verification to fail, got true")
	}
}
