package oskal

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"testing"
	"time"
)

func TestReceiptManagerRequiresExplicitAuthority(t *testing.T) {
	if manager, err := NewReceiptManager(AuthorityRef{}); err == nil || manager != nil {
		t.Fatal("an absent authority created a public SDK signer")
	}
}

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
		SubjectDigest:        ComputeStringDigest(sub.ID),
		ImplementationDigest: ComputeStringDigest("kubernetes:workload"),
		PolicyDigest:         ComputeStringDigest("policy:nist-ac6"),
		AuthorityDigest:      ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
		EnvironmentDigest:    ComputeStringDigest("cluster:local"),
	}
	evidences := []EvidenceRef{
		{Digest: ComputeStringDigest("evidence-payload-01")},
		{Digest: ComputeStringDigest("evidence-payload-02")},
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
	tamperedRoot.EvidenceRoot = ComputeStringDigest("tampered-root")
	if mgr.VerifyReceipt(tamperedRoot) {
		t.Fatal("expected tampered root receipt verification to fail, got true")
	}
}

func TestSDKReceiptManagerRequiresItsConfiguredAuthority(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expected := AuthorityRef{Scheme: "spiffe", Subject: "receipt.test/ns/sdk/sa/signer", TrustDomain: "receipt.test"}
	inner, err := receipts.NewReceiptManagerFromKey(expected, key)
	if err != nil {
		t.Fatal(err)
	}
	manager := &ReceiptManager{inner: inner}
	receipt, err := manager.IssueReceipt(SubjectRef{Scheme: "file", ID: "declared-material"}, ControlRef{Namespace: "example", ID: "record"}, StateUnknown, AssuranceEpoch{}, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !manager.VerifyReceipt(receipt) {
		t.Fatal("same configured authority rejected")
	}
	alternate := expected
	alternate.Subject = "receipt.test/ns/other/sa/signer"
	other, err := receipts.NewReceiptManagerFromKey(alternate, key)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err = other.IssueReceipt(receipt.Subject, receipt.Control, StateUnknown, AssuranceEpoch{}, nil, receipt.EvaluatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := VerifyIndependentReceipt(receipt, manager.PublicKey()); err != nil || !valid {
		t.Fatalf("genuine signature under shared test key rejected: %v", err)
	}
	if manager.VerifyReceipt(receipt) {
		t.Fatal("SDK manager accepted another evaluator using the same key")
	}
}
