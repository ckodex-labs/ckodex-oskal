package assurance_test

import (
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestCapabilityLeaseAdmitTurnSequence(t *testing.T) {
	lease := assurance.NewCapabilityLease(
		"lease-agent-001",
		"workcell:cluster-auditor",
		"namespace:default",
		[]string{"tool:read", "tool:query-metrics"},
		3,
		1*time.Hour,
	)

	now := time.Now().UTC()
	if phase := lease.Phase(now); phase != assurance.LeasePhaseActive {
		t.Fatalf("expected lease phase ACTIVE, got %s", phase)
	}

	// Turn 1
	payload1 := []byte(`{"action": "read_pod_logs", "pod": "payments-api-123"}`)
	rcpt1, err := lease.EvaluateTurn("tool:read", payload1, lease.LastReceiptHash, now)
	if err != nil {
		t.Fatalf("unexpected error in turn 1: %v", err)
	}
	if rcpt1.Disposition != "ADMIT" {
		t.Errorf("expected ADMIT, got %s", rcpt1.Disposition)
	}
	if rcpt1.Turn != 1 {
		t.Errorf("expected turn 1, got %d", rcpt1.Turn)
	}
	if lease.LastReceiptHash != rcpt1.ReceiptHash {
		t.Errorf("expected lease last receipt hash to match rcpt1 hash")
	}

	// Turn 2
	payload2 := []byte(`{"metric": "oskal_assurance_state"}`)
	rcpt2, err := lease.EvaluateTurn("tool:query-metrics", payload2, rcpt1.ReceiptHash, now.Add(5*time.Second))
	if err != nil {
		t.Fatalf("unexpected error in turn 2: %v", err)
	}
	if rcpt2.Disposition != "ADMIT" {
		t.Errorf("expected ADMIT, got %s", rcpt2.Disposition)
	}
	if rcpt2.PrevReceiptHash != rcpt1.ReceiptHash {
		t.Errorf("turn chaining failed: prev hash mismatch")
	}
}

func TestCapabilityLeaseUnauthorizedCapability(t *testing.T) {
	lease := assurance.NewCapabilityLease(
		"lease-agent-002",
		"workcell:auditor",
		"cluster",
		[]string{"tool:read"},
		5,
		1*time.Hour,
	)

	now := time.Now().UTC()
	payload := []byte(`{"command": "rm -rf /data"}`)
	rcpt, err := lease.EvaluateTurn("tool:delete", payload, lease.LastReceiptHash, now)
	if err == nil {
		t.Fatalf("expected error for unauthorized capability, got nil")
	}
	if rcpt.Disposition != "DENY" {
		t.Errorf("expected disposition DENY, got %s", rcpt.Disposition)
	}
}

func TestCapabilityLeaseExhaustion(t *testing.T) {
	lease := assurance.NewCapabilityLease(
		"lease-agent-003",
		"workcell:task",
		"cluster",
		[]string{"tool:read"},
		1, // Max 1 turn
		1*time.Hour,
	)

	now := time.Now().UTC()
	_, err := lease.EvaluateTurn("tool:read", []byte("1"), lease.LastReceiptHash, now)
	if err != nil {
		t.Fatalf("turn 1 failed: %v", err)
	}

	if phase := lease.Phase(now); phase != assurance.LeasePhaseExhausted {
		t.Fatalf("expected EXHAUSTED phase, got %s", phase)
	}

	// Turn 2 should fail
	rcpt, err := lease.EvaluateTurn("tool:read", []byte("2"), lease.LastReceiptHash, now)
	if err == nil {
		t.Fatalf("expected failure on exhausted lease")
	}
	if rcpt.Disposition != "DENY" {
		t.Errorf("expected DENY, got %s", rcpt.Disposition)
	}
}

func TestCapabilityLeaseChainTampering(t *testing.T) {
	lease := assurance.NewCapabilityLease(
		"lease-agent-004",
		"workcell:task",
		"cluster",
		[]string{"tool:read"},
		5,
		1*time.Hour,
	)

	now := time.Now().UTC()
	rcpt, err := lease.EvaluateTurn("tool:read", []byte("test"), "bad-tampered-prev-hash", now)
	if err == nil {
		t.Fatalf("expected chain tampering error")
	}
	if rcpt.Disposition != "DENY" {
		t.Errorf("expected DENY, got %s", rcpt.Disposition)
	}
}

func TestCapabilityLeaseRevocationAndExpiry(t *testing.T) {
	lease := assurance.NewCapabilityLease(
		"lease-agent-005",
		"workcell:task",
		"cluster",
		[]string{"tool:read"},
		5,
		10*time.Millisecond,
	)

	now := time.Now().UTC()
	// Test revocation
	lease.Revoke("Security policy violation detected by Tetragon")
	if phase := lease.Phase(now); phase != assurance.LeasePhaseRevoked {
		t.Fatalf("expected REVOKED phase, got %s", phase)
	}

	// Test expired
	lease2 := assurance.NewCapabilityLease("lease-expired", "agent", "scope", []string{"*"}, 5, 5*time.Millisecond)
	if phase := lease2.Phase(now.Add(1 * time.Second)); phase != assurance.LeasePhaseExpired {
		t.Fatalf("expected EXPIRED phase, got %s", phase)
	}
}
