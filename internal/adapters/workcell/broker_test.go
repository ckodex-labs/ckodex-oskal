package workcell_test

import (
	"context"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/workcell"
)

func TestEffectBrokerExecutionLifecycle(t *testing.T) {
	broker := workcell.NewEffectBroker()
	ctx := context.Background()

	lease := assurance.NewCapabilityLease(
		"lease-test-1",
		"workcell:copilot",
		"namespace:prod",
		[]string{"tool:read", "tool:execute"},
		2,
		1*time.Hour,
	)
	broker.RegisterLease(lease)

	// Turn 1: Admitted
	rcpt1, err := broker.RequestExecution(ctx, "lease-test-1", "tool:read", []byte(`{"read": "config"}`), lease.LastReceiptHash)
	if err != nil {
		t.Fatalf("turn 1 should succeed: %v", err)
	}
	if rcpt1.Disposition != "ADMIT" {
		t.Errorf("expected ADMIT, got %s", rcpt1.Disposition)
	}

	// Turn 2: Admitted with prev receipt hash
	rcpt2, err := broker.RequestExecution(ctx, "lease-test-1", "tool:execute", []byte(`{"run": "script"}`), rcpt1.ReceiptHash)
	if err != nil {
		t.Fatalf("turn 2 should succeed: %v", err)
	}
	if rcpt2.Disposition != "ADMIT" {
		t.Errorf("expected ADMIT, got %s", rcpt2.Disposition)
	}

	// Turn 3: Exhausted
	rcpt3, err := broker.RequestExecution(ctx, "lease-test-1", "tool:read", []byte(`{"read": "more"}`), rcpt2.ReceiptHash)
	if err == nil {
		t.Fatalf("turn 3 should be rejected due to exhaustion")
	}
	if rcpt3.Disposition != "DENY" {
		t.Errorf("expected DENY, got %s", rcpt3.Disposition)
	}
}

func TestEffectBrokerRevocation(t *testing.T) {
	broker := workcell.NewEffectBroker()
	ctx := context.Background()

	lease := assurance.NewCapabilityLease(
		"lease-test-2",
		"workcell:copilot",
		"namespace:prod",
		[]string{"tool:read"},
		10,
		1*time.Hour,
	)
	broker.RegisterLease(lease)

	// Revoke lease
	if err := broker.Revoke("lease-test-2", "anomalous behavior"); err != nil {
		t.Fatalf("revocation failed: %v", err)
	}

	// Attempt execution
	rcpt, err := broker.RequestExecution(ctx, "lease-test-2", "tool:read", []byte(`{"read": "logs"}`), lease.LastReceiptHash)
	if err == nil {
		t.Fatalf("execution after revocation should fail")
	}
	if rcpt.Disposition != "DENY" {
		t.Errorf("expected DENY after revocation, got %s", rcpt.Disposition)
	}
}
