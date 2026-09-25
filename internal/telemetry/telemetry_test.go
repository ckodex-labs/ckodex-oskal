package telemetry_test

import (
	"context"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

func TestMetricsRegistrationAndRecording(t *testing.T) {
	// Test recording helpers
	telemetry.RecordAssuranceState("prod", "binding-01", "ASSURED", "1", true)
	telemetry.RecordEvidenceProcessed("trivy", "vulnerability", "PASS")
	telemetry.RecordReceiptIssued("contract-01", "VALID")
	telemetry.RecordDriftInvalidation("binding-01", "generation_changed")

	timer := prometheus.NewTimer(telemetry.EvaluationDurationSeconds.WithLabelValues("contract-01"))
	timer.ObserveDuration()

	// Verify metrics gather from controller-runtime registry
	mfs, err := crmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics from registry: %v", err)
	}

	foundAssuranceGauge := false
	for _, mf := range mfs {
		if mf.GetName() == "oskal_assurance_state" {
			foundAssuranceGauge = true
			if len(mf.GetMetric()) == 0 {
				t.Fatalf("expected metrics in oskal_assurance_state, got 0")
			}
		}
	}
	if !foundAssuranceGauge {
		t.Errorf("expected oskal_assurance_state in gathered metrics")
	}
}

func TestTracingSpans(t *testing.T) {
	ctx := context.Background()

	ctxEval, spanEval := telemetry.StartEvaluationSpan(ctx, "contract-test", "k8s://prod/test")
	defer spanEval.End()
	if ctxEval == nil {
		t.Errorf("expected non-nil context")
	}

	ctxEv, spanEv := telemetry.StartEvidenceSpan(ctx, "falco", "runtime")
	defer spanEv.End()
	if ctxEv == nil {
		t.Errorf("expected non-nil context")
	}

	ctxMerkle, spanMerkle := telemetry.StartMerkleSpan(ctx, 4)
	defer spanMerkle.End()
	if ctxMerkle == nil {
		t.Errorf("expected non-nil context")
	}

	ctxReceipt, spanReceipt := telemetry.StartReceiptSpan(ctx, "rcpt-123", "cosign:kms")
	defer spanReceipt.End()
	if ctxReceipt == nil {
		t.Errorf("expected non-nil context")
	}
}
