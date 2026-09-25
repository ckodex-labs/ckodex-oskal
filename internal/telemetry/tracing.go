package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	TracerName = "github.com/ckodex-labs/ckodex-oskal"
)

// GetTracer returns the standard OpenTelemetry tracer for OSKAL.
func GetTracer() trace.Tracer {
	return otel.GetTracerProvider().Tracer(TracerName)
}

// StartEvaluationSpan starts a span for evaluating an assurance contract.
func StartEvaluationSpan(ctx context.Context, contractID, subjectID string) (context.Context, trace.Span) {
	return GetTracer().Start(ctx, "AssuranceContract.Evaluate",
		trace.WithAttributes(
			attribute.String("oskal.contract_id", contractID),
			attribute.String("oskal.subject_id", subjectID),
		),
	)
}

// StartEvidenceSpan starts a span for ingesting or processing an evidence envelope.
func StartEvidenceSpan(ctx context.Context, source, evidenceType string) (context.Context, trace.Span) {
	return GetTracer().Start(ctx, "Evidence.Ingest",
		trace.WithAttributes(
			attribute.String("oskal.evidence_source", source),
			attribute.String("oskal.evidence_type", evidenceType),
		),
	)
}

// StartMerkleSpan starts a span for computing Merkle root verification.
func StartMerkleSpan(ctx context.Context, leafCount int) (context.Context, trace.Span) {
	return GetTracer().Start(ctx, "Merkle.DeriveTree",
		trace.WithAttributes(
			attribute.Int("oskal.merkle_leaf_count", leafCount),
		),
	)
}

// StartReceiptSpan starts a span for creating and signing an assurance receipt.
func StartReceiptSpan(ctx context.Context, receiptID, signer string) (context.Context, trace.Span) {
	return GetTracer().Start(ctx, "Receipt.Sign",
		trace.WithAttributes(
			attribute.String("oskal.receipt_id", receiptID),
			attribute.String("oskal.signer", signer),
		),
	)
}
