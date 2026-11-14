package guesttransport

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/guest"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

func verifyPublicationReceipt(ctx context.Context, raw []byte, p guest.Publication, scope ReceiptScope, now time.Time) (receipts.AttestedReceiptVerification, error) {
	result, err := receipts.VerifyAttestedReceipt(ctx, raw, scope.Key, &scope.Authority, now)
	if err != nil {
		return result, err
	}
	body := result.Body
	if body.Receipt.Evaluator != scope.Authority || body.Receipt.Subject.URI() != scope.Subject.URI() || !maps.Equal(body.Receipt.Subject.Attributes, scope.Subject.Attributes) || body.Receipt.Control != scope.Control || body.Receipt.Epoch != scope.Epoch {
		return result, fmt.Errorf("receipt differs from outside-enrolled assessment scope")
	}
	if body.Receipt.EvaluatedAt.Before(p.ObservedAt) || body.Receipt.EvaluatedAt.After(now) {
		return result, fmt.Errorf("receipt does not bind this publication's evaluation interval")
	}
	if body.Telemetry.RecordDigest != p.RecordDigest || body.Telemetry.QuoteDigest != p.QuoteDigest || body.Telemetry.Integrity.SessionID != p.SessionID || !sameStanding(body.Telemetry.Attestation, p.Standing) {
		return result, fmt.Errorf("receipt replay or unrelated session/quote/record binding")
	}
	if !conservativeIntegrity(body.Telemetry.Integrity, p.Integrity) {
		return result, fmt.Errorf("receipt rewrote or upgraded the observed integrity decision")
	}
	if (result.SignedState == assurance.AssuranceStateVerified || result.SignedState == assurance.AssuranceStateAssured) && result.EffectiveState == assurance.AssuranceStateUnknown {
		return result, fmt.Errorf("positive receipt expired before acknowledgement")
	}
	return result, nil
}

func sameStanding(a, b *assurance.TelemetryAttestation) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.SessionID == b.SessionID && a.SourceInstance == b.SourceInstance && a.MeasurementDigest == b.MeasurementDigest && a.ExportKeyDigest == b.ExportKeyDigest && a.ChannelDigest == b.ChannelDigest && a.RootKind == b.RootKind && a.RootLabel == b.RootLabel && slices.Equal(a.Caveats, b.Caveats) && a.StartedAt.Equal(b.StartedAt) && a.VerifiedAt.Equal(b.VerifiedAt) && a.ExpiresAt.Equal(b.ExpiresAt)
}
func conservativeIntegrity(actual, expected assurance.TelemetryIntegrity) bool {
	allowedState := actual.State == expected.State || expected.State == assurance.AssuranceStateVerified && actual.State == assurance.AssuranceStateUnknown
	if !allowedState {
		return false
	}
	if actual.SessionID != expected.SessionID || actual.RootKind != expected.RootKind || actual.RootLabel != expected.RootLabel || !slices.Equal(actual.Caveats, expected.Caveats) || !actual.WindowStart.Equal(expected.WindowStart) || !actual.WindowEnd.Equal(expected.WindowEnd) || !actual.ValidUntil.Equal(expected.ValidUntil) || !slices.Equal(actual.Loss, expected.Loss) || !slices.Equal(actual.Gaps, expected.Gaps) {
		return false
	}
	if len(actual.Reasons) < len(expected.Reasons) || !slices.Equal(actual.Reasons[:len(expected.Reasons)], expected.Reasons) {
		return false
	}
	if actual.State == assurance.AssuranceStateVerified {
		return len(actual.Reasons) == 0 && actual.Recovery == expected.Recovery
	}
	return actual.Recovery == expected.Recovery || expected.Recovery == "" && actual.Recovery == assurance.TelemetryFreshSessionRequired
}
