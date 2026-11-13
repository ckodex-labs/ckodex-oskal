package assurance

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// TelemetryEvidence retains the context used by the application's external
// verifier and integrity gate. These fields do not verify a quote, signature,
// enrolled policy, measurement authority, source, or TLS session by themselves.
type TelemetryEvidence struct {
	Attestation  *TelemetryAttestation `json:"attestation,omitempty"`
	Integrity    TelemetryIntegrity    `json:"integrity"`
	RecordDigest string                `json:"recordDigest,omitempty"`
	QuoteDigest  string                `json:"quoteDigest,omitempty"`
}

// ValidateAt checks the historical coherence of a supplied integrity decision.
// Expiry after evaluatedAt does not rewrite history. Current freshness is a
// separate verification result. UNKNOWN may retain expired or unordered windows.
func (t TelemetryEvidence) ValidateAt(evaluatedAt time.Time) error {
	i := t.Integrity
	if evaluatedAt.IsZero() || (i.State != AssuranceStateUnknown && i.State != AssuranceStateVerified) {
		return fmt.Errorf("telemetry requires an evaluation time and UNKNOWN or VERIFIED integrity")
	}
	if !evidenceText(i.RootKind, 128) || !evidenceText(i.RootLabel, 1024) || len(i.Caveats) == 0 || len(i.Caveats) > 16 {
		return fmt.Errorf("telemetry requires an explicit enrolled root and bounded nonempty caveats")
	}
	for _, text := range i.Caveats {
		if !evidenceText(text, 2048) {
			return fmt.Errorf("telemetry caveats must be bounded valid text")
		}
	}
	if i.RootKind == "SOFTWARE_TPM" && i.RootLabel != "software TPM root \u2014 not hardware-backed" {
		return fmt.Errorf("software TPM telemetry requires its exact software-root label")
	}
	if i.SessionID != "" && !telemetryDigest(i.SessionID) {
		return fmt.Errorf("telemetry session must be an exact digest")
	}
	if len(i.Loss) > MaxTelemetrySignals || len(i.Gaps) > 64 || len(i.Reasons) > MaxTelemetrySignals+32 {
		return fmt.Errorf("telemetry loss, gaps or reasons exceed their bounds")
	}
	for n, loss := range i.Loss {
		if !evidenceText(loss.Signal, 1024) || loss.Delta == 0 || (n > 0 && loss.Signal <= i.Loss[n-1].Signal) {
			return fmt.Errorf("telemetry loss requires sorted unique signals and positive deltas")
		}
	}
	for _, gap := range i.Gaps {
		if (gap.Kind != "HEARTBEAT" && gap.Kind != "SEQUENCE") || gap.First == 0 || gap.Last < gap.First {
			return fmt.Errorf("telemetry gaps require a known kind and a positive inclusive range")
		}
	}
	for _, reason := range i.Reasons {
		if !evidenceText(reason, 2048) {
			return fmt.Errorf("telemetry reasons must be bounded valid text")
		}
	}
	if i.Recovery != "" && i.Recovery != TelemetryFreshSessionRequired {
		return fmt.Errorf("telemetry recovery requires a known transition")
	}
	for _, d := range []string{t.RecordDigest, t.QuoteDigest} {
		if d != "" && !telemetryDigest(d) {
			return fmt.Errorf("telemetry artifact references must be exact digests")
		}
	}
	if t.Attestation != nil {
		a := t.Attestation
		if err := a.Validate(); err != nil {
			return fmt.Errorf("telemetry attestation: %w", err)
		}
		if !evidenceText(a.SourceInstance, 1024) {
			return fmt.Errorf("telemetry attestation source must be bounded valid text")
		}
		if a.RootKind != i.RootKind || a.RootLabel != i.RootLabel || a.SessionID != i.SessionID || !slices.Equal(a.Caveats, i.Caveats) {
			return fmt.Errorf("telemetry attestation and integrity context disagree")
		}
	}
	if i.State == AssuranceStateUnknown {
		if len(i.Reasons) == 0 {
			return fmt.Errorf("UNKNOWN telemetry requires its specific reasons")
		}
		return nil
	}
	if t.Attestation == nil || !telemetryDigest(t.RecordDigest) || !telemetryDigest(t.QuoteDigest) || len(i.Loss) != 0 || len(i.Gaps) != 0 || len(i.Reasons) != 0 || i.Recovery != "" {
		return fmt.Errorf("VERIFIED telemetry requires complete attestation and artifact references without loss, gaps or unresolved reasons")
	}
	a := t.Attestation
	if i.WindowStart.IsZero() || !i.WindowEnd.After(i.WindowStart) || i.WindowEnd.After(evaluatedAt) || !i.ValidUntil.After(evaluatedAt) || i.ValidUntil.After(a.ExpiresAt) || i.WindowStart.Before(a.StartedAt) || a.VerifiedAt.After(i.WindowEnd) || a.VerifiedAt.After(evaluatedAt) {
		return fmt.Errorf("VERIFIED telemetry requires a completed observation window and live attestation at evaluation time")
	}
	return nil
}

// ValidateForEvaluation prevents a positive control projection or receipt from
// bypassing an UNKNOWN visibility gate. It validates claims, not their provenance.
func (t TelemetryEvidence) ValidateForEvaluation(state AssuranceState, root string, evaluatedAt time.Time) error {
	if err := t.ValidateAt(evaluatedAt); err != nil {
		return err
	}
	if root != "" && !telemetryDigest(root) {
		return fmt.Errorf("evaluation evidence root must be an exact digest")
	}
	if state == AssuranceStateVerified || state == AssuranceStateAssured {
		if t.Integrity.State != AssuranceStateVerified || !telemetryDigest(root) || root == ComputeDigest(nil) {
			return fmt.Errorf("positive control standing requires VERIFIED telemetry and a nonempty actual evidence root")
		}
	}
	return nil
}

func evidenceText(text string, maximum int) bool {
	return utf8.ValidString(text) && telemetryIdentifier(text, maximum) && strings.IndexFunc(text, unicode.IsControl) < 0
}
