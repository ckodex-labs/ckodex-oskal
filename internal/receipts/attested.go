package receipts

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
)

const AttestedReceiptPayloadType = "application/vnd.oskal.attested-control-receipt.v2+json"

const AttestedReceiptVerificationScope = "Full DSSE body signature under the supplied public key. Evaluator identity is a signed claim; quote, enrollment policy, source identity, TLS binding, telemetry record signatures and evidence artifacts were not independently reverified."

// AttestedControlReceipt is a distinct full-body protocol. Receipt.Signature
// must be empty: a legacy tuple signature cannot acquire new telemetry semantics.
type AttestedControlReceipt struct {
	Version   int                         `json:"version"`
	Receipt   assurance.ControlReceipt    `json:"receipt"`
	Telemetry assurance.TelemetryEvidence `json:"telemetry"`
}

type AttestedReceiptVerification struct {
	Body            AttestedControlReceipt   `json:"body"`
	SignedState     assurance.AssuranceState `json:"signedState"`
	EffectiveState  assurance.AssuranceState `json:"effectiveState"`
	SignatureStatus string                   `json:"signatureStatus"`
	CheckedAt       time.Time                `json:"checkedAt"`
	Reasons         []string                 `json:"reasons,omitempty"`
	Scope           string                   `json:"scope"`
}

// Validate preserves historical truth. Current expiry is checked independently
// by VerifyAttestedReceipt and never modifies a signed body's state.
func (b AttestedControlReceipt) Validate() error {
	r := b.Receipt
	if b.Version != 2 || r.Signature != "" {
		return fmt.Errorf("attested receipts require version 2 and an unsigned embedded receipt; legacy signatures cannot be upgraded")
	}
	if err := r.Subject.Validate(); err != nil {
		return err
	}
	if err := r.Control.Validate(); err != nil {
		return err
	}
	if err := r.Evaluator.Validate(); err != nil {
		return err
	}
	for _, text := range []string{r.Subject.Scheme, r.Subject.ID, r.Control.Namespace, r.Control.ID, r.Evaluator.Scheme, r.Evaluator.Subject} {
		if !attestedText(text, 2048) {
			return fmt.Errorf("receipt identities must be bounded valid text")
		}
	}
	if (r.Control.Version != "" && !attestedText(r.Control.Version, 256)) || len(r.Subject.Attributes) > 64 {
		return fmt.Errorf("receipt control version or subject attribute count exceeds bounds")
	}
	for key, value := range r.Subject.Attributes {
		if !attestedText(key, 128) || len(value) > 4096 || !utf8.ValidString(value) {
			return fmt.Errorf("receipt subject attributes exceed text bounds")
		}
	}
	positive := r.State == assurance.AssuranceStateVerified || r.State == assurance.AssuranceStateAssured
	switch r.State {
	case assurance.AssuranceStateUnknown, assurance.AssuranceStateObserved, assurance.AssuranceStateVerified, assurance.AssuranceStateAssured, assurance.AssuranceStateStale, assurance.AssuranceStateFailed:
	default:
		return fmt.Errorf("receipt requires a defined assessment state")
	}
	for _, d := range []string{r.Epoch.SubjectDigest, r.Epoch.ImplementationDigest, r.Epoch.PolicyDigest, r.Epoch.AuthorityDigest, r.Epoch.EnvironmentDigest} {
		if (d != "" || positive) && !attestedDigest(d) {
			return fmt.Errorf("receipt epoch must contain exact digests; positive standing requires all five dimensions")
		}
	}
	return b.Telemetry.ValidateForEvaluation(r.State, r.EvidenceRoot, r.EvaluatedAt)
}

// SignAttestedReceipt signs the complete v2 body under this explicitly configured
// evaluator. It neither verifies submitted telemetry nor changes the legacy
// ControlReceipt canonical format. The caller must supply an actual evaluation.
func (m *ReceiptManager) SignAttestedReceipt(ctx context.Context, receipt assurance.ControlReceipt, telemetry assurance.TelemetryEvidence) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("receipt signing context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m == nil || m.evaluator.Validate() != nil {
		return nil, fmt.Errorf("explicit attested receipt signing authority is required")
	}
	if receipt.Evaluator != (assurance.AuthorityRef{}) && receipt.Evaluator != m.evaluator {
		return nil, fmt.Errorf("receipt evaluator differs from configured signing authority")
	}
	receipt.Evaluator = m.evaluator
	body := AttestedControlReceipt{Version: 2, Receipt: receipt, Telemetry: telemetry}
	if err := body.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encode attested receipt: %w", err)
	}
	signer, err := signedrecords.NewSigner(m.privateKey)
	if err != nil {
		return nil, err
	}
	return signer.Sign(ctx, AttestedReceiptPayloadType, payload)
}

// VerifyAttestedReceipt verifies a DSSE signature and structural coherence under
// a pinned key. An optional expected evaluator constrains only the signed claim.
// It never accepts legacy tuple signatures or independently re-verifies a quote.
func VerifyAttestedReceipt(ctx context.Context, raw []byte, pinned ed25519.PublicKey, expectedAuthority *assurance.AuthorityRef, now time.Time) (AttestedReceiptVerification, error) {
	var out AttestedReceiptVerification
	if now.IsZero() {
		return out, fmt.Errorf("receipt verification time is required")
	}
	if expectedAuthority != nil && expectedAuthority.Validate() != nil {
		return out, fmt.Errorf("expected evaluator identity claim is invalid")
	}
	payload, err := signedrecords.Verify(ctx, raw, AttestedReceiptPayloadType, pinned, signedrecords.MaxPayloadBytes)
	if err != nil {
		return out, fmt.Errorf("verify attested receipt signature: %w", err)
	}
	var body AttestedControlReceipt
	if err := signedrecords.DecodeJSON(payload, &body, signedrecords.MaxPayloadBytes); err != nil {
		return out, fmt.Errorf("decode attested receipt body: %w", err)
	}
	if err := body.Validate(); err != nil {
		return out, err
	}
	if body.Receipt.EvaluatedAt.After(now) {
		return out, fmt.Errorf("receipt evaluation time is in the future")
	}
	if expectedAuthority != nil && (body.Receipt.Evaluator.Canonical() != expectedAuthority.Canonical() || (expectedAuthority.TrustDomain != "" && body.Receipt.Evaluator.TrustDomain != expectedAuthority.TrustDomain)) {
		return out, fmt.Errorf("signed evaluator claim differs from expected authority scope")
	}
	out = AttestedReceiptVerification{Body: body, SignedState: body.Receipt.State, EffectiveState: body.Receipt.State, SignatureStatus: "VERIFIED", CheckedAt: now, Scope: AttestedReceiptVerificationScope}
	if body.Receipt.State == assurance.AssuranceStateVerified || body.Receipt.State == assurance.AssuranceStateAssured {
		if !now.Before(body.Telemetry.Integrity.ValidUntil) {
			out.EffectiveState = assurance.AssuranceStateUnknown
			out.Reasons = append(out.Reasons, "signed historical assessment has expired; fresh attestation and a complete observation window are required")
		}
	}
	return out, nil
}

func attestedText(text string, maximum int) bool {
	return len(text) > 0 && len(text) <= maximum && utf8.ValidString(text) && strings.TrimSpace(text) == text && strings.IndexFunc(text, unicode.IsControl) < 0
}

func attestedDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}
