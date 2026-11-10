package verifier

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

var _ ports.EvidenceVerifier = (*DefaultEvidenceVerifier)(nil)

// OSKALVerifier aliases DefaultEvidenceVerifier for callers referencing the canonical verifier name.
type OSKALVerifier = DefaultEvidenceVerifier

// DefaultEvidenceVerifier verifies cryptographic signatures and epoch matching for EvidenceEnvelopes.
type DefaultEvidenceVerifier struct {
	knownPublicKeys map[string]ed25519.PublicKey // producer URI -> public key
}

// NewDefaultEvidenceVerifier creates a new evidence verifier.
func NewDefaultEvidenceVerifier() *DefaultEvidenceVerifier {
	return &DefaultEvidenceVerifier{
		knownPublicKeys: make(map[string]ed25519.PublicKey),
	}
}

// DeriveControlRefs maps an observation's metadata, type, and producer to canonical ControlRefs.
func DeriveControlRefs(obsType, producer string, attrs map[string]string) []assurance.ControlRef {
	for _, key := range []string{"control_id", "control"} {
		if rawCtrl := strings.TrimSpace(attrs[key]); rawCtrl != "" {
			if parts := strings.SplitN(rawCtrl, ":", 2); len(parts) == 2 {
				return []assurance.ControlRef{{Namespace: strings.TrimSpace(parts[0]), ID: strings.TrimSpace(parts[1])}}
			}
			return []assurance.ControlRef{{Namespace: "nist-sp-800-53", ID: rawCtrl}}
		}
	}
	combined := strings.ToLower(obsType + " " + producer)
	switch {
	case strings.Contains(combined, "cilium") || strings.Contains(combined, "network"):
		return []assurance.ControlRef{{Namespace: "nist-sp-800-53", ID: "SC-7"}}
	case strings.Contains(combined, "sigstore") || strings.Contains(combined, "supplychain") || strings.Contains(combined, "cosign"):
		return []assurance.ControlRef{{Namespace: "nist-sp-800-53", ID: "SI-7"}}
	case strings.Contains(combined, "shield") || strings.Contains(combined, "model") || strings.Contains(combined, "aibom"):
		return []assurance.ControlRef{{Namespace: "nist-sp-800-53", ID: "SA-11"}}
	case strings.Contains(combined, "spire") || strings.Contains(combined, "svid") || strings.Contains(combined, "identity"):
		return []assurance.ControlRef{{Namespace: "nist-sp-800-53", ID: "IA-3"}}
	default:
		return []assurance.ControlRef{{Namespace: "nist-sp-800-53", ID: "AC-6"}}
	}
}

// VerifyAndNormalize normalizes a raw Observation into a verified EvidenceEnvelope with derived ControlRefs.
func (v *DefaultEvidenceVerifier) VerifyAndNormalize(ctx context.Context, raw assurance.Observation, currentEpoch assurance.AssuranceEpoch) (assurance.EvidenceEnvelope, error) {
	var art assurance.EvidenceRef
	if len(raw.Evidence) > 0 {
		art = raw.Evidence[0]
	}
	if art.Digest == "" {
		art.Digest = raw.Digest()
	}
	env := assurance.EvidenceEnvelope{
		Schema:          "assurance.ckodex.io/evidence/v1alpha1",
		ID:              "env-" + raw.ID,
		Subject:         raw.Subject,
		ObservationType: raw.Type,
		CapturedAt:      raw.ObservedAt,
		Producer:        raw.Observer,
		Artifact:        art,
		IntegrityDigest: art.Digest,
		Epoch:           currentEpoch,
		ControlRefs:     DeriveControlRefs(raw.Type, raw.Observer.Canonical(), raw.Attributes),
	}
	return env, nil
}

// RegisterPublicKey registers a known public key for an evidence producer.
func (v *DefaultEvidenceVerifier) RegisterPublicKey(producerURI string, pubKey ed25519.PublicKey) {
	v.knownPublicKeys[producerURI] = pubKey
}

// VerifySignature verifies the cryptographic signature of an EvidenceEnvelope.
func (v *DefaultEvidenceVerifier) VerifySignature(ctx context.Context, envelope assurance.EvidenceEnvelope) (bool, error) {
	if envelope.SignatureRef == "" {
		return false, nil
	}

	sigBytes, err := hex.DecodeString(envelope.SignatureRef)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}

	pubKey, exists := v.knownPublicKeys[envelope.Producer.Canonical()]
	if !exists {
		return false, nil
	}

	raw := envelope.SigningDigest()
	return ed25519.Verify(pubKey, []byte(raw), sigBytes), nil
}

// VerifyEpoch checks if the envelope epoch aligns with the current active epoch.
func (v *DefaultEvidenceVerifier) VerifyEpoch(ctx context.Context, envelope assurance.EvidenceEnvelope, currentEpoch assurance.AssuranceEpoch) bool {
	return envelope.Epoch.Matches(currentEpoch)
}
