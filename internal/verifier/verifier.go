package verifier

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

var _ ports.EvidenceVerifier = (*DefaultEvidenceVerifier)(nil)

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

	raw := envelope.Digest()
	return ed25519.Verify(pubKey, []byte(raw), sigBytes), nil
}

// VerifyEpoch checks if the envelope epoch aligns with the current active epoch.
func (v *DefaultEvidenceVerifier) VerifyEpoch(ctx context.Context, envelope assurance.EvidenceEnvelope, currentEpoch assurance.AssuranceEpoch) bool {
	return envelope.Epoch.Matches(currentEpoch)
}
