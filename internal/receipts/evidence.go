package receipts

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

var _ ports.EvidenceSigner = (*ReceiptManager)(nil)

// SignEvidence signs the existing canonical envelope digest. It never changes
// producer, timestamps, subject, epoch or artifact bindings to make them valid.
func (m *ReceiptManager) SignEvidence(ctx context.Context, envelope assurance.EvidenceEnvelope) (assurance.EvidenceEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return assurance.EvidenceEnvelope{}, err
	}
	if m == nil || len(m.privateKey) != ed25519.PrivateKeySize || m.evidenceAuthority.Validate() != nil {
		return assurance.EvidenceEnvelope{}, fmt.Errorf("explicit evidence signing authority and private key are required")
	}
	if envelope.Producer != m.evidenceAuthority {
		return assurance.EvidenceEnvelope{}, fmt.Errorf("evidence producer differs from signing authority")
	}
	if envelope.SignatureRef != "" {
		return assurance.EvidenceEnvelope{}, fmt.Errorf("evidence is already signed")
	}
	envelope.SignatureRef = hex.EncodeToString(ed25519.Sign(m.privateKey, []byte(envelope.SigningDigest())))
	return envelope, nil
}
