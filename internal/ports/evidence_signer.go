package ports

import (
	"context"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// EvidenceSigner authenticates an envelope under an explicitly configured producer.
type EvidenceSigner interface {
	SignEvidence(context.Context, assurance.EvidenceEnvelope) (assurance.EvidenceEnvelope, error)
}

// EvidenceRevisioner exposes source-session availability changes during an evaluation. A changed
// revision invalidates the candidate snapshot; it does not revoke the archive.
type EvidenceRevisioner interface{ Revision() uint64 }
