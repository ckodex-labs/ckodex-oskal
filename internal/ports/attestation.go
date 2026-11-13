package ports

import (
	"context"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// AttestationVerifier verifies a bounded opaque report against outside-enrolled
// trust and the exact verifier-generated qualification. Implementations must
// verify qualification inside the signed report, not in an unsigned wrapper.
// Session freshness and challenge consumption belong to the application.
type AttestationVerifier interface {
	VerifyAttestation(ctx context.Context, report []byte, qualification [64]byte) (assurance.AttestedEnvironment, error)
}

// AttestationProvider obtains a real signed report. It confers no admission
// authority; only the external verifier can admit the resulting evidence.
type AttestationProvider interface {
	Attest(ctx context.Context, qualification [64]byte) ([]byte, error)
}
