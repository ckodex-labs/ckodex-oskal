package guest

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// Publication is the verifier's observed session outcome and its original wire
// material. Accepted is nil for watchdog/fenced outcomes. RecordDigest identifies
// SignedHeartbeat when present, otherwise the last observed signed record; Reason
// distinguishes accepted, rejected and independently detected silence outcomes.
// A nil Standing means no attestation was admitted, never a default trust root.
type Publication struct {
	EnrollmentID         string
	SessionGeneration    uint64
	SessionID            string
	ObservedAt           time.Time
	ExportPublicKey      ed25519.PublicKey
	Challenge            *Challenge
	AttestationReport    []byte
	SignedExportKeyProof []byte
	SignedHeartbeat      []byte
	RecordDigest         string
	Accepted             *AcceptedRecord
	Integrity            assurance.TelemetryIntegrity
	Standing             *assurance.TelemetryAttestation
	QuoteDigest          string
	Reason               string
}

// Publisher durably records the supplied outcome and returns its actual signed
// v2 receipt. It must honor context deadlines and preserve UNKNOWN/fenced outcomes
// against later stale publication attempts. Empty, unsigned or unrelated receipts
// are not successful acknowledgements. Implementations own storage and control
// projection; transports do not construct domain receipts or standing.
type Publisher interface {
	Publish(context.Context, Publication) ([]byte, error)
}

// Sample is an actual producer-side observation batch. Missing reads must remain
// explicit UNKNOWN counters in the sampler; transport must not invent zeroes or
// substitute its current clock for a missing SampledAt.
type Sample struct {
	SourceInstance string
	SampledAt      time.Time
	Counters       []assurance.TelemetryLossCounter
	Observations   []Observation
}

// Sampler owns source I/O and bounded batching. A failed sample fences the client
// stream; transport never converts a sample error into a fabricated heartbeat.
type Sampler interface {
	Sample(context.Context) (Sample, error)
}
