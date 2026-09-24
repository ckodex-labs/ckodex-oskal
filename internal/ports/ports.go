package ports

import (
	"context"
	"io"
	"time"

	"github.com/ckodex-labs/oskal/core/assurance"
)

// ControlResolver determines which controls apply to a subject (Section 30).
type ControlResolver interface {
	ResolveControls(ctx context.Context, subject assurance.SubjectRef) ([]assurance.ControlRef, error)
}

// SubjectResolver discovers and resolves workload subjects in the runtime (Section 62).
type SubjectResolver interface {
	ResolveSubject(ctx context.Context, uri string) (assurance.SubjectRef, error)
	ComputeSubjectDigest(ctx context.Context, subject assurance.SubjectRef) (string, error)
}

// EvidenceRepository abstracts immutable content-addressed evidence storage (Section 28, ADR-002).
type EvidenceRepository interface {
	Put(ctx context.Context, envelope assurance.EvidenceEnvelope, payload io.Reader) (assurance.EvidenceRef, error)
	Get(ctx context.Context, ref assurance.EvidenceRef) (io.ReadCloser, error)
	Verify(ctx context.Context, ref assurance.EvidenceRef) (bool, error)
}

// ObservationSource ingests or observes runtime and admission events (Section 62).
type ObservationSource interface {
	ListObservations(ctx context.Context, subject assurance.SubjectRef, since time.Time) ([]assurance.Observation, error)
}

// EvidenceVerifier cryptographically validates signatures and provenance (Section 62).
type EvidenceVerifier interface {
	VerifySignature(ctx context.Context, envelope assurance.EvidenceEnvelope) (bool, error)
	VerifyEpoch(ctx context.Context, envelope assurance.EvidenceEnvelope, currentEpoch assurance.AssuranceEpoch) bool
}

// ClaimEvaluator evaluates a claim deterministically against evidence contracts (Section 62).
type ClaimEvaluator interface {
	Evaluate(ctx context.Context, claim assurance.Claim, contract assurance.EvidenceContract, currentEpoch assurance.AssuranceEpoch) (assurance.ClaimEvaluation, error)
}

// AssuranceRepository stores and retrieves summary assurance states and receipts (Section 62).
type AssuranceRepository interface {
	GetState(ctx context.Context, subject assurance.SubjectRef) (assurance.AssuranceState, assurance.AssuranceEpoch, error)
	SaveState(ctx context.Context, subject assurance.SubjectRef, state assurance.AssuranceState, epoch assurance.AssuranceEpoch, root string) error
}

// ReceiptSigner signs canonical control evaluation receipts (Section 41, Section 62).
type ReceiptSigner interface {
	SignReceipt(ctx context.Context, receipt assurance.ControlReceipt) (assurance.ControlReceipt, error)
	VerifyReceipt(ctx context.Context, receipt assurance.ControlReceipt) (bool, error)
}

// OscalProjector projects internal assurance claim evaluations into standard OSCAL artifacts (ADR-005, Section 43-47).
type OscalProjector interface {
	ProjectComponentDefinition(ctx context.Context, evaluations []assurance.ClaimEvaluation) ([]byte, error)
	ProjectAssessmentResults(ctx context.Context, evaluations []assurance.ClaimEvaluation) ([]byte, error)
	ProjectSSP(ctx context.Context, subject assurance.SubjectRef, evaluations []assurance.ClaimEvaluation) ([]byte, error)
}

// AuthorityResolver checks if an evidence producer is authorized to assert a claim (Section 25, Section 62).
type AuthorityResolver interface {
	IsAuthorizedProducer(ctx context.Context, producer assurance.AuthorityRef, evidenceType string) (bool, error)
}
