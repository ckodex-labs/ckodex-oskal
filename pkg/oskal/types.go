package oskal

import (
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	commonv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/control/v1"
	evidencev1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/evidence/v1"
	receiptv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/receipt/v1"
)

// Re-export core domain types for clean external consumption.
type (
	SubjectRef             = assurance.SubjectRef
	ControlRef             = assurance.ControlRef
	AuthorityRef           = assurance.AuthorityRef
	AssuranceState         = assurance.AssuranceState
	AssuranceVector        = assurance.AssuranceVector
	AssuranceEpoch         = assurance.AssuranceEpoch
	EvidenceRef            = assurance.EvidenceRef
	EvidenceEnvelope       = assurance.EvidenceEnvelope
	EvidenceRequirement    = assurance.EvidenceRequirement
	EvidenceContract       = assurance.EvidenceContract
	EvidenceCompleteness   = assurance.EvidenceCompleteness
	ClaimEvaluation        = assurance.ClaimEvaluation
	Finding                = assurance.Finding
	ControlException       = assurance.ControlException
	ExplainGraph           = assurance.ExplainGraph
	ExplainAtomicReq       = assurance.ExplainAtomicRequirement
	ExplainImplementation  = assurance.ExplainImplementation
	ExplainEvidenceItem    = assurance.ExplainEvidenceItem
)

// Re-export canonical state constants.
const (
	StateUnspecified = assurance.AssuranceStateUnspecified
	StateUnknown     = assurance.AssuranceStateUnknown
	StateObserved    = assurance.AssuranceStateObserved
	StateVerified    = assurance.AssuranceStateVerified
	StateAssured     = assurance.AssuranceStateAssured
	StateStale       = assurance.AssuranceStateStale
	StateFailed      = assurance.AssuranceStateFailed
)

// Re-export protobuf models for wire interop.
type (
	ProtoSubjectRef     = commonv1.SubjectRef
	ProtoControlRef     = controlv1.ControlRef
	ProtoAssuranceEpoch = commonv1.AssuranceEpoch
	ProtoObservation    = evidencev1.Observation
	ProtoReceipt        = receiptv1.ControlReceipt
)

// StateResponse wraps the response of an assurance state query.
type StateResponse struct {
	Subject       SubjectRef              `json:"subject"`
	State         AssuranceState          `json:"state"`
	EvidenceRoot  string                  `json:"evidenceRoot"`
	Epoch         *AssuranceEpoch         `json:"epoch,omitempty"`
	LastEvaluated time.Time               `json:"lastEvaluated"`
	Freshness     string                  `json:"freshness"`
	RawResponse   commonv1.AssuranceState `json:"rawResponse,omitempty"`
}

// EvaluationResponse wraps the result of evaluating subject claims.
type EvaluationResponse struct {
	Subject      SubjectRef         `json:"subject"`
	SummaryState AssuranceState     `json:"summaryState"`
	Evaluations  []ClaimEvaluation  `json:"evaluations"`
	EvaluatedAt  time.Time          `json:"evaluatedAt"`
}

// ExplainResponse wraps claim explanation and Section 51 render tree.
type ExplainResponse struct {
	Subject          SubjectRef    `json:"subject"`
	Control          ControlRef    `json:"control"`
	CanonicalControl string        `json:"canonicalControl"`
	AssuranceState   AssuranceState `json:"assuranceState"`
	EvidenceRoot     string        `json:"evidenceRoot"`
	Graph            ExplainGraph  `json:"graph"`
	RenderedText     string        `json:"renderedText"`
}
