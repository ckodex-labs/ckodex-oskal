package oskal

import (
	"context"

	"github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
)

// ProjectionContext supplies actual document references and system metadata for projection.
type ProjectionContext = oscal.ProjectionContext
type ComponentContext = oscal.ComponentContext
type SystemContext = oscal.SystemContext
type FindingTargetMapping = oscal.FindingTargetMapping
type ProjectionInputError = oscal.ProjectionInputError
type SystemCharacteristics = oscal.OscalSystemCharacteristics
type SystemInformation = oscal.OscalSystemInformation
type InformationType = oscal.OscalInformationType
type SystemID = oscal.OscalSystemID
type OperationalStatus = oscal.OscalStatus
type AuthorizationBoundary = oscal.OscalAuthorizationBoundary
type SystemImplementation = oscal.OscalSystemImplementation
type SystemComponent = oscal.OscalSSPComponent

const MaxProjectionContextBytes = oscal.MaxProjectionContextBytes

// DecodeProjectionContext strictly decodes a bounded JSON context object.
func DecodeProjectionContext(data []byte) (ProjectionContext, error) {
	return oscal.DecodeProjectionContext(data)
}

// Projector serializes continuous assurance states into standard NIST OSCAL 1.2.3 JSON artifacts.
type Projector struct {
	inner *oscal.Projector
}

// NewProjector initializes an OSCAL 1.2.3 projector.
func NewProjector() *Projector {
	return &Projector{inner: oscal.NewProjector()}
}

// NewProjectorWithContext initializes a projector with caller-supplied OSCAL facts.
// It validates required inputs when each document is projected.
func NewProjectorWithContext(c ProjectionContext) *Projector {
	return &Projector{inner: oscal.NewProjectorWithContext(c)}
}

// ProjectAssessmentResults exports evaluation claims and findings into an OSCAL Assessment Results JSON document.
func (p *Projector) ProjectAssessmentResults(
	ctx context.Context,
	subject SubjectRef,
	evaluations []ClaimEvaluation,
	findings []Finding,
) ([]byte, error) {
	return p.inner.ProjectAssessmentResults(ctx, subject, evaluations, findings)
}

// ProjectComponentDefinition exports continuous assurance control implementations into an OSCAL Component Definition JSON document.
func (p *Projector) ProjectComponentDefinition(
	ctx context.Context,
	componentName string,
	evaluations []ClaimEvaluation,
) ([]byte, error) {
	return p.inner.ProjectComponentDefinition(ctx, componentName, evaluations)
}

// ProjectAssessmentPlan exports an evidence contract into an OSCAL Assessment Plan JSON document.
func (p *Projector) ProjectAssessmentPlan(
	ctx context.Context,
	subject SubjectRef,
	contract EvidenceContract,
	controls []ControlRef,
) ([]byte, error) {
	return p.inner.ProjectAssessmentPlan(ctx, subject, contract, controls)
}

// ProjectPOAM exports remediation findings into an OSCAL Plan of Action and Milestones (POAM) JSON document.
func (p *Projector) ProjectPOAM(
	ctx context.Context,
	subject SubjectRef,
	findings []Finding,
) ([]byte, error) {
	return p.inner.ProjectPOAM(ctx, subject, findings)
}

// ProjectSSP exports a System Security Plan into an OSCAL SSP JSON document.
func (p *Projector) ProjectSSP(
	ctx context.Context,
	systemName string,
	evaluations []ClaimEvaluation,
) ([]byte, error) {
	return p.inner.ProjectSSP(ctx, systemName, evaluations)
}
