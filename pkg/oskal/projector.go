package oskal

import (
	"context"

	"github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
)

// Projector serializes continuous assurance states into standard NIST OSCAL 1.2.3 JSON artifacts.
type Projector struct {
	inner *oscal.Projector
}

// NewProjector initializes an OSCAL 1.2.3 projector.
func NewProjector() *Projector {
	return &Projector{inner: oscal.NewProjector()}
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
