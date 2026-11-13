package oscal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/evaluation"
)

const MaxProjectionRequestBytes = 4 << 20
const MaxProjectionItems = 256

// ProjectionRequest contains actual projection metadata, never client-selected
// assurance outcomes. Evaluations come separately from the server's analysis.
type ProjectionRequest struct {
	Subject           string                      `json:"subject"`
	DocumentType      string                      `json:"document_type"`
	ProjectionContext *ProjectionContext          `json:"projection_context"`
	Control           string                      `json:"control,omitempty"`
	Controls          []assurance.ControlRef      `json:"controls,omitempty"`
	ComponentName     string                      `json:"component_name,omitempty"`
	SystemName        string                      `json:"system_name,omitempty"`
	Contract          *assurance.EvidenceContract `json:"contract,omitempty"`
	Findings          []assurance.Finding         `json:"findings,omitempty"`
}

func DecodeProjectionRequest(data []byte) (ProjectionRequest, error) {
	var request ProjectionRequest
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || len(data) > MaxProjectionRequestBytes || trimmed[0] != '{' {
		return request, fmt.Errorf("projection request must be a JSON object of 1 to %d bytes", MaxProjectionRequestBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return ProjectionRequest{}, fmt.Errorf("decode projection request: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ProjectionRequest{}, fmt.Errorf("projection request must contain exactly one JSON object")
	}
	if request.ProjectionContext == nil {
		return ProjectionRequest{}, fmt.Errorf("projection_context containing actual document references and system metadata is required")
	}
	contextBytes, err := json.Marshal(request.ProjectionContext)
	if err != nil {
		return ProjectionRequest{}, err
	}
	if _, err := DecodeProjectionContext(contextBytes); err != nil {
		return ProjectionRequest{}, err
	}

	if _, err := request.SubjectRef(); err != nil {
		return ProjectionRequest{}, err
	}
	if _, err := NormalizeDocumentType(request.DocumentType); err != nil {
		return ProjectionRequest{}, err
	}
	return request, nil
}

func (r ProjectionRequest) SubjectRef() (assurance.SubjectRef, error) {
	scheme, id, ok := strings.Cut(r.Subject, "://")
	subject := assurance.SubjectRef{Scheme: scheme, ID: id}
	if !ok {
		return assurance.SubjectRef{}, fmt.Errorf("subject requires an explicit URI scheme and identity")
	}
	if err := subject.Validate(); err != nil {
		return assurance.SubjectRef{}, err
	}
	return subject, nil
}

func (r ProjectionRequest) ControlRefs() ([]assurance.ControlRef, error) {
	if len(r.Controls) > MaxProjectionItems || len(r.Findings) > MaxProjectionItems {
		return nil, fmt.Errorf("projection controls and findings must each contain at most %d items", MaxProjectionItems)
	}
	controls := append([]assurance.ControlRef(nil), r.Controls...)
	if r.Control != "" {
		control, err := evaluation.ParseControlReference(r.Control)
		if err != nil {
			return nil, err
		}
		controls = append(controls, control)
	}
	seen := make(map[string]bool)
	unique := make([]assurance.ControlRef, 0, len(controls))
	for _, control := range controls {
		if err := control.Validate(); err != nil {
			return nil, err
		}
		if !seen[control.Canonical()] {
			unique = append(unique, control)
			seen[control.Canonical()] = true
		}
	}
	return unique, nil
}

// Project preserves supplied source semantics and never manufactures controls,
// contracts, remediation findings, or missing document relationships.
func (r ProjectionRequest) Project(ctx context.Context, evaluations []assurance.ClaimEvaluation) ([]byte, error) {
	if r.ProjectionContext == nil {
		return nil, fmt.Errorf("projection_context is required")
	}
	subject, err := r.SubjectRef()
	if err != nil {
		return nil, err
	}
	controls, err := r.ControlRefs()
	if err != nil {
		return nil, err
	}
	for _, e := range evaluations {
		if e.Subject.URI() != subject.URI() {
			return nil, fmt.Errorf("evaluation subject does not match requested projection")
		}
	}
	projector := NewProjectorWithContext(*r.ProjectionContext)
	dt, err := NormalizeDocumentType(r.DocumentType)
	if err != nil {
		return nil, err
	}
	switch dt {
	case DocTypeAssessmentResults:
		return projector.ProjectAssessmentResults(ctx, subject, evaluations, r.Findings)
	case DocTypeComponentDefinition:
		return projector.ProjectComponentDefinition(ctx, r.ComponentName, evaluations)
	case DocTypeSSP:
		systemName := r.SystemName
		if systemName == "" && r.ProjectionContext.System != nil {
			systemName = r.ProjectionContext.System.Characteristics.SystemName
		}
		return projector.ProjectSSP(ctx, systemName, evaluations)
	case DocTypeAssessmentPlan:
		if r.Contract == nil || r.Contract.ID == "" {
			return nil, fmt.Errorf("an actual authored contract is required for an assessment plan; no admission task is inferred")
		}
		return projector.ProjectAssessmentPlan(ctx, subject, *r.Contract, controls)
	case DocTypePOAM:
		return projector.ProjectPOAM(ctx, subject, r.Findings)
	}
	return nil, fmt.Errorf("unsupported projection document type")
}

// ProjectionRequestSchema describes transport metadata. Assurance outcomes are
// intentionally absent: a caller cannot select a server evaluation's state.
func ProjectionRequestSchema() map[string]any {
	return map[string]any{"type": "object", "additionalProperties": false, "required": []string{"subject", "document_type", "projection_context"}, "properties": map[string]any{
		"subject":            map[string]any{"type": "string", "description": "Explicit subject URI"},
		"document_type":      map[string]any{"type": "string", "description": "assessment-results, component-definition, ssp, assessment-plan, or poam"},
		"projection_context": map[string]any{"type": "object", "description": "Actual OSCAL document references and system metadata; strictly decoded"},
		"control":            map[string]any{"type": "string", "description": "Actual namespace:id[@version] reference"},
		"controls":           map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
		"component_name":     map[string]any{"type": "string"}, "system_name": map[string]any{"type": "string"},
		"contract": map[string]any{"type": "object", "description": "Actual authored evidence contract; required for assessment-plan"},
		"findings": map[string]any{"type": "array", "items": map[string]any{"type": "object"}, "description": "Actual caller-selected findings; UNKNOWN is never turned into a finding"},
	}}
}
