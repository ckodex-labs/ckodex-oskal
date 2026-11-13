package oscal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

// OSCAL v1.2.3 JSON schema data structures for projection (ADR-005).

type Link struct {
	Href string `json:"href"`
	Rel  string `json:"rel,omitempty"`
}

type OscalRlink struct {
	Href      string `json:"href"`
	MediaType string `json:"media-type,omitempty"`
}

type OscalRelevantEvidence struct {
	Href        string     `json:"href,omitempty"`
	Description string     `json:"description"`
	Props       []Property `json:"props,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Ns    string `json:"ns,omitempty"`
}

type BackMatterResource struct {
	UUID        string       `json:"uuid"`
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description,omitempty"`
	Props       []Property   `json:"props,omitempty"`
	Rlinks      []OscalRlink `json:"rlinks,omitempty"`
}

type BackMatter struct {
	Resources []BackMatterResource `json:"resources,omitempty"`
}

type OscalMetadata struct {
	Title        string     `json:"title"`
	Published    time.Time  `json:"published,omitzero"`
	LastModified time.Time  `json:"last-modified"`
	Version      string     `json:"version"`
	OscalVersion string     `json:"oscal-version"`
	Props        []Property `json:"props,omitempty"`
	Remarks      string     `json:"remarks,omitempty"`
}

// 1. Assessment Results Document
type OscalObservation struct {
	UUID             string                  `json:"uuid"`
	Title            string                  `json:"title"`
	Description      string                  `json:"description"`
	Collected        time.Time               `json:"collected"`
	Expires          *time.Time              `json:"expires,omitempty"`
	Methods          []string                `json:"methods"`
	Types            []string                `json:"types"`
	RelevantEvidence []OscalRelevantEvidence `json:"relevant-evidence,omitempty"`
	Props            []Property              `json:"props,omitempty"`
}

type OscalFindingTargetStatus struct {
	State  string `json:"state"`            // "satisfied", "not-satisfied"
	Reason string `json:"reason,omitempty"` // "pass", "fail", "other"
}

type OscalFindingTarget struct {
	Type     string                   `json:"type"`      // "objective-id", "statement-id"
	TargetID string                   `json:"target-id"` // e.g. "AC-6"
	Status   OscalFindingTargetStatus `json:"status"`
}

type OscalRelatedObservation struct {
	ObservationUUID string `json:"observation-uuid"`
}

type OscalFinding struct {
	UUID                string                    `json:"uuid"`
	Title               string                    `json:"title"`
	Description         string                    `json:"description"`
	Target              OscalFindingTarget        `json:"target"`
	RelatedObservations []OscalRelatedObservation `json:"related-observations,omitempty"`
	Props               []Property                `json:"props,omitempty"`
}

type OscalControlSelection struct {
	Description     string                 `json:"description,omitempty"`
	IncludeAll      *struct{}              `json:"include-all,omitempty"`
	IncludeControls []OscalSelectedControl `json:"include-controls,omitempty"`
}

type OscalSelectedControl struct {
	ControlID string `json:"control-id"`
}

type OscalReviewedControls struct {
	ControlSelections []OscalControlSelection `json:"control-selections"`
}

type OscalResult struct {
	UUID             string                `json:"uuid"`
	Title            string                `json:"title"`
	Description      string                `json:"description"`
	Start            time.Time             `json:"start"`
	End              time.Time             `json:"end"`
	ReviewedControls OscalReviewedControls `json:"reviewed-controls"`
	Observations     []OscalObservation    `json:"observations"`
	Findings         []OscalFinding        `json:"findings,omitempty"`
}

type ImportAP struct {
	Href string `json:"href"`
}

type AssessmentResultsWrapper struct {
	AssessmentResults struct {
		UUID       string        `json:"uuid"`
		Metadata   OscalMetadata `json:"metadata"`
		ImportAP   ImportAP      `json:"import-ap"`
		Results    []OscalResult `json:"results"`
		BackMatter *BackMatter   `json:"back-matter,omitempty"`
	} `json:"assessment-results"`
}

// 2. Component Definition Document
type OscalImplementedRequirement struct {
	UUID        string     `json:"uuid"`
	ControlID   string     `json:"control-id"`
	Description string     `json:"description"`
	Props       []Property `json:"props,omitempty"`
}

type OscalControlImplementation struct {
	UUID                    string                        `json:"uuid"`
	Source                  string                        `json:"source"`
	Description             string                        `json:"description"`
	ImplementedRequirements []OscalImplementedRequirement `json:"implemented-requirements"`
}

type OscalDefinedComponent struct {
	UUID                   string                       `json:"uuid"`
	Type                   string                       `json:"type"`
	Title                  string                       `json:"title"`
	Description            string                       `json:"description"`
	Purpose                string                       `json:"purpose,omitempty"`
	ControlImplementations []OscalControlImplementation `json:"control-implementations,omitempty"`
}

type ComponentDefinitionWrapper struct {
	ComponentDefinition struct {
		UUID              string                  `json:"uuid"`
		Metadata          OscalMetadata           `json:"metadata"`
		DefinedComponents []OscalDefinedComponent `json:"components"`
	} `json:"component-definition"`
}

// 3. System Security Plan Document
type ImportProfile struct {
	Href string `json:"href"`
}

type OscalSystemID struct {
	ID string `json:"id"`
}

type OscalInformationType struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

type OscalSystemInformation struct {
	InformationTypes []OscalInformationType `json:"information-types"`
}

type OscalStatus struct {
	State   string `json:"state"` // OSCAL operational status, independent of assurance state.
	Remarks string `json:"remarks,omitempty"`
}

type OscalAuthorizationBoundary struct {
	Description string `json:"description"`
}

type OscalSSPComponent struct {
	UUID        string      `json:"uuid"`
	Type        string      `json:"type"` // "this-system", "software"
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Status      OscalStatus `json:"status"`
}

type OscalSystemImplementation struct {
	Components []OscalSSPComponent `json:"components"`
}

type OscalSystemCharacteristics struct {
	SystemIDs             []OscalSystemID            `json:"system-ids"`
	SystemName            string                     `json:"system-name"`
	Description           string                     `json:"description"`
	SystemInformation     OscalSystemInformation     `json:"system-information"`
	Status                OscalStatus                `json:"status"`
	AuthorizationBoundary OscalAuthorizationBoundary `json:"authorization-boundary"`
}

type OscalSSPImplementedRequirement struct {
	UUID      string     `json:"uuid"`
	ControlID string     `json:"control-id"`
	Props     []Property `json:"props,omitempty"`
	Remarks   string     `json:"remarks,omitempty"`
}

type OscalSSPControlImplementation struct {
	Description             string                           `json:"description"`
	ImplementedRequirements []OscalSSPImplementedRequirement `json:"implemented-requirements"`
}

type SSPWrapper struct {
	SystemSecurityPlan struct {
		UUID                  string                        `json:"uuid"`
		Metadata              OscalMetadata                 `json:"metadata"`
		ImportProfile         ImportProfile                 `json:"import-profile"`
		SystemCharacteristics OscalSystemCharacteristics    `json:"system-characteristics"`
		SystemImplementation  OscalSystemImplementation     `json:"system-implementation"`
		ControlImplementation OscalSSPControlImplementation `json:"control-implementation"`
	} `json:"system-security-plan"`
}

// 4. Assessment Plan Document
type OscalAssessmentSubject struct {
	Type        string    `json:"type"`
	Description string    `json:"description,omitempty"`
	IncludeAll  *struct{} `json:"include-all,omitempty"`
}

type OscalAssessmentActivity struct {
	Props       []Property `json:"props,omitempty"`
	UUID        string     `json:"uuid"`
	Type        string     `json:"type"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
}

type ImportSSP struct {
	Href string `json:"href"`
}

type AssessmentPlanWrapper struct {
	AssessmentPlan struct {
		UUID               string                    `json:"uuid"`
		Metadata           OscalMetadata             `json:"metadata"`
		ImportSSP          ImportSSP                 `json:"import-ssp"`
		ReviewedControls   OscalReviewedControls     `json:"reviewed-controls"`
		AssessmentSubjects []OscalAssessmentSubject  `json:"assessment-subjects,omitempty"`
		Tasks              []OscalAssessmentActivity `json:"tasks,omitempty"`
	} `json:"assessment-plan"`
}

// 5. Plan of Action and Milestones Document
type OscalPOAMItem struct {
	UUID        string     `json:"uuid"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Props       []Property `json:"props,omitempty"`
}

type POAMSystemID struct {
	ID string `json:"id"`
}

type POAMWrapper struct {
	PlanOfActionAndMilestones struct {
		UUID      string          `json:"uuid"`
		Metadata  OscalMetadata   `json:"metadata"`
		SystemID  *POAMSystemID   `json:"system-id,omitempty"`
		POAMItems []OscalPOAMItem `json:"poam-items"`
	} `json:"plan-of-action-and-milestones"`
}

var _ ports.OscalProjector = (*Projector)(nil)

// ProjectionContext contains caller-supplied OSCAL document relationships and system facts.
// These inputs are asserted by the caller; projection does not verify their provenance,
// resolve imported documents, or establish their operational truth.
type ProjectionContext struct {
	AssessmentPlanHref     string                          `json:"assessment_plan_href,omitempty"`
	SystemSecurityPlanHref string                          `json:"system_security_plan_href,omitempty"`
	ControlSource          string                          `json:"control_source,omitempty"`
	ControlNamespace       string                          `json:"control_namespace,omitempty"`
	ControlVersion         string                          `json:"control_version,omitempty"`
	Component              *ComponentContext               `json:"component,omitempty"`
	System                 *SystemContext                  `json:"system,omitempty"`
	FindingTargets         map[string]FindingTargetMapping `json:"finding_targets,omitempty"`
}

// MaxProjectionContextBytes bounds context decoding for file and transport adapters.
const MaxProjectionContextBytes = 1 << 20

// DecodeProjectionContext strictly decodes one bounded JSON context object.
// Semantic requirements are checked by each projection method.
func DecodeProjectionContext(data []byte) (ProjectionContext, error) {
	var c ProjectionContext
	if len(data) > MaxProjectionContextBytes {
		return c, fmt.Errorf("projection context exceeds %d bytes", MaxProjectionContextBytes)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return c, fmt.Errorf("projection context must be a JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return ProjectionContext{}, fmt.Errorf("decode projection context: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ProjectionContext{}, fmt.Errorf("projection context must contain exactly one JSON object")
	}
	return c, nil
}

// ComponentContext describes the actual component and its implementation narratives.
type ComponentContext struct {
	Type            string            `json:"type"`
	Description     string            `json:"description"`
	Purpose         string            `json:"purpose,omitempty"`
	Implementations map[string]string `json:"implementations,omitempty"`
}

// SystemContext supplies mandatory SSP facts that claim evaluations cannot establish.
type SystemContext struct {
	ProfileHref                      string                     `json:"profile_href"`
	Characteristics                  OscalSystemCharacteristics `json:"characteristics"`
	Implementation                   OscalSystemImplementation  `json:"implementation"`
	ControlImplementationDescription string                     `json:"control_implementation_description"`
	Implementations                  map[string]string          `json:"implementations"`
}

// FindingTargetMapping maps a canonical control to an actual objective or statement.
// Control IDs are never implicitly treated as objective or statement IDs.
type FindingTargetMapping struct {
	Type     string `json:"type"`
	TargetID string `json:"target_id"`
}

// ProjectionInputError identifies missing or incompatible semantic projection input.
type ProjectionInputError struct {
	DocumentType DocumentType
	Field        string
	Reason       string
}

func (e *ProjectionInputError) Error() string {
	return fmt.Sprintf("project %s: %s: %s", e.DocumentType, e.Field, e.Reason)
}

// Projector converts supplied assurance facts into OSCAL v1.2.3 artifacts.
type Projector struct{ context ProjectionContext }

// NewProjector creates a projector without document relationships or system metadata.
// Methods requiring those facts return a ProjectionInputError until context is supplied.
func NewProjector() *Projector { return NewProjectorWithContext(ProjectionContext{}) }

func NewProjectorWithContext(c ProjectionContext) *Projector { return &Projector{context: c} }

func inputError(dt DocumentType, field, reason string) error {
	return &ProjectionInputError{DocumentType: dt, Field: field, Reason: reason}
}

func requireText(dt DocumentType, field, value string) error {
	if strings.TrimSpace(value) == "" {
		return inputError(dt, field, "provide the actual value; projection cannot infer it")
	}
	return nil
}

func requireHref(dt DocumentType, field, value string) error {
	if err := requireText(dt, field, value); err != nil {
		return err
	}
	u, err := url.Parse(value)
	if err != nil || strings.ContainsAny(value, " \t\r\n") || u.Fragment != "" {
		return inputError(dt, field, "provide a valid reference to an actual external OSCAL document (fragment-only references require back-matter not supplied by this API)")
	}
	return nil
}

func (p *Projector) controls(dt DocumentType, controls []assurance.ControlRef) (OscalReviewedControls, error) {
	if len(controls) == 0 {
		return OscalReviewedControls{}, inputError(dt, "controls", "at least one actual control is required; no baseline is inferred")
	}
	if err := requireText(dt, "control_namespace", p.context.ControlNamespace); err != nil {
		return OscalReviewedControls{}, err
	}
	seen := make(map[string]bool)
	selected := make([]OscalSelectedControl, 0, len(controls))
	for _, c := range controls {
		if err := c.Validate(); err != nil {
			return OscalReviewedControls{}, inputError(dt, "controls", err.Error())
		}
		if c.Namespace != p.context.ControlNamespace || c.Version != p.context.ControlVersion {
			return OscalReviewedControls{}, inputError(dt, "controls", fmt.Sprintf("%s does not match supplied control namespace/version", c.Canonical()))
		}
		if !seen[c.ID] {
			selected = append(selected, OscalSelectedControl{ControlID: c.ID})
			seen[c.ID] = true
		}
	}
	return OscalReviewedControls{ControlSelections: []OscalControlSelection{{IncludeControls: selected}}}, nil
}

func (p *Projector) evaluations(dt DocumentType, subject *assurance.SubjectRef, evaluations []assurance.ClaimEvaluation) (OscalReviewedControls, error) {
	controls := make([]assurance.ControlRef, 0, len(evaluations))
	for _, e := range evaluations {
		if err := e.Subject.Validate(); err != nil {
			return OscalReviewedControls{}, inputError(dt, "evaluations.subject", err.Error())
		}
		if subject != nil && e.Subject.URI() != subject.URI() {
			return OscalReviewedControls{}, inputError(dt, "evaluations.subject", "evaluation belongs to a different subject")
		}
		if e.EvaluatedAt.IsZero() || e.EvaluatedAt.After(time.Now().UTC()) {
			return OscalReviewedControls{}, inputError(dt, "evaluations.evaluatedAt", "supply an actual evaluation timestamp, not zero or a future time")
		}
		controls = append(controls, e.Control)
	}
	return p.controls(dt, controls)
}

func requireUniqueControls(dt DocumentType, evaluations []assurance.ClaimEvaluation) error {
	seen := make(map[string]bool)
	for _, e := range evaluations {
		key := e.Control.Canonical()
		if seen[key] {
			return inputError(dt, "evaluations.control", "multiple evaluations for "+key+" cannot become duplicate implementation requirements; supply one coherent snapshot per control")
		}
		seen[key] = true
	}
	return nil
}

func metadata(title string) OscalMetadata {
	now := time.Now().UTC()
	return OscalMetadata{Title: title, LastModified: now, Version: "1.0.0", OscalVersion: "1.2.3", Remarks: "Projection of caller-supplied facts. Schema validation does not verify source authenticity, imported document resolution, semantic completeness, or system compliance."}
}

func properties(e assurance.ClaimEvaluation) []Property {
	props := []Property{
		{Name: "control-ref", Value: e.Control.Canonical(), Ns: "https://assurance.ckodex.io/ns"},
		{Name: "subject-uri", Value: e.Subject.URI(), Ns: "https://assurance.ckodex.io/ns"},
		{Name: "assurance-state", Value: e.State.String(), Ns: "https://assurance.ckodex.io/ns"},
		{Name: "epoch-composite-digest", Value: e.Epoch.CompositeDigest(), Ns: "https://assurance.ckodex.io/ns"},
	}
	if e.EvidenceRoot != "" {
		props = append(props, Property{Name: "evidence-root", Value: e.EvidenceRoot, Ns: "https://assurance.ckodex.io/ns"})
	}
	return props
}

func marshalProjection(ctx context.Context, dt DocumentType, wrapper any) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(wrapper, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", dt, err)
	}
	v, err := DefaultValidator()
	if err != nil {
		return nil, fmt.Errorf("initialize OSCAL schema validator: %w", err)
	}
	report, err := v.Validate(data, string(dt))
	if err != nil {
		return nil, err
	}
	if !report.Valid {
		return nil, inputError(dt, "document", fmt.Sprintf("supplied inputs do not satisfy pinned OSCAL 1.2.3 schema: %+v", report.Errors))
	}
	return data, nil
}

// ProjectAssessmentResults preserves supplied evaluations, evidence, and confirmed findings.
func (p *Projector) ProjectAssessmentResults(ctx context.Context, subject assurance.SubjectRef, evaluations []assurance.ClaimEvaluation, findings []assurance.Finding) ([]byte, error) {
	dt := DocTypeAssessmentResults
	if err := subject.Validate(); err != nil {
		return nil, inputError(dt, "subject", err.Error())
	}
	if err := requireHref(dt, "assessment_plan_href", p.context.AssessmentPlanHref); err != nil {
		return nil, err
	}
	reviewed, err := p.evaluations(dt, &subject, evaluations)
	if err != nil {
		return nil, err
	}
	wrapper := AssessmentResultsWrapper{}
	ar := &wrapper.AssessmentResults
	ar.UUID = uuid.NewString()
	ar.Metadata = metadata(fmt.Sprintf("OSKAL Assessment Results for %s", subject.URI()))
	ar.ImportAP = ImportAP{Href: p.context.AssessmentPlanHref}
	start, end := evaluations[0].EvaluatedAt, evaluations[0].EvaluatedAt
	for _, e := range evaluations {
		if e.EvaluatedAt.Before(start) {
			start = e.EvaluatedAt
		}
		if e.EvaluatedAt.After(end) {
			end = e.EvaluatedAt
		}
	}
	res := OscalResult{UUID: uuid.NewString(), Title: fmt.Sprintf("Assurance evaluations for %s", subject.URI()), Description: "Projection of supplied claim evaluations; assurance states retain their source meaning.", Start: start, End: end, ReviewedControls: reviewed}
	resources := make(map[string]BackMatterResource)
	observations := make(map[string][]OscalRelatedObservation)
	for _, e := range evaluations {
		obs := OscalObservation{UUID: uuid.NewString(), Title: fmt.Sprintf("Evaluation of %s", e.Control.Canonical()), Description: fmt.Sprintf("Supplied evaluation state: %s (completeness: %s)", e.State, e.Completeness.Summary()), Collected: e.EvaluatedAt, Methods: []string{"AUTOMATED_CONTINUOUS_EVALUATION"}, Types: []string{"assurance-claim-evaluation"}, Props: properties(e)}
		if !e.ValidUntil.IsZero() {
			if e.ValidUntil.Before(e.EvaluatedAt) {
				return nil, inputError(dt, "evaluations.validUntil", "cannot precede evaluatedAt")
			}
			expiry := e.ValidUntil
			obs.Expires = &expiry
		}
		for _, ev := range e.Evidence {
			if err := requireText(dt, "evaluations.evidence.digest", ev.Digest); err != nil {
				return nil, err
			}
			if err := requireText(dt, "evaluations.evidence.uri", ev.URI); err != nil {
				return nil, err
			}
			key := ev.Digest + "\n" + ev.URI + "\n" + ev.MediaType
			resource, exists := resources[key]
			if !exists {
				resource = BackMatterResource{UUID: uuid.NewString(), Title: "Supplied evidence reference", Props: []Property{{Name: "digest", Value: ev.Digest, Ns: "https://assurance.ckodex.io/ns"}}, Rlinks: []OscalRlink{{Href: ev.URI, MediaType: ev.MediaType}}}
				resources[key] = resource
			}
			obs.RelevantEvidence = append(obs.RelevantEvidence, OscalRelevantEvidence{Href: "#" + resource.UUID, Description: "Evidence reference supplied by the source evaluation; content authenticity is not independently verified by projection."})
			observations[e.Control.Canonical()+"\n"+ev.Digest] = append(observations[e.Control.Canonical()+"\n"+ev.Digest], OscalRelatedObservation{ObservationUUID: obs.UUID})
		}
		res.Observations = append(res.Observations, obs)
	}
	for _, f := range findings {
		if f.Subject.URI() != subject.URI() {
			return nil, inputError(dt, "findings.subject", "finding belongs to a different subject")
		}
		target, ok := p.context.FindingTargets[f.Control.Canonical()]
		if !ok || (target.Type != "objective-id" && target.Type != "statement-id") || target.TargetID == "" {
			return nil, inputError(dt, "finding_targets", fmt.Sprintf("provide an actual objective-id or statement-id mapping for %s", f.Control.Canonical()))
		}
		related := []OscalRelatedObservation{}
		seen := make(map[string]bool)
		for _, ev := range f.EvidenceRefs {
			for _, r := range observations[f.Control.Canonical()+"\n"+ev.Digest] {
				if !seen[r.ObservationUUID] {
					related = append(related, r)
					seen[r.ObservationUUID] = true
				}
			}
		}
		if len(related) == 0 {
			return nil, inputError(dt, "findings.evidenceRefs", "finding must reference evidence in an evaluation of the exact same subject and control; no arbitrary observation link is invented")
		}
		res.Findings = append(res.Findings, OscalFinding{UUID: uuid.NewString(), Title: f.Title, Description: f.Description, Target: OscalFindingTarget{Type: target.Type, TargetID: target.TargetID, Status: OscalFindingTargetStatus{State: "not-satisfied", Reason: "fail"}}, RelatedObservations: related, Props: []Property{{Name: "source-finding-id", Value: f.ID, Ns: "https://assurance.ckodex.io/ns"}, {Name: "control-ref", Value: f.Control.Canonical(), Ns: "https://assurance.ckodex.io/ns"}}})
	}
	ar.Results = []OscalResult{res}
	if len(resources) > 0 {
		ar.BackMatter = &BackMatter{}
		keys := make([]string, 0, len(resources))
		for key := range resources {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			ar.BackMatter.Resources = append(ar.BackMatter.Resources, resources[key])
		}
	}
	return marshalProjection(ctx, dt, wrapper)
}

// ProjectComponentDefinition uses actual component facts and explicit implementation narratives.
func (p *Projector) ProjectComponentDefinition(ctx context.Context, componentName string, evaluations []assurance.ClaimEvaluation) ([]byte, error) {
	dt := DocTypeComponentDefinition
	if err := requireText(dt, "componentName", componentName); err != nil {
		return nil, err
	}
	c := p.context.Component
	if c == nil {
		return nil, inputError(dt, "component", "provide actual component type and description")
	}
	if err := requireText(dt, "component.type", c.Type); err != nil {
		return nil, err
	}
	if err := requireText(dt, "component.description", c.Description); err != nil {
		return nil, err
	}
	wrapper := ComponentDefinitionWrapper{}
	cd := &wrapper.ComponentDefinition
	cd.UUID = uuid.NewString()
	cd.Metadata = metadata("OSKAL Component Definition: " + componentName)
	comp := OscalDefinedComponent{UUID: uuid.NewString(), Type: c.Type, Title: componentName, Description: c.Description, Purpose: c.Purpose}
	if len(evaluations) > 0 {
		if err := requireUniqueControls(dt, evaluations); err != nil {
			return nil, err
		}
		if _, err := p.evaluations(dt, nil, evaluations); err != nil {
			return nil, err
		}
		if err := requireHref(dt, "control_source", p.context.ControlSource); err != nil {
			return nil, err
		}
		impl := OscalControlImplementation{UUID: uuid.NewString(), Source: p.context.ControlSource, Description: "Caller-supplied implementation narratives with source evaluation states."}
		for _, e := range evaluations {
			description := c.Implementations[e.Control.Canonical()]
			if err := requireText(dt, "component.implementations["+e.Control.Canonical()+"]", description); err != nil {
				return nil, err
			}
			impl.ImplementedRequirements = append(impl.ImplementedRequirements, OscalImplementedRequirement{UUID: uuid.NewString(), ControlID: e.Control.ID, Description: description, Props: properties(e)})
		}
		comp.ControlImplementations = []OscalControlImplementation{impl}
	}
	cd.DefinedComponents = []OscalDefinedComponent{comp}
	return marshalProjection(ctx, dt, wrapper)
}

// ProjectSSP requires caller-supplied system facts; evaluation state is not operational status.
func (p *Projector) ProjectSSP(ctx context.Context, systemName string, evaluations []assurance.ClaimEvaluation) ([]byte, error) {
	dt := DocTypeSSP
	s := p.context.System
	if s == nil {
		return nil, inputError(dt, "system", "provide actual profile reference, system characteristics, components, and implementation narratives")
	}
	if err := requireHref(dt, "system.profile_href", s.ProfileHref); err != nil {
		return nil, err
	}
	if s.Characteristics.SystemName != systemName {
		return nil, inputError(dt, "system.characteristics.system-name", "must match the requested system name")
	}
	if err := requireText(dt, "system.characteristics.description", s.Characteristics.Description); err != nil {
		return nil, err
	}
	if err := requireText(dt, "system.characteristics.authorization-boundary.description", s.Characteristics.AuthorizationBoundary.Description); err != nil {
		return nil, err
	}
	if err := validateStatus(dt, s.Characteristics.Status, true); err != nil {
		return nil, err
	}
	for _, c := range s.Implementation.Components {
		if err := validateStatus(dt, c.Status, false); err != nil {
			return nil, err
		}
	}
	if _, err := p.evaluations(dt, nil, evaluations); err != nil {
		return nil, err
	}
	if err := requireUniqueControls(dt, evaluations); err != nil {
		return nil, err
	}
	if err := requireText(dt, "system.control_implementation_description", s.ControlImplementationDescription); err != nil {
		return nil, err
	}
	wrapper := SSPWrapper{}
	ssp := &wrapper.SystemSecurityPlan
	ssp.UUID = uuid.NewString()
	ssp.Metadata = metadata("System Security Plan for " + systemName)
	ssp.ImportProfile = ImportProfile{Href: s.ProfileHref}
	ssp.SystemCharacteristics = s.Characteristics
	ssp.SystemImplementation = s.Implementation
	ssp.ControlImplementation.Description = s.ControlImplementationDescription
	for _, e := range evaluations {
		description := s.Implementations[e.Control.Canonical()]
		if err := requireText(dt, "system.implementations["+e.Control.Canonical()+"]", description); err != nil {
			return nil, err
		}
		ssp.ControlImplementation.ImplementedRequirements = append(ssp.ControlImplementation.ImplementedRequirements, OscalSSPImplementedRequirement{UUID: uuid.NewString(), ControlID: e.Control.ID, Remarks: description, Props: properties(e)})
	}
	return marshalProjection(ctx, dt, wrapper)
}

func validateStatus(dt DocumentType, s OscalStatus, system bool) error {
	switch s.State {
	case "operational", "under-development", "disposition":
		return nil
	case "under-major-modification":
		if system {
			return nil
		}
	case "other":
		return requireText(dt, "status.remarks", s.Remarks)
	}
	return inputError(dt, "status.state", "provide an OSCAL operational status; unknown status must use other with explanatory remarks")
}

// ProjectAssessmentPlan selects only supplied controls and tasks from the supplied contract.
func (p *Projector) ProjectAssessmentPlan(ctx context.Context, subject assurance.SubjectRef, contract assurance.EvidenceContract, controls []assurance.ControlRef) ([]byte, error) {
	dt := DocTypeAssessmentPlan
	if err := subject.Validate(); err != nil {
		return nil, inputError(dt, "subject", err.Error())
	}
	if err := requireHref(dt, "system_security_plan_href", p.context.SystemSecurityPlanHref); err != nil {
		return nil, err
	}
	reviewed, err := p.controls(dt, controls)
	if err != nil {
		return nil, err
	}
	wrapper := AssessmentPlanWrapper{}
	ap := &wrapper.AssessmentPlan
	ap.UUID = uuid.NewString()
	ap.Metadata = metadata("Assessment Plan for " + subject.URI())
	ap.Metadata.Props = []Property{{Name: "subject-uri", Value: subject.URI(), Ns: "https://assurance.ckodex.io/ns"}}
	if contract.ID != "" {
		ap.Metadata.Props = append(ap.Metadata.Props, Property{Name: "evidence-contract-id", Value: contract.ID, Ns: "https://assurance.ckodex.io/ns"})
	}
	ap.ImportSSP = ImportSSP{Href: p.context.SystemSecurityPlanHref}
	ap.ReviewedControls = reviewed
	for _, req := range contract.Requirements {
		if err := requireText(dt, "contract.requirements.evidenceType", req.EvidenceType); err != nil {
			return nil, err
		}
		ap.Tasks = append(ap.Tasks, OscalAssessmentActivity{UUID: uuid.NewString(), Type: "action", Title: "Evidence evaluation: " + req.EvidenceType, Description: fmt.Sprintf("Contract requirement %s: evidence type %s; required=%t; max age=%s; accepted producers=%v. This is a planned task, not evidence of execution.", req.ID, req.EvidenceType, req.Required, req.MaxAge, req.AcceptedProducers)})
	}
	return marshalProjection(ctx, dt, wrapper)
}

// ProjectPOAM projects supplied remediation findings. An empty finding set cannot prove conformance.
func (p *Projector) ProjectPOAM(ctx context.Context, subject assurance.SubjectRef, findings []assurance.Finding) ([]byte, error) {
	dt := DocTypePOAM
	if err := subject.Validate(); err != nil {
		return nil, inputError(dt, "subject", err.Error())
	}
	if len(findings) == 0 {
		return nil, inputError(dt, "findings", "OSCAL 1.2.3 requires at least one POA&M item; no supplied remediation findings does not establish control satisfaction")
	}
	wrapper := POAMWrapper{}
	poam := &wrapper.PlanOfActionAndMilestones
	poam.UUID = uuid.NewString()
	poam.Metadata = metadata("Plan of Action and Milestones for " + subject.URI())
	poam.SystemID = &POAMSystemID{ID: subject.URI()}
	for _, f := range findings {
		if f.Subject.URI() != subject.URI() {
			return nil, inputError(dt, "findings.subject", "finding belongs to a different subject")
		}
		if err := f.Control.Validate(); err != nil {
			return nil, inputError(dt, "findings.control", err.Error())
		}
		props := []Property{{Name: "source-finding-id", Value: f.ID, Ns: "https://assurance.ckodex.io/ns"}, {Name: "control-ref", Value: f.Control.Canonical(), Ns: "https://assurance.ckodex.io/ns"}}
		if f.Severity != "" {
			props = append(props, Property{Name: "severity", Value: f.Severity, Ns: "https://assurance.ckodex.io/ns"})
		}
		if !f.DiscoveredAt.IsZero() {
			props = append(props, Property{Name: "discovered-at", Value: f.DiscoveredAt.Format(time.RFC3339Nano), Ns: "https://assurance.ckodex.io/ns"})
		}
		poam.POAMItems = append(poam.POAMItems, OscalPOAMItem{UUID: uuid.NewString(), Title: f.Title, Description: f.Description, Props: props})
	}
	return marshalProjection(ctx, dt, wrapper)
}
