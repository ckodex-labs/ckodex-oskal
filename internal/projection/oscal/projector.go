package oscal

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ckodex-labs/oskal/core/assurance"
)

// OSCAL v1.2.3 JSON schema data structures for projection (ADR-005).

type Link struct {
	Href string `json:"href"`
	Rel  string `json:"rel,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Ns    string `json:"ns,omitempty"`
}

type BackMatterResource struct {
	UUID        string     `json:"uuid"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	Properties  []Property `json:"properties,omitempty"`
	Rlinks      []Link     `json:"rlinks,omitempty"`
}

type BackMatter struct {
	Resources []BackMatterResource `json:"resources,omitempty"`
}

type OscalMetadata struct {
	Title        string    `json:"title"`
	Published    time.Time `json:"published"`
	LastModified time.Time `json:"last-modified"`
	Version      string    `json:"version"`
	OscalVersion string    `json:"oscal-version"`
}

// 1. Assessment Results Document
type OscalObservation struct {
	UUID             string     `json:"uuid"`
	Title            string     `json:"title"`
	Description      string     `json:"description"`
	Collected        time.Time  `json:"collected"`
	Methods          []string   `json:"methods"`
	Types            []string   `json:"types"`
	RelevantEvidence []Link     `json:"relevant-evidence,omitempty"`
	Properties       []Property `json:"properties,omitempty"`
}

type OscalFindingTarget struct {
	Type        string `json:"type"`
	IdRef       string `json:"id-ref"`
	Status      string `json:"status"` // "satisfied", "not-satisfied"
}

type OscalFinding struct {
	UUID        string               `json:"uuid"`
	Title       string               `json:"title"`
	Description string               `json:"description"`
	Target      OscalFindingTarget   `json:"target"`
	RelatedObservations []string     `json:"related-observations,omitempty"`
}

type OscalResult struct {
	UUID         string             `json:"uuid"`
	Title        string             `json:"title"`
	Description  string             `json:"description"`
	Start        time.Time          `json:"start"`
	End          time.Time          `json:"end"`
	Observations []OscalObservation `json:"observations"`
	Findings     []OscalFinding     `json:"findings,omitempty"`
}

type AssessmentResultsWrapper struct {
	AssessmentResults struct {
		UUID       string        `json:"uuid"`
		Metadata   OscalMetadata `json:"metadata"`
		Results    []OscalResult `json:"results"`
		BackMatter BackMatter    `json:"back-matter"`
	} `json:"assessment-results"`
}

// 2. Component Definition Document
type OscalImplementedRequirement struct {
	UUID        string     `json:"uuid"`
	ControlID   string     `json:"control-id"`
	Description string     `json:"description"`
	Properties  []Property `json:"properties,omitempty"`
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
type SSPWrapper struct {
	SystemSecurityPlan struct {
		UUID     string        `json:"uuid"`
		Metadata OscalMetadata `json:"metadata"`
		SystemCharacteristics struct {
			SystemName string `json:"system-name"`
			DeploymentModel string `json:"deployment-model"`
		} `json:"system-characteristics"`
		ControlImplementation struct {
			Description string `json:"description"`
			ImplementedRequirements []OscalImplementedRequirement `json:"implemented-requirements"`
		} `json:"control-implementation"`
	} `json:"system-security-plan"`
}

// 4. Assessment Plan Document
type OscalAssessmentSubject struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type OscalAssessmentActivity struct {
	UUID        string `json:"uuid"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

type AssessmentPlanWrapper struct {
	AssessmentPlan struct {
		UUID               string                    `json:"uuid"`
		Metadata           OscalMetadata             `json:"metadata"`
		AssessmentSubjects []OscalAssessmentSubject   `json:"assessment-subjects"`
		Tasks              []OscalAssessmentActivity `json:"tasks"`
		ReviewedControls   []string                  `json:"reviewed-controls"`
	} `json:"assessment-plan"`
}

// 5. Plan of Action and Milestones Document
type OscalPOAMItem struct {
	UUID        string     `json:"uuid"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Properties  []Property `json:"properties,omitempty"`
}

type POAMWrapper struct {
	PlanOfActionAndMilestones struct {
		UUID      string          `json:"uuid"`
		Metadata  OscalMetadata   `json:"metadata"`
		POAMItems []OscalPOAMItem `json:"poam-items"`
	} `json:"plan-of-action-and-milestones"`
}

// Projector converts continuous assurance evaluations into OSCAL v1.2.3 artifacts.
type Projector struct{}

func NewProjector() *Projector {
	return &Projector{}
}

// ProjectAssessmentResults builds an official OSCAL v1.2.3 Assessment Results artifact.
func (p *Projector) ProjectAssessmentResults(
	ctx context.Context,
	subject assurance.SubjectRef,
	evaluations []assurance.ClaimEvaluation,
	findings []assurance.Finding,
) ([]byte, error) {
	now := time.Now().UTC()

	wrapper := AssessmentResultsWrapper{}
	ar := &wrapper.AssessmentResults
	ar.UUID = uuid.NewString()
	ar.Metadata = OscalMetadata{
		Title:        fmt.Sprintf("OSKAL Assessment Results for %s", subject.URI()),
		Published:    now,
		LastModified: now,
		Version:      "1.0.0",
		OscalVersion: "1.2.3",
	}

	resultUUID := uuid.NewString()
	res := OscalResult{
		UUID:        resultUUID,
		Title:       fmt.Sprintf("Continuous Assurance Result for %s", subject.URI()),
		Description: fmt.Sprintf("Evaluated under composite epoch %s", evaluations[0].Epoch.CompositeDigest()),
		Start:       evaluations[0].EvaluatedAt,
		End:         evaluations[0].ValidUntil,
	}

	resourceMap := make(map[string]BackMatterResource)

	for _, eval := range evaluations {
		obsUUID := uuid.NewString()
		obs := OscalObservation{
			UUID:        obsUUID,
			Title:       fmt.Sprintf("Observation for %s", eval.Control.Canonical()),
			Description: fmt.Sprintf("Assurance state resolved to %s (Completeness: %s)", eval.State, eval.Completeness.Summary()),
			Collected:   eval.EvaluatedAt,
			Methods:     []string{"AUTOMATED_CONTINUOUS_EVALUATION"},
			Types:       []string{"assurance-claim-evaluation"},
			Properties: []Property{
				{Name: "assurance-state", Value: eval.State.String(), Ns: "https://assurance.ckodex.io/ns"},
				{Name: "epoch-composite-digest", Value: eval.Epoch.CompositeDigest(), Ns: "https://assurance.ckodex.io/ns"},
				{Name: "evidence-root", Value: eval.EvidenceRoot, Ns: "https://assurance.ckodex.io/ns"},
			},
		}

		for _, ev := range eval.Evidence {
			obs.RelevantEvidence = append(obs.RelevantEvidence, Link{
				Href: fmt.Sprintf("#%s", ev.Digest),
				Rel:  "evidence-payload",
			})

			if _, exists := resourceMap[ev.Digest]; !exists {
				resourceMap[ev.Digest] = BackMatterResource{
					UUID:        uuid.NewString(),
					Title:       fmt.Sprintf("Evidence Artifact %s", ev.Digest),
					Description: fmt.Sprintf("Stored at %s with media type %s", ev.URI, ev.MediaType),
					Properties: []Property{
						{Name: "digest", Value: ev.Digest, Ns: "https://assurance.ckodex.io/ns"},
						{Name: "media-type", Value: ev.MediaType, Ns: "https://assurance.ckodex.io/ns"},
					},
					Rlinks: []Link{
						{Href: ev.URI, Rel: "evidence-storage"},
					},
				}
			}
		}

		res.Observations = append(res.Observations, obs)
	}

	for _, f := range findings {
		findUUID := uuid.NewString()
		res.Findings = append(res.Findings, OscalFinding{
			UUID:        findUUID,
			Title:       f.Title,
			Description: f.Description,
			Target: OscalFindingTarget{
				Type:   "control-objective",
				IdRef:  f.Control.Canonical(),
				Status: "not-satisfied",
			},
		})
	}

	ar.Results = append(ar.Results, res)

	for _, r := range resourceMap {
		ar.BackMatter.Resources = append(ar.BackMatter.Resources, r)
	}

	return json.MarshalIndent(wrapper, "", "  ")
}

// ProjectComponentDefinition builds an OSCAL v1.2.3 Component Definition.
func (p *Projector) ProjectComponentDefinition(
	ctx context.Context,
	componentName string,
	evaluations []assurance.ClaimEvaluation,
) ([]byte, error) {
	now := time.Now().UTC()

	wrapper := ComponentDefinitionWrapper{}
	cd := &wrapper.ComponentDefinition
	cd.UUID = uuid.NewString()
	cd.Metadata = OscalMetadata{
		Title:        fmt.Sprintf("OSKAL Component Definition: %s", componentName),
		Published:    now,
		LastModified: now,
		Version:      "1.0.0",
		OscalVersion: "1.2.3",
	}

	comp := OscalDefinedComponent{
		UUID:        uuid.NewString(),
		Type:        "software",
		Title:       componentName,
		Description: "Kubernetes workload governed under CKODEX continuous assurance",
		Purpose:     "Assurance Runtime Realization",
	}

	controlImpl := OscalControlImplementation{
		UUID:        uuid.NewString(),
		Source:      "https://assurance.ckodex.io/catalogs/canonical-v1",
		Description: "Realized continuous security controls",
	}

	for _, eval := range evaluations {
		req := OscalImplementedRequirement{
			UUID:        uuid.NewString(),
			ControlID:   eval.Control.Canonical(),
			Description: fmt.Sprintf("Evaluated state: %s with evidence root %s", eval.State, eval.EvidenceRoot),
			Properties: []Property{
				{Name: "assurance-state", Value: eval.State.String(), Ns: "https://assurance.ckodex.io/ns"},
				{Name: "epoch-composite", Value: eval.Epoch.CompositeDigest(), Ns: "https://assurance.ckodex.io/ns"},
			},
		}
		controlImpl.ImplementedRequirements = append(controlImpl.ImplementedRequirements, req)
	}

	comp.ControlImplementations = append(comp.ControlImplementations, controlImpl)
	cd.DefinedComponents = append(cd.DefinedComponents, comp)

	return json.MarshalIndent(wrapper, "", "  ")
}

// ProjectSSP builds an OSCAL v1.2.3 System Security Plan projection.
func (p *Projector) ProjectSSP(
	ctx context.Context,
	systemName string,
	evaluations []assurance.ClaimEvaluation,
) ([]byte, error) {
	now := time.Now().UTC()

	wrapper := SSPWrapper{}
	ssp := &wrapper.SystemSecurityPlan
	ssp.UUID = uuid.NewString()
	ssp.Metadata = OscalMetadata{
		Title:        fmt.Sprintf("System Security Plan for %s", systemName),
		Published:    now,
		LastModified: now,
		Version:      "1.0.0",
		OscalVersion: "1.2.3",
	}

	ssp.SystemCharacteristics.SystemName = systemName
	ssp.SystemCharacteristics.DeploymentModel = "kubernetes-cloud-native"

	ssp.ControlImplementation.Description = "Continuously assured via OSKAL runtime"
	for _, eval := range evaluations {
		ssp.ControlImplementation.ImplementedRequirements = append(
			ssp.ControlImplementation.ImplementedRequirements,
			OscalImplementedRequirement{
				UUID:        uuid.NewString(),
				ControlID:   eval.Control.Canonical(),
				Description: fmt.Sprintf("Continuous State: %s", eval.State),
				Properties: []Property{
					{Name: "state", Value: eval.State.String()},
					{Name: "evidence-root", Value: eval.EvidenceRoot},
				},
			},
		)
	}

	return json.MarshalIndent(wrapper, "", "  ")
}

// ProjectAssessmentPlan builds an OSCAL v1.2.3 Assessment Plan projection (Section 45).
func (p *Projector) ProjectAssessmentPlan(
	ctx context.Context,
	subject assurance.SubjectRef,
	contract assurance.EvidenceContract,
	controls []assurance.ControlRef,
) ([]byte, error) {
	now := time.Now().UTC()

	wrapper := AssessmentPlanWrapper{}
	ap := &wrapper.AssessmentPlan
	ap.UUID = uuid.NewString()
	ap.Metadata = OscalMetadata{
		Title:        fmt.Sprintf("Continuous Assessment Plan for %s", subject.URI()),
		Published:    now,
		LastModified: now,
		Version:      "1.0.0",
		OscalVersion: "1.2.3",
	}

	ap.AssessmentSubjects = append(ap.AssessmentSubjects, OscalAssessmentSubject{
		Type:        "kubernetes-workload",
		Description: subject.URI(),
	})

	for _, req := range contract.Requirements {
		ap.Tasks = append(ap.Tasks, OscalAssessmentActivity{
			UUID:        uuid.NewString(),
			Title:       fmt.Sprintf("Evidence Verification: %s", req.EvidenceType),
			Description: fmt.Sprintf("Evaluated against accepted producers with max age %s", req.MaxAge),
		})
	}

	for _, c := range controls {
		ap.ReviewedControls = append(ap.ReviewedControls, c.Canonical())
	}

	return json.MarshalIndent(wrapper, "", "  ")
}

// ProjectPOAM builds an OSCAL v1.2.3 Plan of Action and Milestones projection (Section 47).
func (p *Projector) ProjectPOAM(
	ctx context.Context,
	subject assurance.SubjectRef,
	findings []assurance.Finding,
) ([]byte, error) {
	now := time.Now().UTC()

	wrapper := POAMWrapper{}
	poam := &wrapper.PlanOfActionAndMilestones
	poam.UUID = uuid.NewString()
	poam.Metadata = OscalMetadata{
		Title:        fmt.Sprintf("Plan of Action and Milestones for %s", subject.URI()),
		Published:    now,
		LastModified: now,
		Version:      "1.0.0",
		OscalVersion: "1.2.3",
	}

	for _, f := range findings {
		item := OscalPOAMItem{
			UUID:        uuid.NewString(),
			Title:       f.Title,
			Description: f.Description,
			Properties: []Property{
				{Name: "control-id", Value: f.Control.Canonical()},
				{Name: "severity", Value: f.Severity},
				{Name: "discovered-at", Value: f.DiscoveredAt.Format(time.RFC3339)},
			},
		}
		poam.POAMItems = append(poam.POAMItems, item)
	}

	return json.MarshalIndent(wrapper, "", "  ")
}
