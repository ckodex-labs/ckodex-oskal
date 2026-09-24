package oscal

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
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
	Title        string    `json:"title"`
	Published    time.Time `json:"published"`
	LastModified time.Time `json:"last-modified"`
	Version      string    `json:"version"`
	OscalVersion string    `json:"oscal-version"`
}

// 1. Assessment Results Document
type OscalObservation struct {
	UUID             string                  `json:"uuid"`
	Title            string                  `json:"title"`
	Description      string                  `json:"description"`
	Collected        time.Time               `json:"collected"`
	Methods          []string                `json:"methods"`
	Types            []string                `json:"types"`
	RelevantEvidence []OscalRelevantEvidence `json:"relevant-evidence,omitempty"`
	Props            []Property              `json:"props,omitempty"`
}

type OscalFindingTarget struct {
	Type   string `json:"type"`
	IdRef  string `json:"id-ref"`
	Status string `json:"status"` // "satisfied", "not-satisfied"
}

type OscalFinding struct {
	UUID                string             `json:"uuid"`
	Title               string             `json:"title"`
	Description         string             `json:"description"`
	Target              OscalFindingTarget `json:"target"`
	RelatedObservations []string           `json:"related-observations,omitempty"`
}

type OscalControlSelection struct {
	Description string    `json:"description,omitempty"`
	IncludeAll  *struct{} `json:"include-all,omitempty"`
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
type SSPWrapper struct {
	SystemSecurityPlan struct {
		UUID                  string        `json:"uuid"`
		Metadata              OscalMetadata `json:"metadata"`
		SystemCharacteristics struct {
			SystemName      string `json:"system-name"`
			DeploymentModel string `json:"deployment-model"`
		} `json:"system-characteristics"`
		ControlImplementation struct {
			Description             string                        `json:"description"`
			ImplementedRequirements []OscalImplementedRequirement `json:"implemented-requirements"`
		} `json:"control-implementation"`
	} `json:"system-security-plan"`
}

// 4. Assessment Plan Document
type OscalAssessmentSubject struct {
	Type        string    `json:"type"`
	Description string    `json:"description,omitempty"`
	IncludeAll  *struct{} `json:"include-all,omitempty"`
}

type OscalAssessmentActivity struct {
	UUID        string `json:"uuid"`
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
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

	ar.ImportAP = ImportAP{
		Href: "assessment-plan.json",
	}

	resultUUID := uuid.NewString()
	res := OscalResult{
		UUID:        resultUUID,
		Title:       fmt.Sprintf("Continuous Assurance Result for %s", subject.URI()),
		Description: fmt.Sprintf("Evaluated under composite epoch %s", evaluations[0].Epoch.CompositeDigest()),
		Start:       evaluations[0].EvaluatedAt,
		End:         evaluations[0].ValidUntil,
		ReviewedControls: OscalReviewedControls{
			ControlSelections: []OscalControlSelection{
				{
					Description: "Continuous automated control assessment",
					IncludeAll:  &struct{}{},
				},
			},
		},
	}

	resourceUUIDs := make(map[string]string)
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
			Props: []Property{
				{Name: "assurance-state", Value: eval.State.String(), Ns: "https://assurance.ckodex.io/ns"},
				{Name: "epoch-composite-digest", Value: eval.Epoch.CompositeDigest(), Ns: "https://assurance.ckodex.io/ns"},
				{Name: "evidence-root", Value: eval.EvidenceRoot, Ns: "https://assurance.ckodex.io/ns"},
			},
		}

		for _, ev := range eval.Evidence {
			resUUID, exists := resourceUUIDs[ev.Digest]
			if !exists {
				resUUID = uuid.NewString()
				resourceUUIDs[ev.Digest] = resUUID
				resourceMap[ev.Digest] = BackMatterResource{
					UUID:        resUUID,
					Title:       fmt.Sprintf("Evidence Artifact %s", ev.Digest),
					Description: fmt.Sprintf("Stored at %s with media type %s", ev.URI, ev.MediaType),
					Props: []Property{
						{Name: "digest", Value: ev.Digest, Ns: "https://assurance.ckodex.io/ns"},
					},
					Rlinks: []OscalRlink{
						{Href: ev.URI, MediaType: ev.MediaType},
					},
				}
			}

			obs.RelevantEvidence = append(obs.RelevantEvidence, OscalRelevantEvidence{
				Href:        fmt.Sprintf("#%s", resUUID),
				Description: fmt.Sprintf("Evidence artifact %s (%s)", ev.Digest, ev.MediaType),
			})
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
				IdRef:  f.Control.ID,
				Status: "not-satisfied",
			},
		})
	}

	ar.Results = append(ar.Results, res)

	if len(resourceMap) > 0 {
		bm := &BackMatter{}
		for _, r := range resourceMap {
			bm.Resources = append(bm.Resources, r)
		}
		ar.BackMatter = bm
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
		ctrlID := eval.Control.ID
		if ctrlID == "" {
			ctrlID = strings.ReplaceAll(eval.Control.Canonical(), ":", "_")
		}
		req := OscalImplementedRequirement{
			UUID:        uuid.NewString(),
			ControlID:   ctrlID,
			Description: fmt.Sprintf("Evaluated state: %s with evidence root %s", eval.State, eval.EvidenceRoot),
			Props: []Property{
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
				ControlID:   eval.Control.ID,
				Description: fmt.Sprintf("Continuous State: %s", eval.State),
				Props: []Property{
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

	ap.ImportSSP = ImportSSP{
		Href: "system-security-plan.json",
	}

	ap.ReviewedControls = OscalReviewedControls{
		ControlSelections: []OscalControlSelection{
			{
				Description: "Continuous assessment controls",
				IncludeAll:  &struct{}{},
			},
		},
	}

	ap.AssessmentSubjects = append(ap.AssessmentSubjects, OscalAssessmentSubject{
		Type:        "component",
		Description: fmt.Sprintf("Kubernetes workload %s", subject.URI()),
		IncludeAll:  &struct{}{},
	})

	for _, req := range contract.Requirements {
		ap.Tasks = append(ap.Tasks, OscalAssessmentActivity{
			UUID:        uuid.NewString(),
			Type:        "action",
			Title:       fmt.Sprintf("Evidence Verification: %s", req.EvidenceType),
			Description: fmt.Sprintf("Evaluated against accepted producers with max age %s", req.MaxAge),
		})
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
			Props: []Property{
				{Name: "control-id", Value: f.Control.Canonical(), Ns: "https://assurance.ckodex.io/ns"},
				{Name: "severity", Value: f.Severity, Ns: "https://assurance.ckodex.io/ns"},
				{Name: "discovered-at", Value: f.DiscoveredAt.Format(time.RFC3339), Ns: "https://assurance.ckodex.io/ns"},
			},
		}
		poam.POAMItems = append(poam.POAMItems, item)
	}

	return json.MarshalIndent(wrapper, "", "  ")
}
