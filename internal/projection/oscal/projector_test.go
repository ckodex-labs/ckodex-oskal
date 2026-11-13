package oscal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

// These are explicit domain examples, not claims about a running cluster. Imported
// documents are deliberately not resolved: projection checks shape, not provenance.
func exampleContext() ProjectionContext {
	return ProjectionContext{
		AssessmentPlanHref: "assessment-plan.json", SystemSecurityPlanHref: "system-security-plan.json",
		ControlSource: "catalog.json", ControlNamespace: "nist-sp-800-53",
		Component: &ComponentContext{Type: "software", Description: "Example payment service", Implementations: map[string]string{"nist-sp-800-53:AC-6": "Example service uses a dedicated unprivileged account."}},
		System: &SystemContext{
			ProfileHref:                      "profile.json",
			Characteristics:                  OscalSystemCharacteristics{SystemIDs: []OscalSystemID{{ID: "payments-system"}}, SystemName: "payments-system", Description: "Example payment system", SystemInformation: OscalSystemInformation{InformationTypes: []OscalInformationType{{Title: "Example transactions", Description: "Example payment transaction records"}}}, Status: OscalStatus{State: "other", Remarks: "Operational status has not been assessed by this example."}, AuthorizationBoundary: OscalAuthorizationBoundary{Description: "Example namespace payments, as declared by the caller; enforcement is not verified by projection."}},
			Implementation:                   OscalSystemImplementation{Components: []OscalSSPComponent{{UUID: "586bc654-a3bd-4c9b-9e8c-b294d1391911", Type: "this-system", Title: "payments-system", Description: "Example payment system component", Status: OscalStatus{State: "other", Remarks: "Component operational status is not assessed."}}}},
			ControlImplementationDescription: "Caller-supplied example implementation narratives.", Implementations: map[string]string{"nist-sp-800-53:AC-6": "Example service uses a dedicated unprivileged account."},
		},
		FindingTargets: map[string]FindingTargetMapping{"nist-sp-800-53:AC-6": {Type: "objective-id", TargetID: "ac-6_obj.a"}},
	}
}

func exampleEvaluation() (assurance.SubjectRef, assurance.ClaimEvaluation) {
	subject := assurance.SubjectRef{Scheme: "k8s", ID: "payments/Deployment/payments-api"}
	now := time.Now().UTC().Add(-time.Minute)
	return subject, assurance.ClaimEvaluation{ID: "evaluation-1", Subject: subject, Control: assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}, State: assurance.AssuranceStateUnknown, Epoch: assurance.AssuranceEpoch{SubjectDigest: subject.Digest()}, EvaluatedAt: now, ValidUntil: now.Add(5 * time.Minute), Completeness: assurance.EvidenceCompleteness{Required: 1}, Evidence: []assurance.EvidenceRef{{URI: "urn:example:evidence:1", Digest: assurance.ComputeStringDigest("example source bytes"), MediaType: "application/json"}}}
}

func exampleFinding(subject assurance.SubjectRef, e assurance.ClaimEvaluation) assurance.Finding {
	return assurance.Finding{ID: "finding-1", Subject: subject, Control: e.Control, Title: "Example confirmed violation", Description: "Example source finding supplied for projection.", Severity: "HIGH", DiscoveredAt: e.EvaluatedAt, EvidenceRefs: e.Evidence}
}

func assertInputError(t *testing.T, data []byte, err error, field string) {
	t.Helper()
	var input *ProjectionInputError
	if data != nil || !errors.As(err, &input) || !strings.Contains(input.Field, field) {
		t.Fatalf("expected no bytes and input error for %s, got %s %v", field, data, err)
	}
	t.Logf("Rejected missing/incompatible input: %v", err)
}

func validateProjection(t *testing.T, dt DocumentType, data []byte) {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft7
	schema, err := compiler.Compile("testdata/" + schemaFileMap[dt])
	if err != nil {
		t.Fatal(err)
	}
	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(parsed); err != nil {
		t.Fatalf("%s violates strict NIST 1.2.3 schema: %v\n%s", dt, err, data)
	}
}

func TestProjectionRequiresSemanticInputs(t *testing.T) {
	subject, e := exampleEvaluation()
	p := NewProjector()
	data, err := p.ProjectAssessmentResults(context.Background(), subject, []assurance.ClaimEvaluation{e}, nil)
	assertInputError(t, data, err, "assessment_plan_href")
	data, err = p.ProjectComponentDefinition(context.Background(), "payments", []assurance.ClaimEvaluation{e})
	assertInputError(t, data, err, "component")
	data, err = p.ProjectSSP(context.Background(), "payments", []assurance.ClaimEvaluation{e})
	assertInputError(t, data, err, "system")
	data, err = p.ProjectAssessmentPlan(context.Background(), subject, assurance.EvidenceContract{}, []assurance.ControlRef{e.Control})
	assertInputError(t, data, err, "system_security_plan_href")
	data, err = p.ProjectPOAM(context.Background(), subject, nil)
	assertInputError(t, data, err, "findings")
}

func TestProjectionDoesNotInventEmptyBaselineOrTasks(t *testing.T) {
	subject, e := exampleEvaluation()
	p := NewProjectorWithContext(exampleContext())
	data, err := p.ProjectAssessmentResults(context.Background(), subject, nil, nil)
	assertInputError(t, data, err, "controls")
	data, err = p.ProjectSSP(context.Background(), "payments-system", nil)
	assertInputError(t, data, err, "controls")
	data, err = p.ProjectAssessmentPlan(context.Background(), subject, assurance.EvidenceContract{}, nil)
	assertInputError(t, data, err, "controls")
	data, err = p.ProjectComponentDefinition(context.Background(), "payments", nil)
	if err != nil {
		t.Fatal(err)
	}
	validateProjection(t, DocTypeComponentDefinition, data)
	if strings.Contains(string(data), "implemented-requirements") || strings.Contains(string(data), "AC-6") {
		t.Fatalf("empty component fabricated controls: %s", data)
	}
	data, err = p.ProjectAssessmentPlan(context.Background(), subject, assurance.EvidenceContract{}, []assurance.ControlRef{e.Control})
	if err != nil {
		t.Fatal(err)
	}
	validateProjection(t, DocTypeAssessmentPlan, data)
	if strings.Contains(string(data), "tasks") || strings.Contains(string(data), "include-all") || strings.Contains(string(data), "assessment-subjects") {
		t.Fatalf("plan fabricated tasks or scope: %s", data)
	}
}

func TestAssessmentResultsPreserveUnknownScopeTimeAndEvidence(t *testing.T) {
	subject, e := exampleEvaluation()
	p := NewProjectorWithContext(exampleContext())
	later := e
	later.ID = "evaluation-2"
	later.EvaluatedAt = e.EvaluatedAt.Add(30 * time.Second)
	later.Epoch.PolicyDigest = assurance.ComputeStringDigest("different example policy")
	later.Evidence = append([]assurance.EvidenceRef(nil), e.Evidence...)
	later.Evidence[0].URI = "urn:example:evidence:alternate-location"
	data, err := p.ProjectAssessmentResults(context.Background(), subject, []assurance.ClaimEvaluation{later, e}, nil)
	if err != nil {
		t.Fatal(err)
	}
	validateProjection(t, DocTypeAssessmentResults, data)
	var got AssessmentResultsWrapper
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	ar := got.AssessmentResults
	r := ar.Results[0]
	if !r.Start.Equal(e.EvaluatedAt) || !r.End.Equal(later.EvaluatedAt) {
		t.Fatalf("result execution interval changed: %s -> %s", r.Start, r.End)
	}
	if r.Observations[0].Expires == nil || !r.Observations[0].Expires.Equal(later.ValidUntil) {
		t.Fatal("evaluation validity must remain expiry, never completed execution time")
	}
	if !ar.Metadata.Published.IsZero() || len(r.Findings) != 0 || r.ReviewedControls.ControlSelections[0].IncludeAll != nil {
		t.Fatalf("fabricated publication/findings/scope: %s", data)
	}
	selected := r.ReviewedControls.ControlSelections[0].IncludeControls
	if len(selected) != 1 || selected[0].ControlID != e.Control.ID {
		t.Fatalf("incorrect exact controls: %+v", selected)
	}
	for _, obs := range r.Observations {
		unknown := false
		for _, prop := range obs.Props {
			if prop.Name == "assurance-state" && prop.Value == "UNKNOWN" {
				unknown = true
			}
		}
		if !unknown {
			t.Fatalf("UNKNOWN changed: %+v", obs)
		}
	}
	if ar.BackMatter == nil || len(ar.BackMatter.Resources) != 2 {
		t.Fatal("distinct source evidence locations must survive projection")
	}
	resources := make(map[string]BackMatterResource)
	for _, resource := range ar.BackMatter.Resources {
		resources[resource.UUID] = resource
	}
	for i, obs := range r.Observations {
		resource := resources[strings.TrimPrefix(obs.RelevantEvidence[0].Href, "#")]
		source := []assurance.ClaimEvaluation{later, e}[i].Evidence[0]
		if resource.Props[0].Value != source.Digest || resource.Rlinks[0].Href != source.URI {
			t.Fatalf("evidence source was reinterpreted: %+v", resource)
		}
	}
	t.Logf("UNKNOWN preserved; exact control selection=%s; no satisfaction assertion; end=%s, expiry=%s", selected[0].ControlID, r.End, r.Observations[0].Expires)
}

func TestAssessmentFindingsRequireActualTargetAndExactEvidenceLink(t *testing.T) {
	subject, e := exampleEvaluation()
	e.State = assurance.AssuranceStateFailed
	f := exampleFinding(subject, e)
	c := exampleContext()
	p := NewProjectorWithContext(c)
	data, err := p.ProjectAssessmentResults(context.Background(), subject, []assurance.ClaimEvaluation{e}, []assurance.Finding{f})
	if err != nil {
		t.Fatal(err)
	}
	validateProjection(t, DocTypeAssessmentResults, data)
	var got AssessmentResultsWrapper
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	r := got.AssessmentResults.Results[0]
	if r.Findings[0].Target.TargetID != "ac-6_obj.a" || r.Findings[0].RelatedObservations[0].ObservationUUID != r.Observations[0].UUID {
		t.Fatalf("target/provenance mapping changed: %+v", r)
	}
	c.FindingTargets = nil
	data, err = NewProjectorWithContext(c).ProjectAssessmentResults(context.Background(), subject, []assurance.ClaimEvaluation{e}, []assurance.Finding{f})
	assertInputError(t, data, err, "finding_targets")
	c = exampleContext()
	f.EvidenceRefs = nil
	data, err = NewProjectorWithContext(c).ProjectAssessmentResults(context.Background(), subject, []assurance.ClaimEvaluation{e}, []assurance.Finding{f})
	assertInputError(t, data, err, "findings.evidenceRefs")
	f = exampleFinding(subject, e)
	f.Control.ID = "AC-60"
	c.FindingTargets[f.Control.Canonical()] = FindingTargetMapping{Type: "objective-id", TargetID: "ac-60_obj.a"}
	data, err = NewProjectorWithContext(c).ProjectAssessmentResults(context.Background(), subject, []assurance.ClaimEvaluation{e}, []assurance.Finding{f})
	assertInputError(t, data, err, "findings.evidenceRefs")
}

func TestSSPRequiresActualBoundaryStatusAndNarrative(t *testing.T) {
	_, e := exampleEvaluation()
	c := exampleContext()
	data, err := NewProjectorWithContext(c).ProjectSSP(context.Background(), "payments-system", []assurance.ClaimEvaluation{e})
	if err != nil {
		t.Fatal(err)
	}
	validateProjection(t, DocTypeSSP, data)
	var got SSPWrapper
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	facts := got.SystemSecurityPlan.SystemCharacteristics
	if facts.Status.State != "other" || facts.Status.Remarks != c.System.Characteristics.Status.Remarks || facts.AuthorizationBoundary.Description != c.System.Characteristics.AuthorizationBoundary.Description {
		t.Fatalf("caller system facts replaced: %+v", facts)
	}
	c.System.Characteristics.Status.Remarks = ""
	data, err = NewProjectorWithContext(c).ProjectSSP(context.Background(), "payments-system", []assurance.ClaimEvaluation{e})
	assertInputError(t, data, err, "status.remarks")
	c = exampleContext()
	c.System.Characteristics.AuthorizationBoundary.Description = ""
	data, err = NewProjectorWithContext(c).ProjectSSP(context.Background(), "payments-system", []assurance.ClaimEvaluation{e})
	assertInputError(t, data, err, "authorization-boundary")
	c = exampleContext()
	c.System.Implementations = nil
	data, err = NewProjectorWithContext(c).ProjectSSP(context.Background(), "payments-system", []assurance.ClaimEvaluation{e})
	assertInputError(t, data, err, "system.implementations")
}

func TestProjectionRejectsCrossSubjectAndFrameworkInputs(t *testing.T) {
	subject, e := exampleEvaluation()
	p := NewProjectorWithContext(exampleContext())
	e.Subject.ID = "another-workload"
	data, err := p.ProjectAssessmentResults(context.Background(), subject, []assurance.ClaimEvaluation{e}, nil)
	assertInputError(t, data, err, "evaluations.subject")
	_, e = exampleEvaluation()
	e.Control.Namespace = "unrelated-framework"
	data, err = p.ProjectComponentDefinition(context.Background(), "payments", []assurance.ClaimEvaluation{e})
	assertInputError(t, data, err, "controls")
	_, e = exampleEvaluation()
	e.EvaluatedAt = time.Now().UTC().Add(time.Hour)
	data, err = p.ProjectAssessmentResults(context.Background(), subject, []assurance.ClaimEvaluation{e}, nil)
	assertInputError(t, data, err, "evaluations.evaluatedAt")
}

func TestStrictNISTOscalV123SchemaConformance(t *testing.T) {
	subject, e := exampleEvaluation()
	f := exampleFinding(subject, e)
	p := NewProjectorWithContext(exampleContext())
	tests := []struct {
		name    DocumentType
		project func() ([]byte, error)
	}{
		{DocTypeAssessmentResults, func() ([]byte, error) {
			return p.ProjectAssessmentResults(context.Background(), subject, []assurance.ClaimEvaluation{e}, []assurance.Finding{f})
		}},
		{DocTypeComponentDefinition, func() ([]byte, error) {
			return p.ProjectComponentDefinition(context.Background(), "payments", []assurance.ClaimEvaluation{e})
		}},
		{DocTypeSSP, func() ([]byte, error) {
			return p.ProjectSSP(context.Background(), "payments-system", []assurance.ClaimEvaluation{e})
		}},
		{DocTypeAssessmentPlan, func() ([]byte, error) {
			return p.ProjectAssessmentPlan(context.Background(), subject, assurance.EvidenceContract{ID: "example-contract", Requirements: []assurance.EvidenceRequirement{{ID: "r1", EvidenceType: "admission", Required: true, MaxAge: time.Minute, AcceptedProducers: []string{"spiffe://example.test/collector"}}}}, []assurance.ControlRef{e.Control})
		}},
		{DocTypePOAM, func() ([]byte, error) { return p.ProjectPOAM(context.Background(), subject, []assurance.Finding{f}) }},
	}
	for _, test := range tests {
		t.Run(string(test.name), func(t *testing.T) {
			data, err := test.project()
			if err != nil {
				t.Fatal(err)
			}
			validateProjection(t, test.name, data)
			t.Logf("strict NIST 1.2.3 schema accepted %s", test.name)
		})
	}
}

func TestDecodeProjectionContextStrictBoundedJSON(t *testing.T) {
	valid, err := json.Marshal(exampleContext())
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeProjectionContext(valid)
	if err != nil || got.AssessmentPlanHref != "assessment-plan.json" || got.System.Characteristics.Status.State != "other" {
		t.Fatalf("context decode lost facts: %+v %v", got, err)
	}
	for _, input := range []string{"", "null", "[]", `{`, `{"unknown":"field"}`, `{"component":{"unexpected_field":"typo"}}`, `{} {}`, `{} trailing`, strings.Repeat(" ", MaxProjectionContextBytes+1)} {
		if _, err := DecodeProjectionContext([]byte(input)); err == nil {
			t.Fatalf("accepted invalid/oversized context %q", input[:min(len(input), 100)])
		}
	}
}

func TestImplementationProjectionRejectsAmbiguousDuplicateSnapshots(t *testing.T) {
	_, e := exampleEvaluation()
	p := NewProjectorWithContext(exampleContext())
	data, err := p.ProjectComponentDefinition(context.Background(), "payments", []assurance.ClaimEvaluation{e, e})
	assertInputError(t, data, err, "evaluations.control")
	data, err = p.ProjectSSP(context.Background(), "payments-system", []assurance.ClaimEvaluation{e, e})
	assertInputError(t, data, err, "evaluations.control")
}
