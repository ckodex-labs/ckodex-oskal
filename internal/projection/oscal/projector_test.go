package oscal

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestProjectAssessmentResultsExposesSourceEvidenceReference(t *testing.T) {
	projector := NewProjector()
	now := time.Now().UTC()

	sub := assurance.SubjectRef{
		Scheme: "k8s",
		ID:     "payments/payments-api/Deployment/payments-api",
	}

	epoch := assurance.AssuranceEpoch{
		SubjectDigest:        assurance.ComputeStringDigest(sub.URI()),
		ImplementationDigest: assurance.ComputeStringDigest("kubernetes:workload"),
		PolicyDigest:         assurance.ComputeStringDigest("cel:policy:restricted-containers"),
		AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
		EnvironmentDigest:    assurance.ComputeStringDigest("cluster:local"),
	}

	evidenceDigest := assurance.ComputeStringDigest("payload-json-content-01")
	evidenceURI := "s3://evidence/payments/ev-01.json"

	eval := assurance.ClaimEvaluation{
		ID:      "eval-01",
		Control: assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"},
		Subject: sub,
		State:   assurance.AssuranceStateAssured,
		Epoch:   epoch,
		Evidence: []assurance.EvidenceRef{
			{
				URI:       evidenceURI,
				Digest:    evidenceDigest,
				MediaType: "application/json",
			},
		},
		Completeness: assurance.EvidenceCompleteness{Required: 1, Verified: 1},
		EvidenceRoot: assurance.ComputeStringDigest("merkle-root-123"),
		EvaluatedAt:  now,
		ValidUntil:   now.Add(5 * time.Minute),
	}

	finding := assurance.Finding{
		ID:          "find-01",
		Subject:     sub,
		Control:     assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"},
		Severity:    "HIGH",
		Title:       "Test finding",
		Description: "Simulated vulnerability finding",
	}

	data, err := projector.ProjectAssessmentResults(context.Background(), sub, []assurance.ClaimEvaluation{eval}, []assurance.Finding{finding})
	if err != nil {
		t.Fatalf("failed to project assessment results: %v", err)
	}

	// Milestone 10 Exit Criteria:
	// Every projected assertion exposes source assurance/evidence reference.
	var parsed AssessmentResultsWrapper
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("projected document is not valid JSON: %v", err)
	}

	if parsed.AssessmentResults.Metadata.OscalVersion != "1.2.3" {
		t.Fatalf("expected OSCAL version 1.2.3, got %s", parsed.AssessmentResults.Metadata.OscalVersion)
	}

	if len(parsed.AssessmentResults.Results) == 0 {
		t.Fatalf("expected at least one result")
	}

	res := parsed.AssessmentResults.Results[0]
	if len(res.Observations) == 0 {
		t.Fatalf("expected at least one observation")
	}

	obs := res.Observations[0]
	if len(obs.RelevantEvidence) == 0 {
		t.Fatalf("M10 Exit Failure: Observation has no relevant-evidence links")
	}

	resourceUUID := strings.TrimPrefix(obs.RelevantEvidence[0].Href, "#")
	if resourceUUID == "" {
		t.Fatalf("M10 Exit Failure: Expected non-empty resource UUID in href: %s", obs.RelevantEvidence[0].Href)
	}

	// Back-matter must contain the referenced resource with the matching digest and UUID
	if parsed.AssessmentResults.BackMatter == nil || len(parsed.AssessmentResults.BackMatter.Resources) == 0 {
		t.Fatalf("M10 Exit Failure: Back-matter contains no resources")
	}

	if len(res.Findings) == 0 || len(res.Findings[0].RelatedObservations) == 0 {
		t.Fatalf("Finding must link RelatedObservations")
	}

	foundResource := false
	for _, r := range parsed.AssessmentResults.BackMatter.Resources {
		if r.UUID == resourceUUID {
			for _, p := range r.Props {
				if p.Name == "digest" && p.Value == evidenceDigest {
					foundResource = true
					break
				}
			}
		}
	}
	if !foundResource {
		t.Fatalf("M10 Exit Failure: Back-matter does not contain matching resource %s for evidence digest %s", resourceUUID, evidenceDigest)
	}

	// Empty evaluations must not panic and must produce valid JSON
	emptyData, err := projector.ProjectAssessmentResults(context.Background(), sub, nil, nil)
	if err != nil {
		t.Fatalf("failed to project empty assessment results: %v", err)
	}
	if !strings.Contains(string(emptyData), "assessment-results") {
		t.Fatalf("unexpected empty assessment results output: %s", string(emptyData))
	}

	t.Logf("Projected OSCAL Assessment Results:\n%s", string(data[:400])+"...")
}

func TestProjectComponentDefinitionAndSSP(t *testing.T) {
	projector := NewProjector()
	now := time.Now().UTC()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "payments/payments-api"}
	epoch := assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeStringDigest("subject-01")}

	eval := assurance.ClaimEvaluation{
		ID:           "eval-01",
		Control:      assurance.ControlRef{Namespace: "ckodex", ID: "container.least-privilege"},
		Subject:      sub,
		State:        assurance.AssuranceStateAssured,
		Epoch:        epoch,
		EvidenceRoot: assurance.ComputeStringDigest("root-evidence"),
		EvaluatedAt:  now,
		ValidUntil:   now.Add(5 * time.Minute),
	}

	// Component Definition
	cdBytes, err := projector.ProjectComponentDefinition(context.Background(), "payments-api", []assurance.ClaimEvaluation{eval})
	if err != nil {
		t.Fatalf("failed to project component definition: %v", err)
	}
	if !strings.Contains(string(cdBytes), "component-definition") || !strings.Contains(string(cdBytes), "container.least-privilege") {
		t.Fatalf("unexpected component definition output: %s", string(cdBytes))
	}

	// SSP
	sspBytes, err := projector.ProjectSSP(context.Background(), "Payments System", []assurance.ClaimEvaluation{eval})
	if err != nil {
		t.Fatalf("failed to project SSP: %v", err)
	}
	if !strings.Contains(string(sspBytes), "system-security-plan") || !strings.Contains(string(sspBytes), "Payments System") {
		t.Fatalf("unexpected SSP output: %s", string(sspBytes))
	}
	if !strings.Contains(string(sspBytes), "import-profile") {
		t.Fatalf("expected SSP to include import-profile: %s", string(sspBytes))
	}
}

func TestProjectAssessmentPlanAndPOAM(t *testing.T) {
	projector := NewProjector()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "payments/payments-api"}
	contract := assurance.EvidenceContract{
		ID: "contract-01",
		Requirements: []assurance.EvidenceRequirement{
			{ID: "req-1", EvidenceType: "admission", MaxAge: 5 * time.Minute},
		},
	}
	controls := []assurance.ControlRef{
		{Namespace: "nist-sp-800-53", ID: "AC-6"},
	}

	// 1. Assessment Plan
	apBytes, err := projector.ProjectAssessmentPlan(context.Background(), sub, contract, controls)
	if err != nil {
		t.Fatalf("failed to project assessment plan: %v", err)
	}
	if !strings.Contains(string(apBytes), "assessment-plan") || !strings.Contains(string(apBytes), "admission") {
		t.Fatalf("unexpected assessment plan output: %s", string(apBytes))
	}

	// 2. POA&M
	findings := []assurance.Finding{
		{
			ID:           "find-01",
			Subject:      sub,
			Control:      assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"},
			Severity:     "HIGH",
			Title:        "Remediation required for privileged container",
			Description:  "Pod security admission denied root execution",
			DiscoveredAt: time.Now().UTC(),
		},
	}
	poamBytes, err := projector.ProjectPOAM(context.Background(), sub, findings)
	if err != nil {
		t.Fatalf("failed to project poam: %v", err)
	}
	if !strings.Contains(string(poamBytes), "plan-of-action-and-milestones") || !strings.Contains(string(poamBytes), "Remediation required") {
		t.Fatalf("unexpected poam output: %s", string(poamBytes))
	}
	if !strings.Contains(string(poamBytes), "system-id") {
		t.Fatalf("expected POAM to include system-id: %s", string(poamBytes))
	}
}

func TestStrictNISTOscalV123SchemaConformance(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft7

	// 1. Assessment Results Schema
	arSchema, err := compiler.Compile("testdata/schemas/oscal_assessment-results_schema.json")
	if err != nil {
		t.Fatalf("failed to compile Assessment Results schema: %v", err)
	}

	// 2. Component Definition Schema
	cdSchema, err := compiler.Compile("testdata/schemas/oscal_component_schema.json")
	if err != nil {
		t.Fatalf("failed to compile Component Definition schema: %v", err)
	}

	// 3. System Security Plan Schema
	sspSchema, err := compiler.Compile("testdata/schemas/oscal_ssp_schema.json")
	if err != nil {
		t.Fatalf("failed to compile SSP schema: %v", err)
	}

	// 4. Assessment Plan Schema
	apSchema, err := compiler.Compile("testdata/schemas/oscal_assessment-plan_schema.json")
	if err != nil {
		t.Fatalf("failed to compile Assessment Plan schema: %v", err)
	}

	// 5. POAM Schema
	poamSchema, err := compiler.Compile("testdata/schemas/oscal_poam_schema.json")
	if err != nil {
		t.Fatalf("failed to compile POAM schema: %v", err)
	}

	projector := NewProjector()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "payments/payments-api/Deployment/payments-api"}
	now := time.Now().UTC()
	epoch := assurance.AssuranceEpoch{
		SubjectDigest:        assurance.ComputeStringDigest(sub.URI()),
		ImplementationDigest: assurance.ComputeStringDigest("kubernetes:workload"),
		PolicyDigest:         assurance.ComputeStringDigest("cel:policy:restricted-containers"),
		AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
		EnvironmentDigest:    assurance.ComputeStringDigest("cluster:local"),
	}

	eval := assurance.ClaimEvaluation{
		ID:      "eval-01",
		Control: assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"},
		Subject: sub,
		State:   assurance.AssuranceStateAssured,
		Epoch:   epoch,
		Evidence: []assurance.EvidenceRef{
			{
				URI:       "s3://evidence/payments/ev-01.json",
				Digest:    assurance.ComputeStringDigest("payload-json-content-01"),
				MediaType: "application/json",
			},
		},
		Completeness: assurance.EvidenceCompleteness{Required: 1, Verified: 1},
		EvidenceRoot: assurance.ComputeStringDigest("merkle-root-123"),
		EvaluatedAt:  now,
		ValidUntil:   now.Add(5 * time.Minute),
	}

	finding := assurance.Finding{
		ID:          "find-01",
		Subject:     sub,
		Control:     assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"},
		Severity:    "HIGH",
		Title:       "Test finding",
		Description: "Simulated vulnerability finding",
	}

	// Validate Assessment Results
	arBytes, err := projector.ProjectAssessmentResults(context.Background(), sub, []assurance.ClaimEvaluation{eval}, []assurance.Finding{finding})
	if err != nil {
		t.Fatalf("failed to project AR: %v", err)
	}
	var arVal interface{}
	if err := json.Unmarshal(arBytes, &arVal); err != nil {
		t.Fatalf("failed to unmarshal AR JSON: %v", err)
	}
	if err := arSchema.Validate(arVal); err != nil {
		t.Fatalf("Assessment Results failed strict NIST OSCAL v1.2.3 schema validation: %v\nJSON:\n%s", err, string(arBytes))
	}

	// Validate Component Definition
	cdBytes, err := projector.ProjectComponentDefinition(context.Background(), "payments-api", []assurance.ClaimEvaluation{eval})
	if err != nil {
		t.Fatalf("failed to project Component Definition: %v", err)
	}
	var cdVal interface{}
	if err := json.Unmarshal(cdBytes, &cdVal); err != nil {
		t.Fatalf("failed to unmarshal CD JSON: %v", err)
	}
	if err := cdSchema.Validate(cdVal); err != nil {
		t.Fatalf("Component Definition failed strict NIST OSCAL v1.2.3 schema validation: %v\nJSON:\n%s", err, string(cdBytes))
	}

	// Validate System Security Plan (SSP)
	sspBytes, err := projector.ProjectSSP(context.Background(), "payments-system", []assurance.ClaimEvaluation{eval})
	if err != nil {
		t.Fatalf("failed to project SSP: %v", err)
	}
	var sspVal interface{}
	if err := json.Unmarshal(sspBytes, &sspVal); err != nil {
		t.Fatalf("failed to unmarshal SSP JSON: %v", err)
	}
	if err := sspSchema.Validate(sspVal); err != nil {
		t.Fatalf("SSP failed strict NIST OSCAL v1.2.3 schema validation: %v\nJSON:\n%s", err, string(sspBytes))
	}

	// Validate Assessment Plan
	contract := assurance.EvidenceContract{
		ID: "contract-01",
		Requirements: []assurance.EvidenceRequirement{
			{ID: "req-1", EvidenceType: "admission", Required: true, MaxAge: 5 * time.Minute},
		},
	}
	controls := []assurance.ControlRef{
		{Namespace: "nist-sp-800-53", ID: "AC-6"},
	}
	apBytes, err := projector.ProjectAssessmentPlan(context.Background(), sub, contract, controls)
	if err != nil {
		t.Fatalf("failed to project Assessment Plan: %v", err)
	}
	var apVal interface{}
	if err := json.Unmarshal(apBytes, &apVal); err != nil {
		t.Fatalf("failed to unmarshal AP JSON: %v", err)
	}
	if err := apSchema.Validate(apVal); err != nil {
		t.Fatalf("Assessment Plan failed strict NIST OSCAL v1.2.3 schema validation: %v\nJSON:\n%s", err, string(apBytes))
	}

	// Validate POAM (with findings and without findings)
	poamWithFindings, err := projector.ProjectPOAM(context.Background(), sub, []assurance.Finding{finding})
	if err != nil {
		t.Fatalf("failed to project POAM: %v", err)
	}
	var poamVal1 interface{}
	if err := json.Unmarshal(poamWithFindings, &poamVal1); err != nil {
		t.Fatalf("failed to unmarshal POAM JSON: %v", err)
	}
	if err := poamSchema.Validate(poamVal1); err != nil {
		t.Fatalf("POAM (with findings) failed strict NIST OSCAL v1.2.3 schema validation: %v\nJSON:\n%s", err, string(poamWithFindings))
	}

	poamWithoutFindings, err := projector.ProjectPOAM(context.Background(), sub, nil)
	if err != nil {
		t.Fatalf("failed to project empty POAM: %v", err)
	}
	var poamVal2 interface{}
	if err := json.Unmarshal(poamWithoutFindings, &poamVal2); err != nil {
		t.Fatalf("failed to unmarshal empty POAM JSON: %v", err)
	}
	if err := poamSchema.Validate(poamVal2); err != nil {
		t.Fatalf("POAM (without findings) failed strict NIST OSCAL v1.2.3 schema validation: %v\nJSON:\n%s", err, string(poamWithoutFindings))
	}
}
