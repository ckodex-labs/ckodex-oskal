package oscal

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestValidatorEmbeddedCompilation(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	if v == nil {
		t.Fatal("validator instance is nil")
	}
}

func TestValidatorValidDocuments(t *testing.T) {
	v, err := DefaultValidator()
	if err != nil {
		t.Fatalf("failed to get default validator: %v", err)
	}

	projector := NewProjector()
	now := time.Now().UTC()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "prod/payments/Deployment/payments-api"}
	epoch := assurance.AssuranceEpoch{
		SubjectDigest:        assurance.ComputeStringDigest(sub.URI()),
		ImplementationDigest: assurance.ComputeStringDigest("kubernetes:workload"),
		PolicyDigest:         assurance.ComputeStringDigest("cel:restricted"),
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
				URI:       "s3://evidence/ev-01.json",
				Digest:    assurance.ComputeStringDigest("data"),
				MediaType: "application/json",
			},
		},
		Completeness: assurance.EvidenceCompleteness{Required: 1, Verified: 1},
		EvidenceRoot: assurance.ComputeStringDigest("root-01"),
		EvaluatedAt:  now,
		ValidUntil:   now.Add(5 * time.Minute),
	}

	// 1. Validate Assessment Results
	arBytes, err := projector.ProjectAssessmentResults(context.Background(), sub, []assurance.ClaimEvaluation{eval}, nil)
	if err != nil {
		t.Fatalf("failed to project AR: %v", err)
	}
	report, err := v.Validate(arBytes, "")
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if !report.Valid {
		t.Fatalf("expected valid AR, got errors: %+v", report.Errors)
	}
	if report.DocumentType != DocTypeAssessmentResults {
		t.Fatalf("expected doc type %s, got %s", DocTypeAssessmentResults, report.DocumentType)
	}
	if report.OscalVersion != "1.2.3" {
		t.Fatalf("expected oscal version 1.2.3, got %s", report.OscalVersion)
	}

	// 2. Validate Component Definition
	cdBytes, err := projector.ProjectComponentDefinition(context.Background(), "payments-api", []assurance.ClaimEvaluation{eval})
	if err != nil {
		t.Fatalf("failed to project CD: %v", err)
	}
	reportCD, err := v.Validate(cdBytes, "auto")
	if err != nil {
		t.Fatalf("CD validation failed: %v", err)
	}
	if !reportCD.Valid {
		t.Fatalf("expected valid CD, got errors: %+v", reportCD.Errors)
	}

	// 3. Validate SSP
	sspBytes, err := projector.ProjectSSP(context.Background(), "payments-system", []assurance.ClaimEvaluation{eval})
	if err != nil {
		t.Fatalf("failed to project SSP: %v", err)
	}
	reportSSP, err := v.Validate(sspBytes, "ssp")
	if err != nil {
		t.Fatalf("SSP validation failed: %v", err)
	}
	if !reportSSP.Valid {
		t.Fatalf("expected valid SSP, got errors: %+v", reportSSP.Errors)
	}

	// 4. Validate Assessment Plan
	contract := assurance.EvidenceContract{
		ID: "contract-01",
		Requirements: []assurance.EvidenceRequirement{
			{ID: "req-1", EvidenceType: "admission", Required: true, MaxAge: 5 * time.Minute},
		},
	}
	apBytes, err := projector.ProjectAssessmentPlan(context.Background(), sub, contract, []assurance.ControlRef{{Namespace: "nist-sp-800-53", ID: "AC-6"}})
	if err != nil {
		t.Fatalf("failed to project AP: %v", err)
	}
	reportAP, err := v.Validate(apBytes, "assessment-plan")
	if err != nil {
		t.Fatalf("AP validation failed: %v", err)
	}
	if !reportAP.Valid {
		t.Fatalf("expected valid AP, got errors: %+v", reportAP.Errors)
	}

	// 5. Validate POAM
	poamBytes, err := projector.ProjectPOAM(context.Background(), sub, nil)
	if err != nil {
		t.Fatalf("failed to project POAM: %v", err)
	}
	reportPOAM, err := v.Validate(poamBytes, "poam")
	if err != nil {
		t.Fatalf("POAM validation failed: %v", err)
	}
	if !reportPOAM.Valid {
		t.Fatalf("expected valid POAM, got errors: %+v", reportPOAM.Errors)
	}
}

func TestValidatorInvalidDocumentCatchesErrors(t *testing.T) {
	v, err := DefaultValidator()
	if err != nil {
		t.Fatalf("failed to get default validator: %v", err)
	}

	invalidJSON := []byte(`{
		"assessment-results": {
			"uuid": "not-a-valid-uuid",
			"metadata": {
				"title": "Invalid Document"
			}
		}
	}`)

	report, err := v.Validate(invalidJSON, "assessment-results")
	if err != nil {
		t.Fatalf("unexpected validation execution error: %v", err)
	}
	if report.Valid {
		t.Fatal("expected invalid document to fail validation")
	}
	if len(report.Errors) == 0 {
		t.Fatal("expected at least one validation error")
	}

	hasUUIDError := false
	for _, errItem := range report.Errors {
		if strings.Contains(errItem.Path, "uuid") || strings.Contains(errItem.Message, "uuid") || strings.Contains(errItem.Message, "required") {
			hasUUIDError = true
			break
		}
	}
	if !hasUUIDError {
		t.Logf("Errors received: %+v", report.Errors)
	}
}

func TestValidatorYAMLSupport(t *testing.T) {
	v, err := DefaultValidator()
	if err != nil {
		t.Fatalf("failed to get default validator: %v", err)
	}

	yamlDoc := `
component-definition:
  uuid: "00000000-0000-4000-8000-000000000001"
  metadata:
    title: "Minimal Test Component"
    published: "2026-01-01T00:00:00Z"
    last-modified: "2026-01-01T00:00:00Z"
    version: "1.0.0"
    oscal-version: "1.2.3"
  components:
    - uuid: "00000000-0000-4000-8000-000000000002"
      type: "software"
      title: "Core Service"
      description: "Sample test component"
`
	report, err := v.Validate([]byte(yamlDoc), "")
	if err != nil {
		t.Fatalf("YAML validation failed: %v", err)
	}
	if !report.Valid {
		t.Fatalf("expected valid YAML component-definition, got errors: %+v", report.Errors)
	}
	if report.DocumentType != DocTypeComponentDefinition {
		t.Fatalf("expected doc type %s, got %s", DocTypeComponentDefinition, report.DocumentType)
	}
}
