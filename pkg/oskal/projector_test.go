package oskal

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestProjectorExport(t *testing.T) {
	ctx := context.Background()
	// Explicit example facts test projection without claiming a live deployment.
	projector := NewProjectorWithContext(ProjectionContext{
		AssessmentPlanHref: "assessment-plan.json", SystemSecurityPlanHref: "system-security-plan.json", ControlNamespace: "nist-sp-800-53", ControlSource: "catalog.json",
		Component: &ComponentContext{Type: "software", Description: "Example payments API", Implementations: map[string]string{"nist-sp-800-53:AC-6": "Example service uses a dedicated account."}},
		System: &SystemContext{
			ProfileHref:                      "profile.json",
			Characteristics:                  SystemCharacteristics{SystemIDs: []SystemID{{ID: "payments-cluster"}}, SystemName: "payments-cluster", Description: "Example payments cluster", SystemInformation: SystemInformation{InformationTypes: []InformationType{{Title: "Example transactions", Description: "Example payment records"}}}, Status: OperationalStatus{State: "other", Remarks: "Operational status not assessed."}, AuthorizationBoundary: AuthorizationBoundary{Description: "Example caller-declared namespace boundary."}},
			Implementation:                   SystemImplementation{Components: []SystemComponent{{UUID: "6306c850-eebc-4e46-bab7-44527f3d94be", Type: "this-system", Title: "payments-cluster", Description: "Example payments system", Status: OperationalStatus{State: "other", Remarks: "Operational status not assessed."}}}},
			ControlImplementationDescription: "Example implementation narrative.", Implementations: map[string]string{"nist-sp-800-53:AC-6": "Example service uses a dedicated account."},
		},
	})

	sub := SubjectRef{Scheme: "k8s", ID: "prod/payments/Deployment/payments-api"}
	ctrl := ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
	now := time.Now().UTC()

	eval := ClaimEvaluation{
		ID:      "eval-01",
		Subject: sub,
		Control: ctrl,
		State:   StateAssured,
		Epoch: AssuranceEpoch{
			SubjectDigest:        ComputeStringDigest(sub.ID),
			ImplementationDigest: ComputeStringDigest("kubernetes:workload"),
			PolicyDigest:         ComputeStringDigest("policy:nist-ac6"),
			AuthorityDigest:      ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
			EnvironmentDigest:    ComputeStringDigest("cluster:local"),
		},
		Evidence: []EvidenceRef{
			{URI: "s3://evidence/01", Digest: ComputeStringDigest("evidence-01"), MediaType: "application/json"},
		},
		Completeness: EvidenceCompleteness{Required: 1, Present: 1, Verified: 1},
		EvidenceRoot: ComputeStringDigest("root-evidence-merkle"),
		EvaluatedAt:  now,
		ValidUntil:   now.Add(5 * time.Minute),
	}

	// 1. Assessment Results
	arBytes, err := projector.ProjectAssessmentResults(ctx, sub, []ClaimEvaluation{eval}, nil)
	if err != nil {
		t.Fatalf("failed to project Assessment Results: %v", err)
	}
	var arMap map[string]interface{}
	if err := json.Unmarshal(arBytes, &arMap); err != nil {
		t.Fatalf("invalid JSON generated for Assessment Results: %v", err)
	}

	// 2. Component Definition
	cdBytes, err := projector.ProjectComponentDefinition(ctx, "payments-api", []ClaimEvaluation{eval})
	if err != nil {
		t.Fatalf("failed to project Component Definition: %v", err)
	}
	var cdMap map[string]interface{}
	if err := json.Unmarshal(cdBytes, &cdMap); err != nil {
		t.Fatalf("invalid JSON generated for Component Definition: %v", err)
	}

	// 3. Assessment Plan
	contract := EvidenceContract{
		ID:   "contract-01",
		Name: "Least Privilege Contract",
		Requirements: []EvidenceRequirement{
			{ID: "req-1", EvidenceType: "admission", MaxAge: 5 * time.Minute},
		},
	}
	apBytes, err := projector.ProjectAssessmentPlan(ctx, sub, contract, []ControlRef{ctrl})
	if err != nil {
		t.Fatalf("failed to project Assessment Plan: %v", err)
	}
	var apMap map[string]interface{}
	if err := json.Unmarshal(apBytes, &apMap); err != nil {
		t.Fatalf("invalid JSON generated for Assessment Plan: %v", err)
	}

	// 4. POAM
	findings := []Finding{
		{
			ID:           "find-01",
			Subject:      sub,
			Control:      ctrl,
			Severity:     "HIGH",
			Title:        "Unrestricted execution detected",
			Description:  "Pod allowed root UID execution",
			DiscoveredAt: now,
		},
	}
	poamBytes, err := projector.ProjectPOAM(ctx, sub, findings)
	if err != nil {
		t.Fatalf("failed to project POAM: %v", err)
	}
	var poamMap map[string]interface{}
	if err := json.Unmarshal(poamBytes, &poamMap); err != nil {
		t.Fatalf("invalid JSON generated for POAM: %v", err)
	}

	// 5. SSP
	sspBytes, err := projector.ProjectSSP(ctx, "payments-cluster", []ClaimEvaluation{eval})
	if err != nil {
		t.Fatalf("failed to project SSP: %v", err)
	}
	var sspMap map[string]interface{}
	if err := json.Unmarshal(sspBytes, &sspMap); err != nil {
		t.Fatalf("invalid JSON generated for SSP: %v", err)
	}
}

func TestProjectorWithoutContextReturnsActionableError(t *testing.T) {
	data, err := NewProjector().ProjectSSP(context.Background(), "payments", nil)
	var input *ProjectionInputError
	if data != nil || !errors.As(err, &input) || input.Field != "system" {
		t.Fatalf("expected missing system facts, got %s %v", data, err)
	}
}
