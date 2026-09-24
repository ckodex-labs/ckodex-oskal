package oskal

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestProjectorExport(t *testing.T) {
	ctx := context.Background()
	projector := NewProjector()

	sub := SubjectRef{Scheme: "k8s", ID: "prod/payments/Deployment/payments-api"}
	ctrl := ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
	now := time.Now().UTC()

	eval := ClaimEvaluation{
		ID:      "eval-01",
		Subject: sub,
		Control: ctrl,
		State:   StateAssured,
		Epoch: AssuranceEpoch{
			SubjectDigest:        "sha256:sub",
			ImplementationDigest: "sha256:imp",
			PolicyDigest:         "sha256:pol",
			AuthorityDigest:      "sha256:auth",
			EnvironmentDigest:    "sha256:env",
		},
		Evidence: []EvidenceRef{
			{URI: "s3://evidence/01", Digest: "sha256:ev01", MediaType: "application/json"},
		},
		Completeness: EvidenceCompleteness{Required: 1, Present: 1, Verified: 1},
		EvidenceRoot: "sha256:root01",
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
