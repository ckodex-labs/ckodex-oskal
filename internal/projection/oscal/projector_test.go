package oscal

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/oskal/core/assurance"
)

func TestProjectAssessmentResultsExposesSourceEvidenceReference(t *testing.T) {
	projector := NewProjector()
	now := time.Now().UTC()

	sub := assurance.SubjectRef{
		Scheme: "k8s",
		ID:     "payments/payments-api/Deployment/payments-api",
	}

	epoch := assurance.AssuranceEpoch{
		SubjectDigest:        "sha256:sub123",
		ImplementationDigest: "sha256:imp123",
		PolicyDigest:         "sha256:pol123",
		AuthorityDigest:      "sha256:auth123",
		EnvironmentDigest:    "sha256:env123",
	}

	evidenceDigest := "sha256:evPayload123456789"
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
		EvidenceRoot: "sha256:merkleRoot123",
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

	expectedHref := "#" + evidenceDigest
	if obs.RelevantEvidence[0].Href != expectedHref {
		t.Fatalf("M10 Exit Failure: Expected evidence href %s, got %s", expectedHref, obs.RelevantEvidence[0].Href)
	}

	// Back-matter must contain the referenced resource with the matching digest
	if len(parsed.AssessmentResults.BackMatter.Resources) == 0 {
		t.Fatalf("M10 Exit Failure: Back-matter contains no resources")
	}

	foundResource := false
	for _, r := range parsed.AssessmentResults.BackMatter.Resources {
		for _, p := range r.Properties {
			if p.Name == "digest" && p.Value == evidenceDigest {
				foundResource = true
				break
			}
		}
	}
	if !foundResource {
		t.Fatalf("M10 Exit Failure: Back-matter does not contain resource for evidence digest %s", evidenceDigest)
	}

	t.Logf("Projected OSCAL Assessment Results:\n%s", string(data[:400])+"...")
}

func TestProjectComponentDefinitionAndSSP(t *testing.T) {
	projector := NewProjector()
	now := time.Now().UTC()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "payments/payments-api"}
	epoch := assurance.AssuranceEpoch{SubjectDigest: "sha256:sub"}

	eval := assurance.ClaimEvaluation{
		ID:           "eval-01",
		Control:      assurance.ControlRef{Namespace: "ckodex", ID: "container.least-privilege"},
		Subject:      sub,
		State:        assurance.AssuranceStateAssured,
		Epoch:        epoch,
		EvidenceRoot: "sha256:root",
		EvaluatedAt:  now,
		ValidUntil:   now.Add(5 * time.Minute),
	}

	// Component Definition
	cdBytes, err := projector.ProjectComponentDefinition(context.Background(), "payments-api", []assurance.ClaimEvaluation{eval})
	if err != nil {
		t.Fatalf("failed to project component definition: %v", err)
	}
	if !strings.Contains(string(cdBytes), "component-definition") || !strings.Contains(string(cdBytes), "ckodex:container.least-privilege") {
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
}
