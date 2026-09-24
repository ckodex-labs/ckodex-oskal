package shield

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/oskal/core/assurance"
	"github.com/ckodex-labs/oskal/internal/projection/oscal"
)

func TestShieldAIModelAssuranceEvaluation(t *testing.T) {
	observer := NewShieldObserver(assurance.AuthorityRef{
		Scheme:  "spiffe",
		Subject: "prod/ns/shield-system/sa/shield-admission-inspector",
	})
	now := time.Now().UTC()

	// 1. Model Subject Reference
	modelURI := "registry.corp/models/glm-4-chat"
	weightsDigest := "sha256:7f8e9d0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e"
	subject := BuildModelSubjectRef(modelURI, weightsDigest)

	if subject.URI() != "model://registry.corp/models/glm-4-chat@"+weightsDigest {
		t.Fatalf("unexpected model URI: %s", subject.URI())
	}

	epoch := assurance.AssuranceEpoch{
		SubjectDigest:        subject.Digest(),
		ImplementationDigest: assurance.ComputeStringDigest("shield-engine:v2"),
		PolicyDigest:         assurance.ComputeStringDigest("ai-safety-policy:regulated"),
		AuthorityDigest:      assurance.ComputeStringDigest("spiffe://prod/ns/shield-system"),
		EnvironmentDigest:    assurance.ComputeStringDigest("accelerator:nvidia-h100:cuda-12"),
	}

	forensics := ModelForensics{
		ModelURI:      modelURI,
		WeightsDigest: weightsDigest,
		Format:        "safetensors",
		TamperProof:   true,
		AIBOMDigest:   "sha256:aibom_cyclonedx_001",
		SafetyScore:   0.94,
	}

	// 2. Generate SHIELD evidence
	evidences, finding, err := observer.GenerateModelEvidence(subject, forensics, epoch, now)
	if err != nil || finding != nil {
		t.Fatalf("failed to generate model evidence: %v", err)
	}

	if len(evidences) != 2 {
		t.Fatalf("expected 2 evidence envelopes, got %d", len(evidences))
	}

	// 3. Milestone 14 Verification:
	// Evaluate with the exact same Technology-Neutral Assurance Core and Evidence Contract!
	aiContract := assurance.EvidenceContract{
		ID:   "ai-model-trust-contract",
		Name: "AI Model Forensics & Provenance Contract",
		Requirements: []assurance.EvidenceRequirement{
			{
				ID:                "weights-forensics",
				EvidenceType:      "model.weights.forensics",
				Required:          true,
				MaxAge:            72 * time.Hour,
				AcceptedProducers: []string{"spiffe://prod/ns/shield-system/sa/shield-admission-inspector"},
			},
			{
				ID:                "aibom-provenance",
				EvidenceType:      "model.aibom",
				Required:          true,
				MaxAge:            72 * time.Hour,
				AcceptedProducers: []string{"spiffe://prod/ns/shield-system/sa/shield-admission-inspector"},
			},
		},
		OnMissingRequiredState: assurance.AssuranceStateUnknown,
	}

	evalResult := aiContract.Evaluate(evidences, epoch, now)
	if evalResult.State != assurance.AssuranceStateVerified {
		t.Fatalf("M14 Failure: AI model evaluation expected VERIFIED, got %s (%s)",
			evalResult.State, evalResult.Completeness.Summary())
	}

	// 4. Project into standard NIST OSCAL v1.2.3 Assessment Results!
	eval := assurance.ClaimEvaluation{
		ID:           "ai-eval-01",
		Subject:      subject,
		Control:      assurance.ControlRef{Namespace: "ckodex", ID: "ai.weight.integrity"},
		State:        assurance.AssuranceStateAssured,
		Epoch:        epoch,
		Evidence:     []assurance.EvidenceRef{evidences[0].Artifact, evidences[1].Artifact},
		Completeness: evalResult.Completeness,
		EvidenceRoot: "sha256:aiEvidenceRoot",
		EvaluatedAt:  now,
		ValidUntil:   now.Add(24 * time.Hour),
	}

	projector := oscal.NewProjector()
	oscalData, err := projector.ProjectAssessmentResults(context.Background(), subject, []assurance.ClaimEvaluation{eval}, nil)
	if err != nil {
		t.Fatalf("failed to project AI model assessment into OSCAL: %v", err)
	}

	if !strings.Contains(string(oscalData), subject.URI()) || !strings.Contains(string(oscalData), "ai.weight.integrity") {
		t.Fatalf("projected OSCAL does not contain AI model claim information")
	}

	// 5. Test Tampering Detection
	tamperedForensics := forensics
	tamperedForensics.TamperProof = false
	_, tamperFinding, err := observer.GenerateModelEvidence(subject, tamperedForensics, epoch, now)
	if err == nil || tamperFinding == nil {
		t.Fatalf("expected tamper violation to be detected")
	}
	if tamperFinding.Severity != "CRITICAL" {
		t.Fatalf("expected CRITICAL severity for weight tampering, got %s", tamperFinding.Severity)
	}
}

func TestAgentSubjectConstruction(t *testing.T) {
	agentSub := BuildAgentSubjectRef("research-agent", "v3", "sha256:prompt123")
	if agentSub.URI() != "agent://research-agent:v3" {
		t.Fatalf("unexpected agent URI: %s", agentSub.URI())
	}
	if agentSub.Attributes["type"] != "autonomous-agent" {
		t.Fatalf("expected autonomous-agent type, got %s", agentSub.Attributes["type"])
	}
}
