package airgap

import (
	"context"
	"testing"
	"time"

	"github.com/ckodex-labs/oskal/core/assurance"
	"github.com/ckodex-labs/oskal/internal/adapters/cel"
	"github.com/ckodex-labs/oskal/internal/projection/oscal"
	"github.com/ckodex-labs/oskal/internal/receipts"
)

// Section 92 Acceptance Test: Air Gap
// Verifies full offline continuous assurance without external network access.
func TestAirGapAcceptanceWithoutPublicNetwork(t *testing.T) {
	now := time.Now().UTC()

	// 1. Local Subject
	sub := assurance.SubjectRef{
		Scheme: "k8s",
		ID:     "airgap-cluster/secure-zone/Deployment/isolated-workload",
		Attributes: map[string]string{
			"zone":      "airgap",
			"namespace": "secure-zone",
			"name":      "isolated-workload",
		},
	}

	// 2. Local Policy & Admission (CEL in-process, no webhook or SaaS egress)
	policy := cel.SampleRestrictedContainerPolicy()
	policyDigest := cel.ComputePolicyDigest(policy)

	epoch := assurance.AssuranceEpoch{
		SubjectDigest:        assurance.ComputeStringDigest(sub.URI()),
		ImplementationDigest: assurance.ComputeStringDigest("local-cel-engine:v1"),
		PolicyDigest:         policyDigest,
		AuthorityDigest:      assurance.ComputeStringDigest("spiffe://airgap-pki/root-ca"),
		EnvironmentDigest:    assurance.ComputeStringDigest("k8s:local:v1.31"),
	}

	// 3. Local SPIFFE Authority
	localAuthority := assurance.AuthorityRef{
		Scheme:      "spiffe",
		Subject:     "airgap-pki/ns/oskal/sa/airgap-observer",
		TrustDomain: "airgap-pki",
	}

	observer := cel.NewAdmissionObserver(localAuthority)
	evidence, err := observer.GenerateAdmissionEvidence(sub, policy, true, epoch, now)
	if err != nil {
		t.Fatalf("local admission evidence generation failed: %v", err)
	}

	// 4. Local Evidence Contract Evaluation
	contract := assurance.EvidenceContract{
		ID:   "airgap-least-privilege",
		Name: "Air-gap Verification Contract",
		Requirements: []assurance.EvidenceRequirement{
			{
				ID:                "admission",
				EvidenceType:      "kubernetes.admission",
				Required:          true,
				MaxAge:            10 * time.Minute,
				AcceptedProducers: []string{"spiffe://airgap-pki/ns/oskal/sa/airgap-observer"},
			},
		},
		OnMissingRequiredState: assurance.AssuranceStateUnknown,
	}

	contractResult := contract.Evaluate([]assurance.EvidenceEnvelope{evidence}, epoch, now)
	if contractResult.State != assurance.AssuranceStateVerified {
		t.Fatalf("Air-gap acceptance failure: Expected state VERIFIED, got %s", contractResult.State)
	}

	// 5. Local Cryptographic Receipt Signing (Offline Ed25519)
	receiptMgr, err := receipts.NewReceiptManager(localAuthority)
	if err != nil {
		t.Fatalf("failed to create local receipt manager: %v", err)
	}

	ctrl := assurance.ControlRef{Namespace: "ckodex", ID: "container.least-privilege"}
	receipt, err := receiptMgr.IssueReceipt(sub, ctrl, assurance.AssuranceStateAssured, epoch, []assurance.EvidenceRef{evidence.Artifact}, now)
	if err != nil {
		t.Fatalf("failed to sign local receipt: %v", err)
	}

	// Independent local verification
	valid, err := receipts.VerifyIndependentReceipt(receipt, receiptMgr.PublicKey())
	if err != nil || !valid {
		t.Fatalf("failed to verify local receipt: %v", err)
	}

	// 6. Local XOSCAL Projection & OSCAL Export
	eval := assurance.ClaimEvaluation{
		ID:           "airgap-eval-01",
		Subject:      sub,
		Control:      ctrl,
		State:        assurance.AssuranceStateAssured,
		Epoch:        epoch,
		Evidence:     []assurance.EvidenceRef{evidence.Artifact},
		Completeness: contractResult.Completeness,
		EvidenceRoot: receipt.EvidenceRoot,
		EvaluatedAt:  now,
		ValidUntil:   now.Add(10 * time.Minute),
	}

	projector := oscal.NewProjector()
	oscalJSON, err := projector.ProjectAssessmentResults(context.Background(), sub, []assurance.ClaimEvaluation{eval}, nil)
	if err != nil {
		t.Fatalf("failed to project local OSCAL assessment results: %v", err)
	}

	if len(oscalJSON) == 0 {
		t.Fatalf("OSCAL export yielded empty bytes")
	}

	t.Logf("Air-gap acceptance test successful: Complete lifecycle executed without external dependencies.")
}
