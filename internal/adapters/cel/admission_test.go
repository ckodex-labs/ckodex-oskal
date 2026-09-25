package cel

import (
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestNativeCELAdmissionEvidenceSatisfiesContract(t *testing.T) {
	observerID := assurance.AuthorityRef{
		Scheme:      "spiffe",
		Subject:     "prod/ns/ckodex-assurance/sa/cel-admission-observer",
		TrustDomain: "prod",
	}

	observer := NewAdmissionObserver(observerID)
	policy := SampleRestrictedContainerPolicy()

	sub := assurance.SubjectRef{
		Scheme: "k8s",
		ID:     "payments/payments-api/Deployment/payments-api",
		Attributes: map[string]string{
			"namespace": "payments",
			"name":      "payments-api",
		},
	}

	policyDigest := ComputePolicyDigest(policy)
	if policyDigest == "" {
		t.Fatalf("expected non-empty policy digest")
	}

	epoch := assurance.AssuranceEpoch{
		SubjectDigest:        assurance.ComputeStringDigest(sub.URI()),
		ImplementationDigest: assurance.ComputeStringDigest("kubernetes:validating-admission-policy"),
		PolicyDigest:         policyDigest,
		AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/cel-admission"),
		EnvironmentDigest:    assurance.ComputeStringDigest("cluster:local"),
	}

	now := time.Now()

	// Generate verified admission evidence envelope
	envelope, err := observer.GenerateAdmissionEvidence(sub, policy, true, epoch, now)
	if err != nil {
		t.Fatalf("failed to generate admission evidence: %v", err)
	}

	if envelope.ObservationType != "kubernetes.admission" {
		t.Fatalf("expected observation type kubernetes.admission, got %s", envelope.ObservationType)
	}

	// Milestone 5 Exit Criteria:
	// Native Kubernetes admission evidence can satisfy an EvidenceContract.
	contract := assurance.EvidenceContract{
		ID:   "admission-contract",
		Name: "CEL Admission Verification",
		Requirements: []assurance.EvidenceRequirement{
			{
				ID:                "admission-check",
				EvidenceType:      "kubernetes.admission",
				Required:          true,
				MaxAge:            5 * time.Minute,
				AcceptedProducers: []string{"spiffe://prod/ns/ckodex-assurance/sa/cel-admission-observer"},
			},
		},
		OnMissingRequiredState: assurance.AssuranceStateUnknown,
	}

	result := contract.Evaluate([]assurance.EvidenceEnvelope{envelope}, epoch, now)
	if result.State != assurance.AssuranceStateVerified {
		t.Fatalf("M5 Exit Failure: Expected admission evidence to satisfy contract with state VERIFIED, got %s (completeness: %s)",
			result.State, result.Completeness.Summary())
	}

	if !result.Completeness.IsComplete() {
		t.Fatalf("expected completeness to be complete: %s", result.Completeness.Summary())
	}
}

func TestDeniedAdmissionCannotGenerateEvidence(t *testing.T) {
	observer := NewAdmissionObserver(assurance.AuthorityRef{})
	policy := SampleRestrictedContainerPolicy()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "payments/insecure-pod"}
	epoch := assurance.AssuranceEpoch{}

	_, err := observer.GenerateAdmissionEvidence(sub, policy, false, epoch, time.Now())
	if err == nil {
		t.Fatalf("expected error generating evidence for denied admission")
	}
}
