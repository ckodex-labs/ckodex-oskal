package contract

import (
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/cel"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/cilium"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragon"
)

func TestDeclarativeAndRuntimeEvidenceComposeIntoOneClaim(t *testing.T) {
	now := time.Now()
	sub := assurance.SubjectRef{
		Scheme: "k8s",
		ID:     "payments/payments-api/Deployment/payments-api",
		Attributes: map[string]string{
			"namespace": "payments",
			"name":      "payments-api",
		},
	}

	policy := cel.SampleRestrictedContainerPolicy()
	policyDigest := cel.ComputePolicyDigest(policy)

	epoch := assurance.AssuranceEpoch{
		SubjectDigest:        "sha256:sub",
		ImplementationDigest: "sha256:imp",
		PolicyDigest:         policyDigest,
		AuthorityDigest:      "sha256:auth",
		EnvironmentDigest:    "sha256:env",
	}

	// 1. Declarative Evidence from CEL Admission
	admissionObserver := cel.NewAdmissionObserver(assurance.AuthorityRef{
		Scheme:  "spiffe",
		Subject: "prod/ns/ckodex-assurance/sa/cel-admission-observer",
	})
	admissionEnv, err := admissionObserver.GenerateAdmissionEvidence(sub, policy, true, epoch, now)
	if err != nil {
		t.Fatalf("failed to generate admission evidence: %v", err)
	}

	// 2. Runtime Evidence from Tetragon
	tetragonObserver := tetragon.NewTetragonObserver(assurance.AuthorityRef{
		Scheme:  "spiffe",
		Subject: "prod/ns/ckodex-evidence/sa/tetragon-collector",
	})
	normalProcEvent := tetragon.ProcessEvent{
		Binary:        "/usr/local/bin/payments-api",
		UID:           10001, // Non-root
		Capabilities:  []string{"CAP_NET_BIND_SERVICE"},
		ContainerName: "api",
	}
	runtimeEnv, finding, err := tetragonObserver.GenerateProcessEvidence(sub, normalProcEvent, epoch, now)
	if err != nil || finding != nil {
		t.Fatalf("failed to generate runtime process evidence: %v", err)
	}

	// 3. Network Isolation Evidence from Cilium
	ciliumObserver := cilium.NewCiliumObserver(assurance.AuthorityRef{
		Scheme:  "spiffe",
		Subject: "prod/ns/ckodex-evidence/sa/cilium-collector",
	})
	flowEvent := cilium.NetworkFlowEvent{
		SourcePod:        "payments-api",
		DestinationPod:   "db",
		EgressIsolated:   true,
		AppliedPolicyRef: "cilium-network-policy/restrict-payments",
	}
	networkEnv, findingNet, err := ciliumObserver.GenerateNetworkEvidence(sub, flowEvent, epoch, now)
	if err != nil || findingNet != nil {
		t.Fatalf("failed to generate network evidence: %v", err)
	}

	// Milestone 8 Exit Criteria:
	// Declarative + runtime evidence can compose into one claim.
	compositeContract := assurance.EvidenceContract{
		ID:   "workload-least-privilege-composite",
		Name: "Composite Least Privilege Contract",
		Requirements: []assurance.EvidenceRequirement{
			{
				ID:                "admission",
				EvidenceType:      "kubernetes.admission",
				Required:          true,
				MaxAge:            5 * time.Minute,
				AcceptedProducers: []string{"spiffe://prod/ns/ckodex-assurance/sa/cel-admission-observer"},
			},
			{
				ID:                "runtime",
				EvidenceType:      "workload.runtime.process",
				Required:          true,
				MaxAge:            5 * time.Minute,
				AcceptedProducers: []string{"spiffe://prod/ns/ckodex-evidence/sa/tetragon-collector"},
			},
			{
				ID:                "network",
				EvidenceType:      "network.flow.isolation",
				Required:          true,
				MaxAge:            5 * time.Minute,
				AcceptedProducers: []string{"spiffe://prod/ns/ckodex-evidence/sa/cilium-collector"},
			},
		},
		OnMissingRequiredState: assurance.AssuranceStateUnknown,
	}

	allEvidences := []assurance.EvidenceEnvelope{admissionEnv, runtimeEnv, networkEnv}

	evalResult := compositeContract.Evaluate(allEvidences, epoch, now)
	if evalResult.State != assurance.AssuranceStateVerified {
		t.Fatalf("M8 Exit Failure: Composite evaluation expected VERIFIED, got %s (summary: %s)",
			evalResult.State, evalResult.Completeness.Summary())
	}

	if !evalResult.Completeness.IsComplete() || evalResult.Completeness.Verified != 3 {
		t.Fatalf("expected all 3 requirements to be satisfied, got %s", evalResult.Completeness.Summary())
	}

	// Transition to ASSURED
	assuredState, err := assurance.Transition(evalResult.State, assurance.EventPolicyAssured)
	if err != nil || assuredState != assurance.AssuranceStateAssured {
		t.Fatalf("expected transition to ASSURED: %v", err)
	}

	// Section 86 Canonical Scenario Part 2:
	// Tetragon observes prohibited capability -> FAILED!
	violationEvent := tetragon.ProcessEvent{
		Binary:        "/bin/sh",
		UID:           0, // Root violation!
		Capabilities:  []string{"CAP_SYS_ADMIN"},
		ContainerName: "api",
	}

	_, rootFinding, err := tetragonObserver.GenerateProcessEvidence(sub, violationEvent, epoch, now)
	if err == nil || rootFinding == nil {
		t.Fatalf("expected root process violation finding to be produced")
	}

	failedState, err := assurance.Transition(assuredState, assurance.EventViolationConfirmed)
	if err != nil || failedState != assurance.AssuranceStateFailed {
		t.Fatalf("expected confirmed violation to transition state from ASSURED to FAILED, got %s", failedState)
	}
}
