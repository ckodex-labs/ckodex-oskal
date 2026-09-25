package cilium

import (
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestCiliumObserver_IsolatedEgress(t *testing.T) {
	observer := NewCiliumObserver(assurance.AuthorityRef{})
	now := time.Now().UTC()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "payments/payments-api"}
	epoch := assurance.AssuranceEpoch{
		SubjectDigest: assurance.ComputeStringDigest(sub.URI()),
	}

	event := NetworkFlowEvent{
		SourcePod:        "payments-api-1234",
		DestinationPod:   "postgres-0",
		DestinationPort:  5432,
		TrafficAllowed:   true,
		EgressIsolated:   true,
		AppliedPolicyRef: "cilium-network-policy:payments-egress",
	}

	env, finding, err := observer.GenerateNetworkEvidence(sub, event, epoch, now)
	if err != nil {
		t.Fatalf("unexpected error generating network evidence: %v", err)
	}
	if finding != nil {
		t.Fatalf("expected nil finding on compliant egress flow, got: %+v", finding)
	}
	if env.ObservationType != "network.flow.isolation" {
		t.Fatalf("unexpected observation type: %s", env.ObservationType)
	}
	if env.IntegrityDigest == "" {
		t.Fatal("expected non-empty integrity digest")
	}
	if len(env.ControlRefs) != 1 || env.ControlRefs[0].ID != "network.isolated" {
		t.Fatalf("unexpected control refs: %+v", env.ControlRefs)
	}
}

func TestCiliumObserver_UnisolatedEgressViolation(t *testing.T) {
	observer := NewCiliumObserver(assurance.AuthorityRef{
		Scheme:  "spiffe",
		Subject: "prod/ns/sec/sa/cilium",
	})
	now := time.Now().UTC()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "payments/unisolated-api"}
	epoch := assurance.AssuranceEpoch{
		SubjectDigest: assurance.ComputeStringDigest(sub.URI()),
	}

	event := NetworkFlowEvent{
		SourcePod:        "unisolated-api-1234",
		DestinationPod:   "evil-host",
		DestinationPort:  80,
		TrafficAllowed:   true,
		EgressIsolated:   false,
		AppliedPolicyRef: "",
	}

	_, finding, err := observer.GenerateNetworkEvidence(sub, event, epoch, now)
	if err == nil {
		t.Fatal("expected error on unisolated egress flow")
	}
	if finding == nil {
		t.Fatal("expected finding for unisolated egress flow violation")
	}
	if finding.Severity != "HIGH" {
		t.Fatalf("expected HIGH severity, got: %s", finding.Severity)
	}
	if finding.Control.ID != "network.isolated" {
		t.Fatalf("expected control network.isolated, got: %s", finding.Control.ID)
	}
}
