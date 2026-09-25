package tetragon

import (
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestTetragonObserver_CompliantExecution(t *testing.T) {
	observer := NewTetragonObserver(assurance.AuthorityRef{})
	now := time.Now().UTC()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "payments/payments-api"}
	epoch := assurance.AssuranceEpoch{
		SubjectDigest: assurance.ComputeStringDigest(sub.URI()),
	}

	event := ProcessEvent{
		Binary:        "/usr/local/bin/payments",
		UID:           10001,
		GID:           10001,
		Capabilities:  []string{"CAP_NET_BIND_SERVICE"},
		PodNamespace:  "payments",
		PodName:       "payments-api-1234",
		ContainerName: "payments-api",
	}

	env, finding, err := observer.GenerateProcessEvidence(sub, event, epoch, now)
	if err != nil {
		t.Fatalf("unexpected error generating process evidence: %v", err)
	}
	if finding != nil {
		t.Fatalf("expected nil finding on compliant execution, got: %+v", finding)
	}
	if env.ObservationType != "workload.runtime.process" {
		t.Fatalf("unexpected observation type: %s", env.ObservationType)
	}
	if env.IntegrityDigest == "" {
		t.Fatal("expected non-empty integrity digest")
	}
	if len(env.ControlRefs) != 1 || env.ControlRefs[0].ID != "container.least-privilege" {
		t.Fatalf("unexpected control refs: %+v", env.ControlRefs)
	}
}

func TestTetragonObserver_RootExecutionViolation(t *testing.T) {
	observer := NewTetragonObserver(assurance.AuthorityRef{
		Scheme:  "spiffe",
		Subject: "prod/ns/sec/sa/tetragon",
	})
	now := time.Now().UTC()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "payments/payments-api"}
	epoch := assurance.AssuranceEpoch{
		SubjectDigest: assurance.ComputeStringDigest(sub.URI()),
	}

	event := ProcessEvent{
		Binary:        "/bin/bash",
		UID:           0,
		GID:           0,
		Capabilities:  nil,
		PodNamespace:  "payments",
		PodName:       "payments-api-1234",
		ContainerName: "payments-api",
	}

	_, finding, err := observer.GenerateProcessEvidence(sub, event, epoch, now)
	if err == nil {
		t.Fatal("expected error on root execution event")
	}
	if finding == nil {
		t.Fatal("expected finding on root execution violation")
	}
	if finding.Severity != "CRITICAL" {
		t.Fatalf("expected CRITICAL severity, got: %s", finding.Severity)
	}
}

func TestTetragonObserver_ProhibitedCapabilityViolation(t *testing.T) {
	observer := NewTetragonObserver(assurance.AuthorityRef{})
	now := time.Now().UTC()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "payments/payments-api"}
	epoch := assurance.AssuranceEpoch{
		SubjectDigest: assurance.ComputeStringDigest(sub.URI()),
	}

	for _, capName := range []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN"} {
		event := ProcessEvent{
			Binary:        "/usr/sbin/iptables",
			UID:           1001,
			GID:           1001,
			Capabilities:  []string{capName},
			PodNamespace:  "payments",
			PodName:       "payments-api-1234",
			ContainerName: "payments-api",
		}

		_, finding, err := observer.GenerateProcessEvidence(sub, event, epoch, now)
		if err == nil {
			t.Fatalf("expected error for prohibited capability %s", capName)
		}
		if finding == nil {
			t.Fatalf("expected finding for prohibited capability %s", capName)
		}
		if finding.Severity != "HIGH" {
			t.Fatalf("expected HIGH severity, got: %s", finding.Severity)
		}
	}
}
