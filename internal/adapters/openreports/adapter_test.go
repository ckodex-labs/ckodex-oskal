package openreports

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ckodex-labs/oskal/core/assurance"
)

func TestOpenReportsIngestionAndNormalization(t *testing.T) {
	adapter := NewAdapter(assurance.AuthorityRef{
		Scheme:  "spiffe",
		Subject: "prod/ns/ckodex-evidence/sa/openreports-normalizer",
	})

	now := time.Now().UTC()
	epoch := assurance.AssuranceEpoch{
		SubjectDigest: "sha256:sub",
	}

	report := OpenReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "payments-api-scan",
			Namespace: "payments",
		},
		Spec: OpenReportSpec{
			Subject: OpenReportSubject{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Namespace:  "payments",
				Name:       "payments-api",
				UID:        "uid-998877",
			},
			Findings: []OpenReportFinding{
				{
					Rule:      "disallow-privileged-containers",
					Source:    "kyverno",
					Result:    "pass",
					Severity:  "high",
					Message:   "Workload passes privileged container restriction",
					Timestamp: now,
				},
				{
					Rule:      "CVE-2026-1029",
					Source:    "trivy",
					Result:    "fail",
					Severity:  "critical",
					Message:   "Remote code execution in openssl dependency",
					Timestamp: now,
				},
				{
					Rule:      "cis-k8s-4.2.6",
					Source:    "kube-bench",
					Result:    "pass",
					Severity:  "medium",
					Message:   "Ensure root filesystem is read-only",
					Timestamp: now,
				},
			},
		},
	}

	// Milestone 9 Exit Criteria:
	// OpenReports result becomes normalized observation without leaking provider-specific types into Assurance Core.
	obs, findings, envelopes := adapter.IngestReport(report, epoch, now)

	// 1. Check Observations count & normalization
	if len(obs) != 3 {
		t.Fatalf("expected 3 normalized observations, got %d", len(obs))
	}
	for _, o := range obs {
		if o.Subject.URI() != "k8s://payments/Deployment/payments-api" {
			t.Fatalf("unexpected subject URI on observation: %s", o.Subject.URI())
		}
		if len(o.Evidence) != 1 {
			t.Fatalf("expected 1 evidence ref per observation")
		}
	}

	// 2. Check Findings (Trivy CVE failure)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for failed rule, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != "CRITICAL" {
		t.Fatalf("expected normalized CRITICAL severity, got %s", f.Severity)
	}
	if f.Control.ID != "CVE-2026-1029" {
		t.Fatalf("expected control ID CVE-2026-1029, got %s", f.Control.ID)
	}
	if f.Control.Namespace != "external-scanner" {
		t.Fatalf("expected namespace external-scanner, got %s", f.Control.Namespace)
	}

	// 3. Check Evidence Envelopes for Passing Rules (Kyverno + Kube-bench)
	if len(envelopes) != 2 {
		t.Fatalf("expected 2 evidence envelopes for passing rules, got %d", len(envelopes))
	}
	if envelopes[0].ObservationType != "scanner.kyverno" {
		t.Fatalf("expected observation type scanner.kyverno, got %s", envelopes[0].ObservationType)
	}
	if envelopes[1].ObservationType != "scanner.kube-bench" {
		t.Fatalf("expected observation type scanner.kube-bench, got %s", envelopes[1].ObservationType)
	}

	// 4. Verify evidence contract evaluates normalized envelopes cleanly
	contract := assurance.EvidenceContract{
		ID:   "scanner-contract",
		Name: "External Scanner Contract",
		Requirements: []assurance.EvidenceRequirement{
			{
				ID:           "kyverno-pass",
				EvidenceType: "scanner.kyverno",
				Required:     true,
			},
		},
	}
	contractRes := contract.Evaluate(envelopes, epoch, now)
	if contractRes.State != assurance.AssuranceStateVerified {
		t.Fatalf("expected normalized scanner evidence to satisfy contract: state=%s", contractRes.State)
	}
}
