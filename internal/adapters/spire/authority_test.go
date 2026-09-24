package spire

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/oskal/core/assurance"
)

func TestSpireAuthorityAuthenticationAndAuthorization(t *testing.T) {
	resolver := NewSpireAuthorityResolver(nil)
	ctx := context.Background()

	// 1. Valid producer with valid evidence type -> Accepted
	validTetragon := assurance.AuthorityRef{
		Scheme:      "spiffe",
		Subject:     "prod/ns/ckodex-evidence/sa/tetragon-collector",
		TrustDomain: "prod",
	}
	authorized, err := resolver.IsAuthorizedProducer(ctx, validTetragon, "workload.runtime.process")
	if err != nil || !authorized {
		t.Fatalf("expected valid tetragon collector to be authorized for runtime process: %v", err)
	}

	// 2. Valid producer with wrong evidence authority -> Rejected (Exit criteria 2)
	// Tetragon cannot assert supply-chain signatures!
	authorizedWrongType, err := resolver.IsAuthorizedProducer(ctx, validTetragon, "supply-chain.signature")
	if authorizedWrongType || err == nil {
		t.Fatalf("M6 Exit Failure: Tetragon collector incorrectly authorized to assert supply-chain.signature")
	}

	// 3. Unauthorized producer identity -> Rejected (Exit criteria 1)
	unauthorizedProducer := assurance.AuthorityRef{
		Scheme:      "spiffe",
		Subject:     "prod/ns/compromised/sa/malicious-agent",
		TrustDomain: "prod",
	}
	authorizedMalicious, err := resolver.IsAuthorizedProducer(ctx, unauthorizedProducer, "workload.runtime.process")
	if authorizedMalicious || err == nil {
		t.Fatalf("M6 Exit Failure: Malicious producer unexpectedly authorized")
	}

	// 4. Untrusted trust domain -> Rejected
	foreignTrustDomain := assurance.AuthorityRef{
		Scheme:      "spiffe",
		Subject:     "external-corp/ns/attacker/sa/pwn",
		TrustDomain: "external-corp",
	}
	authorizedForeign, err := resolver.IsAuthorizedProducer(ctx, foreignTrustDomain, "workload.runtime.process")
	if authorizedForeign || err == nil {
		t.Fatalf("M6 Exit Failure: Foreign untrusted trust domain authorized")
	}

	// 5. Identity appears in Explain Graph (Exit criteria 4)
	graph := assurance.ExplainGraph{
		Subject:          assurance.SubjectRef{Scheme: "k8s", ID: "payments/payments-api"},
		Control:          assurance.ControlRef{Namespace: "ckodex", ID: "container.least-privilege"},
		CanonicalControl: "ckodex:least-privilege",
		Applicability:    "applicable",
		Evidence: []assurance.ExplainEvidenceItem{
			{
				Type:       "workload.runtime.process",
				CapturedAt: time.Now(),
				Producer:   validTetragon.Canonical(),
				Digest:     "sha256:tetragon123",
				Verified:   true,
			},
		},
		Completeness:   assurance.EvidenceCompleteness{Required: 1, Verified: 1},
		Freshness:      "current",
		Authority:      "verified (" + validTetragon.Canonical() + ")",
		AssuranceState: assurance.AssuranceStateAssured,
		EvidenceRoot:   "sha256:root",
	}

	rendered := graph.RenderText()
	if !strings.Contains(rendered, validTetragon.Canonical()) {
		t.Fatalf("M6 Exit Failure: Producer SPIFFE identity does not appear in Explain Graph render:\n%s", rendered)
	}
}
