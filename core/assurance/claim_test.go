package assurance

import (
	"strings"
	"testing"
	"time"
)

func TestControlExceptionValidity(t *testing.T) {
	now := time.Now()
	sub := SubjectRef{Scheme: "k8s", ID: "prod/payments/Deployment/payments-api"}
	ctrl := ControlRef{Namespace: "ckodex", ID: "container.least-privilege"}

	exc := ControlException{
		ID:            "exc-01",
		Subject:       sub,
		Controls:      []ControlRef{ctrl},
		Justification: "Migration risk approved",
		RequiredApprovers: []AuthorityRef{
			{Scheme: "spiffe", Subject: "corp/security/platform"},
		},
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
		CompensatingControls: []ControlRef{
			{Namespace: "ckodex", ID: "network.isolated"},
		},
	}

	// Active within validity window
	if !exc.IsValidAt(now) {
		t.Fatalf("expected exception to be valid at current time")
	}

	// Before window
	if exc.IsValidAt(now.Add(-2 * time.Hour)) {
		t.Fatalf("expected exception to be invalid before NotBefore")
	}

	// After expiry
	if exc.IsValidAt(now.Add(48 * time.Hour)) {
		t.Fatalf("expected exception to be invalid after NotAfter")
	}

	// Invariant I-05: Unbounded exception with zero times must be invalid
	excUnbounded := exc
	excUnbounded.NotAfter = time.Time{}
	if excUnbounded.IsValidAt(now) {
		t.Fatalf("expected unbounded exception (zero NotAfter) to be invalid")
	}

	// Scope match
	if !exc.AppliesTo(sub, ctrl) {
		t.Fatalf("expected exception to apply to matching subject and control")
	}

	otherSub := SubjectRef{Scheme: "k8s", ID: "prod/other/Deployment/other-api"}
	if exc.AppliesTo(otherSub, ctrl) {
		t.Fatalf("exception must not apply to different subject")
	}
}

func TestControlReceiptCanonicalBytesAndDigest(t *testing.T) {
	sub := SubjectRef{Scheme: "k8s", ID: "prod/payments/Deployment/payments-api"}
	ctrl := ControlRef{Namespace: "ckodex", ID: "container.least-privilege"}
	epoch := AssuranceEpoch{
		SubjectDigest:        "sha256:sub",
		ImplementationDigest: "sha256:imp",
		PolicyDigest:         "sha256:pol",
		AuthorityDigest:      "sha256:auth",
		EnvironmentDigest:    "sha256:env",
	}

	receipt := ControlReceipt{
		Subject:      sub,
		Control:      ctrl,
		State:        AssuranceStateAssured,
		Epoch:        epoch,
		EvidenceRoot: "sha256:root12345",
		Evaluator:    AuthorityRef{Scheme: "spiffe", Subject: "prod/ns/oskal/sa/evaluator"},
		EvaluatedAt:  time.Unix(1790200000, 0),
	}

	b1 := receipt.CanonicalBytes()
	b2 := receipt.CanonicalBytes()
	if string(b1) != string(b2) {
		t.Fatalf("expected deterministic canonical receipt bytes")
	}

	d1 := receipt.Digest()
	d2 := receipt.Digest()
	if d1 != d2 || !strings.HasPrefix(d1, "sha256:") {
		t.Fatalf("expected deterministic receipt digest with sha256 prefix: %s", d1)
	}
}

func TestExplainGraphRendering(t *testing.T) {
	sub := SubjectRef{Scheme: "k8s", ID: "prod/payments/Deployment/payments-api"}
	ctrl := ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
	epoch := AssuranceEpoch{
		SubjectDigest:        "sha256:sub",
		ImplementationDigest: "sha256:imp",
		PolicyDigest:         "sha256:pol",
		AuthorityDigest:      "sha256:auth",
		EnvironmentDigest:    "sha256:env",
	}

	graph := ExplainGraph{
		Subject:          sub,
		Control:          ctrl,
		CanonicalControl: "ckodex:least-privilege",
		Applicability:    "applicable",
		AtomicRequirements: []ExplainAtomicRequirement{
			{ID: "non-root execution", Satisfied: true},
			{ID: "capability restriction", Satisfied: true},
			{ID: "workload identity", Satisfied: true},
		},
		Implementations: []ExplainImplementation{
			{Requirement: "non-root", Provider: "kubernetes ValidatingAdmissionPolicy", Digest: "sha256:cel123"},
			{Requirement: "identity", Provider: "SPIFFE/SPIRE", Digest: "sha256:spire456"},
		},
		Evidence: []ExplainEvidenceItem{
			{Type: "admission decision", Verified: true},
			{Type: "workload identity", Verified: true},
			{Type: "runtime process observation", Verified: true},
		},
		Completeness: EvidenceCompleteness{
			Required: 3,
			Present:  3,
			Verified: 3,
		},
		Freshness:      "current",
		Authority:      "verified",
		Epoch:          epoch,
		AssuranceState: AssuranceStateAssured,
		EvidenceRoot:   "sha256:merkle999",
		Projections: map[string]string{
			"Component Definition": "AC-6 implemented-requirement",
			"Assessment Results":   "3 observations, 0 findings",
		},
	}

	rendered := graph.RenderText()

	// Verify key sections from Section 51
	expectedSections := []string{
		"SUBJECT\nk8s://prod/payments/Deployment/payments-api",
		"CONTROL\nnist-sp-800-53:AC-6",
		"CANONICAL CONTROL\nckodex:least-privilege",
		"APPLICABILITY\n✓ applicable",
		"ATOMIC REQUIREMENTS",
		"✓ non-root execution",
		"IMPLEMENTATIONS",
		"kubernetes ValidatingAdmissionPolicy",
		"EVIDENCE",
		"✓ admission decision",
		"COMPLETENESS\n3 / 3 required",
		"FRESHNESS\ncurrent",
		"AUTHORITY\nverified",
		"ASSURANCE\nASSURED",
		"EVIDENCE ROOT\nsha256:merkle999",
	}

	for _, sec := range expectedSections {
		if !strings.Contains(rendered, sec) {
			t.Errorf("missing expected text in render:\n%s\n--- Full Output ---\n%s", sec, rendered)
		}
	}
}
