package assurance

import (
	"testing"
	"time"
)

// Section 65 Property 1 & Section 87 Acceptance Test: No Evidence
// ASSURED cannot exist with missing mandatory evidence.
// Given control applicable, implementation configured, runtime evidence missing:
// Expected: UNKNOWN, Forbidden: ASSURED / PASS.
func TestProperty_MissingMandatoryEvidenceCannotProduceAssured(t *testing.T) {
	contract := EvidenceContract{
		ID: "contract-property-1",
		Requirements: []EvidenceRequirement{
			{ID: "req-1", EvidenceType: "admission", Required: true},
			{ID: "req-2", EvidenceType: "runtime", Required: true},
		},
		OnMissingRequiredState: AssuranceStateUnknown,
	}

	epoch := AssuranceEpoch{SubjectDigest: "sha256:sub", ImplementationDigest: "sha256:imp"}
	now := time.Now()

	// Only 1 of 2 required evidence items provided
	ev1 := EvidenceEnvelope{
		ObservationType: "admission",
		CapturedAt:      now,
		Epoch:           epoch,
	}

	result := contract.Evaluate([]EvidenceEnvelope{ev1}, epoch, now)
	if result.State == AssuranceStateAssured || result.State == AssuranceStateVerified {
		t.Fatalf("Property violation: Missing mandatory evidence produced %s; expected UNKNOWN", result.State)
	}
	if result.State != AssuranceStateUnknown {
		t.Fatalf("Expected UNKNOWN when mandatory evidence is missing, got %s", result.State)
	}

	// Also check Vector State
	v := NewDefaultAssuranceVector()
	v.Applicability = ValencePositive
	v.Completeness = ValenceUnresolved // missing
	state := v.Resolve(VectorResolutionPolicy{RequireFresh: true})
	if state == AssuranceStateAssured {
		t.Fatalf("Vector State Property violation: unresolved completeness produced ASSURED")
	}
}

// Section 65 Property 2: Expired evidence cannot produce fresh assurance.
func TestProperty_ExpiredEvidenceCannotProduceFreshAssurance(t *testing.T) {
	contract := EvidenceContract{
		ID: "contract-property-2",
		Requirements: []EvidenceRequirement{
			{ID: "req-1", EvidenceType: "runtime", Required: true, MaxAge: 5 * time.Minute},
		},
		OnMissingRequiredState: AssuranceStateUnknown,
	}

	epoch := AssuranceEpoch{SubjectDigest: "sha256:sub"}
	now := time.Now()

	// Evidence is 10 minutes old (exceeds 5m maxAge)
	evExpired := EvidenceEnvelope{
		ObservationType: "runtime",
		CapturedAt:      now.Add(-10 * time.Minute),
		Epoch:           epoch,
	}

	result := contract.Evaluate([]EvidenceEnvelope{evExpired}, epoch, now)
	if result.State == AssuranceStateAssured || result.State == AssuranceStateVerified {
		t.Fatalf("Property violation: Expired evidence produced %s", result.State)
	}
	if result.State != AssuranceStateStale {
		t.Fatalf("Expected STALE when evidence is expired, got %s", result.State)
	}
}

// Section 65 Property 3: Changing policy digest invalidates matching epoch.
func TestProperty_ChangingPolicyDigestInvalidatesEpoch(t *testing.T) {
	epochInitial := AssuranceEpoch{
		SubjectDigest:        "sha256:sub1",
		ImplementationDigest: "sha256:imp1",
		PolicyDigest:         "sha256:policyV1",
		AuthorityDigest:      "sha256:auth1",
		EnvironmentDigest:    "sha256:env1",
	}

	epochUpdatedPolicy := epochInitial
	epochUpdatedPolicy.PolicyDigest = "sha256:policyV2"

	if epochInitial.Matches(epochUpdatedPolicy) {
		t.Fatalf("Property violation: Divergent policy digest matched initial epoch")
	}

	diffs := epochInitial.Diff(epochUpdatedPolicy)
	if len(diffs) != 1 || diffs[0] != DriftPolicy {
		t.Fatalf("Expected DriftPolicy, got %v", diffs)
	}

	contract := EvidenceContract{
		ID: "contract-property-3",
		Requirements: []EvidenceRequirement{
			{ID: "req-1", EvidenceType: "runtime", Required: true},
		},
	}
	now := time.Now()

	// Evidence bound to initial epoch evaluated against updated policy epoch
	ev := EvidenceEnvelope{
		ObservationType: "runtime",
		CapturedAt:      now,
		Epoch:           epochInitial,
	}

	result := contract.Evaluate([]EvidenceEnvelope{ev}, epochUpdatedPolicy, now)
	if result.State == AssuranceStateVerified || result.State == AssuranceStateAssured {
		t.Fatalf("Property violation: Outdated epoch evidence accepted as verified under new policy epoch")
	}
	if result.State != AssuranceStateStale {
		t.Fatalf("Expected STALE on epoch divergence, got %s", result.State)
	}
}

// Section 65 Property 4 & Section 90 Acceptance Test: Expired exception cannot suppress finding.
func TestProperty_ExpiredExceptionCannotSuppressFinding(t *testing.T) {
	now := time.Now()
	sub := SubjectRef{Scheme: "k8s", ID: "prod/payments/Deployment/payments-api"}
	ctrl := ControlRef{Namespace: "ckodex", ID: "container.least-privilege"}

	expiredException := ControlException{
		ID:            "exc-expired",
		Subject:       sub,
		Controls:      []ControlRef{ctrl},
		Justification: "Temporary derogation",
		NotBefore:     now.Add(-48 * time.Hour),
		NotAfter:      now.Add(-1 * time.Hour), // Expired 1 hour ago
	}

	if expiredException.IsValidAt(now) {
		t.Fatalf("Property violation: Expired exception reported as valid")
	}

	// Under expired exception, violation must resolve to FAILED / finding
	fsmState, err := Transition(AssuranceStateAssured, EventViolationConfirmed)
	if err != nil || fsmState != AssuranceStateFailed {
		t.Fatalf("Expected violation transition to FAILED, got %v", fsmState)
	}
}

// Section 65 Property 5: Evidence for subject A cannot satisfy subject B.
func TestProperty_SubjectSubstitutionRejection(t *testing.T) {
	subA := SubjectRef{Scheme: "k8s", ID: "prod/payments/Deployment/payments-api", Attributes: map[string]string{"uid": "uid-A"}}
	subB := SubjectRef{Scheme: "k8s", ID: "prod/auth/Deployment/auth-api", Attributes: map[string]string{"uid": "uid-B"}}
	ctrl := ControlRef{Namespace: "ckodex", ID: "container.least-privilege"}

	exc := ControlException{
		ID:        "exc-A",
		Subject:   subA,
		Controls:  []ControlRef{ctrl},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}

	if exc.AppliesTo(subB, ctrl) {
		t.Fatalf("Property violation: Exception for Subject A applied to Subject B")
	}

	if subA.Digest() == subB.Digest() {
		t.Fatalf("Property violation: Distinct subjects have identical digests")
	}
}

// Section 89 Acceptance Test: Forged Evidence
// Given valid payload but invalid producer authority -> Evidence rejected.
func TestProperty_ForgedProducerAuthorityRejection(t *testing.T) {
	contract := EvidenceContract{
		ID: "contract-auth-gate",
		Requirements: []EvidenceRequirement{
			{
				ID:                "runtime",
				EvidenceType:      "workload.runtime.process",
				Required:          true,
				AcceptedProducers: []string{"spiffe://prod/ns/oskal/sa/tetragon-collector"},
			},
		},
		OnMissingRequiredState: AssuranceStateUnknown,
	}

	epoch := AssuranceEpoch{SubjectDigest: "sha256:sub"}
	now := time.Now()

	// Attacker tries to submit evidence with untrusted SPIFFE ID
	forgedEvidence := EvidenceEnvelope{
		ObservationType: "workload.runtime.process",
		Producer:        AuthorityRef{Scheme: "spiffe", Subject: "untrusted/compromised/sa"},
		CapturedAt:      now,
		Epoch:           epoch,
	}

	result := contract.Evaluate([]EvidenceEnvelope{forgedEvidence}, epoch, now)
	if result.State == AssuranceStateVerified || result.State == AssuranceStateAssured {
		t.Fatalf("Security failure: Forged producer authority produced verified assurance!")
	}
	if len(result.VerifiedEvidences) != 0 {
		t.Fatalf("Security failure: Forged evidence accepted into verified list!")
	}
	if result.State != AssuranceStateUnknown {
		t.Fatalf("Expected UNKNOWN on rejected unauthorized evidence, got %s", result.State)
	}
}

// Section 88 Acceptance Test: Stale Evidence
// Given all evidence verified, then subject generation changes -> STALE immediately.
func TestProperty_SubjectGenerationChangeTriggersStale(t *testing.T) {
	epochGen1 := AssuranceEpoch{
		SubjectDigest: ComputeStringDigest("k8s://prod/payments/Deployment/payments-api:generation:1"),
	}

	epochGen2 := AssuranceEpoch{
		SubjectDigest: ComputeStringDigest("k8s://prod/payments/Deployment/payments-api:generation:2"),
	}

	if epochGen1.Matches(epochGen2) {
		t.Fatalf("Property violation: generation increment did not alter epoch")
	}

	diffs := epochGen1.Diff(epochGen2)
	if len(diffs) != 1 || diffs[0] != DriftSubject {
		t.Fatalf("Expected DriftSubject on generation increment, got %v", diffs)
	}
}
