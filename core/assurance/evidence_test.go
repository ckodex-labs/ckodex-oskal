package assurance

import (
	"testing"
	"time"
)

func TestSubjectRefURIAndDigest(t *testing.T) {
	sub := SubjectRef{
		Scheme: "k8s",
		ID:     "prod/payments/Deployment/payments-api",
		Attributes: map[string]string{
			"uid":             "uid-12345",
			"generation":      "3",
			"resourceVersion": "987654",
		},
	}

	if sub.URI() != "k8s://prod/payments/Deployment/payments-api" {
		t.Fatalf("unexpected URI: %s", sub.URI())
	}

	d1 := sub.Digest()
	d2 := sub.Digest()
	if d1 != d2 {
		t.Fatalf("expected deterministic digest")
	}

	sub2 := sub
	sub2.Attributes = map[string]string{
		"resourceVersion": "987654",
		"uid":             "uid-12345",
		"generation":      "3",
	}
	if sub2.Digest() != d1 {
		t.Fatalf("expected identical digest regardless of attribute map ordering")
	}
}

func TestControlRefCanonical(t *testing.T) {
	c1 := ControlRef{Namespace: "ckodex", ID: "container.least-privilege"}
	if c1.Canonical() != "ckodex:container.least-privilege" {
		t.Fatalf("expected ckodex:container.least-privilege, got %s", c1.Canonical())
	}

	c2 := ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6", Version: "rev5"}
	if c2.Canonical() != "nist-sp-800-53:AC-6@rev5" {
		t.Fatalf("expected nist-sp-800-53:AC-6@rev5, got %s", c2.Canonical())
	}
}

func TestEvidenceRequirementFreshnessAndProducer(t *testing.T) {
	req := EvidenceRequirement{
		ID:           "admission",
		EvidenceType: "kubernetes.admission",
		Required:     true,
		MaxAge:       5 * time.Minute,
		AcceptedProducers: []string{
			"spiffe://prod/ns/oskal/sa/admission-observer",
			"spiffe://prod/ns/oskal/sa/root-*",
		},
	}

	now := time.Now()

	// 2 minutes old -> fresh
	if !req.IsFresh(now.Add(-2*time.Minute), now) {
		t.Fatalf("expected 2-minute-old evidence to be fresh for 5m maxAge")
	}

	// 10 minutes old -> stale
	if req.IsFresh(now.Add(-10*time.Minute), now) {
		t.Fatalf("expected 10-minute-old evidence to be stale for 5m maxAge")
	}

	// Future timestamp -> invalid
	if req.IsFresh(now.Add(1*time.Minute), now) {
		t.Fatalf("expected future timestamp to be rejected as not fresh")
	}

	// Producer authorization
	if !req.IsProducerAccepted("spiffe://prod/ns/oskal/sa/admission-observer") {
		t.Fatalf("expected exact producer match to be accepted")
	}
	if !req.IsProducerAccepted("spiffe://prod/ns/oskal/sa/root-ca") {
		t.Fatalf("expected wildcard producer match to be accepted")
	}
	if req.IsProducerAccepted("spiffe://untrusted/attacker") {
		t.Fatalf("expected untrusted producer to be rejected")
	}
}

func TestEvidenceContractEvaluation(t *testing.T) {
	now := time.Now()
	epoch := AssuranceEpoch{
		SubjectDigest:        ComputeStringDigest("workload://payments-api"),
		ImplementationDigest: ComputeStringDigest("kubernetes:workload-specification"),
		PolicyDigest:         ComputeStringDigest("policy:restricted-containers"),
		AuthorityDigest:      ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
		EnvironmentDigest:    ComputeStringDigest("cluster:local"),
	}

	contract := EvidenceContract{
		ID:   "workload-least-privilege",
		Name: "Least Privilege Contract",
		Requirements: []EvidenceRequirement{
			{
				ID:                "admission",
				EvidenceType:      "kubernetes.admission",
				Required:          true,
				MaxAge:            5 * time.Minute,
				AcceptedProducers: []string{"spiffe://prod/ns/oskal/sa/admission-observer"},
			},
			{
				ID:                "runtime",
				EvidenceType:      "workload.runtime.process",
				Required:          true,
				MaxAge:            5 * time.Minute,
				AcceptedProducers: []string{"spiffe://prod/ns/oskal/sa/tetragon-collector"},
			},
		},
		OnMissingRequiredState: AssuranceStateUnknown,
	}

	sub := SubjectRef{Scheme: "k8s", ID: "prod/payments/Deployment/payments-api"}

	evAdmission := EvidenceEnvelope{
		Schema:          "assurance.ckodex.io/evidence/v1alpha1",
		ID:              "ev-01",
		Subject:         sub,
		ObservationType: "kubernetes.admission",
		CapturedAt:      now.Add(-1 * time.Minute),
		Producer:        AuthorityRef{Scheme: "spiffe", Subject: "prod/ns/oskal/sa/admission-observer"},
		Artifact:        EvidenceRef{URI: "s3://evidence/ev-01", Digest: ComputeStringDigest("ev-01-artifact"), MediaType: "application/json"},
		IntegrityDigest: ComputeStringDigest("int-01"),
		Epoch:           epoch,
	}

	evRuntime := EvidenceEnvelope{
		Schema:          "assurance.ckodex.io/evidence/v1alpha1",
		ID:              "ev-02",
		Subject:         sub,
		ObservationType: "workload.runtime.process",
		CapturedAt:      now.Add(-2 * time.Minute),
		Producer:        AuthorityRef{Scheme: "spiffe", Subject: "prod/ns/oskal/sa/tetragon-collector"},
		Artifact:        EvidenceRef{URI: "s3://evidence/ev-02", Digest: ComputeStringDigest("ev-02-artifact"), MediaType: "application/json"},
		IntegrityDigest: ComputeStringDigest("int-02"),
		Epoch:           epoch,
	}

	// 1. Both present and fresh -> Verified
	res := contract.Evaluate([]EvidenceEnvelope{evAdmission, evRuntime}, epoch, now)
	if res.State != AssuranceStateVerified {
		t.Fatalf("expected state VERIFIED, got %s (summary: %s)", res.State, res.Completeness.Summary())
	}
	if !res.Completeness.IsComplete() {
		t.Fatalf("expected completeness to be complete: %s", res.Completeness.Summary())
	}

	// 2. Runtime evidence missing -> UNKNOWN (Invariant I-02)
	resMissing := contract.Evaluate([]EvidenceEnvelope{evAdmission}, epoch, now)
	if resMissing.State != AssuranceStateUnknown {
		t.Fatalf("expected state UNKNOWN on missing required evidence, got %s", resMissing.State)
	}
	if len(resMissing.MissingRequirements) != 1 {
		t.Fatalf("expected 1 missing requirement, got %d", len(resMissing.MissingRequirements))
	}

	// 3. Stale evidence (older than maxAge) -> STALE
	evRuntimeStale := evRuntime
	evRuntimeStale.CapturedAt = now.Add(-10 * time.Minute)
	resStale := contract.Evaluate([]EvidenceEnvelope{evAdmission, evRuntimeStale}, epoch, now)
	if resStale.State != AssuranceStateStale {
		t.Fatalf("expected state STALE when evidence exceeds maxAge, got %s", resStale.State)
	}

	// 4. Epoch divergence -> STALE
	divergedEpoch := epoch
	divergedEpoch.PolicyDigest = ComputeStringDigest("new-policy-v2")
	resEpochDiverged := contract.Evaluate([]EvidenceEnvelope{evAdmission, evRuntime}, divergedEpoch, now)
	if resEpochDiverged.State != AssuranceStateStale {
		t.Fatalf("expected state STALE on epoch mismatch, got %s", resEpochDiverged.State)
	}

	// 5. Optional requirement missing does not break completeness
	contractWithOptional := contract
	contractWithOptional.Requirements = append(contractWithOptional.Requirements, EvidenceRequirement{
		ID:           "optional-telemetry",
		EvidenceType: "telemetry.trace",
		Required:     false,
		MaxAge:       10 * time.Minute,
	})
	resOptional := contractWithOptional.Evaluate([]EvidenceEnvelope{evAdmission, evRuntime}, epoch, now)
	if resOptional.State != AssuranceStateVerified {
		t.Fatalf("expected state VERIFIED when optional requirement is missing, got %s", resOptional.State)
	}
	if !resOptional.Completeness.IsComplete() {
		t.Fatalf("expected completeness to remain complete with missing optional requirement: %s", resOptional.Completeness.Summary())
	}

	// 6. Future-dated evidence (even +30s ahead) must be rejected as Missing/UNKNOWN, never STALE
	evFuture := evAdmission
	evFuture.CapturedAt = now.Add(30 * time.Second)
	singleContract := EvidenceContract{
		ID: "single-adm",
		Requirements: []EvidenceRequirement{
			{
				ID:                "req-adm",
				EvidenceType:      "k8s:admission:review",
				Required:          true,
				MaxAge:            15 * time.Minute,
				AcceptedProducers: []string{"spiffe://", "k8s:admission-controller://"},
			},
		},
		OnMissingRequiredState: AssuranceStateUnknown,
	}
	resFuture := singleContract.Evaluate([]EvidenceEnvelope{evFuture}, epoch, now)
	if resFuture.State != AssuranceStateUnknown || resFuture.Completeness.Missing != 1 || resFuture.Completeness.Stale != 0 {
		t.Fatalf("expected future-dated evidence to be rejected as Missing/UNKNOWN, got state=%s, completeness=%+v", resFuture.State, resFuture.Completeness)
	}

	// 7. Colon-delimited k8s:admission:review matches kubernetes.admission and admission
	resColonMatch := singleContract.Evaluate([]EvidenceEnvelope{evAdmission}, epoch, now)
	if resColonMatch.State != AssuranceStateVerified {
		t.Fatalf("expected k8s:admission:review to match kubernetes.admission, got %s", resColonMatch.State)
	}
}

func TestProducerAntiSpoofing(t *testing.T) {
	req := EvidenceRequirement{
		ID:           "test-req",
		EvidenceType: "test.type",
		Required:     true,
		AcceptedProducers: []string{
			"spiffe://prod/ns/oskal/sa/admission-observer",
		},
	}

	// Substrings or fragments MUST NOT be accepted
	if req.IsProducerAccepted("sa") {
		t.Fatalf("reverse substring 'sa' must be rejected")
	}
	if req.IsProducerAccepted("admission") {
		t.Fatalf("substring 'admission' must be rejected")
	}
	if req.IsProducerAccepted("spiffe://prod") {
		t.Fatalf("unmatching prefix must be rejected")
	}
	if !req.IsProducerAccepted("spiffe://prod/ns/oskal/sa/admission-observer") {
		t.Fatalf("exact match must be accepted")
	}
}

func TestEnvelopeDigestSensitivity(t *testing.T) {
	now := time.Now()
	env := EvidenceEnvelope{
		Schema:          "test/v1",
		ID:              "env-1",
		ObservationType: "obs.type",
		CapturedAt:      now,
		Producer:        AuthorityRef{Scheme: "spiffe", Subject: "author"},
		Artifact:        EvidenceRef{Digest: "sha256:art1"},
		IntegrityDigest: "sha256:int1",
	}

	d1 := env.Digest()

	// Modify SignatureRef
	envWithSig := env
	envWithSig.SignatureRef = "sig-12345"
	d2 := envWithSig.Digest()
	if d1 == d2 {
		t.Fatalf("digest must change when SignatureRef is added")
	}

	// Modify ControlRefs
	envWithCtrl := env
	envWithCtrl.ControlRefs = []ControlRef{{Namespace: "ckodex", ID: "AC-6"}}
	d3 := envWithCtrl.Digest()
	if d1 == d3 {
		t.Fatalf("digest must change when ControlRefs is added")
	}
}

func TestAdverseObservationDominatesContractEvaluation(t *testing.T) {
	now := time.Now().UTC()
	sub := SubjectRef{Scheme: "k8s", ID: "prod/payments/Deployment/payments-api"}
	epoch := AssuranceEpoch{SubjectDigest: ComputeStringDigest(sub.URI())}

	contract := EvidenceContract{
		ID: "contract-strict",
		Requirements: []EvidenceRequirement{
			{
				ID:           "req-adm",
				EvidenceType: "kubernetes.admission",
				Required:     true,
				MaxAge:       15 * time.Minute,
			},
		},
	}

	goodEnv := EvidenceEnvelope{
		ID:              "ev-good",
		Subject:         sub,
		ObservationType: "kubernetes.admission",
		CapturedAt:      now.Add(-1 * time.Minute),
		Producer:        AuthorityRef{Scheme: "spiffe", Subject: "prod/ns/system/sa/observer"},
		Artifact:        EvidenceRef{Digest: ComputeStringDigest("good-payload")},
		Epoch:           epoch,
	}
	adverseEnv := EvidenceEnvelope{
		ID:              "ev-adverse",
		Subject:         sub,
		ObservationType: "kubernetes.admission.violation",
		CapturedAt:      now,
		Producer:        AuthorityRef{Scheme: "spiffe", Subject: "prod/ns/system/sa/observer"},
		Artifact:        EvidenceRef{Digest: ComputeStringDigest("adverse-payload")},
		Epoch:           epoch,
	}

	res := contract.Evaluate([]EvidenceEnvelope{goodEnv, adverseEnv}, epoch, now)
	if res.State != AssuranceStateFailed {
		t.Fatalf("expected adverse observation to dominate contract evaluation with AssuranceStateFailed (Section 23), got %v", res.State)
	}
}
