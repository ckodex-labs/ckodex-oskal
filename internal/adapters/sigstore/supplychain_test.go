package sigstore

import (
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestSigstoreSupplyChainVerificationAndContinuity(t *testing.T) {
	verifier := NewSigstoreVerifier(nil)
	now := time.Now()

	sub := assurance.SubjectRef{
		Scheme: "k8s",
		ID:     "payments/payments-api/Deployment/payments-api",
		Attributes: map[string]string{
			"namespace": "payments",
			"name":      "payments-api",
		},
	}

	artifact := ArtifactMetadata{
		ImageURI:     "registry.example/payments/payments-api",
		Digest:       "sha256:d8a57e3f2b4c10a112233445566778899aabbccddeeff0011223344556677889",
		SignatureRef: "oci://registry.example/payments/payments-api:sha256-d8a57e.sig",
		Signer:       "spiffe://prod/ns/ci/sa/dagger-builder",
		SBOMDigest:   "sha256:sbom12345",
		SLSACommit:   "git-commit-abc1234",
	}

	epoch := assurance.AssuranceEpoch{
		SubjectDigest: "sha256:sub",
	}

	// 1. Generate evidence envelopes
	evidences, err := verifier.GenerateSupplyChainEvidence(sub, artifact, epoch, now)
	if err != nil {
		t.Fatalf("failed to generate supply chain evidence: %v", err)
	}

	if len(evidences) != 2 {
		t.Fatalf("expected 2 evidence envelopes (signature + provenance), got %d", len(evidences))
	}

	// 2. Validate against EvidenceContract
	contract := assurance.EvidenceContract{
		ID:   "supply-chain-contract",
		Name: "Sigstore Provenance Contract",
		Requirements: []assurance.EvidenceRequirement{
			{
				ID:                "artifact-signature",
				EvidenceType:      "supply-chain.signature",
				Required:          true,
				MaxAge:            24 * time.Hour,
				AcceptedProducers: []string{"spiffe://prod/ns/ckodex-evidence/sa/sigstore-verifier"},
			},
			{
				ID:                "artifact-provenance",
				EvidenceType:      "supply-chain.provenance",
				Required:          true,
				MaxAge:            24 * time.Hour,
				AcceptedProducers: []string{"spiffe://prod/ns/ckodex-evidence/sa/sigstore-verifier"},
			},
		},
		OnMissingRequiredState: assurance.AssuranceStateUnknown,
	}

	res := contract.Evaluate(evidences, epoch, now)
	if res.State != assurance.AssuranceStateVerified {
		t.Fatalf("expected contract state VERIFIED, got %s (%s)", res.State, res.Completeness.Summary())
	}

	// 3. Milestone 7 Exit Criteria:
	// Running Deployment traces to admitted signed artifact.
	runningImageDigest := artifact.Digest
	admittedImageDigest := artifact.Digest
	signedImageDigest := artifact.Digest

	ok, lineageDigest := VerifyArtifactContinuity(runningImageDigest, admittedImageDigest, signedImageDigest)
	if !ok || lineageDigest == "" {
		t.Fatalf("M7 Exit Failure: Running deployment failed to trace to admitted signed artifact")
	}

	// Check divergence detection (anti-substitution)
	divergedRunning := "sha256:tamperedDigest"
	okDiverged, msg := VerifyArtifactContinuity(divergedRunning, admittedImageDigest, signedImageDigest)
	if okDiverged {
		t.Fatalf("M7 Failure: Divergent running digest was accepted as continuous!")
	}
	t.Logf("Continuity check successfully blocked divergence: %s", msg)
}

func TestUntrustedSignerRejection(t *testing.T) {
	verifier := NewSigstoreVerifier(nil)
	untrustedArtifact := ArtifactMetadata{
		ImageURI: "registry.example/evil",
		Digest:   "sha256:112233",
		Signer:   "attacker@evil.com",
	}

	_, err := verifier.GenerateSupplyChainEvidence(assurance.SubjectRef{}, untrustedArtifact, assurance.AssuranceEpoch{}, time.Now())
	if err == nil {
		t.Fatalf("expected error verifying artifact with untrusted signer")
	}
}
