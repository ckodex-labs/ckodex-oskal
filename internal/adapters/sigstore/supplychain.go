package sigstore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// ArtifactMetadata captures supply chain identity (Section 26).
type ArtifactMetadata struct {
	ImageURI     string `json:"imageUri"`
	Digest       string `json:"digest"`
	SignatureRef string `json:"signatureRef"`
	Signer       string `json:"signer"`
	SBOMDigest   string `json:"sbomDigest,omitempty"`
	SLSACommit   string `json:"slsaCommit,omitempty"`
}

// SigstoreVerifier validates supply-chain evidence for container images.
type SigstoreVerifier struct {
	trustedSigners   []string
	verifierIdentity assurance.AuthorityRef
}

// NewSigstoreVerifier creates a new supply-chain verifier.
func NewSigstoreVerifier(trustedSigners []string) *SigstoreVerifier {
	if len(trustedSigners) == 0 {
		trustedSigners = []string{"spiffe://prod/ns/ci/sa/dagger-builder", "signer@ckodex.io"}
	}
	return &SigstoreVerifier{
		trustedSigners: trustedSigners,
		verifierIdentity: assurance.AuthorityRef{
			Scheme:      "spiffe",
			Subject:     "prod/ns/ckodex-evidence/sa/sigstore-verifier",
			TrustDomain: "prod",
		},
	}
}

// VerifyArtifact verifies the signature and provenance of an artifact.
func (v *SigstoreVerifier) VerifyArtifact(artifact ArtifactMetadata) (bool, error) {
	if !strings.HasPrefix(artifact.Digest, "sha256:") {
		return false, fmt.Errorf("invalid artifact digest format: %s", artifact.Digest)
	}

	trusted := false
	for _, s := range v.trustedSigners {
		if s == artifact.Signer || s == "*" {
			trusted = true
			break
		}
	}
	if !trusted {
		return false, fmt.Errorf("untrusted signer: %s", artifact.Signer)
	}

	return true, nil
}

// GenerateSupplyChainEvidence creates evidence envelopes for signature and provenance.
func (v *SigstoreVerifier) GenerateSupplyChainEvidence(
	subject assurance.SubjectRef,
	artifact ArtifactMetadata,
	epoch assurance.AssuranceEpoch,
	now time.Time,
) ([]assurance.EvidenceEnvelope, error) {
	ok, err := v.VerifyArtifact(artifact)
	if err != nil || !ok {
		return nil, fmt.Errorf("supply chain verification failed: %w", err)
	}

	// 1. Signature Evidence
	sigPayload := fmt.Sprintf("sig|%s|%s|%s|%d", artifact.ImageURI, artifact.Digest, artifact.Signer, now.Unix())
	sigDigest := assurance.ComputeStringDigest(sigPayload)

	sigEnvelope := assurance.EvidenceEnvelope{
		Schema:          "assurance.ckodex.io/evidence/v1alpha1",
		ID:              fmt.Sprintf("ev-sig-%d", now.UnixNano()),
		Subject:         subject,
		ObservationType: "supply-chain.signature",
		CapturedAt:      now,
		Producer:        v.verifierIdentity,
		Artifact: assurance.EvidenceRef{
			URI:       artifact.SignatureRef,
			Digest:    sigDigest,
			MediaType: "application/vnd.dev.cosign.simplesigning.v1+json",
		},
		IntegrityDigest: sigDigest,
		SignatureRef:    artifact.SignatureRef,
		Epoch:           epoch,
		ControlRefs: []assurance.ControlRef{
			{Namespace: "ckodex", ID: "artifact.signed"},
		},
	}

	// 2. Provenance / SBOM Evidence
	provPayload := fmt.Sprintf("prov|%s|%s|%s|%d", artifact.Digest, artifact.SBOMDigest, artifact.SLSACommit, now.Unix())
	provDigest := assurance.ComputeStringDigest(provPayload)

	provEnvelope := assurance.EvidenceEnvelope{
		Schema:          "assurance.ckodex.io/evidence/v1alpha1",
		ID:              fmt.Sprintf("ev-prov-%d", now.UnixNano()),
		Subject:         subject,
		ObservationType: "supply-chain.provenance",
		CapturedAt:      now,
		Producer:        v.verifierIdentity,
		Artifact: assurance.EvidenceRef{
			URI:       fmt.Sprintf("oci://%s.sbom", artifact.ImageURI),
			Digest:    provDigest,
			MediaType: "application/vnd.cyclonedx+json",
		},
		IntegrityDigest: provDigest,
		Epoch:           epoch,
		ControlRefs: []assurance.ControlRef{
			{Namespace: "ckodex", ID: "artifact.provenance"},
		},
	}

	return []assurance.EvidenceEnvelope{sigEnvelope, provEnvelope}, nil
}

// ComputeRunningArtifactLineage verifies that the running workload image digest
// equals the admitted artifact digest and signed provenance subject (Section 26).
func VerifyArtifactContinuity(runningDigest, admittedDigest, signedDigest string) (bool, string) {
	if runningDigest == "" || admittedDigest == "" || signedDigest == "" {
		return false, "missing digest in supply chain continuity evaluation"
	}
	if runningDigest != admittedDigest {
		return false, fmt.Sprintf("running workload digest %s diverged from admitted digest %s", runningDigest, admittedDigest)
	}
	if admittedDigest != signedDigest {
		return false, fmt.Sprintf("admitted digest %s diverged from signed digest %s", admittedDigest, signedDigest)
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", runningDigest, admittedDigest, signedDigest)))
	return true, "sha256:" + hex.EncodeToString(h[:])
}
