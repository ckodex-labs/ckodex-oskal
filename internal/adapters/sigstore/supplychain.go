package sigstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const maxBundleBytes = 4 << 20

// BundleVerifier verifies offline Sigstore bundles using explicitly supplied
// trust roots. Root distribution, TUF refresh and offline expiry policy belong
// to the caller; roots MUST come from trusted custody, never from the bundle.
type BundleVerifier struct {
	verifier   *verify.Verifier
	identity   verify.CertificateIdentity
	rootDigest string
}

// VerifiedBundle contains only facts established by signature verification.
// Private fields prevent callers from manufacturing verification results.
type VerifiedBundle struct {
	artifactDigest string
	bundleDigest   string
	rootDigest     string
	issuer         string
	signer         string
	predicateType  string
	verifiedAt     time.Time
}

func (b *VerifiedBundle) ArtifactDigest() string { return b.artifactDigest }
func (b *VerifiedBundle) Signer() string         { return b.signer }
func (b *VerifiedBundle) Issuer() string         { return b.issuer }
func (b *VerifiedBundle) PredicateType() string  { return b.predicateType }

// NewBundleVerifier requires exact identity constraints and enforces certificate
// transparency, artifact transparency and a trusted observer timestamp.
func NewBundleVerifier(trustedRootJSON []byte, exactIssuer, exactSAN string) (*BundleVerifier, error) {
	if strings.TrimSpace(exactIssuer) == "" || strings.TrimSpace(exactSAN) == "" || exactIssuer == "*" || exactSAN == "*" {
		return nil, fmt.Errorf("exact issuer and signer identity are required")
	}
	if len(trustedRootJSON) == 0 || len(trustedRootJSON) > maxBundleBytes {
		return nil, fmt.Errorf("trusted root must contain between 1 and %d bytes", maxBundleBytes)
	}
	trusted, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("parse trusted root: %w", err)
	}
	identity, err := verify.NewShortCertificateIdentity(exactIssuer, "", exactSAN, "")
	if err != nil {
		return nil, fmt.Errorf("create signer policy: %w", err)
	}
	verifier, err := verify.NewVerifier(trusted, verify.WithTransparencyLog(1), verify.WithSignedCertificateTimestamps(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return nil, fmt.Errorf("create Sigstore verifier: %w", err)
	}
	digest := sha256.Sum256(trustedRootJSON)
	return &BundleVerifier{verifier: verifier, identity: identity, rootDigest: "sha256:" + hex.EncodeToString(digest[:])}, nil
}

// VerifyBundle verifies a detached signature or in-toto statement bound to the
// supplied SHA-256 artifact digest. It performs no network access and accepts no
// caller-provided provenance claims. A verified predicate type identifies the
// signed statement format; it does not by itself establish SLSA conformance.
func (v *BundleVerifier) VerifyBundle(ctx context.Context, raw []byte, artifactDigest string) (*VerifiedBundle, error) {
	if v == nil || v.verifier == nil {
		return nil, fmt.Errorf("configured verifier is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > maxBundleBytes {
		return nil, fmt.Errorf("bundle must contain between 1 and %d bytes", maxBundleBytes)
	}
	if !strings.HasPrefix(artifactDigest, "sha256:") {
		return nil, fmt.Errorf("artifact digest must use sha256")
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(artifactDigest, "sha256:"))
	if err != nil || len(digest) != sha256.Size {
		return nil, fmt.Errorf("artifact digest must contain exactly 32 SHA-256 bytes")
	}
	var signed bundle.Bundle
	if err := json.Unmarshal(raw, &signed); err != nil {
		return nil, fmt.Errorf("parse Sigstore bundle: %w", err)
	}
	result, err := v.verifier.Verify(&signed, verify.NewPolicy(verify.WithArtifactDigest("sha256", digest), verify.WithCertificateIdentity(v.identity)))
	if err != nil {
		return nil, fmt.Errorf("verify Sigstore bundle: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if result.Signature == nil || result.Signature.Certificate == nil || result.VerifiedIdentity == nil {
		return nil, fmt.Errorf("verified bundle has no certificate identity")
	}
	bundleHash := sha256.Sum256(raw)
	facts := &VerifiedBundle{artifactDigest: "sha256:" + hex.EncodeToString(digest), bundleDigest: "sha256:" + hex.EncodeToString(bundleHash[:]), rootDigest: v.rootDigest, issuer: result.Signature.Certificate.Issuer, signer: result.Signature.Certificate.SubjectAlternativeName, verifiedAt: time.Now().UTC()}
	if result.Statement != nil {
		facts.predicateType = result.Statement.PredicateType
	}
	return facts, nil
}

// Evidence records verification facts and the exact bundle and trust-root
// digests. The producer must be the authenticated verifier, not the signer.
func (b *VerifiedBundle) Evidence(subject assurance.SubjectRef, producer assurance.AuthorityRef, bundleURI string, epoch assurance.AssuranceEpoch) (*assurance.EvidenceEnvelope, error) {
	if b == nil || b.bundleDigest == "" {
		return nil, fmt.Errorf("verified bundle is required")
	}
	if producer.Scheme == "" || producer.Subject == "" || bundleURI == "" {
		return nil, fmt.Errorf("verifier identity and bundle URI are required")
	}
	payload, err := b.Receipt()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	receiptDigest := "sha256:" + hex.EncodeToString(digest[:])
	observation := "supply-chain.signature"
	if b.predicateType == "https://slsa.dev/provenance/v1" {
		observation = "supply-chain.provenance"
	}
	return &assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/evidence/v1alpha1", ID: "ev-sigstore-" + hex.EncodeToString(digest[:]), Subject: subject, ObservationType: observation, CapturedAt: b.verifiedAt, Producer: producer, Artifact: assurance.EvidenceRef{URI: bundleURI, Digest: b.bundleDigest, MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json"}, IntegrityDigest: receiptDigest, SignatureRef: bundleURI, Epoch: epoch}, nil
}

// Receipt serializes the verified facts for durable evidence storage.
func (b *VerifiedBundle) Receipt() ([]byte, error) {
	if b == nil || b.bundleDigest == "" {
		return nil, fmt.Errorf("verified bundle is required")
	}
	return json.Marshal(struct {
		ArtifactDigest    string    `json:"artifactDigest"`
		BundleDigest      string    `json:"bundleDigest"`
		TrustedRootDigest string    `json:"trustedRootDigest"`
		Issuer            string    `json:"issuer"`
		Signer            string    `json:"signer"`
		PredicateType     string    `json:"predicateType,omitempty"`
		VerifiedAt        time.Time `json:"verifiedAt"`
	}{b.artifactDigest, b.bundleDigest, b.rootDigest, b.issuer, b.signer, b.predicateType, b.verifiedAt})
}

// ComputeRunningArtifactLineage verifies that the running workload image digest
// equals the admitted artifact digest and signed provenance subject (Section 26).
func VerifyArtifactContinuity(runningDigest, admittedDigest, signedDigest string) (bool, string) {
	for _, digest := range []string{runningDigest, admittedDigest, signedDigest} {
		raw, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
		if !strings.HasPrefix(digest, "sha256:") || err != nil || len(raw) != sha256.Size || digest != strings.ToLower(digest) {
			return false, "invalid SHA-256 digest in supply chain continuity evaluation"
		}
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
