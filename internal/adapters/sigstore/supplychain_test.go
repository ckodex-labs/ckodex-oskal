package sigstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

const releaseIssuer = "https://token.actions.githubusercontent.com"
const releaseSigner = "https://github.com/ckodex-labs/ckodex-oskal/.github/workflows/release.yml@refs/heads/p1/release"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPublishedSigstoreBundles(t *testing.T) {
	v, err := NewBundleVerifier(fixture(t, "trusted_root.json"), releaseIssuer, releaseSigner)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(fixture(t, "checksums.txt"))
	for _, tc := range []struct{ name, digest, predicate string }{
		{"checksums", "sha256:" + hex.EncodeToString(digest[:]), ""},
		{"provenance", "sha256:c2b0360be777cb99754b02f4c18a53686e7da98e387875d6f72735b85ae714a1", "https://slsa.dev/provenance/v1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := v.VerifyBundle(t.Context(), fixture(t, tc.name+".sigstore.json"), tc.digest)
			if err != nil {
				t.Fatal(err)
			}
			if result.ArtifactDigest() != tc.digest || result.Signer() != releaseSigner || result.Issuer() != releaseIssuer || result.PredicateType() != tc.predicate {
				t.Fatalf("incorrect verified facts: %+v", result)
			}
			envelope, err := result.Evidence(assurance.SubjectRef{Scheme: "artifact", ID: tc.digest}, assurance.AuthorityRef{Scheme: "spiffe", Subject: "prod/verifier"}, "file:///bundles/"+tc.name+".sigstore.json", assurance.AssuranceEpoch{})
			if err != nil || envelope.IntegrityDigest == "" {
				t.Fatalf("receipt: %v", err)
			}
			if tc.predicate == "" && envelope.ObservationType != "supply-chain.signature" {
				t.Fatal("signature promoted to provenance")
			}
		})
	}
}

func TestPublishedBundleRejectsInvalidTrustAndArtifact(t *testing.T) {
	root := fixture(t, "trusted_root.json")
	raw := fixture(t, "checksums.sigstore.json")
	hash := sha256.Sum256(fixture(t, "checksums.txt"))
	digest := "sha256:" + hex.EncodeToString(hash[:])
	for _, tc := range []struct{ name, issuer, signer, digest string }{
		{"wrong issuer", "https://attacker.invalid", releaseSigner, digest},
		{"wrong identity", releaseIssuer, releaseSigner + "-wrong", digest},
		{"wrong digest", releaseIssuer, releaseSigner, "sha256:" + strings.Repeat("0", 64)},
		{"short digest", releaseIssuer, releaseSigner, "sha256:ab"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewBundleVerifier(root, tc.issuer, tc.signer)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := v.VerifyBundle(t.Context(), raw, tc.digest); err == nil || result != nil {
				t.Fatal("invalid verification accepted")
			}
		})
	}
	v, err := NewBundleVerifier(root, releaseIssuer, releaseSigner)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"signature", "transparency", "certificate", "inclusion"} {
		t.Run(change, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			material := doc["verificationMaterial"].(map[string]any)
			switch change {
			case "signature":
				doc["messageSignature"].(map[string]any)["signature"] = "AAAA"
			case "transparency":
				delete(material, "tlogEntries")
			case "certificate":
				delete(material, "certificate")
				delete(material, "x509CertificateChain")
			case "inclusion":
				for _, entry := range material["tlogEntries"].([]any) {
					delete(entry.(map[string]any), "inclusionProof")
					delete(entry.(map[string]any), "inclusionPromise")
				}
			}
			modified, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := v.VerifyBundle(t.Context(), modified, digest); err == nil || result != nil {
				t.Fatal("tampered bundle accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := v.VerifyBundle(ctx, raw, digest); err == nil {
		t.Fatal("canceled request accepted")
	}
}

func TestMissingTrustConfigurationFails(t *testing.T) {
	for _, pair := range [][2]string{{"", releaseSigner}, {releaseIssuer, ""}, {"*", releaseSigner}, {releaseIssuer, "*"}} {
		if _, err := NewBundleVerifier(fixture(t, "trusted_root.json"), pair[0], pair[1]); err == nil {
			t.Fatal("missing identity accepted")
		}
	}
	if _, err := NewBundleVerifier(nil, releaseIssuer, releaseSigner); err == nil {
		t.Fatal("missing root accepted")
	}
	var empty VerifiedBundle
	if _, err := empty.Evidence(assurance.SubjectRef{}, assurance.AuthorityRef{}, "", assurance.AssuranceEpoch{}); err == nil {
		t.Fatal("zero-value verification accepted")
	}
}

func TestArtifactContinuity(t *testing.T) {
	digest := assurance.ComputeStringDigest("artifact")
	if ok, _ := VerifyArtifactContinuity(digest, digest, digest); !ok {
		t.Fatal("matching digests rejected")
	}
	if ok, _ := VerifyArtifactContinuity(assurance.ComputeStringDigest("tampered"), digest, digest); ok {
		t.Fatal("divergent digest accepted")
	}
	if ok, _ := VerifyArtifactContinuity("", digest, digest); ok {
		t.Fatal("missing digest accepted")
	}
}

func TestInvalidContinuityDigests(t *testing.T) {
	if ok, _ := VerifyArtifactContinuity("sha256:aa", "sha256:aa", "sha256:aa"); ok {
		t.Fatal("malformed matching digests accepted")
	}
}
