package verifier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestEvidenceVerifier(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	verifier := NewDefaultEvidenceVerifier()
	producerURI := "spiffe://prod/ns/oskal/sa/producer"
	verifier.RegisterPublicKey(producerURI, pub)

	producer := assurance.AuthorityRef{
		Scheme:      "spiffe",
		Subject:     "prod/ns/oskal/sa/producer",
		TrustDomain: "prod",
	}

	epoch := assurance.AssuranceEpoch{
		SubjectDigest: assurance.ComputeStringDigest("sub"),
	}

	env := assurance.EvidenceEnvelope{
		ID:              "env-1",
		ObservationType: "admission",
		Subject:         assurance.SubjectRef{Scheme: "k8s", ID: "ns/deploy"},
		Producer:        producer,
		Epoch:           epoch,
		CapturedAt:      time.Now().UTC(),
	}

	// Sign envelope digest
	raw := env.Digest()
	sig := ed25519.Sign(priv, []byte(raw))
	env.SignatureRef = hex.EncodeToString(sig)

	ctx := context.Background()
	valid, err := verifier.VerifySignature(ctx, env)
	if err != nil || !valid {
		t.Fatalf("expected signature to verify, valid=%v, err=%v", valid, err)
	}

	// Epoch matching
	if !verifier.VerifyEpoch(ctx, env, epoch) {
		t.Fatal("expected epoch to match")
	}

	driftEpoch := epoch
	driftEpoch.SubjectDigest = "sha256:different"
	if verifier.VerifyEpoch(ctx, env, driftEpoch) {
		t.Fatal("expected drifted epoch not to match")
	}
}
