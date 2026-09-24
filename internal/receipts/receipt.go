package receipts

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// ReceiptManager handles creation, signing, and verification of ControlReceipts (Section 41 & 42).
type ReceiptManager struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	evaluator  assurance.AuthorityRef
}

// NewReceiptManager creates a receipt manager with an Ed25519 keypair.
func NewReceiptManager(evaluator assurance.AuthorityRef) (*ReceiptManager, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate receipt signing keypair: %w", err)
	}

	if evaluator.Scheme == "" {
		evaluator = assurance.AuthorityRef{
			Scheme:      "spiffe",
			Subject:     "prod/ns/ckodex-assurance/sa/evaluator",
			TrustDomain: "prod",
		}
	}

	return &ReceiptManager{
		publicKey:  pub,
		privateKey: priv,
		evaluator:  evaluator,
	}, nil
}

// PublicKey returns the public key hex for independent verifiers.
func (m *ReceiptManager) PublicKey() string {
	return hex.EncodeToString(m.publicKey)
}

// ComputeEvidenceRoot derives a deterministic Merkle-like root from evidence references (Section 42).
func ComputeEvidenceRoot(evidences []assurance.EvidenceRef) string {
	if len(evidences) == 0 {
		return assurance.ComputeStringDigest("empty:evidence:root")
	}

	digests := make([]string, len(evidences))
	for i, e := range evidences {
		digests[i] = e.Digest
	}
	sort.Strings(digests)

	canonicalLeaves := strings.Join(digests, "\n")
	return assurance.ComputeStringDigest(canonicalLeaves)
}

// IssueReceipt constructs and signs a ControlReceipt for an evaluated claim.
func (m *ReceiptManager) IssueReceipt(
	subject assurance.SubjectRef,
	control assurance.ControlRef,
	state assurance.AssuranceState,
	epoch assurance.AssuranceEpoch,
	evidences []assurance.EvidenceRef,
	evaluatedAt time.Time,
) (assurance.ControlReceipt, error) {
	evidenceRoot := ComputeEvidenceRoot(evidences)

	receipt := assurance.ControlReceipt{
		Subject:      subject,
		Control:      control,
		State:        state,
		Epoch:        epoch,
		EvidenceRoot: evidenceRoot,
		Evaluator:    m.evaluator,
		EvaluatedAt:  evaluatedAt,
	}

	canonicalBytes := receipt.CanonicalBytes()
	sig := ed25519.Sign(m.privateKey, canonicalBytes)
	receipt.Signature = hex.EncodeToString(sig)

	return receipt, nil
}

// VerifyIndependentReceipt allows any independent process to verify the signature of a receipt.
func VerifyIndependentReceipt(receipt assurance.ControlReceipt, publicKeyHex string) (bool, error) {
	pubBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid public key hex: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size: %d, expected %d", len(pubBytes), ed25519.PublicKeySize)
	}

	sigBytes, err := hex.DecodeString(receipt.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}

	canonicalBytes := receipt.CanonicalBytes()
	valid := ed25519.Verify(pubBytes, canonicalBytes, sigBytes)
	return valid, nil
}
