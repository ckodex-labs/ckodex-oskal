package receipts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

var _ ports.ReceiptSigner = (*ReceiptManager)(nil)

// ReceiptManager handles creation, signing, and verification of ControlReceipts (Section 41 & 42).
type ReceiptManager struct {
	publicKey         ed25519.PublicKey
	privateKey        ed25519.PrivateKey
	evaluator         assurance.AuthorityRef
	evidenceAuthority assurance.AuthorityRef
}

// NewReceiptManager creates a keypair for an explicitly supplied authority claim.
// Key generation does not authenticate that authority or establish its trust.
func NewReceiptManager(evaluator assurance.AuthorityRef) (*ReceiptManager, error) {
	if err := evaluator.Validate(); err != nil {
		return nil, fmt.Errorf("explicit receipt signing authority is required: %w", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate receipt signing keypair: %w", err)
	}
	return NewReceiptManagerFromKey(evaluator, priv)
}

// NewReceiptManagerFromKey creates a receipt manager from an existing Ed25519 private key.
func NewReceiptManagerFromKey(evaluator assurance.AuthorityRef, privKey ed25519.PrivateKey) (*ReceiptManager, error) {
	if err := evaluator.Validate(); err != nil {
		return nil, fmt.Errorf("explicit receipt signing authority is required: %w", err)
	}
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: %d, expected %d", len(privKey), ed25519.PrivateKeySize)
	}
	owned := ed25519.NewKeyFromSeed(privKey[:ed25519.SeedSize])
	if !bytes.Equal(owned[ed25519.SeedSize:], privKey[ed25519.SeedSize:]) {
		return nil, fmt.Errorf("Ed25519 private key public half does not match its seed")
	}

	return &ReceiptManager{
		publicKey:         append(ed25519.PublicKey(nil), owned[ed25519.SeedSize:]...),
		privateKey:        owned,
		evaluator:         evaluator,
		evidenceAuthority: evaluator,
	}, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".oskal-key-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// LoadOrCreateReceiptManager loads a persistent Ed25519 receipt signing keypair from dir,
// or generates and writes one (`receipt-signing.key` and `receipt-signing.pub`) if absent.
func LoadOrCreateReceiptManager(evaluator assurance.AuthorityRef, dir string) (*ReceiptManager, error) {
	if err := evaluator.Validate(); err != nil {
		return nil, fmt.Errorf("explicit receipt signing authority is required: %w", err)
	}
	if dir == "" {
		return NewReceiptManager(evaluator)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create receipt key directory: %w", err)
	}
	privPath := filepath.Join(dir, "receipt-signing.key")
	pubPath := filepath.Join(dir, "receipt-signing.pub")

	if privBytes, err := readKeyHex(privPath, ed25519.PrivateKeySize); err == nil {
		mgr, err := NewReceiptManagerFromKey(evaluator, ed25519.PrivateKey(privBytes))
		if err != nil {
			return nil, err
		}
		public, err := readKeyHex(pubPath, ed25519.PublicKeySize)
		if os.IsNotExist(err) {
			if err := writeFileAtomic(pubPath, []byte(mgr.PublicKey()+"\n"), 0644); err != nil {
				return nil, fmt.Errorf("failed to persist regenerated receipt-signing.pub: %w", err)
			}
		} else if err != nil {
			return nil, fmt.Errorf("read persistent receipt public key: %w", err)
		} else if !bytes.Equal(public, mgr.publicKey) {
			return nil, fmt.Errorf("persistent receipt public key differs from the private key; preserve both files and restore the intended signing identity")
		}
		return mgr, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read receipt-signing.key: %w", err)
	}
	if _, err := os.Lstat(pubPath); err == nil {
		return nil, fmt.Errorf("receipt public key exists without its private key; preserve the public key and restore the intended signing identity")
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect receipt public key before creating a signing identity: %w", err)
	}

	mgr, err := NewReceiptManager(evaluator)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(privPath, []byte(hex.EncodeToString(mgr.privateKey)+"\n"), 0600); err != nil {
		return nil, fmt.Errorf("failed to persist receipt-signing.key: %w", err)
	}
	if err := writeFileAtomic(pubPath, []byte(mgr.PublicKey()+"\n"), 0644); err != nil {
		return nil, fmt.Errorf("failed to persist receipt-signing.pub: %w", err)
	}
	return mgr, nil
}

// Keys are fixed-size hex with an optional final LF or CRLF. Never read an
// arbitrary file into memory or silently reinterpret malformed key material.
func readKeyHex(path string, size int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("signing key file must be regular")
	}
	maximum := 2*size + 2
	if info.Size() > int64(maximum) {
		return nil, fmt.Errorf("signing key file exceeds its fixed encoding bound")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, int64(maximum+1)))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(raw) > maximum {
		return nil, fmt.Errorf("signing key file exceeds its fixed encoding bound")
	}
	encoded := string(raw)
	if strings.HasSuffix(encoded, "\n") {
		encoded = strings.TrimSuffix(encoded, "\n")
		encoded = strings.TrimSuffix(encoded, "\r")
	}
	if len(encoded) != 2*size {
		return nil, fmt.Errorf("signing key requires exactly %d hexadecimal characters", 2*size)
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid signing key hexadecimal encoding: %w", err)
	}
	return decoded, nil
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
	if m == nil || len(m.privateKey) != ed25519.PrivateKeySize || m.evaluator.Validate() != nil {
		return assurance.ControlReceipt{}, fmt.Errorf("explicit receipt signing authority and private key are required")
	}
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

// SignReceipt signs an existing ControlReceipt using the manager's private key (implements ports.ReceiptSigner).
func (m *ReceiptManager) SignReceipt(ctx context.Context, receipt assurance.ControlReceipt) (assurance.ControlReceipt, error) {
	if err := ctx.Err(); err != nil {
		return assurance.ControlReceipt{}, err
	}
	if m == nil || len(m.privateKey) != ed25519.PrivateKeySize || m.evaluator.Validate() != nil {
		return assurance.ControlReceipt{}, fmt.Errorf("explicit receipt signing authority and private key are required")
	}
	if receipt.Evaluator == (assurance.AuthorityRef{}) {
		receipt.Evaluator = m.evaluator
	} else if receipt.Evaluator != m.evaluator {
		return assurance.ControlReceipt{}, fmt.Errorf("receipt evaluator differs from signing authority")
	}
	if receipt.EvaluatedAt.IsZero() {
		receipt.EvaluatedAt = time.Now().UTC()
	}
	canonicalBytes := receipt.CanonicalBytes()
	sig := ed25519.Sign(m.privateKey, canonicalBytes)
	receipt.Signature = hex.EncodeToString(sig)
	return receipt, nil
}

// VerifyReceipt requires the configured full evaluator reference as well as a
// valid legacy-format signature. It does not verify observations or live standing.
func (m *ReceiptManager) VerifyReceipt(ctx context.Context, receipt assurance.ControlReceipt) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if m == nil || len(m.publicKey) != ed25519.PublicKeySize || m.evaluator.Validate() != nil {
		return false, fmt.Errorf("explicit receipt verification authority and public key are required")
	}
	if receipt.Evaluator != m.evaluator {
		return false, fmt.Errorf("receipt evaluator differs from configured verification authority")
	}
	return VerifyIndependentReceipt(receipt, hex.EncodeToString(m.publicKey))
}

// VerifyIndependentReceipt validates evaluator semantics and verifies the legacy
// canonical tuple under a supplied key. Supplemental metadata is not signed;
// a trusted full-JSON archive reference is required to bind those exact bytes.
func VerifyIndependentReceipt(receipt assurance.ControlReceipt, publicKeyHex string) (bool, error) {
	if err := receipt.Evaluator.Validate(); err != nil {
		return false, fmt.Errorf("invalid receipt evaluator: %w", err)
	}
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
