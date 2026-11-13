package receipts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func generatedPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSigningConstructorsRequireExplicitAuthorityBeforePersistence(t *testing.T) {
	key := generatedPrivateKey(t)
	for _, authority := range []assurance.AuthorityRef{{}, {Scheme: "local"}, {Subject: "operator"}, {Scheme: " ", Subject: "operator"}, {Scheme: "local", Subject: " "}} {
		if manager, err := NewReceiptManager(authority); err == nil || manager != nil {
			t.Fatal("missing authority generated a signer")
		}
		if manager, err := NewReceiptManagerFromKey(authority, key); err == nil || manager != nil {
			t.Fatal("missing authority loaded a signer")
		}
		directory := filepath.Join(t.TempDir(), "must-not-exist")
		if manager, err := LoadOrCreateReceiptManager(authority, directory); err == nil || manager != nil {
			t.Fatal("missing authority created a persistent signer")
		}
		if _, err := os.Stat(directory); !os.IsNotExist(err) {
			t.Fatalf("missing authority created persistent state: %v", err)
		}
	}
}

func TestReceiptKeyConsistencyOwnershipAndEvaluatorBinding(t *testing.T) {
	authority := assurance.AuthorityRef{Scheme: "local", Subject: "explicit-test-signer"}
	key := generatedPrivateKey(t)
	inconsistent := append(ed25519.PrivateKey(nil), key...)
	inconsistent[ed25519.SeedSize] ^= 1
	if manager, err := NewReceiptManagerFromKey(authority, inconsistent); err == nil || manager != nil {
		t.Fatal("a private key with a contradictory public half was accepted")
	}
	manager, err := NewReceiptManagerFromKey(authority, key)
	if err != nil {
		t.Fatal(err)
	}
	public := manager.PublicKey()
	key[0] ^= 1
	key[ed25519.SeedSize] ^= 1
	receipt := assurance.ControlReceipt{Subject: assurance.SubjectRef{Scheme: "file", ID: "test-material"}, Control: assurance.ControlRef{Namespace: "example", ID: "observed"}, State: assurance.AssuranceStateUnknown}
	for _, evaluator := range []assurance.AuthorityRef{{}, authority} {
		receipt.Evaluator = evaluator
		signed, err := manager.SignReceipt(t.Context(), receipt)
		if err != nil {
			t.Fatal(err)
		}
		if signed.Evaluator != authority || signed.EvaluatedAt.IsZero() {
			t.Fatal("receipt lost its explicitly configured signer identity")
		}
		if valid, err := VerifyIndependentReceipt(signed, public); err != nil || !valid {
			t.Fatalf("caller mutation changed the owned key: %v", err)
		}
	}
	for _, evaluator := range []assurance.AuthorityRef{{Scheme: "spiffe", Subject: "prod/ns/operator/sa/forged"}, {Scheme: "local", Subject: "other"}, {Scheme: "local", Subject: authority.Subject, TrustDomain: "contradictory"}, {Subject: "partial"}} {
		receipt.Evaluator = evaluator
		if result, err := manager.SignReceipt(t.Context(), receipt); err == nil || result.Signature != "" || !result.EvaluatedAt.IsZero() {
			t.Fatal("the signer asserted a different or partial evaluator identity")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := manager.SignReceipt(ctx, receipt); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled signing continued: %v", err)
	}
}

func TestReceiptSignerRejectsDifferentEvaluatorBeforeMutation(t *testing.T) {
	manager, err := NewReceiptManager(assurance.AuthorityRef{Scheme: "local", Subject: "explicit-test-signer"})
	if err != nil {
		t.Fatal(err)
	}
	receipt := assurance.ControlReceipt{Evaluator: assurance.AuthorityRef{Scheme: "spiffe", Subject: "prod/ns/operator/sa/forged"}}
	if signed, err := manager.SignReceipt(t.Context(), receipt); err == nil || signed.Signature != "" || !signed.EvaluatedAt.IsZero() {
		t.Fatal("a local signer signed a different evaluator identity")
	}
	if receipt.Signature != "" || !receipt.EvaluatedAt.IsZero() {
		t.Fatal("rejected receipt input was mutated")
	}
}

func TestPersistentSigningIdentityRejectsChangedFilesWithoutRotation(t *testing.T) {
	authority := assurance.AuthorityRef{Scheme: "local", Subject: "persistent-test-signer"}
	for _, test := range []struct {
		name, file string
		change     func(*testing.T, []byte) []byte
	}{
		{"private-public-half", "receipt-signing.key", func(t *testing.T, raw []byte) []byte {
			decoded, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
			if err != nil {
				t.Fatal(err)
			}
			decoded[ed25519.SeedSize] ^= 1
			return []byte(hex.EncodeToString(decoded) + "\n")
		}},
		{"oversized-private", "receipt-signing.key", func(_ *testing.T, _ []byte) []byte { return bytes.Repeat([]byte("a"), 131) }},
		{"malformed-private", "receipt-signing.key", func(_ *testing.T, _ []byte) []byte { return bytes.Repeat([]byte("g"), 128) }},
		{"mismatched-public", "receipt-signing.pub", func(t *testing.T, _ []byte) []byte {
			return []byte(hex.EncodeToString(generatedPrivateKey(t)[ed25519.SeedSize:]) + "\n")
		}},
		{"oversized-public", "receipt-signing.pub", func(_ *testing.T, _ []byte) []byte { return bytes.Repeat([]byte("a"), 67) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			manager, err := LoadOrCreateReceiptManager(authority, directory)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, test.file)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := test.change(t, raw)
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			privateBefore, err := os.ReadFile(filepath.Join(directory, "receipt-signing.key"))
			if err != nil {
				t.Fatal(err)
			}
			publicBefore, err := os.ReadFile(filepath.Join(directory, "receipt-signing.pub"))
			if err != nil {
				t.Fatal(err)
			}
			if reopened, err := LoadOrCreateReceiptManager(authority, directory); err == nil || reopened != nil {
				t.Fatal("changed key files were accepted")
			}
			for name, before := range map[string][]byte{"receipt-signing.key": privateBefore, "receipt-signing.pub": publicBefore} {
				after, err := os.ReadFile(filepath.Join(directory, name))
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("refusal changed historical key material")
				}
			}
			if manager.PublicKey() == "" {
				t.Fatal("original signer was changed by a failed reopen")
			}
		})
	}
}

func TestPersistentSigningIdentityRestoresOnlyItsOwnPublicKey(t *testing.T) {
	authority := assurance.AuthorityRef{Scheme: "local", Subject: "persistent-test-signer"}
	key := generatedPrivateKey(t)
	directory := t.TempDir()
	private := filepath.Join(directory, "receipt-signing.key")
	public := filepath.Join(directory, "receipt-signing.pub")
	publicBytes := []byte(hex.EncodeToString(key[ed25519.SeedSize:]) + "\n")
	if err := os.WriteFile(public, publicBytes, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateReceiptManager(authority, directory); err == nil {
		t.Fatal("an orphan public key was silently rotated")
	}
	if _, err := os.Stat(private); !os.IsNotExist(err) {
		t.Fatal("orphan public key caused private key creation")
	}
	if after, err := os.ReadFile(public); err != nil || !bytes.Equal(after, publicBytes) {
		t.Fatal("orphan public key changed")
	}
	privateOnly := t.TempDir()
	if err := os.WriteFile(filepath.Join(privateOnly, "receipt-signing.key"), []byte(hex.EncodeToString(key)+"\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := LoadOrCreateReceiptManager(authority, privateOnly)
	if err != nil {
		t.Fatal(err)
	}
	if manager.PublicKey() != hex.EncodeToString(key[ed25519.SeedSize:]) {
		t.Fatal("recovery changed the signing identity")
	}
	if after, err := os.ReadFile(filepath.Join(privateOnly, "receipt-signing.pub")); err != nil || !bytes.Equal(after, publicBytes) {
		t.Fatal("missing public key was not derived from the existing private key")
	}
	if info, err := os.Stat(filepath.Join(privateOnly, "receipt-signing.key")); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private key permissions changed")
	}
}
