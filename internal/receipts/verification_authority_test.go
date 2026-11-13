package receipts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
)

func authorityReceipt(t *testing.T, manager *ReceiptManager) assurance.ControlReceipt {
	t.Helper()
	receipt, err := manager.SignReceipt(t.Context(), assurance.ControlReceipt{Subject: assurance.SubjectRef{Scheme: "file", ID: "declared-material", Attributes: map[string]string{"uid": "supplemental-metadata"}}, Control: assurance.ControlRef{Namespace: "example", ID: "record"}, State: assurance.AssuranceStateUnknown, EvaluatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestReceiptTrustDomainMutationIsRejected(t *testing.T) {
	for _, authority := range []assurance.AuthorityRef{{Scheme: "spiffe", Subject: "receipt.test/ns/observer/sa/signer", TrustDomain: "receipt.test"}, {Scheme: "local", Subject: "explicit-local-signer"}} {
		t.Run(authority.Scheme, func(t *testing.T) {
			manager, err := NewReceiptManager(authority)
			if err != nil {
				t.Fatal(err)
			}
			original := authorityReceipt(t, manager)
			if valid, err := VerifyIndependentReceipt(original, manager.PublicKey()); err != nil || !valid {
				t.Fatalf("unchanged receipt rejected: %v", err)
			}
			mutated := original
			mutated.Evaluator.TrustDomain = "contradictory.test"
			if !bytes.Equal(original.CanonicalBytes(), mutated.CanonicalBytes()) {
				t.Fatal("test changed legacy signature bytes")
			}
			if valid, err := VerifyIndependentReceipt(mutated, manager.PublicKey()); valid {
				t.Errorf("independent verifier accepted TrustDomain-only mutation: valid=%v err=%v", valid, err)
			}
			if valid, err := manager.VerifyReceipt(t.Context(), mutated); valid {
				t.Errorf("configured manager accepted TrustDomain-only mutation: valid=%v err=%v", valid, err)
			}
			t.Log("real Ed25519 signature unchanged by metadata mutation; semantic and configured-authority checks must reject it")
		})
	}
}

func TestManagerVerificationRequiresExactConfiguredAuthority(t *testing.T) {
	key := generatedPrivateKey(t)
	expected := assurance.AuthorityRef{Scheme: "spiffe", Subject: "receipt.test/ns/observer/sa/signer", TrustDomain: "receipt.test"}
	manager, err := NewReceiptManagerFromKey(expected, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []assurance.AuthorityRef{{Scheme: "spiffe", Subject: expected.Subject}, {Scheme: "spiffe", Subject: "receipt.test/ns/other/sa/signer", TrustDomain: "receipt.test"}} {
		signer, err := NewReceiptManagerFromKey(other, key)
		if err != nil {
			t.Fatal(err)
		}
		receipt := authorityReceipt(t, signer)
		if valid, err := VerifyIndependentReceipt(receipt, manager.PublicKey()); err != nil || !valid {
			t.Fatalf("valid independent signature rejected: %v", err)
		}
		if valid, err := manager.VerifyReceipt(t.Context(), receipt); valid {
			t.Errorf("manager accepted different configured authority: %+v err=%v", other, err)
		}
	}
}

func TestContradictoryAuthorityRejectedBeforeKeyFiles(t *testing.T) {
	for _, authority := range []assurance.AuthorityRef{{Scheme: "spiffe", Subject: "receipt.test/ns/signer", TrustDomain: "other.test"}, {Scheme: "local", Subject: "signer", TrustDomain: "receipt.test"}} {
		directory := filepath.Join(t.TempDir(), "must-not-exist")
		if manager, err := LoadOrCreateReceiptManager(authority, directory); err == nil || manager != nil {
			t.Error("contradictory authority created signer")
		}
		if _, err := os.Stat(directory); !os.IsNotExist(err) {
			t.Error("contradictory authority created key directory")
		}
	}
}

func TestLegacySignatureScopeAndFullJSONReceiptIdentity(t *testing.T) {
	manager, err := NewReceiptManager(assurance.AuthorityRef{Scheme: "spiffe", Subject: "receipt.test/ns/signer", TrustDomain: "receipt.test"})
	if err != nil {
		t.Fatal(err)
	}
	original := authorityReceipt(t, manager)
	changed := original
	changed.Subject.Attributes = map[string]string{"uid": "different-supplemental-metadata"}
	if !bytes.Equal(original.CanonicalBytes(), changed.CanonicalBytes()) {
		t.Fatal("legacy canonical signature scope unexpectedly changed")
	}
	if valid, err := VerifyIndependentReceipt(changed, manager.PublicKey()); err != nil || !valid {
		t.Fatalf("this test documents unsigned supplemental fields, not a format migration: %v", err)
	}
	originalJSON, err := json.MarshalIndent(original, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	changedJSON, err := json.MarshalIndent(changed, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := storage.NewFilesystemEvidenceRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := repo.PutReceipt(t.Context(), original)
	if err != nil {
		t.Fatal(err)
	}
	second, err := repo.PutReceipt(t.Context(), changed)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || assurance.ComputeDigest(originalJSON) == assurance.ComputeDigest(changedJSON) {
		t.Fatal("full JSON identity failed to bind supplemental metadata")
	}
	t.Log("legacy signature binds its documented canonical tuple; actual CAS receipt references distinguish additional Subject.Attributes bytes")
}
