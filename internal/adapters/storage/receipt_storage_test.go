package storage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

func receiptFixture(t *testing.T) (*receipts.ReceiptManager, assurance.ControlReceipt) {
	t.Helper()
	signer, err := receipts.LoadOrCreateReceiptManager(assurance.AuthorityRef{Scheme: "spiffe", Subject: "test.oskal/evaluator"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	receipt := assurance.ControlReceipt{Subject: assurance.SubjectRef{Scheme: "k8s", ID: "local/ns/Pod/example"}, Control: assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}, State: assurance.AssuranceStateVerified, Epoch: assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeStringDigest("pod-uid")}, EvidenceRoot: assurance.ComputeStringDigest("actual-proof"), EvaluatedAt: time.Now().UTC()}
	receipt, err = signer.SignReceipt(context.Background(), receipt)
	if err != nil {
		t.Fatal(err)
	}
	return signer, receipt
}
func serializedReceipt(t *testing.T, receipt assurance.ControlReceipt) []byte {
	t.Helper()
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestReceiptVersionsRetainImmutableFullIdentities(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	repo, err := NewFilesystemEvidenceRepository(directory)
	if err != nil {
		t.Fatal(err)
	}
	signer, first := receiptFixture(t)
	second := first
	second.State = assurance.AssuranceStateUnknown
	second.EvidenceRoot = ""
	second.EvaluatedAt = first.EvaluatedAt.Add(time.Second)
	second.Signature = ""
	second, err = signer.SignReceipt(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	firstID, err := repo.PutReceipt(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := repo.PutReceipt(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstID) != 69 || len(secondID) != 69 || firstID == secondID {
		t.Fatalf("immutable identities absent: %s %s", firstID, secondID)
	}
	for _, check := range []struct {
		id      string
		receipt assurance.ControlReceipt
	}{{firstID, first}, {secondID, second}} {
		data, err := os.ReadFile(filepath.Join(directory, "receipts", check.id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if "rcpt-"+strings.TrimPrefix(assurance.ComputeDigest(data), "sha256:") != check.id {
			t.Fatal("reference is not full JSON SHA-256")
		}
		if len(data) == 0 {
			t.Fatal("empty receipt")
		}
	}
	// A late historical write cannot roll back the current compatibility alias.
	if repeated, err := repo.PutReceipt(ctx, first); err != nil || repeated != firstID {
		t.Fatalf("idempotent old write failed: %s %v", repeated, err)
	}
	restored, err := NewFilesystemEvidenceRepository(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, store := range []*ContentAddressedEvidenceRepository{repo, restored} {
		for _, check := range []struct {
			id    string
			state assurance.AssuranceState
		}{{firstID, assurance.AssuranceStateVerified}, {secondID, assurance.AssuranceStateUnknown}, {"rcpt-AC-6", assurance.AssuranceStateUnknown}, {"rcpt-example-AC-6", assurance.AssuranceStateUnknown}, {"sha256:" + strings.TrimPrefix(firstID, "rcpt-"), assurance.AssuranceStateVerified}} {
			got, err := store.GetReceipt(ctx, check.id)
			if err != nil || got.State != check.state {
				t.Fatalf("receipt %s changed: %+v %v", check.id, got, err)
			}
			valid, err := receipts.VerifyIndependentReceipt(got, signer.PublicKey())
			if err != nil || !valid {
				t.Fatalf("receipt signature invalid: %v", err)
			}
		}
	}
	t.Logf("two real signed versions survive reopen: %s and %s", firstID, secondID)
}

func TestReceiptTraversalAndReservedAliasesAreRejected(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	repo, err := NewFilesystemEvidenceRepository(directory)
	if err != nil {
		t.Fatal(err)
	}
	signer, receipt := receiptFixture(t)
	id, err := repo.PutReceipt(ctx, receipt)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(directory, "receipts", id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, control := range []string{"../../escape", `..\escape`, "/absolute", "foo/../../escape", strings.TrimPrefix(id, "rcpt-"), strings.ToUpper(strings.TrimPrefix(id, "rcpt-")), strings.TrimPrefix(id, "rcpt-")[:12]} {
		bad := receipt
		bad.Control.ID = control
		bad.Signature = ""
		bad, err = signer.SignReceipt(ctx, bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.PutReceipt(ctx, bad); err == nil {
			t.Fatalf("unsafe or reserved control accepted: %q", control)
		}
	}
	for _, lookup := range []string{"../escape", "rcpt-../../escape", `rcpt-..\escape`, "/tmp/outside", "sha256:../../outside", "sha256:" + strings.Repeat("f", 12), "bad\x00name"} {
		if _, err := repo.GetReceipt(ctx, lookup); err == nil {
			t.Fatalf("unsafe lookup accepted: %q", lookup)
		}
	}
	after, err := os.ReadFile(filepath.Join(directory, "receipts", id+".json"))
	if err != nil || string(before) != string(after) {
		t.Fatal("reserved alias overwrote immutable receipt")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "escape") {
			t.Fatal("traversal produced a file")
		}
	}
}

func TestReceiptDigestFilenameTamperingFailsRecovery(t *testing.T) {
	for _, width := range []int{12, 64} {
		t.Run(strings.Repeat("x", width), func(t *testing.T) {
			directory := t.TempDir()
			repo, err := NewFilesystemEvidenceRepository(directory)
			if err != nil {
				t.Fatal(err)
			}
			signer, receipt := receiptFixture(t)
			id, err := repo.PutReceipt(context.Background(), receipt)
			if err != nil {
				t.Fatal(err)
			}
			// A cryptographically valid different receipt still cannot occupy this identity.
			altered := receipt
			altered.Control.ID = strings.TrimPrefix(id, "rcpt-")[:width]
			altered.Signature = ""
			altered, err = signer.SignReceipt(context.Background(), altered)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "receipts", "rcpt-"+strings.TrimPrefix(id, "rcpt-")[:width]+".json")
			data := serializedReceipt(t, altered)
			if err := os.WriteFile(path, data, 0644); err != nil {
				t.Fatal(err)
			}
			if width == 64 {
				if _, err := repo.PutReceipt(context.Background(), receipt); err == nil {
					t.Fatal("immutable corruption was overwritten or ignored")
				}
			}
			if _, err := NewFilesystemEvidenceRepository(directory); err == nil {
				t.Fatal("mismatched digest filename accepted because control ID matched suffix")
			}
			preserved, err := os.ReadFile(path)
			if err != nil || string(preserved) != string(data) {
				t.Fatal("forensic receipt bytes not preserved")
			}
		})
	}
}

func TestSafeLegacyReceiptAliasesRemainReadable(t *testing.T) {
	directory := t.TempDir()
	if _, err := NewFilesystemEvidenceRepository(directory); err != nil {
		t.Fatal(err)
	}
	_, receipt := receiptFixture(t)
	data := serializedReceipt(t, receipt)
	hash := strings.TrimPrefix(assurance.ComputeDigest(data), "sha256:")
	if err := os.MkdirAll(filepath.Join(directory, "receipts"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"rcpt-AC-6", "rcpt-" + hash[:12]} {
		if err := os.WriteFile(filepath.Join(directory, "receipts", key+".json"), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	restored, err := NewFilesystemEvidenceRepository(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"rcpt-AC-6", "rcpt-" + hash[:12], "rcpt-" + hash} {
		got, err := restored.GetReceipt(context.Background(), key)
		if err != nil || got.Signature != receipt.Signature {
			t.Fatalf("legacy lookup %s failed: %v", key, err)
		}
	}
}

func TestReceiptWritesAndRecoveryCannotFollowOutsideSymlinks(t *testing.T) {
	for _, target := range []string{"directory", "alias", "immutable"} {
		t.Run(target, func(t *testing.T) {
			directory := t.TempDir()
			outside := t.TempDir()
			repo, err := NewFilesystemEvidenceRepository(directory)
			if err != nil {
				t.Fatal(err)
			}
			_, receipt := receiptFixture(t)
			data := serializedReceipt(t, receipt)
			id := "rcpt-" + strings.TrimPrefix(assurance.ComputeDigest(data), "sha256:")
			sentinel := filepath.Join(outside, "sentinel.json")
			if err := os.WriteFile(sentinel, []byte("outside sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
			if target == "directory" {
				if err := os.Symlink(outside, filepath.Join(directory, "receipts")); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.MkdirAll(filepath.Join(directory, "receipts"), 0755); err != nil {
					t.Fatal(err)
				}
				name := "rcpt-AC-6.json"
				if target == "immutable" {
					name = id + ".json"
				}
				if err := os.Symlink(sentinel, filepath.Join(directory, "receipts", name)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := repo.PutReceipt(context.Background(), receipt); err == nil {
				t.Fatal("symlink receipt target accepted")
			}
			if _, err := NewFilesystemEvidenceRepository(directory); err == nil {
				t.Fatal("symlink receipt path restored")
			}
			after, err := os.ReadFile(sentinel)
			if err != nil || string(after) != "outside sentinel" {
				t.Fatal("outside file overwritten")
			}
			entries, err := os.ReadDir(outside)
			if err != nil || len(entries) != 1 {
				t.Fatal("receipt written outside its root")
			}
		})
	}
}
