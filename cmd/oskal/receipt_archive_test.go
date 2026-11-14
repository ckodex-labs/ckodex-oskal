package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

func TestActualCLIReceiptLookupHonorsBudgetAndConfinement(t *testing.T) {
	binary := buildCLI(t)
	directory := t.TempDir()
	store := filepath.Join(directory, "archive")
	archive, err := storage.NewFilesystemEvidenceRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "observed-file")
	if err := os.WriteFile(source, []byte("actual local receipt material"), 0600); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := receipts.NewReceiptManager(assurance.AuthorityRef{Scheme: "local", Subject: "receipt-budget-test"})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := signer.SignReceipt(t.Context(), assurance.ControlReceipt{Subject: assurance.SubjectRef{Scheme: "file", ID: source}, Control: assurance.ControlRef{Namespace: "example", ID: "receipt-only"}, State: assurance.AssuranceStateUnknown, Epoch: assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeDigest(actual)}, EvaluatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	id, err := archive.PutReceipt(t.Context(), receipt)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	standalone := filepath.Join(directory, "outside-receipt.json")
	if err := os.WriteFile(standalone, raw, 0600); err != nil {
		t.Fatal(err)
	}
	publicKeyFile := filepath.Join(directory, "trusted.pub")
	if err := os.WriteFile(publicKeyFile, []byte(signer.PublicKey()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	keyFileOutput, keyFileErr := exec.CommandContext(t.Context(), binary, "assurance", "receipt", "verify", "--receipt-file", standalone, "--public-key", publicKeyFile).CombinedOutput()
	if keyFileErr != nil || !bytes.Contains(keyFileOutput, []byte("[VERIFIED]")) {
		t.Fatalf("legacy key-file verification failed: %v %s", keyFileErr, keyFileOutput)
	}
	verify := func(want int, contains string, args ...string) []byte {
		t.Helper()
		args = append([]string{"assurance", "receipt", "verify", "--public-key", signer.PublicKey()}, args...)
		output, err := exec.CommandContext(t.Context(), binary, args...).CombinedOutput()
		code := 0
		if err != nil {
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal(err)
			}
			code = exit.ExitCode()
		}
		if code != want || !bytes.Contains(output, []byte(contains)) {
			t.Fatalf("actual receipt CLI code%d want%d: %v %s", code, want, err, output)
		}
		return output
	}
	before := archiveSnapshot(t, store)
	verify(0, "[VERIFIED]", "--receipt-id", id, "--evidence-dir", store, "--archive-max-bytes=1048576")
	verify(0, "[VERIFIED]", "--receipt-id", "rcpt-receipt-only.json", "--evidence-dir", store)
	verify(1, "evidence archive capacity exhausted", "--receipt-id", id, "--evidence-dir", store, "--archive-max-bytes=1")
	for _, bad := range []string{"../outside-receipt.json", standalone, "receipts/" + id} {
		verify(1, "unsafe receipt lookup ID", "--receipt-id", bad, "--evidence-dir", store)
	}
	verify(1, "requires --evidence-dir", "--receipt-id", id)
	verify(0, "[VERIFIED]", "--receipt-file", standalone)
	oversized := filepath.Join(directory, "oversized-valid-receipt.json")
	padded := append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), storage.MaxMetadataBytes+1-len(raw))...)
	if err := os.WriteFile(oversized, padded, 0600); err != nil {
		t.Fatal(err)
	}
	verify(1, "65536", "--receipt-file", oversized)
	link := filepath.Join(store, "receipts", "rcpt-escape.json")
	if err := os.Symlink(standalone, link); err != nil {
		t.Fatal(err)
	}
	output := verify(1, "open receipt archive", "--receipt-id", "rcpt-escape", "--evidence-dir", store)
	if bytes.Contains(output, []byte("[VERIFIED]")) {
		t.Fatal("archive symlink escaped receipt boundary")
	}
	if err := os.Rename(link, filepath.Join(directory, "retained-escape-link")); err != nil {
		t.Fatal(err)
	}
	sameArchive(t, before, archiveSnapshot(t, store))
	verify(0, "[VERIFIED]", "--receipt-id", strings.TrimPrefix(id, "rcpt-"), "--evidence-dir", store)
	t.Log("actual signed immutable/legacy receipt IDs and bounded standalone file verified; low budget, traversal, archive symlink, oversized standalone file refused without historical mutation")
}
