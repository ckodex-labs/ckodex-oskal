package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/diagnostics"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func archiveSnapshot(t *testing.T, directory string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		result[name] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func sameArchive(t *testing.T, before, after map[string]string) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatal("archive object set changed during refusal")
	}
	for name, data := range before {
		if after[name] != data {
			t.Fatalf("historical archive bytes changed: %s", name)
		}
	}
}
func TestActualCLIArchiveBudgetsRefuseWithoutDeletingHistory(t *testing.T) {
	binary := buildCLI(t)
	directory := t.TempDir()
	store := filepath.Join(directory, "store")
	manifest := filepath.Join(directory, "manifest.yaml")
	if err := os.WriteFile(manifest, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  namespace: example\n  name: archived-material\ndata:\n  authored: test-material\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"record", "manifest", "--file", manifest, "--archive-max-bytes=0"}, {"record", "manifest", "--file", manifest, "--archive-max-entries=0"}, {"utcp", "call", "run_doctor", "--archive-max-bytes=0", "--lease-kubeconfig", filepath.Join(directory, "missing-kubeconfig")}, {"utcp", "call", "run_doctor", "--archive-max-entries=1000001", "--lease-kubeconfig", filepath.Join(directory, "missing-kubeconfig")}} {
		absent := filepath.Join(t.TempDir(), "never-created")
		args = append(args, "--evidence-dir", absent)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, args...)
		output, err := command.CombinedOutput()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || !bytes.Contains(output, []byte("archive limits require")) {
			t.Fatalf("invalid archive limits did not fail before execution/files: %v %s", err, output)
		}
		if _, err := os.Stat(absent); !os.IsNotExist(err) {
			t.Fatalf("invalid limit created archive: %v", err)
		}
	}
	runCLIJSON(t, binary, 0, "record", "manifest", "--file", manifest, "--evidence-dir", store, "--archive-max-bytes=65536", "--archive-max-entries=100")
	before := archiveSnapshot(t, store)
	refuse := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, args...)
		output, err := command.CombinedOutput()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || !bytes.Contains(output, []byte("evidence archive capacity exhausted")) {
			t.Fatalf("small actual budget did not propagate refusal: %v %s", err, output)
		}
	}
	refuse("record", "manifest", "--file", manifest, "--evidence-dir", store, "--archive-max-bytes=1")
	refuse("assurance", "state", "k8s://example/ConfigMap/archived-material", "--evidence-dir", store, "--archive-max-bytes=1")
	refuse("utcp", "call", "get_assurance_state", "--subject", "k8s://example/ConfigMap/archived-material", "--evidence-dir", store, "--archive-max-bytes=1")
	refuse("cockpit", "--once", "--subject", "k8s://example/ConfigMap/archived-material", "--evidence-dir", store, "--archive-max-bytes=1")
	refuse("utcp", "call", "get_assurance_state", "--subject", "k8s://example/ConfigMap/archived-material", "--evidence-dir", store, "--archive-max-entries=1")
	pki := createGRPCTestPKI(t)
	refuse("serve", "--port=0", "--tls-cert-file", pki.serverCert, "--tls-key-file", pki.serverKey, "--evidence-dir", store, "--archive-max-bytes=1")
	doctor := exec.CommandContext(t.Context(), binary, "doctor", "--output=json", "--evidence-dir", store, "--archive-max-bytes=1")
	doctor.Env = append(os.Environ(), "KUBECONFIG="+filepath.Join(directory, "missing-config"), "SPIFFE_ENDPOINT_SOCKET="+filepath.Join(directory, "missing.sock"), "TUF_ROOT="+filepath.Join(directory, "missing-tuf"))
	doctorOutput, doctorErr := doctor.Output()
	if exit, ok := doctorErr.(*exec.ExitError); !ok || exit.ExitCode() != 3 {
		t.Fatalf("actual doctor did not report failed archive budget: %v %s", doctorErr, doctorOutput)
	}
	var report diagnostics.DoctorReport
	if err := json.Unmarshal(doctorOutput, &report); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, check := range report.Checks {
		if strings.Contains(check.Message, "evidence archive capacity exhausted") {
			found = true
		}
	}
	if !found {
		t.Fatalf("doctor hid archive refusal: %s", doctorOutput)
	}

	// MCP transports an archive refusal as an explicit tool error, not a success payload.
	mcp := exec.CommandContext(t.Context(), binary, "mcp", "--evidence-dir", store, "--archive-max-bytes=1")
	mcp.Stdin = strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"get_assurance_state\",\"arguments\":{\"subject\":\"k8s://example/ConfigMap/archived-material\"}}}\n")
	output, err := mcp.Output()
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		t.Fatal(err)
	}
	if !response.Result.IsError || len(response.Result.Content) != 1 || !strings.Contains(response.Result.Content[0].Text, "evidence archive capacity exhausted") {
		t.Fatalf("MCP archive refusal lost: %s", output)
	}
	sameArchive(t, before, archiveSnapshot(t, store))
	result := runCLIJSON(t, binary, 0, "utcp", "call", "get_assurance_state", "--subject", "k8s://example/ConfigMap/archived-material", "--evidence-dir", store, "--archive-max-bytes=65536", "--archive-max-entries=100")
	state := result["output"].(map[string]any)
	if state["state"] != "UNKNOWN" || state["supplied_envelopes"].(float64) != 1 {
		t.Fatalf("reviewed higher budget did not preserve untrusted history: %+v", state)
	}
	sameArchive(t, before, archiveSnapshot(t, store))
	t.Log("actual CLI direct, UTCP, MCP, cockpit refused lower budgets; invalid flags made no archive; higher reviewed budgets reopened identical history")
}
