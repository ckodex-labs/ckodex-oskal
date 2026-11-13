package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildCLI(t *testing.T) string {
	t.Helper()
	if binary := os.Getenv("OSKAL_CLI_TEST_BINARY"); binary != "" {
		if _, err := os.Stat(binary); err != nil {
			t.Fatal(err)
		}
		return binary
	}
	binary := filepath.Join(t.TempDir(), "oskal")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual CLI: %v\n%s", err, output)
	}
	return binary
}

func runCLIJSON(t *testing.T, binary string, wantCode int, args ...string) map[string]any {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	if code != wantCode {
		t.Fatalf("CLI %v exited %d, want%d\nstdout=%s\nstderr=%s", args, code, wantCode, output, stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("CLI stdout must be exactly one JSON object: %v\n%s\nstderr=%s", err, output, stderr.String())
	}
	t.Logf("actual CLI exit=%d JSONstatus=%v", code, result["status"])
	return result
}

func TestBackendCommandsActualSubprocess(t *testing.T) {
	binary := buildCLI(t)
	fixtures, err := filepath.Abs("../../internal/adapters/sigstore/testdata")
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(fixtures, "trusted_root.json")
	rootBytes, err := os.ReadFile(root)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(rootBytes)
	pin := "sha256:" + hex.EncodeToString(sum[:])
	issuer := "https://token.actions.githubusercontent.com"
	signer := "https://github.com/ckodex-labs/ckodex-oskal/.github/workflows/release.yml@refs/heads/p1/release"
	args := []string{"verify", "bundle", "--bundle", filepath.Join(fixtures, "checksums.sigstore.json"), "--artifact", filepath.Join(fixtures, "checksums.txt"), "--trusted-root", root, "--trusted-root-sha256", pin, "--issuer", issuer, "--signer", signer}
	result := runCLIJSON(t, binary, 0, args...)
	if result["status"] != "VERIFIED" || result["verification"].(map[string]any)["signer"] != signer {
		t.Fatalf("published real Sigstore bundle not verified: %+v", result)
	}
	wrong := append([]string(nil), args...)
	wrong[len(wrong)-1] = signer + "-wrong"
	result = runCLIJSON(t, binary, 3, wrong...)
	if result["status"] != "DENIED" {
		t.Fatal("wrong signer was accepted")
	}
	wrong = append([]string(nil), args...)
	for i, value := range wrong {
		if value == "--trusted-root-sha256" {
			wrong[i+1] = "sha256:" + strings.Repeat("0", 64)
		}
	}
	runCLIJSON(t, binary, 3, wrong...)
	changed := filepath.Join(t.TempDir(), "changed-artifact")
	if err := os.WriteFile(changed, []byte("different actual artifact bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	wrong = append([]string(nil), args...)
	for i, value := range wrong {
		if value == "--artifact" {
			wrong[i+1] = changed
		}
	}
	runCLIJSON(t, binary, 3, wrong...)
	identity := runCLIJSON(t, binary, 2, "identity", "--workload-api", "unix://"+filepath.Join(t.TempDir(), "missing.sock"), "--spiffe-id", "spiffe://phase1.oskal.test/cli", "--timeout", "100ms")
	if identity["status"] != "UNKNOWN" {
		t.Fatalf("unavailable SPIRE backend manufactured identity: %+v", identity)
	}
}
