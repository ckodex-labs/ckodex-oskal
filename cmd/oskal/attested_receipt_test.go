package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

// Execute the production-registered command in an isolated compiled subprocess.
func TestAttestedReceiptCommandProcess(t *testing.T) {
	if os.Getenv("OSKAL_ATTESTED_RECEIPT_COMMAND_CHILD") != "1" {
		return
	}
	root := NewRootCommand()
	for i, arg := range os.Args {
		if arg == "--" {
			root.SetArgs(os.Args[i+1:])
			os.Exit(commandExitCode(root.ExecuteContext(context.Background())))
		}
	}
	t.Fatal("subprocess command arguments missing")
}

func TestAttestedReceiptCompiledCommandStatesAndInputRejection(t *testing.T) {
	m, err := receipts.NewReceiptManager(assurance.AuthorityRef{Scheme: "local", Subject: "compiled-artifact-test"})
	if err != nil {
		t.Fatal(err)
	}
	// Generated Ed25519 signatures authenticate protocol fixtures, not a live TPM.
	now := time.Now().UTC().Add(-time.Second)
	d := assurance.ComputeStringDigest("CLI protocol conformance fixture")
	a := assurance.TelemetryAttestation{SessionID: d, SourceInstance: "fixture", MeasurementDigest: d, ExportKeyDigest: d, ChannelDigest: d, RootKind: "SOFTWARE_TPM", RootLabel: "software TPM root \u2014 not hardware-backed", Caveats: []string{"Signed fixture claim; runtime quote and policy are not independently verified."}, StartedAt: now.Add(-time.Minute), VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	telemetry := assurance.TelemetryEvidence{Attestation: &a, Integrity: assurance.TelemetryIntegrity{State: assurance.AssuranceStateVerified, RootKind: a.RootKind, RootLabel: a.RootLabel, Caveats: a.Caveats, SessionID: d, WindowStart: now.Add(-2 * time.Second), WindowEnd: now.Add(-time.Second), ValidUntil: a.ExpiresAt}, RecordDigest: d, QuoteDigest: d}
	r := assurance.ControlReceipt{Subject: assurance.SubjectRef{Scheme: "file", ID: "protocol-fixture"}, Control: assurance.ControlRef{Namespace: "test", ID: "fixture"}, State: assurance.AssuranceStateVerified, Epoch: assurance.AssuranceEpoch{SubjectDigest: d, ImplementationDigest: d, PolicyDigest: d, AuthorityDigest: d, EnvironmentDigest: d}, EvidenceRoot: d, EvaluatedAt: now}
	write := func(name string, state assurance.AssuranceState, context assurance.TelemetryEvidence, validUntil time.Time) string {
		t.Helper()
		input := r
		input.State = state
		raw, err := m.SignAttestedReceipt(t.Context(), input, context, validUntil)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	positive := write("positive.dsse", assurance.AssuranceStateVerified, telemetry, telemetry.Integrity.ValidUntil)
	keyFile := filepath.Join(t.TempDir(), "trusted.pub")
	if err := os.WriteFile(keyFile, []byte(m.PublicKey()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	unknownContext := telemetry
	unknownContext.Integrity.State = assurance.AssuranceStateUnknown
	unknownContext.Integrity.Reasons = []string{"missing scheduled heartbeat"}
	unknownContext.Integrity.Gaps = []assurance.TelemetryGap{{Kind: "HEARTBEAT", First: 2, Last: 3}}
	unknown := write("unknown.dsse", assurance.AssuranceStateUnknown, unknownContext, unknownContext.Integrity.ValidUntil)
	failed := write("failed.dsse", assurance.AssuranceStateFailed, telemetry, telemetry.Integrity.ValidUntil)
	// The required evidence has expired while the source window remains live.
	expired := write("expired.dsse", assurance.AssuranceStateVerified, telemetry, now.Add(100*time.Millisecond))
	for _, test := range []struct {
		path  string
		code  int
		state assurance.AssuranceState
	}{
		{positive, 0, assurance.AssuranceStateVerified}, {unknown, 2, assurance.AssuranceStateUnknown}, {failed, 3, assurance.AssuranceStateFailed}, {expired, 2, assurance.AssuranceStateUnknown},
	} {
		for _, key := range []string{m.PublicKey(), keyFile} {
			stdout, stderr, code := attestedSubprocess(t, "--receipt-file", test.path, "--public-key", key, "--json")
			if code != test.code || !strings.Contains(stderr, "signature valid") || strings.Contains(stderr, "Error:") || strings.Count(stderr, "signature valid") != 1 {
				t.Fatalf("CLI result %d want %d: stdout=%s stderr=%s", code, test.code, stdout, stderr)
			}
			var result receipts.AttestedReceiptVerification
			if err := json.Unmarshal([]byte(stdout), &result); err != nil {
				t.Fatalf("stdout mixed result and status: %v %s", err, stdout)
			}
			if result.EffectiveState != test.state || !strings.Contains(result.Scope, "not independently reverified") {
				t.Fatalf("CLI result lost assessment/scope: %+v", result)
			}
		}
	}
	root := NewRootCommand()
	var reusedOut, reusedErr bytes.Buffer
	root.SetOut(&reusedOut)
	root.SetErr(&reusedErr)
	for _, test := range []struct {
		args []string
		code int
	}{
		{[]string{"--receipt-file", unknown, "--public-key", m.PublicKey()}, 2},
		{[]string{"--receipt-file", positive, "--public-key", strings.Repeat("z", 64)}, 1},
		{[]string{"--receipt-file", failed, "--public-key", m.PublicKey()}, 3},
		{[]string{"--public-keey", m.PublicKey()}, 1},
	} {
		reusedOut.Reset()
		reusedErr.Reset()
		root.SetArgs(append([]string{"assurance", "receipt", "verify-attested"}, test.args...))
		err := root.ExecuteContext(t.Context())
		code := commandExitCode(err)
		if code != test.code {
			t.Fatalf("reused command exit %d, want %d: %q", code, test.code, reusedErr.String())
		}
		if code == 2 || code == 3 {
			if !strings.Contains(reusedErr.String(), "signature valid") || strings.Contains(reusedErr.String(), "Error:") {
				t.Fatalf("reused command mislabeled assessment: %d %q", code, reusedErr.String())
			}
		} else if code != 1 || !strings.Contains(reusedErr.String(), "Error:") || reusedOut.Len() != 0 {
			t.Fatalf("reused command suppressed genuine error: %d %q %q", code, reusedOut.String(), reusedErr.String())
		}
	}
	stdout, stderr, code := attestedSubprocess(t, "--help")
	if code != 0 || stderr != "" || !strings.Contains(stdout, "--public-key") || !strings.Contains(stdout, "key file") || strings.Contains(stdout, "--server") || strings.Contains(stdout, "--config") || strings.Contains(stdout, "Global Flags:") {
		t.Fatalf("standalone help advertises rejected flags or omits key-file input: %d %q %q", code, stdout, stderr)
	}
	for _, args := range [][]string{
		{"--receipt-file", positive, "--public-keey", m.PublicKey()},
		{"--receipt-file", "/must-not-be-opened", "--public-key", strings.Repeat("z", 64)},
		{"--receipt-file", positive, "--public-key", m.PublicKey(), "--expected-authority", "invalid"},
		{"--config", "/must-not-be-opened", "--receipt-file", positive, "--public-key", m.PublicKey()},
		{"--receipt-file", "/must-not-be-opened", "--public-key", "/must-not-be-opened.pub", "--expected-authority", "invalid"},
		{"--server", "invalid", "--receipt-file", positive, "--public-key", keyFile},
	} {
		stdout, stderr, code := attestedSubprocess(t, args...)
		if code != 1 || stdout != "" || strings.Contains(stderr, "no such file") {
			t.Fatalf("invalid flags/trust input reached I/O or stdout: %d %q %q", code, stdout, stderr)
		}
		if strings.Contains(strings.Join(args, " "), "public-keey") && !strings.Contains(stderr, "use --receipt-file") {
			t.Fatal("unknown flag omitted correction guidance")
		}
	}
	badKeyFile := filepath.Join(t.TempDir(), "bad.pub")
	for _, raw := range [][]byte{[]byte("not a public key"), bytes.Repeat([]byte("a"), 4097)} {
		if err := os.WriteFile(badKeyFile, raw, 0600); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := attestedSubprocess(t, "--receipt-file", "/receipt-must-not-be-opened", "--public-key", badKeyFile)
		if code != 1 || stdout != "" || !strings.Contains(stderr, "Error:") || strings.Contains(stderr, "receipt-must-not-be-opened") {
			t.Fatalf("bad key file reached receipt or lost error: %d %q %q", code, stdout, stderr)
		}
	}
	other, err := receipts.NewReceiptManager(assurance.AuthorityRef{Scheme: "local", Subject: "wrong-test-key"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badKeyFile, []byte(other.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = attestedSubprocess(t, "--receipt-file", positive, "--public-key", badKeyFile)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "Error:") {
		t.Fatalf("wrong key file was not a run failure: %d %q %q", code, stdout, stderr)
	}
	oversized := filepath.Join(t.TempDir(), "oversized.dsse")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte("x"), (2<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, _, code = attestedSubprocess(t, "--receipt-file", oversized, "--public-key", m.PublicKey())
	if code != 1 || stdout != "" {
		t.Fatal("oversized artifact produced a verification result")
	}
}

func attestedSubprocess(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	commandArgs := []string{"-test.run=^TestAttestedReceiptCommandProcess$", "--", "assurance", "receipt", "verify-attested"}
	command := exec.CommandContext(t.Context(), executable, append(commandArgs, args...)...)
	command.Env = append(os.Environ(), "OSKAL_ATTESTED_RECEIPT_COMMAND_CHILD=1")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err = command.Run()
	code := 0
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}
