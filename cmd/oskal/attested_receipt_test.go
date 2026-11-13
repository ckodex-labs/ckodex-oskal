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

// This is the actual compiled command in a subprocess, with root registration
// performed only by this harness. Production registration remains the root's task.
func TestAttestedReceiptCommandProcess(t *testing.T) {
	if os.Getenv("OSKAL_ATTESTED_RECEIPT_COMMAND_CHILD") != "1" {
		return
	}
	root := NewRootCommand()
	receipt, _, err := root.Find([]string{"assurance", "receipt"})
	if err != nil {
		t.Fatal(err)
	}
	receipt.AddCommand(newGuestReceiptVerifyCommand())
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
	write := func(name string, state assurance.AssuranceState, context assurance.TelemetryEvidence) string {
		t.Helper()
		input := r
		input.State = state
		raw, err := m.SignAttestedReceipt(t.Context(), input, context)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	positive := write("positive.dsse", assurance.AssuranceStateVerified, telemetry)
	unknownContext := telemetry
	unknownContext.Integrity.State = assurance.AssuranceStateUnknown
	unknownContext.Integrity.Reasons = []string{"missing scheduled heartbeat"}
	unknownContext.Integrity.Gaps = []assurance.TelemetryGap{{Kind: "HEARTBEAT", First: 2, Last: 3}}
	unknown := write("unknown.dsse", assurance.AssuranceStateUnknown, unknownContext)
	failed := write("failed.dsse", assurance.AssuranceStateFailed, telemetry)
	expiredContext := telemetry
	expiredContext.Integrity.ValidUntil = now.Add(100 * time.Millisecond)
	expired := write("expired.dsse", assurance.AssuranceStateVerified, expiredContext)
	for _, test := range []struct {
		path  string
		code  int
		state assurance.AssuranceState
	}{
		{positive, 0, assurance.AssuranceStateVerified}, {unknown, 2, assurance.AssuranceStateUnknown}, {failed, 3, assurance.AssuranceStateFailed}, {expired, 2, assurance.AssuranceStateUnknown},
	} {
		stdout, stderr, code := attestedSubprocess(t, "--receipt-file", test.path, "--public-key", m.PublicKey(), "--json")
		if code != test.code || !strings.Contains(stderr, "signature valid") {
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
	for _, args := range [][]string{
		{"--receipt-file", positive, "--public-keey", m.PublicKey()},
		{"--receipt-file", "/must-not-be-opened", "--public-key", "not-a-key"},
		{"--receipt-file", positive, "--public-key", m.PublicKey(), "--expected-authority", "invalid"},
		{"--config", "/must-not-be-opened", "--receipt-file", positive, "--public-key", m.PublicKey()},
	} {
		stdout, stderr, code := attestedSubprocess(t, args...)
		if code != 1 || stdout != "" || strings.Contains(stderr, "no such file") {
			t.Fatalf("invalid flags/trust input reached I/O or stdout: %d %q %q", code, stdout, stderr)
		}
		if strings.Contains(strings.Join(args, " "), "public-keey") && !strings.Contains(stderr, "use --receipt-file") {
			t.Fatal("unknown flag omitted correction guidance")
		}
	}
	oversized := filepath.Join(t.TempDir(), "oversized.dsse")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte("x"), (2<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, _, code := attestedSubprocess(t, "--receipt-file", oversized, "--public-key", m.PublicKey())
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
