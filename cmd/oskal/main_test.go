package main

import (
	"bytes"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_HelpAndVersion(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error executing --help: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "OSKAL is the Continuous Kubernetes Assurance Runtime") {
		t.Fatalf("unexpected help output: %s", out)
	}

	cmdVer := NewRootCommand()
	bufVer := new(bytes.Buffer)
	cmdVer.SetOut(bufVer)
	cmdVer.SetErr(bufVer)
	cmdVer.SetArgs([]string{"version"})
	if err := cmdVer.Execute(); err != nil {
		t.Fatalf("unexpected error executing version: %v", err)
	}
	if !strings.Contains(bufVer.String(), "oskal v1.0.1") {
		t.Fatalf("unexpected version output: %s", bufVer.String())
	}
}

func TestCLI_AssuranceExplain(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"assurance", "explain", "k8s://prod/payments/Deployment/payments-api", "--control", "ckodex:least-privilege"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error executing assurance explain: %v", err)
	}
}

func TestCLI_ExportOSCALRequiresExplicitContext(t *testing.T) {
	cmd := NewRootCommand()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"export", "assessment-results", "--subject", "k8s://example/Pod/material", "--control", "example:observed"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "projection-context") {
		t.Fatalf("missing OSCAL context was accepted: %v", err)
	}
}

func TestCLI_ParseSubjectURI(t *testing.T) {
	sub1 := parseSubjectURI("k8s://prod/payments/Deployment/payments-api")
	if sub1.Scheme != "k8s" || sub1.ID != "prod/payments/Deployment/payments-api" {
		t.Fatalf("unexpected parsed subject: %+v", sub1)
	}

	sub2 := parseSubjectURI("payments/api")
	if sub2.Scheme != "k8s" || sub2.ID != "payments/api" {
		t.Fatalf("unexpected parsed subject: %+v", sub2)
	}
}

func TestCLI_WebhookHelp(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"webhook", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error executing webhook --help: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "declared Pod settings") || strings.Contains(out, "attestation") {
		t.Fatalf("unexpected webhook help output: %s", out)
	}
}

func TestCLI_Doctor(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"doctor", "--output", "json"})

	if err := cmd.Execute(); err != nil && commandExitCode(err) == 1 {
		t.Fatalf("doctor failed to run: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"Runtime Substrate"`) || !strings.Contains(out, `"NIST OSCAL v1.2.3 Schemas"`) {
		t.Fatalf("unexpected doctor output: %s", out)
	}
}

func TestCLI_Inspect(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"inspect", "k8s://prod/payments/Deployment/payments-api", "--output", "tree", "--control", "example:observed"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error executing inspect: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Channel 1: Telemetry") || !strings.Contains(out, "Channel 4: Evidence Trace") {
		t.Fatalf("unexpected inspect tree output: %s", out)
	}
}

func TestCLI_Scaffold(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"scaffold", "nist-sp-800-53", "--workload", "order-service", "--output", "yaml"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error executing scaffold: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "kind: EvidenceContract") || !strings.Contains(out, "kind: ControlBinding") {
		t.Fatalf("unexpected scaffold output: %s", out)
	}
}

func TestCLI_CockpitOnce(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"cockpit", "--once"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error executing cockpit --once: %v", err)
	}
}

func TestCLI_Config(t *testing.T) {
	// 1. config view
	cmdView := NewRootCommand()
	bufView := new(bytes.Buffer)
	cmdView.SetOut(bufView)
	cmdView.SetErr(bufView)
	cmdView.SetArgs([]string{"config", "view"})

	if err := cmdView.Execute(); err != nil {
		t.Fatalf("unexpected error executing config view: %v", err)
	}
	outView := bufView.String()
	if !strings.Contains(outView, "CONFIG FILE:") || !strings.Contains(outView, "PROFILE:") {
		t.Fatalf("unexpected config view output: %s", outView)
	}

	// 2. config init
	tmpFile := t.TempDir() + "/.oskal.yaml"
	cmdInit := NewRootCommand()
	bufInit := new(bytes.Buffer)
	cmdInit.SetOut(bufInit)
	cmdInit.SetErr(bufInit)
	cmdInit.SetArgs([]string{"config", "init", tmpFile})

	if err := cmdInit.Execute(); err != nil {
		t.Fatalf("unexpected error executing config init: %v", err)
	}
	outInit := bufInit.String()
	if !strings.Contains(outInit, "Created default configuration file") {
		t.Fatalf("unexpected config init output: %s", outInit)
	}
}

func TestCLI_Prune(t *testing.T) {
	tmpDir := t.TempDir()
	if _, err := storage.NewFilesystemEvidenceRepository(tmpDir); err != nil {
		t.Fatal(err)
	}
	cmdPrune := NewRootCommand()
	bufPrune := new(bytes.Buffer)
	cmdPrune.SetOut(bufPrune)
	cmdPrune.SetErr(bufPrune)
	cmdPrune.SetArgs([]string{"prune", "--evidence-dir", tmpDir, "--dry-run", "--older-than", "1h"})

	if err := cmdPrune.Execute(); err != nil {
		t.Fatalf("unexpected error executing prune: %v", err)
	}
	outPrune := bufPrune.String()
	if !strings.Contains(outPrune, "DRY-RUN (would prune): 0 envelopes") {
		t.Fatalf("unexpected prune output: %s", outPrune)
	}
}

func TestCLI_UTCPCommands(t *testing.T) {
	// 1. oskal utcp manual
	cmdManual := NewRootCommand()
	bufManual := new(bytes.Buffer)
	cmdManual.SetOut(bufManual)
	cmdManual.SetErr(bufManual)
	cmdManual.SetArgs([]string{"utcp", "manual", "--transport", "http"})
	if err := cmdManual.Execute(); err != nil {
		t.Fatalf("utcp manual failed: %v", err)
	}
	if !strings.Contains(bufManual.String(), `"utcp_version": "1.0.1"`) {
		t.Fatalf("unexpected utcp manual output: %s", bufManual.String())
	}

	// 2. oskal utcp validate
	manualPath := filepath.Join(t.TempDir(), "utcp.json")
	if err := os.WriteFile(manualPath, bufManual.Bytes(), 0600); err != nil {
		t.Fatalf("failed to write utcp.json: %v", err)
	}
	cmdVal := NewRootCommand()
	bufVal := new(bytes.Buffer)
	cmdVal.SetOut(bufVal)
	cmdVal.SetErr(bufVal)
	cmdVal.SetArgs([]string{"utcp", "validate", manualPath})
	if err := cmdVal.Execute(); err != nil {
		t.Fatalf("utcp validate failed: %v", err)
	}
	if !strings.Contains(bufVal.String(), "[PASS]") {
		t.Fatalf("expected [PASS] in utcp validate output, got: %s", bufVal.String())
	}

	// 3. oskal utcp search
	cmdSearch := NewRootCommand()
	bufSearch := new(bytes.Buffer)
	cmdSearch.SetOut(bufSearch)
	cmdSearch.SetErr(bufSearch)
	cmdSearch.SetArgs([]string{"utcp", "search", "doctor"})
	if err := cmdSearch.Execute(); err != nil {
		t.Fatalf("utcp search failed: %v", err)
	}
	if !strings.Contains(bufSearch.String(), `"run_doctor"`) {
		t.Fatalf("expected run_doctor in search output, got: %s", bufSearch.String())
	}

	// 4. oskal utcp call
	cmdCall := NewRootCommand()
	bufCall := new(bytes.Buffer)
	cmdCall.SetOut(bufCall)
	cmdCall.SetErr(bufCall)
	cmdCall.SetArgs([]string{"utcp", "call", "get_assurance_state", "--args", `{"subject":"k8s://prod/payments/Deployment/payments-api"}`})
	if err := cmdCall.Execute(); err != nil {
		t.Fatalf("utcp call failed: %v", err)
	}
	if !strings.Contains(bufCall.String(), `"tool_name": "get_assurance_state"`) {
		t.Fatalf("unexpected utcp call output: %s", bufCall.String())
	}

	// 5. oskal utcp sdk-config
	cmdSDK := NewRootCommand()
	bufSDK := new(bytes.Buffer)
	cmdSDK.SetOut(bufSDK)
	cmdSDK.SetErr(bufSDK)
	cmdSDK.SetArgs([]string{"utcp", "sdk-config", "--lang", "all"})
	if err := cmdSDK.Execute(); err != nil {
		t.Fatalf("utcp sdk-config failed: %v", err)
	}
	for _, repo := range []string{
		"universal-tool-calling-protocol/go-utcp",
		"universal-tool-calling-protocol/rs-utcp",
		"universal-tool-calling-protocol/typescript-utcp",
		"universal-tool-calling-protocol/python-utcp",
		"universal-tool-calling-protocol/utcp-mcp",
	} {
		if !strings.Contains(bufSDK.String(), repo) {
			t.Fatalf("expected %s in sdk-config output, got: %s", repo, bufSDK.String())
		}
	}

	// 6. F-03: oskal utcp list-tools and top-level oskal list-tools (for go-utcp CLI discovery)
	for _, args := range [][]string{{"utcp", "list-tools"}, {"list-tools"}} {
		cmdLT := NewRootCommand()
		bufLT := new(bytes.Buffer)
		cmdLT.SetOut(bufLT)
		cmdLT.SetErr(bufLT)
		cmdLT.SetArgs(args)
		if err := cmdLT.Execute(); err != nil {
			t.Fatalf("list-tools (%v) failed: %v", args, err)
		}
		if !strings.Contains(bufLT.String(), `"tools"`) || !strings.Contains(bufLT.String(), `"get_assurance_state"`) {
			t.Fatalf("unexpected list-tools (%v) output: %s", args, bufLT.String())
		}
	}

	// 7. F-03: oskal utcp call with --<key> <val> flags and unsubstituted UTCP_ARG_<arg>_UTCP_END placeholder
	cmdFlags := NewRootCommand()
	bufFlags := new(bytes.Buffer)
	cmdFlags.SetOut(bufFlags)
	cmdFlags.SetErr(bufFlags)
	cmdFlags.SetArgs([]string{
		"utcp", "call", "explain_claim",
		"--subject", "k8s://prod/payments/Deployment/payments-api",
		"--control", "example:observed",
	})
	if err := cmdFlags.Execute(); err != nil {
		t.Fatalf("utcp call with --<key> flags failed: %v", err)
	}
	if !strings.Contains(bufFlags.String(), `"tool_name": "explain_claim"`) {
		t.Fatalf("unexpected utcp call with flags output: %s", bufFlags.String())
	}

	// 8. F-03: top-level oskal call <provider> <tool> with JSON on stdin (for go-utcp / rs-utcp)
	cmdStdin := NewRootCommand()
	bufStdin := new(bytes.Buffer)
	cmdStdin.SetOut(bufStdin)
	cmdStdin.SetErr(bufStdin)
	cmdStdin.SetIn(strings.NewReader(`{"subject":"k8s://prod/payments/Deployment/payments-api"}`))
	cmdStdin.SetArgs([]string{"call", "ckodex_oskal", "get_assurance_state"})
	if err := cmdStdin.Execute(); err != nil {
		t.Fatalf("top-level call with stdin failed: %v", err)
	}
	if !strings.Contains(bufStdin.String(), `"tool_name": "get_assurance_state"`) {
		t.Fatalf("unexpected top-level call output: %s", bufStdin.String())
	}

	// 9. F-03 edge case: --<key>=<value> containing embedded '=' characters
	cmdEq := NewRootCommand()
	bufEq := new(bytes.Buffer)
	cmdEq.SetOut(bufEq)
	cmdEq.SetErr(bufEq)
	cmdEq.SetArgs([]string{
		"utcp", "call", "get_assurance_state",
		"--subject=k8s://prod/payments/Deployment/payments-api?digest=sha256=abc==",
	})
	if err := cmdEq.Execute(); err != nil {
		t.Fatalf("utcp call with embedded '=' in --key=value failed: %v", err)
	}
	if !strings.Contains(bufEq.String(), "digest=sha256=abc==") {
		t.Fatalf("expected embedded '=' value preserved in output, got: %s", bufEq.String())
	}
}
