package main

import (
	"bytes"
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

func TestCLI_ExportOSCAL(t *testing.T) {
	// 1. assessment-results
	cmdAR := NewRootCommand()
	bufAR := new(bytes.Buffer)
	cmdAR.SetOut(bufAR)
	cmdAR.SetArgs([]string{"export", "assessment-results", "--subject", "k8s://prod/payments/Deployment/payments-api"})
	if err := cmdAR.Execute(); err != nil {
		t.Fatalf("unexpected error exporting assessment results: %v", err)
	}

	// 2. component-definition
	cmdCD := NewRootCommand()
	bufCD := new(bytes.Buffer)
	cmdCD.SetOut(bufCD)
	cmdCD.SetArgs([]string{"export", "component-definition", "--component", "payments-api"})
	if err := cmdCD.Execute(); err != nil {
		t.Fatalf("unexpected error exporting component definition: %v", err)
	}

	// 3. assessment-plan
	cmdAP := NewRootCommand()
	bufAP := new(bytes.Buffer)
	cmdAP.SetOut(bufAP)
	cmdAP.SetArgs([]string{"export", "assessment-plan", "--subject", "k8s://prod/payments/Deployment/payments-api"})
	if err := cmdAP.Execute(); err != nil {
		t.Fatalf("unexpected error exporting assessment plan: %v", err)
	}

	// 4. poam
	cmdPOAM := NewRootCommand()
	bufPOAM := new(bytes.Buffer)
	cmdPOAM.SetOut(bufPOAM)
	cmdPOAM.SetArgs([]string{"export", "poam", "--subject", "k8s://prod/payments/Deployment/payments-api"})
	if err := cmdPOAM.Execute(); err != nil {
		t.Fatalf("unexpected error exporting poam: %v", err)
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
	if !strings.Contains(out, "Start the Kubernetes Validating Admission Webhook") {
		t.Fatalf("unexpected webhook help output: %s", out)
	}
}

func TestCLI_Doctor(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"doctor", "--output", "json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error executing doctor: %v", err)
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
	cmd.SetArgs([]string{"inspect", "k8s://prod/payments/Deployment/payments-api", "--output", "tree"})

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
