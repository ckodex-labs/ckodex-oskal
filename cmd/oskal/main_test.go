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
