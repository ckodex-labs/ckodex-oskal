package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
	"github.com/google/uuid"
)

func authoredProjectionFiles(t *testing.T) (string, string, string) {
	t.Helper()
	directory := t.TempDir()
	subject := assurance.SubjectRef{Scheme: "k8s", ID: "example/Pod/material"}
	control := assurance.ControlRef{Namespace: "example", ID: "observed"}
	context := oscal.ProjectionContext{AssessmentPlanHref: "authored-plan.json", SystemSecurityPlanHref: "authored-ssp.json", ControlSource: "authored-catalog.json", ControlNamespace: control.Namespace, Component: &oscal.ComponentContext{Type: "software", Description: "Caller-authored test component; operational behavior is unassessed.", Implementations: map[string]string{control.Canonical(): "Caller-authored example narrative; no implementation determination is asserted by this test."}}, System: &oscal.SystemContext{ProfileHref: "authored-profile.json", Characteristics: oscal.OscalSystemCharacteristics{SystemIDs: []oscal.OscalSystemID{{ID: "authored-system"}}, SystemName: "authored-system", Description: "Authored example system; not a claim about a running cluster.", SystemInformation: oscal.OscalSystemInformation{InformationTypes: []oscal.OscalInformationType{{Title: "Test material", Description: "Caller-authored projection material."}}}, Status: oscal.OscalStatus{State: "other", Remarks: "Operational state is not assessed."}, AuthorizationBoundary: oscal.OscalAuthorizationBoundary{Description: "Caller-declared test boundary; enforcement is not verified."}}, Implementation: oscal.OscalSystemImplementation{Components: []oscal.OscalSSPComponent{{UUID: uuid.NewString(), Type: "this-system", Title: "authored-system", Description: "Caller-authored example component.", Status: oscal.OscalStatus{State: "other", Remarks: "Operational state is not assessed."}}}}, ControlImplementationDescription: "Caller-authored implementation narrative.", Implementations: map[string]string{control.Canonical(): "Caller-authored example narrative, not inferred from evidence."}}}
	save := func(name string, value any) string {
		path := filepath.Join(directory, name)
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	contextPath := save("context.json", context)
	contractPath := save("contract.json", assurance.EvidenceContract{ID: "authored-contract", Requirements: []assurance.EvidenceRequirement{}})
	findingsPath := save("findings.json", []assurance.Finding{{ID: uuid.NewString(), Subject: subject, Control: control, Title: "Caller-selected remediation example", Description: "Supplied finding, not inferred from UNKNOWN assurance.", DiscoveredAt: time.Now().UTC()}})
	return contextPath, contractPath, findingsPath
}

func TestProjectionCommandsActualSubprocess(t *testing.T) {
	binary := buildCLI(t)
	contextPath, contractPath, findingsPath := authoredProjectionFiles(t)
	validator, err := oscal.DefaultValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"assessment-results", "component-definition", "assessment-plan", "ssp", "poam"} {
		args := []string{"export", kind, "--projection-context", contextPath, "--subject", "k8s://example/Pod/material", "--control", "example:observed", "--component", "authored-component"}
		if kind == "assessment-plan" {
			args = append(args, "--contract-file", contractPath)
		}
		if kind == "poam" {
			args = append(args, "--findings-file", findingsPath)
		}
		command := exec.Command(binary, args...)
		output, err := command.Output()
		if err != nil {
			t.Fatalf("actual %s command failed: %v\n%s", kind, err, output)
		}
		report, err := validator.Validate(output, kind)
		if err != nil || !report.Valid {
			t.Fatalf("actual %s command violated pinned schema: %+v %v\n%s", kind, report, err, output)
		}
		if kind == "assessment-results" && (!strings.Contains(string(output), "UNKNOWN") || strings.Contains(string(output), "ASSURED")) {
			t.Fatalf("unverified export invented assurance: %s", output)
		}
		t.Logf("actual CLI %s exit0, NIST1.2.3 structural validation passed", kind)
	}
	for _, args := range [][]string{{"export", "assessment-results", "--subject", "k8s://example/Pod/material", "--control", "example:observed"}, {"export", "poam", "--projection-context", contextPath, "--subject", "k8s://example/Pod/material"}} {
		command := exec.Command(binary, args...)
		output, err := command.Output()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || len(output) != 0 {
			t.Fatalf("missing mandatory projection facts did not fail without output: %s %v", output, err)
		}
	}
}

func TestUntrustedMaterialAndReadonlyActualSubprocess(t *testing.T) {
	binary := buildCLI(t)
	directory := t.TempDir()
	store := filepath.Join(directory, "store")
	manifest := filepath.Join(directory, "manifest.yaml")
	if err := os.WriteFile(manifest, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  namespace: example\n  name: material\nspec:\n  containers:\n    - name: pause\n      image: registry.k8s.io/pause:3.10\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result := runCLIJSON(t, binary, 0, "record", "manifest", "--file", manifest, "--evidence-dir", store)
	if result["status"] != "RECORDED_UNTRUSTED" {
		t.Fatalf("material asserted admission: %+v", result)
	}
	if _, err := os.Stat(filepath.Join(store, "receipts")); !os.IsNotExist(err) {
		t.Fatalf("manifest recording manufactured receipts: %v", err)
	}
	result = runCLIJSON(t, binary, 0, "utcp", "call", "get_assurance_state", "--subject", "k8s://example/Pod/material", "--evidence-dir", store)
	state := result["output"].(map[string]any)
	if state["state"] != "UNKNOWN" || state["verified_envelopes"].(float64) != 0 || state["supplied_envelopes"].(float64) != 1 {
		t.Fatalf("raw material was promoted: %+v", state)
	}
	absent := filepath.Join(directory, "never-created")
	missingStore := exec.Command(binary, "utcp", "call", "get_assurance_state", "--subject", "k8s://example/Pod/material", "--evidence-dir", absent)
	if _, err := missingStore.Output(); err == nil {
		t.Fatal("missing configured store did not propagate its read error")
	}
	if _, err := os.Stat(absent); !os.IsNotExist(err) {
		t.Fatalf("read-only call created storage: %v", err)
	}
	retiredStore := filepath.Join(directory, "retired-store")
	command := exec.Command(binary, "record", "admission", "--file", manifest, "--evidence-dir", retiredStore)
	if _, err := command.Output(); err == nil {
		t.Fatal("file-only admission claim still succeeds")
	}
	if _, err := os.Stat(retiredStore); !os.IsNotExist(err) {
		t.Fatalf("retired admission command mutated storage: %v", err)
	}
}
