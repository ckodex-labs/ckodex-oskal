package integration

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCLIHonestStateReporting(t *testing.T) {
	// Exercise fail-closed callers without treating unsigned material or local
	// manifest validation as successful admission. Supplied-context projection
	// and independent receipt cryptography have their own component tests.
	binary := filepath.Join(t.TempDir(), "oskal-test")
	build, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(build, "go", "build", "-o", binary, "../../cmd/oskal")
	command.WaitDelay = 2 * time.Second
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build whole CLI package: %v\n%s", err, output)
	}
	directory := t.TempDir()
	config := filepath.Join(directory, "config.json")
	if err := os.WriteFile(config, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		prefix := []string{"--config", config, "--server=", "--evidence-dir="}
		command := exec.CommandContext(ctx, binary, append(prefix, args...)...)
		command.Dir = directory
		command.WaitDelay = time.Second
		var output, diagnostic bytes.Buffer
		command.Stdout, command.Stderr = &output, &diagnostic
		err := command.Run()
		return output.String(), diagnostic.String(), err
	}
	subject := "k8s://example/Pod/material"
	state, diagnostic, err := run("assurance", "state", subject)
	if err != nil || !strings.Contains(state, "STATE:           UNKNOWN") || !strings.Contains(state, "EVIDENCE ROOT:   none") {
		t.Fatalf("missing evidence must remain UNKNOWN without a root: %v\n%s\n%s", err, state, diagnostic)
	}
	explanation, diagnostic, err := run("assurance", "explain", subject)
	if err != nil || !strings.Contains(explanation, "ASSURANCE\nUNKNOWN") {
		t.Fatalf("missing evidence must not acquire standing in explanation: %v\n%s\n%s", err, explanation, diagnostic)
	}
	for _, test := range []struct {
		document, selector, value, missing string
	}{
		{"assessment-results", "--subject", subject, "assessment_plan_href"},
		{"component-definition", "--component", "material", "component"},
		{"assessment-plan", "--subject", subject, "system_security_plan_href"},
		{"ssp", "--subject", subject, "system"},
	} {
		t.Run(test.document, func(t *testing.T) {
			output, diagnostic, err := run("export", test.document, test.selector, test.value)
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() <= 0 || output != "" || !strings.Contains(diagnostic, test.missing) {
				t.Fatalf("missing authored context must produce no artifact and a concrete input error: %v\nstdout=%s\nstderr=%s", err, output, diagnostic)
			}
		})
	}
	output, diagnostic, err := run("assurance", "receipt", "verify", "--receipt-id", "missing-receipt")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() <= 0 || output != "" || !strings.Contains(diagnostic, "not found") {
		t.Fatalf("missing receipt unexpectedly verified: %v\nstdout=%s\nstderr=%s", err, output, diagnostic)
	}
	for _, test := range []struct{ name, manifest string }{
		{"privileged-pod", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: denied\nspec:\n  containers:\n    - name: process\n      image: example.invalid/process\n      securityContext:\n        privileged: true\n"},
		{"privileged-second-document", "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: example\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: denied\nspec:\n  template:\n    spec:\n      containers:\n        - name: process\n          image: example.invalid/process\n          securityContext:\n            privileged: true\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest := filepath.Join(t.TempDir(), "workload.yaml")
			if err := os.WriteFile(manifest, []byte(test.manifest), 0600); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(t.TempDir(), "refused")
			output, diagnostic, err := run("record", "admission", "--file", manifest, "--evidence-dir", archive)
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() <= 0 || output != "" || !strings.Contains(diagnostic, "privileged") {
				t.Fatalf("unsafe manifest was not rejected before recording: %v\nstdout=%s\nstderr=%s", err, output, diagnostic)
			}
			if _, err := os.Stat(archive); !os.IsNotExist(err) {
				t.Fatalf("refused manifest created evidence state: %v", err)
			}
		})
	}
}
