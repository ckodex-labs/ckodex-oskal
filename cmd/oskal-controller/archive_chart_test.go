package main

import (
	"bytes"
	"os/exec"
	"testing"
)

func TestArchiveBudgetsRenderAndRejectInvalidValues(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("actual helm binary required")
	}
	base := []string{"template", "archive-check", "../../deploy/helm/ckodex-oskal", "--set", "webhook.enabled=false"}
	render := func(args ...string) []byte {
		t.Helper()
		output, err := exec.CommandContext(t.Context(), helm, append(append([]string(nil), base...), args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("actual Helm render failed: %v %s", err, output)
		}
		return output
	}
	defaults := render()
	if !bytes.Contains(defaults, []byte("--archive-max-bytes=67108864")) || !bytes.Contains(defaults, []byte("--archive-max-entries=8192")) {
		t.Fatal("rendered archive defaults differ from storage contract")
	}
	custom := render("--set", "archiveLimits.maxBytes=1048576", "--set", "archiveLimits.maxEntries=128")
	if !bytes.Contains(custom, []byte("--archive-max-bytes=1048576")) || !bytes.Contains(custom, []byte("--archive-max-entries=128")) {
		t.Fatal("operator archive budgets were not rendered into actual command args")
	}
	for _, setting := range []string{"archiveLimits.maxBytes=0", "archiveLimits.maxEntries=0", "archiveLimits.maxBytes=1099511627777", "archiveLimits.maxEntries=1000001", "archiveLimits.maxBytes=1.5"} {
		output, err := exec.CommandContext(t.Context(), helm, append(append([]string(nil), base...), "--set", setting)...).CombinedOutput()
		if err == nil || !bytes.Contains(output, []byte("archiveLimits")) {
			t.Fatalf("invalid actual chart budget rendered: %s %v %s", setting, err, output)
		}
	}
}
