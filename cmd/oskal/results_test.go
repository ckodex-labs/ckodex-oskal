package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/internal/application/diagnostics"
)

func TestDoctorStructuredResultsPreserveExitDisposition(t *testing.T) {
	t.Setenv("TUF_ROOT", "")
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing-config"))
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", filepath.Join(t.TempDir(), "missing-socket"))
	for _, damaged := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "corrupt-store"}[damaged], func(t *testing.T) {
			dir := t.TempDir()
			if damaged {
				blobs := filepath.Join(dir, "blobs", "sha256")
				if err := os.MkdirAll(blobs, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(blobs, strings.Repeat("0", 64)+".json"), []byte("damaged bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			command := NewRootCommand()
			var out, stderr bytes.Buffer
			command.SetOut(&out)
			command.SetErr(&stderr)
			command.SetArgs([]string{"doctor", "--output", "json", "--evidence-dir", dir})
			err := command.Execute()
			var report diagnostics.DoctorReport
			if decodeErr := json.Unmarshal(out.Bytes(), &report); decodeErr != nil {
				t.Fatalf("result stdout is not one valid JSON document: %v; %s", decodeErr, out.String())
			}
			wantStatus, wantCode := diagnostics.StatusUnknown, 2
			if damaged {
				wantStatus, wantCode = diagnostics.StatusFail, 3
			}
			if report.OverallState != wantStatus || commandExitCode(err) != wantCode {
				t.Fatalf("status=%s code=%d err=%v; want %s/%d", report.OverallState, commandExitCode(err), err, wantStatus, wantCode)
			}
		})
	}
}
