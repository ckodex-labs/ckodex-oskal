package diagnostics

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
)

func TestDoctorInvalidCustomBudgetStopsBeforeEffects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-created")
	report := RunDoctorWithLimits(t.Context(), path, storage.ArchiveLimits{MaxBytes: 0, MaxEntries: 1})
	if report.OverallState != StatusFail || len(report.Checks) != 1 || report.Checks[0].Name != "Archive Limits" {
		t.Fatalf("invalid budget continued diagnostic effects: %+v", report)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("invalid SDK budget created archive: %v", err)
	}
}
