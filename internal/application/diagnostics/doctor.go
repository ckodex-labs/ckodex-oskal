package diagnostics

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
)

// CheckStatus indicates the health of a subsystem.
type CheckStatus string

const (
	StatusPass    CheckStatus = "PASS"
	StatusWarn    CheckStatus = "WARN"
	StatusFail    CheckStatus = "FAIL"
	StatusUnknown CheckStatus = "UNKNOWN"
)

// DiagnosticCheck represents a single preflight verification step.
type DiagnosticCheck struct {
	Name        string      `json:"name"`
	Target      string      `json:"target"`
	Status      CheckStatus `json:"status"`
	Duration    string      `json:"duration"`
	Message     string      `json:"message"`
	Remediation string      `json:"remediation,omitempty"`
}

// DoctorReport aggregates all system diagnostic results.
type DoctorReport struct {
	Timestamp    time.Time         `json:"timestamp"`
	OverallState CheckStatus       `json:"overall_state"`
	Duration     string            `json:"total_duration"`
	Checks       []DiagnosticCheck `json:"checks"`
}

// RunDoctor performs deep system preflight diagnostics (Constitution Section 36 & 37).
func RunDoctor(ctx context.Context, evidenceDir string) *DoctorReport {
	return RunDoctorWithLimits(ctx, evidenceDir, storage.DefaultArchiveLimits())
}

// RunDoctorWithLimits validates an explicit archive budget before any diagnostic effects.
func RunDoctorWithLimits(ctx context.Context, evidenceDir string, limits storage.ArchiveLimits) *DoctorReport {
	start := time.Now()
	report := &DoctorReport{
		Timestamp:    start.UTC(),
		OverallState: StatusPass,
	}

	if err := limits.Validate(); err != nil {
		report.OverallState = StatusFail
		report.Duration = formatDurationASCII(time.Since(start))
		report.addCheck(DiagnosticCheck{Name: "Archive Limits", Target: evidenceDir, Status: StatusFail, Message: err.Error(), Remediation: "Use reviewed positive archive byte and entry budgets"})
		return report
	}
	// 1. Runtime Substrate Check
	report.addCheck(checkRuntimeSubstrate())

	// 2. Embedded NIST OSCAL Schema Integrity Check
	report.addCheck(checkOscalSchemas())

	// 3. Evidence Storage / CAS Integrity Check
	report.addCheck(checkEvidenceStorageWithLimits(ctx, evidenceDir, limits))

	// 4. SPIFFE / SPIRE Workload API Socket Check
	report.addCheck(checkSPIFFEWorkloadAPI(ctx))

	// 5. Sigstore / Cosign Infrastructure Check
	report.addCheck(checkSigstoreInfrastructure(ctx))

	// 6. Kubernetes Cluster Connectivity Check
	report.addCheck(checkKubernetesConnectivity(ctx))

	// Calculate overall disposition
	hasFail := false
	hasWarn := false
	hasUnknown := false
	for _, c := range report.Checks {
		switch c.Status {
		case StatusFail:
			hasFail = true
		case StatusWarn:
			hasWarn = true
		case StatusUnknown:
			hasUnknown = true
		}
	}

	if hasFail {
		report.OverallState = StatusFail
	} else if hasUnknown {
		report.OverallState = StatusUnknown
	} else if hasWarn {
		report.OverallState = StatusWarn
	} else {
		report.OverallState = StatusPass
	}

	report.Duration = formatDurationASCII(time.Since(start))
	return report
}

func formatDurationASCII(d time.Duration) string {
	return strings.ReplaceAll(d.String(), "\u00b5", "u")
}

func (r *DoctorReport) addCheck(c DiagnosticCheck) {
	r.Checks = append(r.Checks, c)
}

func checkRuntimeSubstrate() DiagnosticCheck {
	start := time.Now()
	desc := fmt.Sprintf("OS: %s, Arch: %s, Go: %s, CPUs: %d", runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU())
	return DiagnosticCheck{
		Name:     "Runtime Substrate",
		Target:   "OS / Kernel / Process",
		Status:   StatusPass,
		Duration: formatDurationASCII(time.Since(start)),
		Message:  desc,
	}
}

func checkOscalSchemas() DiagnosticCheck {
	start := time.Now()
	_, err := oscal.DefaultValidator()
	if err != nil {
		return DiagnosticCheck{
			Name:        "NIST OSCAL v1.2.3 Schemas",
			Target:      "Embedded JSON Schemas (AR, CD, SSP, AP, POAM)",
			Status:      StatusFail,
			Duration:    formatDurationASCII(time.Since(start)),
			Message:     fmt.Sprintf("Failed to initialize and compile schemas: %v", err),
			Remediation: "Verify internal/projection/oscal/schemas/ assets are present and valid JSON",
		}
	}

	return DiagnosticCheck{
		Name:     "NIST OSCAL v1.2.3 Schemas",
		Target:   "Embedded JSON Schemas (AR, CD, SSP, AP, POAM)",
		Status:   StatusPass,
		Duration: formatDurationASCII(time.Since(start)),
		Message:  "All 5 embedded schema validators compiled; this does not evaluate a workload",
	}
}

func checkEvidenceStorageWithLimits(ctx context.Context, dir string, limits storage.ArchiveLimits) DiagnosticCheck {
	start := time.Now()
	if dir == "" {
		return DiagnosticCheck{
			Name:        "Content-Addressable Storage (CAS)",
			Target:      "Local Evidence Store",
			Status:      StatusWarn,
			Duration:    formatDurationASCII(time.Since(start)),
			Message:     "No evidence directory configured (--evidence-dir not specified)",
			Remediation: "Set --evidence-dir to enable local forensic evidence envelope persistence",
		}
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return DiagnosticCheck{
			Name:        "Content-Addressable Storage (CAS)",
			Target:      dir,
			Status:      StatusFail,
			Duration:    formatDurationASCII(time.Since(start)),
			Message:     fmt.Sprintf("Cannot create evidence directory: %v", err),
			Remediation: "Check filesystem write permissions for evidence directory",
		}
	}

	tmpProbe, err := os.CreateTemp(dir, ".oskal-doctor-probe-*")
	if err != nil {
		return DiagnosticCheck{
			Name:        "Content-Addressable Storage (CAS)",
			Target:      dir,
			Status:      StatusFail,
			Duration:    formatDurationASCII(time.Since(start)),
			Message:     fmt.Sprintf("Directory not writable: %v", err),
			Remediation: "Ensure user has write permissions to evidence directory",
		}
	}
	probeName := tmpProbe.Name()
	probeContent := []byte(fmt.Sprintf("probe-%d", time.Now().UnixNano()))
	_, writeErr := tmpProbe.Write(probeContent)
	_ = tmpProbe.Close()
	_ = os.Remove(probeName)
	if writeErr != nil {
		return DiagnosticCheck{
			Name:        "Content-Addressable Storage (CAS)",
			Target:      dir,
			Status:      StatusFail,
			Duration:    formatDurationASCII(time.Since(start)),
			Message:     fmt.Sprintf("Directory probe write failed: %v", writeErr),
			Remediation: "Check available disk space and write permissions for evidence directory",
		}
	}

	repo, err := storage.NewFilesystemEvidenceRepositoryWithLimits(dir, limits)
	if err != nil {
		return DiagnosticCheck{
			Name:        "Content-Addressable Storage (CAS)",
			Target:      dir,
			Status:      StatusFail,
			Duration:    formatDurationASCII(time.Since(start)),
			Message:     fmt.Sprintf("Failed to open CAS repository: %v", err),
			Remediation: "Inspect CAS directory permissions and envelope JSON structure",
		}
	}
	verifiedCount, err := repo.VerifyIntegrity(ctx)
	if err != nil {
		return DiagnosticCheck{
			Name:        "Content-Addressable Storage (CAS)",
			Target:      dir,
			Status:      StatusFail,
			Duration:    formatDurationASCII(time.Since(start)),
			Message:     fmt.Sprintf("CAS cryptographic integrity check failed: %v", err),
			Remediation: "Quarantine tampered CAS blobs and restore from signed AirgapBundle",
		}
	}

	return DiagnosticCheck{
		Name:     "Content-Addressable Storage (CAS)",
		Target:   dir,
		Status:   StatusPass,
		Duration: formatDurationASCII(time.Since(start)),
		Message:  fmt.Sprintf("Evidence directory writable and verified (%d CAS blobs integrity-checked)", verifiedCount),
	}
}

func checkSPIFFEWorkloadAPI(ctx context.Context) DiagnosticCheck {
	start := time.Now()
	socketPath := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if socketPath == "" {
		socketPath = "/tmp/spire-agent/public/api.sock"
	}

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return DiagnosticCheck{
			Name:        "SPIFFE / SPIRE Workload API",
			Target:      socketPath,
			Status:      StatusWarn,
			Duration:    formatDurationASCII(time.Since(start)),
			Message:     fmt.Sprintf("SPIFFE Workload API socket not found at %s", socketPath),
			Remediation: "Ensure SPIRE agent DaemonSet is running and exposes SPIFFE_ENDPOINT_SOCKET",
		}
	}

	dialer := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return DiagnosticCheck{
			Name:        "SPIFFE / SPIRE Workload API",
			Target:      socketPath,
			Status:      StatusWarn,
			Duration:    formatDurationASCII(time.Since(start)),
			Message:     fmt.Sprintf("Socket exists but connection refused: %v", err),
			Remediation: "Check SPIRE agent service status and unix permissions",
		}
	}
	_ = conn.Close()

	return DiagnosticCheck{
		Name:     "SPIFFE / SPIRE Workload API",
		Target:   socketPath,
		Status:   StatusUnknown,
		Duration: formatDurationASCII(time.Since(start)),
		Message:  "Unix socket accepted a connection; Workload API identity and trust bundle were not verified",
	}
}

func checkSigstoreInfrastructure(_ context.Context) DiagnosticCheck {
	start := time.Now()
	tufRoot := os.Getenv("TUF_ROOT")
	if tufRoot == "" {
		return DiagnosticCheck{
			Name:     "Sigstore / Supply-Chain Attestation",
			Target:   "TUF Root / Rekor / Fulcio",
			Status:   StatusUnknown,
			Duration: formatDurationASCII(time.Since(start)),
			Message:  "No explicit Sigstore trust root configured; trust, Fulcio and transparency verification are UNKNOWN",
		}
	}

	if _, err := os.Stat(tufRoot); err != nil {
		return DiagnosticCheck{
			Name:        "Sigstore / Supply-Chain Attestation",
			Target:      fmt.Sprintf("Private TUF Root: %s", tufRoot),
			Status:      StatusFail,
			Duration:    formatDurationASCII(time.Since(start)),
			Message:     fmt.Sprintf("Configured TUF_ROOT path does not exist or is unreadable: %v", err),
			Remediation: "Ensure TUF_ROOT points to an existing air-gapped TUF root file or directory",
		}
	}

	return DiagnosticCheck{
		Name:     "Sigstore / Supply-Chain Attestation",
		Target:   fmt.Sprintf("Private TUF Root: %s", tufRoot),
		Status:   StatusUnknown,
		Duration: formatDurationASCII(time.Since(start)),
		Message:  "Configured TUF_ROOT path exists; root contents, signatures, expiry and trust were not verified",
	}
}

func checkKubernetesConnectivity(_ context.Context) DiagnosticCheck {
	start := time.Now()
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, _ := os.UserHomeDir()
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	inClusterToken := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	if _, err := os.Stat(inClusterToken); err == nil {
		return DiagnosticCheck{
			Name:     "Kubernetes Control Plane",
			Target:   "In-Cluster ServiceAccount",
			Status:   StatusUnknown,
			Duration: formatDurationASCII(time.Since(start)),
			Message:  "In-cluster token file exists; API authentication and authorization were not tested",
		}
	}

	data, err := os.ReadFile(kubeconfig)
	if err != nil {
		return DiagnosticCheck{
			Name:        "Kubernetes Control Plane",
			Target:      kubeconfig,
			Status:      StatusWarn,
			Duration:    formatDurationASCII(time.Since(start)),
			Message:     "No active kubeconfig found (local/offline mode)",
			Remediation: "Configure KUBECONFIG or run inside a Kubernetes cluster with proper RBAC",
		}
	}

	content := string(data)
	if len(strings.TrimSpace(content)) == 0 || (!strings.Contains(content, "clusters:") && !strings.Contains(content, "server:")) {
		return DiagnosticCheck{
			Name:        "Kubernetes Control Plane",
			Target:      kubeconfig,
			Status:      StatusWarn,
			Duration:    formatDurationASCII(time.Since(start)),
			Message:     "Kubeconfig file is empty or missing cluster server definitions",
			Remediation: "Populate a valid kubeconfig with 'clusters:' and 'server:' entries",
		}
	}

	return DiagnosticCheck{
		Name:     "Kubernetes Control Plane",
		Target:   kubeconfig,
		Status:   StatusUnknown,
		Duration: formatDurationASCII(time.Since(start)),
		Message:  fmt.Sprintf("Kubeconfig text found at %s; API connectivity, authentication and authorization were not tested", kubeconfig),
	}
}
