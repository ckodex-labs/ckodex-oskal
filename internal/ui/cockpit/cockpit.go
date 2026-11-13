package cockpit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/ui/format"
)

// WorkloadStatusSummary holds the real-time assurance snapshot for a workload.
type WorkloadStatusSummary struct {
	Subject      string
	State        string
	Presence     string
	Valence      string
	Coherence    string
	EvidenceRoot string
	Freshness    string
	Controls     string
	Archived     int
	Verified     int
}

// CockpitConfig holds display options for the cockpit dashboard.
type CockpitConfig struct {
	RefreshInterval time.Duration
	Once            bool
	EvidenceDir     string
	// A zero ArchiveLimits value selects conservative storage defaults.
	ArchiveLimits storage.ArchiveLimits
	SubjectFilter string
	Writer        io.Writer
}

// Cockpit renders an interactive live ASCII terminal dashboard.
type Cockpit struct {
	cfg CockpitConfig
}

// NewCockpit creates a new Cockpit instance.
func NewCockpit(cfg CockpitConfig) *Cockpit {
	if cfg.ArchiveLimits == (storage.ArchiveLimits{}) {
		cfg.ArchiveLimits = storage.DefaultArchiveLimits()
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 2 * time.Second
	}
	if cfg.Writer == nil {
		cfg.Writer = os.Stdout
	}
	return &Cockpit{cfg: cfg}
}

// Run executes the cockpit rendering loop.
func (c *Cockpit) Run(ctx context.Context) error {
	if err := c.cfg.ArchiveLimits.Validate(); err != nil {
		return err
	}
	if c.cfg.Once {
		return c.renderSnapshot(ctx)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(c.cfg.RefreshInterval)
	defer ticker.Stop()

	// Initial render
	if err := c.renderSnapshot(ctx); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sigCh:
			_, _ = fmt.Fprintln(c.cfg.Writer, "\n[OSKAL Cockpit exited gracefully]")
			return nil
		case <-ticker.C:
			// Clear screen using pure ASCII escape sequence
			_, _ = fmt.Fprint(c.cfg.Writer, "\033[H\033[2J")
			if err := c.renderSnapshot(ctx); err != nil {
				return err
			}
		}
	}
}

// RenderSnapshot writes an archive inventory, without inferring current assurance.
func (c *Cockpit) RenderSnapshot() error { return c.renderSnapshot(context.Background()) }

func (c *Cockpit) renderSnapshot(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	workloads, err := c.gatherWorkloads(ctx)
	if err != nil {
		return err
	}
	var output bytes.Buffer
	w := &output
	divider := strings.Repeat("=", 78)
	fmt.Fprintln(w, divider)
	fmt.Fprintln(w, "  OSKAL ASSURANCE COCKPIT -- READ-ONLY ARCHIVE INVENTORY")
	fmt.Fprintf(w, "  Observed at: %s | Live assessment: NOT CONFIGURED\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintln(w, divider)
	headers := []string{"SUBJECT", "STATE", "MATERIAL", "ARCHIVED", "VERIFIED", "COHERENCE", "FRESHNESS"}
	var rows [][]string
	for _, workload := range workloads {
		rows = append(rows, []string{workload.Subject, workload.State, workload.Presence, fmt.Sprint(workload.Archived), fmt.Sprint(workload.Verified), workload.Coherence, workload.Freshness})
	}
	if err := format.RenderTable(w, headers, rows); err != nil {
		return err
	}
	if len(workloads) == 0 {
		fmt.Fprintln(w, "  No archived subjects; assurance UNKNOWN.")
	}
	fmt.Fprintln(w, strings.Repeat("-", 78))
	fmt.Fprintln(w, "  Authority: UNKNOWN | Current evidence root: UNKNOWN | Semantic drift: UNKNOWN")
	fmt.Fprintln(w, "  Material counts describe stored envelopes, not verified live evidence.")
	if !c.cfg.Once {
		fmt.Fprintln(w, "  [Press Ctrl+C to exit cockpit]")
	}
	fmt.Fprintln(w, divider)
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := c.cfg.Writer.Write(output.Bytes())
	if err == nil && n != output.Len() {
		return io.ErrShortWrite
	}
	return err
}

func parseCockpitSubject(raw string) assurance.SubjectRef {
	if strings.Contains(raw, "://") {
		parts := strings.SplitN(raw, "://", 2)
		return assurance.SubjectRef{Scheme: parts[0], ID: parts[1]}
	}
	return assurance.SubjectRef{Scheme: "k8s", ID: raw}
}

func (c *Cockpit) gatherWorkloads(ctx context.Context) ([]WorkloadStatusSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var selected assurance.SubjectRef
	if c.cfg.SubjectFilter != "" {
		selected = parseCockpitSubject(c.cfg.SubjectFilter)
		if err := selected.Validate(); err != nil {
			return nil, err
		}
	}
	dir := c.cfg.EvidenceDir
	if dir == "" {
		info, err := os.Stat("evidence")
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if err == nil {
			if !info.IsDir() {
				return nil, fmt.Errorf("evidence path is not a directory")
			}
			dir = "evidence"
		}
	}
	bySubject := make(map[string]int)
	if selected.ID != "" {
		bySubject[selected.URI()] = 0
	}
	if dir != "" {
		repo, err := storage.OpenFilesystemEvidenceRepositoryWithLimits(dir, c.cfg.ArchiveLimits)
		if err != nil {
			return nil, fmt.Errorf("open cockpit archive: %w", err)
		}
		var envelopes []assurance.EvidenceEnvelope
		if selected.ID != "" {
			envelopes, err = repo.ListBySubject(ctx, selected)
		} else {
			envelopes, err = repo.ListAll(ctx)
		}
		if err != nil {
			return nil, fmt.Errorf("read cockpit archive: %w", err)
		}
		for _, envelope := range envelopes {
			bySubject[envelope.Subject.URI()]++
			if len(bySubject) > 4096 {
				return nil, fmt.Errorf("cockpit inventory exceeds 4096 subjects; select an explicit subject")
			}
		}
	}
	var subjects []string
	for subject := range bySubject {
		subjects = append(subjects, subject)
	}
	sort.Strings(subjects)
	var results []WorkloadStatusSummary
	for _, subject := range subjects {
		presence := "EMPTY"
		if bySubject[subject] > 0 {
			presence = "PRESENT"
		}
		results = append(results, WorkloadStatusSummary{Subject: subject, State: "UNKNOWN", Presence: presence, Valence: "UNRESOLVED", Coherence: "UNKNOWN", EvidenceRoot: "", Freshness: "UNKNOWN", Archived: bySubject[subject], Verified: 0})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
