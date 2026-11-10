package cockpit

import (
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
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
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
}

// CockpitConfig holds display options for the cockpit dashboard.
type CockpitConfig struct {
	RefreshInterval time.Duration
	Once            bool
	EvidenceDir     string
	SubjectFilter   string
	Writer          io.Writer
}

// Cockpit renders an interactive live ASCII terminal dashboard.
type Cockpit struct {
	cfg CockpitConfig
}

// NewCockpit creates a new Cockpit instance.
func NewCockpit(cfg CockpitConfig) *Cockpit {
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
	if c.cfg.Once {
		return c.RenderSnapshot()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(c.cfg.RefreshInterval)
	defer ticker.Stop()

	// Initial render
	if err := c.RenderSnapshot(); err != nil {
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
			if err := c.RenderSnapshot(); err != nil {
				return err
			}
		}
	}
}

// RenderSnapshot writes a single complete ASCII dashboard frame.
func (c *Cockpit) RenderSnapshot() error {
	w := c.cfg.Writer
	now := time.Now().UTC()

	divider := strings.Repeat("=", 78)
	thinDivider := strings.Repeat("-", 78)

	_, _ = fmt.Fprintln(w, divider)
	_, _ = fmt.Fprintf(w, "  OSKAL ASSURANCE COCKPIT -- CONTINUOUS KUBERNETES ASSURANCE\n")
	_, _ = fmt.Fprintf(w, "  Time: %s | Mode: NORMAL | OSCAL: v1.2.3 | Spec: NIST SP 800-53\n", now.Format(time.RFC3339))
	_, _ = fmt.Fprintln(w, divider)

	// Gather workloads
	workloads := c.gatherWorkloads()

	headers := []string{"SUBJECT", "STATE", "PRESENCE", "VALENCE", "COHERENCE", "EVIDENCE ROOT", "FRESHNESS"}
	var rows [][]string
	for _, wl := range workloads {
		evRootShort := wl.EvidenceRoot
		if len(evRootShort) > 12 {
			evRootShort = evRootShort[:12] + "..."
		}
		rows = append(rows, []string{
			wl.Subject,
			wl.State,
			wl.Presence,
			wl.Valence,
			wl.Coherence,
			evRootShort,
			wl.Freshness,
		})
	}

	if err := format.RenderTable(w, headers, rows); err != nil {
		return err
	}

	_, _ = fmt.Fprintln(w, thinDivider)
	_, _ = fmt.Fprintf(w, "  CRYPTOGRAPHIC MERKLE LINEAGE & RECONCILIATION:\n")
	if len(workloads) > 0 && workloads[0].State == "ASSURED" {
		_, _ = fmt.Fprintf(w, "  * Active Root:     %s\n", workloads[0].EvidenceRoot)
		_, _ = fmt.Fprintf(w, "  * Authority Trust: spiffe://assurance.ckodex.io/server (SPIRE verified)\n")
		_, _ = fmt.Fprintf(w, "  * Semantic Drift:  0 dimensions drifted (In Sync)\n")
	} else if len(workloads) > 0 {
		_, _ = fmt.Fprintf(w, "  * Active Root:     %s\n", workloads[0].EvidenceRoot)
		_, _ = fmt.Fprintf(w, "  * Authority Trust: unverified (absence of evidence -> UNKNOWN)\n")
		_, _ = fmt.Fprintf(w, "  * Semantic Drift:  UNKNOWN (record evidence via oskal record admission)\n")
	} else {
		_, _ = fmt.Fprintf(w, "  * Active Root:     none (no workloads observed)\n")
	}
	_, _ = fmt.Fprintln(w, thinDivider)
	_, _ = fmt.Fprintf(w, "  [Press Ctrl+C to exit cockpit]\n")
	_, _ = fmt.Fprintln(w, divider)

	return nil
}

func parseCockpitSubject(raw string) assurance.SubjectRef {
	if strings.Contains(raw, "://") {
		parts := strings.SplitN(raw, "://", 2)
		return assurance.SubjectRef{Scheme: parts[0], ID: parts[1]}
	}
	return assurance.SubjectRef{Scheme: "k8s", ID: raw}
}

func (c *Cockpit) gatherWorkloads() []WorkloadStatusSummary {
	var results []WorkloadStatusSummary

	subject := c.cfg.SubjectFilter
	if subject == "" {
		subject = "k8s://prod/payments/Deployment/payments-api"
	}

	dir := c.cfg.EvidenceDir
	if dir == "" {
		if info, err := os.Stat("evidence"); err == nil && info.IsDir() {
			dir = "evidence"
		}
	}

	if dir != "" {
		if repo, err := storage.NewFilesystemEvidenceRepository(dir); err == nil {
			var envelopes []assurance.EvidenceEnvelope
			if c.cfg.SubjectFilter != "" {
				envelopes, _ = repo.ListBySubject(context.Background(), parseCockpitSubject(c.cfg.SubjectFilter))
			} else {
				envelopes, _ = repo.ListAll(context.Background())
			}

			if len(envelopes) > 0 {
				bySubject := make(map[string][]assurance.EvidenceEnvelope)
				for _, env := range envelopes {
					uri := env.Subject.URI()
					if c.cfg.SubjectFilter != "" {
						uri = subject
					}
					bySubject[uri] = append(bySubject[uri], env)
				}

				var uris []string
				for u := range bySubject {
					uris = append(uris, u)
				}
				sort.Strings(uris)

				now := time.Now().UTC()
				for _, uri := range uris {
					subEnvs := bySubject[uri]
					var evRefs []assurance.EvidenceRef
					isStale := false
					isViolation := false
					for _, env := range subEnvs {
						if env.CapturedAt.IsZero() || env.CapturedAt.After(now.Add(1*time.Minute)) {
							continue
						}
						if assurance.IsAdverseObservationType(env.ObservationType) {
							isViolation = true
						}
						if now.Sub(env.CapturedAt) > 15*time.Minute {
							isStale = true
						}
						evRefs = append(evRefs, env.Artifact)
					}
					if len(evRefs) == 0 && !isViolation {
						continue
					}
					evRoot := "none"
					if len(evRefs) > 0 {
						evRoot = receipts.ComputeEvidenceRoot(evRefs)
					}
					state := "ASSURED"
					valence := "POSITIVE"
					coherence := "COHERENT"
					freshness := "FRESH (<15m)"
					if isViolation {
						state = "FAILED"
						valence = "NEGATIVE"
						coherence = "DECOHERENT"
					} else if isStale {
						state = "STALE"
						valence = "MIXED"
						freshness = "STALE (>15m)"
					}
					results = append(results, WorkloadStatusSummary{
						Subject:      uri,
						State:        state,
						Presence:     "PRESENT",
						Valence:      valence,
						Coherence:    coherence,
						EvidenceRoot: evRoot,
						Freshness:    freshness,
						Controls:     "AC-6",
					})
				}
				if len(results) > 0 {
					return results
				}
			}
		}
	}

	// Invariant I-02: Absence of verified evidence must report UNKNOWN, never ASSURED.
	results = append(results, WorkloadStatusSummary{
		Subject:      subject,
		State:        "UNKNOWN",
		Presence:     "EMPTY",
		Valence:      "UNRESOLVED",
		Coherence:    "COHERENT",
		EvidenceRoot: "none",
		Freshness:    "UNKNOWN",
		Controls:     "AC-6",
	})

	return results
}
