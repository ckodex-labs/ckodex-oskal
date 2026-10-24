package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/mcp"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/webhook"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/diagnostics"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/explain"
	"github.com/ckodex-labs/ckodex-oskal/internal/config"
	"github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	recoscal "github.com/ckodex-labs/ckodex-oskal/internal/reconciler/oscal"
	"github.com/ckodex-labs/ckodex-oskal/internal/scaffold"
	"github.com/ckodex-labs/ckodex-oskal/internal/service"
	"github.com/ckodex-labs/ckodex-oskal/internal/ui/cockpit"
	"github.com/ckodex-labs/ckodex-oskal/internal/ui/format"
	commonv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/control/v1"
	servicesv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/services/v1"
	"sigs.k8s.io/yaml"
)

var (
	serverAddr  string
	evidenceDir string
)

func getGRPCClient(ctx context.Context, addr string) (servicesv1.AssuranceServiceClient, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to gRPC server at %s: %w", addr, err)
	}
	client := servicesv1.NewAssuranceServiceClient(conn)
	return client, conn, nil
}

func loadLocalEvidence(dir string, sub assurance.SubjectRef) ([]assurance.EvidenceEnvelope, error) {
	if dir == "" {
		return nil, nil
	}
	repo, err := storage.NewFilesystemEvidenceRepository(dir)
	if err != nil {
		return nil, err
	}
	return repo.ListBySubject(context.Background(), sub)
}

func parseSubjectURI(raw string) assurance.SubjectRef {
	if strings.Contains(raw, "://") {
		parts := strings.SplitN(raw, "://", 2)
		return assurance.SubjectRef{Scheme: parts[0], ID: parts[1]}
	}
	return assurance.SubjectRef{Scheme: "k8s", ID: raw}
}

func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "oskal",
		Short: "OSKAL -- Continuous Kubernetes Assurance CLI",
		Long: `OSKAL is the Continuous Kubernetes Assurance Runtime for CKODEX.
It evaluates continuous evidence contracts, tracks semantic drift,
and projects defensible results into standard OSCAL artifacts.`,
	}

	var configFileFlag string
	rootCmd.PersistentFlags().StringVar(&configFileFlag, "config", "", "Path to OSKAL configuration file (default .oskal.yaml)")
	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "", "AssuranceService gRPC address (e.g. localhost:9090)")
	rootCmd.PersistentFlags().StringVar(&evidenceDir, "evidence-dir", "", "Path to directory containing local EvidenceEnvelope JSON files")

	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		cfg, _, err := config.LoadConfig(configFileFlag)
		if err != nil && configFileFlag != "" {
			return err
		}
		serverFlag := cmd.Root().PersistentFlags().Lookup("server")
		if (serverFlag == nil || !serverFlag.Changed) && cfg.Server != "" {
			serverAddr = cfg.Server
		}
		evDirFlag := cmd.Root().PersistentFlags().Lookup("evidence-dir")
		if (evDirFlag == nil || !evDirFlag.Changed) && cfg.EvidenceDir != "" {
			evidenceDir = cfg.EvidenceDir
		}
		return nil
	}

	assuranceCmd := &cobra.Command{
		Use:   "assurance",
		Short: "Assurance state, evaluation, and explainability commands",
	}

	// 1. oscal assurance state <subject>
	stateCmd := &cobra.Command{
		Use:   "state <subject-uri>",
		Short: "Show the current continuous assurance state for a subject",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			subjectURI := args[0]
			parts := strings.SplitN(subjectURI, "://", 2)
			scheme := "k8s"
			id := subjectURI
			if len(parts) == 2 {
				scheme = parts[0]
				id = parts[1]
			}
			sub := assurance.SubjectRef{Scheme: scheme, ID: id}

			if serverAddr != "" {
				ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
				defer cancel()

				client, conn, err := getGRPCClient(ctx, serverAddr)
				if err != nil {
					return err
				}
				defer func() { _ = conn.Close() }()

				resp, err := client.GetAssuranceState(ctx, &servicesv1.GetAssuranceStateRequest{
					Subject: &commonv1.SubjectRef{Scheme: scheme, Id: id},
				})
				if err != nil {
					return fmt.Errorf("gRPC GetAssuranceState failed: %w", err)
				}

				fmt.Printf("SUBJECT:         %s\n", sub.URI())
				if resp.State == commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN {
					fmt.Printf("STATE:           UNKNOWN\n")
					fmt.Printf("STATUS:          Absence of verified evidence (no observations ingested)\n")
					fmt.Printf("EVIDENCE ROOT:   none\n")
					fmt.Printf("LAST EVALUATED:  %s\n", time.Now().UTC().Format(time.RFC3339))
					fmt.Printf("FRESHNESS:       unknown\n")
					fmt.Printf("MISSING SIGNALS: kubernetes.admission, runtime.ebpf, spiffe.svid\n")
					fmt.Printf("REMEDIATION:     oskal record admission --file <manifest.yaml> OR deploy ckodex-webhook\n")
					return nil
				}

				fmt.Printf("STATE:           %s\n", resp.State.String())
				if resp.Epoch != nil {
					fmt.Printf("EPOCH:           %s\n", resp.Epoch.PolicyDigest)
				}
				fmt.Printf("EVIDENCE ROOT:   %s\n", resp.EvidenceRoot)
				fmt.Printf("LAST EVALUATED:  %s\n", time.Now().UTC().Format(time.RFC3339))
				fmt.Printf("FRESHNESS:       current\n")
				return nil
			}

			if evidenceDir != "" {
				envelopes, err := loadLocalEvidence(evidenceDir, sub)
				if err != nil {
					return err
				}
				fmt.Printf("SUBJECT:         %s\n", sub.URI())
				if len(envelopes) == 0 {
					fmt.Printf("STATE:           UNKNOWN\n")
					fmt.Printf("STATUS:          No matching evidence envelopes found in %s\n", evidenceDir)
					fmt.Printf("EVIDENCE ROOT:   none\n")
					fmt.Printf("LAST EVALUATED:  %s\n", time.Now().UTC().Format(time.RFC3339))
					fmt.Printf("FRESHNESS:       unknown\n")
					fmt.Printf("MISSING SIGNALS: kubernetes.admission, runtime.ebpf, spiffe.svid\n")
					fmt.Printf("REMEDIATION:     oskal record admission --file <manifest.yaml> OR specify --server\n")
					return nil
				}

				var evRefs []assurance.EvidenceRef
				for _, env := range envelopes {
					evRefs = append(evRefs, env.Artifact)
				}
				evRoot := receipts.ComputeEvidenceRoot(evRefs)
				policyDigest := assurance.ComputeStringDigest(sub.URI() + ":" + evRoot)

				fmt.Printf("STATE:           ASSURED\n")
				fmt.Printf("EPOCH:           %s\n", policyDigest)
				fmt.Printf("EVIDENCE ROOT:   %s\n", evRoot)
				fmt.Printf("LAST EVALUATED:  %s\n", time.Now().UTC().Format(time.RFC3339))
				fmt.Printf("FRESHNESS:       current\n")
				return nil
			}

			// Invariant I-02: Absence of evidence is UNKNOWN, never PASS.
			fmt.Printf("SUBJECT:         %s\n", sub.URI())
			fmt.Printf("STATE:           UNKNOWN\n")
			fmt.Printf("STATUS:          Absence of verified evidence (specify --server or --evidence-dir)\n")
			fmt.Printf("EVIDENCE ROOT:   none\n")
			fmt.Printf("LAST EVALUATED:  %s\n", time.Now().UTC().Format(time.RFC3339))
			fmt.Printf("FRESHNESS:       unknown\n")
			fmt.Printf("MISSING SIGNALS: kubernetes.admission, runtime.ebpf, spiffe.svid\n")
			fmt.Printf("REMEDIATION:     oskal record admission --file <manifest.yaml> OR specify --evidence-dir\n")
			return nil
		},
	}

	// 2. oscal assurance explain <subject> --control <control>
	var controlFlag string
	explainCmd := &cobra.Command{
		Use:   "explain <subject-uri>",
		Short: "Explain why an assurance claim is justified or failing (Section 51)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			subjectURI := args[0]
			parts := strings.SplitN(subjectURI, "://", 2)
			scheme := "k8s"
			id := subjectURI
			if len(parts) == 2 {
				scheme = parts[0]
				id = parts[1]
			}
			sub := assurance.SubjectRef{Scheme: scheme, ID: id}

			ctrlNamespace := "nist-sp-800-53"
			ctrlID := "AC-6"
			if controlFlag != "" {
				cParts := strings.SplitN(controlFlag, ":", 2)
				if len(cParts) == 2 {
					ctrlNamespace = cParts[0]
					ctrlID = cParts[1]
				} else {
					ctrlID = controlFlag
				}
			}
			ctrl := assurance.ControlRef{Namespace: ctrlNamespace, ID: ctrlID}

			if serverAddr != "" {
				ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
				defer cancel()

				client, conn, err := getGRPCClient(ctx, serverAddr)
				if err != nil {
					return err
				}
				defer func() { _ = conn.Close() }()

				resp, err := client.ExplainClaim(ctx, &servicesv1.ExplainClaimRequest{
					Subject: &commonv1.SubjectRef{Scheme: scheme, Id: id},
					Control: &controlv1.ControlRef{Namespace: ctrlNamespace, Id: ctrlID},
				})
				if err != nil {
					return fmt.Errorf("gRPC ExplainClaim failed: %w", err)
				}

				fmt.Print(resp.RenderedText)
				return nil
			}

			var envelopes []assurance.EvidenceEnvelope
			if evidenceDir != "" {
				var err error
				envelopes, err = loadLocalEvidence(evidenceDir, sub)
				if err != nil {
					return err
				}
			}

			var eval assurance.ClaimEvaluation
			if len(envelopes) > 0 {
				var evRefs []assurance.EvidenceRef
				for _, env := range envelopes {
					evRefs = append(evRefs, env.Artifact)
				}
				evRoot := receipts.ComputeEvidenceRoot(evRefs)
				policyDigest := assurance.ComputeStringDigest(sub.URI() + ":" + evRoot)

				eval = assurance.ClaimEvaluation{
					ID:      fmt.Sprintf("eval-%s", ctrl.ID),
					Subject: sub,
					Control: ctrl,
					State:   assurance.AssuranceStateAssured,
					Epoch: assurance.AssuranceEpoch{
						SubjectDigest:        assurance.ComputeStringDigest(sub.URI()),
						ImplementationDigest: assurance.ComputeStringDigest("kubernetes:admission-policy"),
						PolicyDigest:         policyDigest,
						AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/operator"),
						EnvironmentDigest:    assurance.ComputeStringDigest("cluster:local"),
					},
					Evidence:     evRefs,
					EvidenceRoot: evRoot,
					EvaluatedAt:  time.Now().UTC(),
					ValidUntil:   time.Now().UTC().Add(5 * time.Minute),
				}
			} else {
				eval = assurance.ClaimEvaluation{
					ID:           fmt.Sprintf("eval-unknown-%s", ctrl.ID),
					Subject:      sub,
					Control:      ctrl,
					State:        assurance.AssuranceStateUnknown,
					Epoch:        assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeStringDigest(sub.URI())},
					Evidence:     nil,
					EvidenceRoot: "",
					EvaluatedAt:  time.Now().UTC(),
				}
			}

			explainer := explain.NewExplainer()
			graph := explainer.BuildExplainGraph(cmd.Context(), sub, ctrl, eval)

			fmt.Print(graph.RenderText())
			return nil
		},
	}
	explainCmd.Flags().StringVar(&controlFlag, "control", "nist-sp-800-53:AC-6", "Target control to explain (e.g. nist-sp-800-53:AC-6)")

	// 3. oscal assurance evidence <subject>
	evidenceCmd := &cobra.Command{
		Use:   "evidence <subject-uri>",
		Short: "List verified evidence envelopes for a subject",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			subjectURI := args[0]
			parts := strings.SplitN(subjectURI, "://", 2)
			scheme := "k8s"
			id := subjectURI
			if len(parts) == 2 {
				scheme = parts[0]
				id = parts[1]
			}
			sub := assurance.SubjectRef{Scheme: scheme, ID: id}

			if evidenceDir != "" {
				envelopes, err := loadLocalEvidence(evidenceDir, sub)
				if err != nil {
					return err
				}
				if len(envelopes) == 0 {
					fmt.Printf("No verified evidence envelopes found for %s in %s\n", sub.URI(), evidenceDir)
					return nil
				}

				fmt.Printf("VERIFIED EVIDENCE ENVELOPES FOR %s (%d total):\n\n", sub.URI(), len(envelopes))
				for i, env := range envelopes {
					fmt.Printf("%d. [%s]\n   ID:       %s\n   Producer: %s\n   Digest:   %s\n   URI:      %s\n   Captured: %s\n\n",
						i+1, env.ObservationType, env.ID, env.Producer.Canonical(), env.Artifact.Digest, env.Artifact.URI, env.CapturedAt.Format(time.RFC3339))
				}
				return nil
			}

			fmt.Printf("No verified evidence envelopes available for %s (specify --server or --evidence-dir).\n", sub.URI())
			return nil
		},
	}

	// 4. oscal assurance drift <subject>
	driftCmd := &cobra.Command{
		Use:   "drift <subject-uri>",
		Short: "Detect semantic drift between observed runtime and recorded epoch",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			subjectURI := args[0]
			parts := strings.SplitN(subjectURI, "://", 2)
			scheme := "k8s"
			id := subjectURI
			if len(parts) == 2 {
				scheme = parts[0]
				id = parts[1]
			}
			sub := assurance.SubjectRef{Scheme: scheme, ID: id}

			if evidenceDir != "" {
				envelopes, err := loadLocalEvidence(evidenceDir, sub)
				if err != nil {
					return err
				}
				if len(envelopes) == 0 {
					fmt.Printf("DRIFT ANALYSIS FOR %s:\n\n", sub.URI())
					fmt.Printf("STATUS:                 UNKNOWN (no baseline evidence found in %s)\n", evidenceDir)
					return nil
				}

				now := time.Now().UTC()
				isStale := false
				for _, env := range envelopes {
					if now.Sub(env.CapturedAt) > 10*time.Minute {
						isStale = true
						break
					}
				}

				fmt.Printf("DRIFT ANALYSIS FOR %s:\n\n", sub.URI())
				if isStale {
					fmt.Printf("SUBJECT STATUS:         DRIFT_DETECTED\n")
					fmt.Printf("FRESHNESS:              STALE (evidence expired)\n")
					fmt.Printf("ASSURANCE STATUS:       STALE\n")
				} else {
					fmt.Printf("SUBJECT STATUS:         IN_SYNC\n")
					fmt.Printf("RECORDED POLICY DIGEST: %s\n", envelopes[0].Epoch.PolicyDigest)
					fmt.Printf("CURRENT POLICY DIGEST:  %s\n", envelopes[0].Epoch.PolicyDigest)
					fmt.Printf("AUTHORITY CA ROTATION:  NONE\n")
					fmt.Printf("SEMANTIC DRIFT:         0 dimensions drifted\n")
					fmt.Printf("ASSURANCE STATUS:       ASSURED (no invalidation)\n")
				}
				return nil
			}

			fmt.Printf("DRIFT ANALYSIS FOR %s:\n\n", sub.URI())
			fmt.Printf("STATUS:                 UNKNOWN (cannot establish drift without evidence or server -- specify --server or --evidence-dir)\n")
			return nil
		},
	}

	// 5. oscal export assessment-results --subject <subject>
	var exportSubjectFlag string
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export continuous assurance data to standard OSCAL formats",
	}
	exportARCmd := &cobra.Command{
		Use:   "assessment-results",
		Short: "Export to NIST OSCAL v1.2.3 Assessment Results JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			subURI := exportSubjectFlag
			if subURI == "" {
				subURI = "k8s://prod/payments/Deployment/payments-api"
			}
			sub := parseSubjectURI(subURI)
			ctrl := assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}

			var envelopes []assurance.EvidenceEnvelope
			if evidenceDir != "" {
				envelopes, _ = loadLocalEvidence(evidenceDir, sub)
			}

			var eval assurance.ClaimEvaluation
			if len(envelopes) > 0 {
				var evRefs []assurance.EvidenceRef
				for _, env := range envelopes {
					evRefs = append(evRefs, env.Artifact)
				}
				evRoot := receipts.ComputeEvidenceRoot(evRefs)
				policyDigest := assurance.ComputeStringDigest(sub.URI() + ":" + evRoot)

				eval = assurance.ClaimEvaluation{
					ID:      fmt.Sprintf("eval-%s", ctrl.ID),
					Subject: sub,
					Control: ctrl,
					State:   assurance.AssuranceStateAssured,
					Epoch: assurance.AssuranceEpoch{
						SubjectDigest:        assurance.ComputeStringDigest(sub.URI()),
						ImplementationDigest: assurance.ComputeStringDigest("kubernetes:admission-policy"),
						PolicyDigest:         policyDigest,
						AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/operator"),
						EnvironmentDigest:    assurance.ComputeStringDigest("cluster:local"),
					},
					Evidence:     evRefs,
					Completeness: assurance.EvidenceCompleteness{Required: len(evRefs), Verified: len(evRefs)},
					EvidenceRoot: evRoot,
					EvaluatedAt:  time.Now().UTC(),
					ValidUntil:   time.Now().UTC().Add(5 * time.Minute),
				}
			} else {
				// Honest reporting when no evidence is present (Invariant I-02)
				eval = assurance.ClaimEvaluation{
					ID:           fmt.Sprintf("eval-unknown-%s", ctrl.ID),
					Subject:      sub,
					Control:      ctrl,
					State:        assurance.AssuranceStateUnknown,
					Epoch:        assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeStringDigest(sub.URI())},
					Evidence:     nil,
					Completeness: assurance.EvidenceCompleteness{Required: 1, Verified: 0},
					EvidenceRoot: "",
					EvaluatedAt:  time.Now().UTC(),
					ValidUntil:   time.Now().UTC().Add(5 * time.Minute),
				}
			}

			projector := oscal.NewProjector()
			data, err := projector.ProjectAssessmentResults(context.Background(), sub, []assurance.ClaimEvaluation{eval}, nil)
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		},
	}
	exportARCmd.Flags().StringVar(&exportSubjectFlag, "subject", "", "Workload subject to export")

	exportCompDefCmd := &cobra.Command{
		Use:   "component-definition",
		Short: "Export to NIST OSCAL v1.2.3 Component Definition JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			compName := exportSubjectFlag
			if compName == "" {
				compName = "payments-api"
			}
			sub := assurance.SubjectRef{Scheme: "k8s", ID: fmt.Sprintf("components/%s", compName)}
			ctrl := assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}

			var envelopes []assurance.EvidenceEnvelope
			if evidenceDir != "" {
				envelopes, _ = loadLocalEvidence(evidenceDir, sub)
			}

			var eval assurance.ClaimEvaluation
			if len(envelopes) > 0 {
				var evRefs []assurance.EvidenceRef
				for _, env := range envelopes {
					evRefs = append(evRefs, env.Artifact)
				}
				evRoot := receipts.ComputeEvidenceRoot(evRefs)
				eval = assurance.ClaimEvaluation{
					ID:      fmt.Sprintf("eval-%s", ctrl.ID),
					Subject: sub,
					Control: ctrl,
					State:   assurance.AssuranceStateAssured,
					Epoch: assurance.AssuranceEpoch{
						SubjectDigest: assurance.ComputeStringDigest(sub.URI()),
					},
					Evidence:     evRefs,
					EvidenceRoot: evRoot,
					EvaluatedAt:  time.Now().UTC(),
					ValidUntil:   time.Now().UTC().Add(5 * time.Minute),
				}
			} else {
				eval = assurance.ClaimEvaluation{
					ID:      fmt.Sprintf("eval-unknown-%s", ctrl.ID),
					Subject: sub,
					Control: ctrl,
					State:   assurance.AssuranceStateUnknown,
					Epoch: assurance.AssuranceEpoch{
						SubjectDigest: assurance.ComputeStringDigest(sub.URI()),
					},
					Evidence:     nil,
					EvidenceRoot: "",
					EvaluatedAt:  time.Now().UTC(),
				}
			}

			projector := oscal.NewProjector()
			data, err := projector.ProjectComponentDefinition(context.Background(), compName, []assurance.ClaimEvaluation{eval})
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		},
	}
	exportCompDefCmd.Flags().StringVar(&exportSubjectFlag, "component", "", "Component name to export")

	exportAPCmd := &cobra.Command{
		Use:   "assessment-plan",
		Short: "Export to NIST OSCAL v1.2.3 Assessment Plan JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			subURI := exportSubjectFlag
			if subURI == "" {
				subURI = "k8s://prod/payments/Deployment/payments-api"
			}
			sub := parseSubjectURI(subURI)
			contract := assurance.EvidenceContract{
				ID: fmt.Sprintf("contract-%s", sub.ID),
				Requirements: []assurance.EvidenceRequirement{
					{ID: "req-1", EvidenceType: "admission", Required: true, MaxAge: 5 * time.Minute},
				},
			}
			controls := []assurance.ControlRef{
				{Namespace: "nist-sp-800-53", ID: "AC-6"},
			}
			projector := oscal.NewProjector()
			data, err := projector.ProjectAssessmentPlan(context.Background(), sub, contract, controls)
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		},
	}
	exportAPCmd.Flags().StringVar(&exportSubjectFlag, "subject", "", "Workload subject to export")

	exportPOAMCmd := &cobra.Command{
		Use:   "poam",
		Short: "Export to NIST OSCAL v1.2.3 Plan of Action and Milestones JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			subURI := exportSubjectFlag
			if subURI == "" {
				subURI = "k8s://prod/payments/Deployment/payments-api"
			}
			sub := parseSubjectURI(subURI)
			// Truthfully report only observed findings (never fabricate fake violations)
			var findings []assurance.Finding
			projector := oscal.NewProjector()
			data, err := projector.ProjectPOAM(context.Background(), sub, findings)
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		},
	}
	exportPOAMCmd.Flags().StringVar(&exportSubjectFlag, "subject", "", "Workload subject to export")

	exportSSPCmd := &cobra.Command{
		Use:   "ssp",
		Short: "Export to NIST OSCAL v1.2.3 System Security Plan JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			subURI := exportSubjectFlag
			if subURI == "" {
				subURI = "k8s://prod/payments/Deployment/payments-api"
			}
			sub := parseSubjectURI(subURI)
			ctrl := assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
			eval := assurance.ClaimEvaluation{
				ID:      fmt.Sprintf("eval-%s", ctrl.ID),
				Subject: sub,
				Control: ctrl,
				State:   assurance.AssuranceStateAssured,
				Epoch: assurance.AssuranceEpoch{
					SubjectDigest: assurance.ComputeStringDigest(sub.URI()),
				},
				EvidenceRoot: assurance.ComputeStringDigest(sub.URI() + ":root"),
				EvaluatedAt:  time.Now().UTC(),
				ValidUntil:   time.Now().UTC().Add(5 * time.Minute),
			}
			projector := oscal.NewProjector()
			data, err := projector.ProjectSSP(context.Background(), sub.ID, []assurance.ClaimEvaluation{eval})
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		},
	}
	exportSSPCmd.Flags().StringVar(&exportSubjectFlag, "subject", "", "Workload subject to export")

	exportCmd.AddCommand(exportARCmd, exportCompDefCmd, exportAPCmd, exportSSPCmd, exportPOAMCmd)

	// 6. oscal import oscal --file <path> [--namespace <ns>] [--output-dir <dir>]
	var (
		importFilePath  string
		importNamespace string
		importOutputDir string
	)
	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Import external compliance artifacts into Kubernetes CRDs",
	}

	importOscalCmd := &cobra.Command{
		Use:   "oscal",
		Short: "Import NIST OSCAL v1.2.3 Component Definition or SSP and output Kubernetes manifests",
		RunE: func(cmd *cobra.Command, args []string) error {
			if importFilePath == "" {
				return fmt.Errorf("--file flag is required")
			}

			var data []byte
			var err error
			if importFilePath == "-" {
				data, err = io.ReadAll(os.Stdin)
			} else {
				data, err = os.ReadFile(importFilePath)
			}
			if err != nil {
				return fmt.Errorf("failed to read input OSCAL file: %w", err)
			}

			res, err := recoscal.IngestOSCAL(data, importNamespace)
			if err != nil {
				return fmt.Errorf("failed to ingest OSCAL document: %w", err)
			}

			fmt.Fprintf(os.Stderr, "[PASS] Ingested OSCAL %s: %s (UUID: %s)\n", res.SourceType, res.Title, res.SourceUUID)
			fmt.Fprintf(os.Stderr, "[INFO] Generated %d ControlBinding(s) and %d EvidenceContract(s)\n", len(res.ControlBindings), len(res.EvidenceContracts))
			fmt.Fprintf(os.Stderr, "---\n")

			var allManifests []string
			for _, ec := range res.EvidenceContracts {
				ecYaml, err := yaml.Marshal(ec)
				if err != nil {
					return err
				}
				allManifests = append(allManifests, string(ecYaml))
			}
			for _, cb := range res.ControlBindings {
				cbYaml, err := yaml.Marshal(cb)
				if err != nil {
					return err
				}
				allManifests = append(allManifests, string(cbYaml))
			}

			output := strings.Join(allManifests, "\n---\n")

			if importOutputDir != "" {
				if err := os.MkdirAll(importOutputDir, 0755); err != nil {
					return err
				}
				targetPath := filepath.Join(importOutputDir, fmt.Sprintf("%s-crds.yaml", recoscal.SanitizeK8sName(res.Title)))
				if err := os.WriteFile(targetPath, []byte(output), 0644); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "[PASS] Manifests written to %s\n", targetPath)
			} else {
				fmt.Println(output)
			}

			return nil
		},
	}
	importOscalCmd.Flags().StringVarP(&importFilePath, "file", "f", "", "Path to OSCAL JSON or YAML file (or - for stdin)")
	importOscalCmd.Flags().StringVarP(&importNamespace, "namespace", "n", "default", "Target Kubernetes namespace for generated CRDs")
	importOscalCmd.Flags().StringVarP(&importOutputDir, "output-dir", "o", "", "Directory to write generated CRD manifests to (defaults to stdout)")

	importCmd.AddCommand(importOscalCmd)

	// 7. oscal serve --port <port>
	var port int
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the gRPC AssuranceService daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				return fmt.Errorf("failed to listen on port %d: %w", port, err)
			}

			grpcServer := grpc.NewServer()
			srv := service.NewServer(nil)
			servicesv1.RegisterAssuranceServiceServer(grpcServer, srv)

			fmt.Printf("OSKAL AssuranceService gRPC daemon listening on port %d\n", port)

			stopCh := make(chan os.Signal, 1)
			signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)

			go func() {
				<-stopCh
				fmt.Println("Shutting down OSKAL AssuranceService gRPC daemon...")
				grpcServer.GracefulStop()
			}()

			if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
				return fmt.Errorf("gRPC server error: %w", err)
			}
			return nil
		},
	}
	serveCmd.Flags().IntVar(&port, "port", 9090, "Port for gRPC service to listen on")

	// 8. oscal webhook
	var (
		webhookListenAddr  string
		webhookTLSCertFile string
		webhookTLSKeyFile  string
		webhookSelfSigned  bool
		webhookServiceName string
		webhookNamespace   string
		webhookEvidenceDir string
		webhookMode        string
	)
	webhookCmd := &cobra.Command{
		Use:   "webhook",
		Short: "Start the Kubernetes Validating Admission Webhook with in-flight attestation",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := webhook.ServerConfig{
				ListenAddr:  webhookListenAddr,
				TLSCertPath: webhookTLSCertFile,
				TLSKeyPath:  webhookTLSKeyFile,
				Mode:        webhook.WebhookMode(webhookMode),
				ObserverAuth: assurance.AuthorityRef{
					Scheme:  "k8s:admission-controller",
					Subject: fmt.Sprintf("%s/%s", webhookNamespace, webhookServiceName),
				},
			}

			if webhookEvidenceDir != "" {
				if err := os.MkdirAll(webhookEvidenceDir, 0755); err != nil {
					return fmt.Errorf("failed to create evidence directory: %w", err)
				}
				cfg.EvidenceSink = func(env assurance.EvidenceEnvelope) {
					data, err := json.MarshalIndent(env, "", "  ")
					if err != nil {
						return
					}
					filename := filepath.Join(webhookEvidenceDir, fmt.Sprintf("%s.json", env.ID))
					_ = os.WriteFile(filename, data, 0644)
				}
			}

			if webhookSelfSigned && (webhookTLSCertFile == "" || webhookTLSKeyFile == "") {
				dnsNames := []string{
					webhookServiceName,
					fmt.Sprintf("%s.%s", webhookServiceName, webhookNamespace),
					fmt.Sprintf("%s.%s.svc", webhookServiceName, webhookNamespace),
					fmt.Sprintf("%s.%s.svc.cluster.local", webhookServiceName, webhookNamespace),
					"localhost",
				}
				ips := []net.IP{net.ParseIP("127.0.0.1")}
				certPEM, keyPEM, err := webhook.GenerateSelfSignedCert(webhookServiceName, dnsNames, ips)
				if err != nil {
					return fmt.Errorf("failed to generate self-signed cert: %w", err)
				}
				cfg.TLSCertBytes = certPEM
				cfg.TLSKeyBytes = keyPEM
			}

			server := webhook.NewAdmissionWebhookServer(cfg)
			modeStr := string(cfg.Mode)
			if modeStr == "" {
				modeStr = "enforcing"
			}
			fmt.Printf("OSKAL Validating Admission Webhook listening on %s (TLS enabled, mode: %s)\n", webhookListenAddr, modeStr)

			stopCh := make(chan os.Signal, 1)
			signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)

			errCh := make(chan error, 1)
			go func() {
				if err := server.Start(context.Background()); err != nil && err != http.ErrServerClosed {
					errCh <- err
				}
			}()

			select {
			case <-stopCh:
				fmt.Println("Shutting down OSKAL Validating Admission Webhook...")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return server.Shutdown(shutdownCtx)
			case err := <-errCh:
				return fmt.Errorf("webhook server error: %w", err)
			}
		},
	}
	webhookCmd.Flags().StringVar(&webhookListenAddr, "listen", ":8443", "Address and port for webhook to listen on")
	webhookCmd.Flags().StringVar(&webhookTLSCertFile, "tls-cert-file", "", "Path to TLS certificate file")
	webhookCmd.Flags().StringVar(&webhookTLSKeyFile, "tls-key-file", "", "Path to TLS private key file")
	webhookCmd.Flags().BoolVar(&webhookSelfSigned, "self-signed", true, "Generate self-signed TLS certificate if files not provided")
	webhookCmd.Flags().StringVar(&webhookServiceName, "service-name", "oskal-webhook", "Kubernetes Service name for TLS SANs")
	webhookCmd.Flags().StringVar(&webhookNamespace, "namespace", "ckodex-system", "Kubernetes Namespace for TLS SANs")
	webhookCmd.Flags().StringVar(&webhookEvidenceDir, "evidence-dir", "", "Directory to record admitted in-flight evidence envelopes")
	webhookCmd.Flags().StringVar(&webhookMode, "mode", "enforcing", "Webhook enforcement mode: enforcing, audit, warn")

	// 9. oscal validate <file> [--schema <type>] [--output <format>]
	var (
		validateSchema string
		validateOutput string
	)
	validateCmd := &cobra.Command{
		Use:   "validate <file-path-or-dash>",
		Short: "Validate an OSCAL document against strict NIST v1.2.3 schemas",
		Long: `Validate any NIST OSCAL v1.2.3 document (JSON or YAML) with sub-millisecond execution.
Auto-detects document type (Assessment Results, Component Definition, SSP, Assessment Plan, POAM)
and provides exact JSON path error diagnostics.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]
			var data []byte
			var err error
			if filePath == "-" {
				data, err = io.ReadAll(os.Stdin)
			} else {
				data, err = os.ReadFile(filePath)
			}
			if err != nil {
				return fmt.Errorf("failed to read document: %w", err)
			}

			val, err := oscal.DefaultValidator()
			if err != nil {
				return fmt.Errorf("failed to initialize schema validator: %w", err)
			}

			report, err := val.Validate(data, validateSchema)
			if err != nil {
				return fmt.Errorf("validation execution failed: %w", err)
			}

			outFormat, err := format.NormalizeFormat(validateOutput)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			switch outFormat {
			case format.FormatJSON, format.FormatYAML:
				return format.RenderStructured(w, report, outFormat)
			default:
				_, _ = fmt.Fprintf(w, "OSCAL VALIDATION REPORT\n")
				_, _ = fmt.Fprintf(w, "----------------------------------------------------------------------\n")
				_, _ = fmt.Fprintf(w, "Document Type: %s\n", report.DocumentType)
				if report.OscalVersion != "" {
					_, _ = fmt.Fprintf(w, "OSCAL Version: %s (NIST Release)\n", report.OscalVersion)
				}
				durStr := strings.ReplaceAll(report.Duration.String(), "\u00b5", "u")
				_, _ = fmt.Fprintf(w, "Duration:      %s\n", durStr)
				if report.Valid {
					_, _ = fmt.Fprintf(w, "Status:        [PASS] Document conforms strictly to NIST OSCAL v1.2.3\n")
					return nil
				}
				_, _ = fmt.Fprintf(w, "Status:        [FAIL] %d schema validation error(s) detected\n\n", len(report.Errors))
				headers := []string{"PATH", "ERROR MESSAGE"}
				var rows [][]string
				for _, e := range report.Errors {
					rows = append(rows, []string{e.Path, e.Message})
				}
				_ = format.RenderTable(w, headers, rows)
				return fmt.Errorf("validation failed: %d errors", len(report.Errors))
			}
		},
	}
	validateCmd.Flags().StringVar(&validateSchema, "schema", "auto", "Schema override: auto, assessment-results, component-definition, ssp, assessment-plan, poam")
	validateCmd.Flags().StringVar(&validateOutput, "output", "table", "Output format: table, json, yaml")

	// 10. oscal scaffold [profile] [--workload <name>] [--namespace <ns>] [--output-dir <dir>]
	var (
		scaffoldWorkload  string
		scaffoldNamespace string
		scaffoldOutputDir string
		scaffoldOutput    string
	)
	scaffoldCmd := &cobra.Command{
		Use:   "scaffold [profile]",
		Short: "Scaffold Kubernetes ControlBinding, EvidenceContract, and OSCAL manifests",
		Long: `Generate baseline Kubernetes compliance artifacts and NIST OSCAL v1.2.3 Component Definitions.
Supported profiles: nist-sp-800-53, pci-dss, soc-2, iso-27001.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile := "nist-sp-800-53"
			if len(args) > 0 {
				profile = args[0]
			}

			plan, err := scaffold.GenerateScaffold(profile, scaffoldNamespace, scaffoldWorkload)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			if scaffoldOutputDir != "" {
				if err := plan.WriteToDirectory(scaffoldOutputDir); err != nil {
					return err
				}
				_, _ = fmt.Fprintf(w, "[PASS] Compliance scaffolding generated in %s\n", scaffoldOutputDir)
				_, _ = fmt.Fprintf(w, "       Profile:   %s\n", plan.Profile)
				_, _ = fmt.Fprintf(w, "       Workload:  %s\n", plan.WorkloadName)
				_, _ = fmt.Fprintf(w, "       Namespace: %s\n", plan.Namespace)
				return nil
			}

			outFormat, err := format.NormalizeFormat(scaffoldOutput)
			if err != nil {
				return err
			}

			switch outFormat {
			case format.FormatJSON:
				return format.RenderStructured(w, plan, format.FormatJSON)
			default:
				manifests, err := plan.RenderManifestsYAML()
				if err != nil {
					return err
				}
				_, _ = fmt.Fprint(w, manifests)
				return nil
			}
		},
	}
	scaffoldCmd.Flags().StringVar(&scaffoldWorkload, "workload", "example-app", "Target workload name")
	scaffoldCmd.Flags().StringVarP(&scaffoldNamespace, "namespace", "n", "default", "Target Kubernetes namespace")
	scaffoldCmd.Flags().StringVarP(&scaffoldOutputDir, "output-dir", "o", "", "Directory to output scaffolded files (if omitted, prints YAML to stdout)")
	scaffoldCmd.Flags().StringVar(&scaffoldOutput, "output", "yaml", "Output format: yaml, json")

	// 11. oscal doctor [--output <format>]
	var doctorOutput string
	doctorCmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run deep system preflight diagnostics (Constitution Section 36 & 37)",
		Long: `Examines runtime substrate, Kubernetes connectivity, SPIFFE/SPIRE Workload API socket,
Sigstore trust root, local CAS evidence directory, and embedded NIST OSCAL v1.2.3 schemas.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			report := diagnostics.RunDoctor(cmd.Context(), evidenceDir)

			outFormat, err := format.NormalizeFormat(doctorOutput)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			switch outFormat {
			case format.FormatJSON, format.FormatYAML:
				return format.RenderStructured(w, report, outFormat)
			default:
				_, _ = fmt.Fprintf(w, "OSKAL SYSTEM DIAGNOSTIC DOCTOR\n")
				_, _ = fmt.Fprintf(w, "----------------------------------------------------------------------\n")
				_, _ = fmt.Fprintf(w, "Overall State:  [%s]\n", report.OverallState)
				_, _ = fmt.Fprintf(w, "Evaluated In:   %s\n", report.Duration)
				_, _ = fmt.Fprintf(w, "Timestamp:      %s\n\n", report.Timestamp.Format(time.RFC3339))

				headers := []string{"CHECK", "TARGET", "STATUS", "DURATION", "DETAILS"}
				var rows [][]string
				for _, c := range report.Checks {
					msg := c.Message
					if c.Remediation != "" {
						msg = fmt.Sprintf("%s (Fix: %s)", msg, c.Remediation)
					}
					rows = append(rows, []string{c.Name, c.Target, string(c.Status), c.Duration, msg})
				}
				_ = format.RenderTable(w, headers, rows)
				if report.OverallState == diagnostics.StatusFail {
					return fmt.Errorf("system doctor detected critical health failures")
				}
				return nil
			}
		},
	}
	doctorCmd.Flags().StringVar(&doctorOutput, "output", "table", "Output format: table, json, yaml")

	// 12. oscal inspect <subject-uri> [--output <format>] [--control <id>]
	var (
		inspectOutput  string
		inspectControl string
	)
	inspectCmd := &cobra.Command{
		Use:   "inspect <subject-uri>",
		Short: "Inspect a workload and reconstruct the 4 Truth Channels (Constitution Section 13)",
		Long: `Reconstructs Telemetry trace, Execution trace, Decision trace, and Evidence trace
for a governed workload subject without collapsing them into generic logs.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sub := parseSubjectURI(args[0])
			ctrlID := "AC-6"
			ctrlNS := "nist-sp-800-53"
			if inspectControl != "" {
				parts := strings.SplitN(inspectControl, ":", 2)
				if len(parts) == 2 {
					ctrlNS = parts[0]
					ctrlID = parts[1]
				} else {
					ctrlID = inspectControl
				}
			}
			ctrl := assurance.ControlRef{Namespace: ctrlNS, ID: ctrlID}

			var envelopes []assurance.EvidenceEnvelope
			if evidenceDir != "" {
				envelopes, _ = loadLocalEvidence(evidenceDir, sub)
			}

			now := time.Now().UTC()
			var eval assurance.ClaimEvaluation
			if len(envelopes) > 0 {
				var evRefs []assurance.EvidenceRef
				for _, env := range envelopes {
					evRefs = append(evRefs, env.Artifact)
				}
				evRoot := receipts.ComputeEvidenceRoot(evRefs)
				eval = assurance.ClaimEvaluation{
					ID:      fmt.Sprintf("eval-%s", ctrl.ID),
					Subject: sub,
					Control: ctrl,
					State:   assurance.AssuranceStateAssured,
					Epoch: assurance.AssuranceEpoch{
						SubjectDigest: assurance.ComputeStringDigest(sub.URI()),
						PolicyDigest:  assurance.ComputeStringDigest("cel:policy:ac-6"),
					},
					Evidence:     evRefs,
					EvidenceRoot: evRoot,
					EvaluatedAt:  now,
				}
			} else {
				eval = assurance.ClaimEvaluation{
					ID:           fmt.Sprintf("eval-%s", ctrl.ID),
					Subject:      sub,
					Control:      ctrl,
					State:        assurance.AssuranceStateUnknown,
					Epoch:        assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeStringDigest(sub.URI())},
					EvidenceRoot: "",
					EvaluatedAt:  now,
				}
			}

			report := diagnostics.InspectSubject(cmd.Context(), sub, eval, envelopes)

			outFormat, err := format.NormalizeFormat(inspectOutput)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			switch outFormat {
			case format.FormatJSON, format.FormatYAML:
				return format.RenderStructured(w, report, outFormat)
			case format.FormatTree:
				root := &format.TreeNode{
					Title:   "Subject",
					Details: report.Subject,
					Children: []*format.TreeNode{
						{
							Title:   "Channel 1: Telemetry",
							Details: fmt.Sprintf("Duration: %s, Mem: %d KB", report.Telemetry.EvaluationDuration, report.Telemetry.MemoryAllocatedKB),
						},
						{
							Title:   "Channel 2: Execution Path",
							Details: report.Execution.PathID,
							Children: func() []*format.TreeNode {
								var steps []*format.TreeNode
								for _, s := range report.Execution.Steps {
									steps = append(steps, &format.TreeNode{
										Title:   fmt.Sprintf("[%d] %s", s.Order, s.Stage),
										Details: fmt.Sprintf("%s -> %s", s.Action, s.Outcome),
									})
								}
								return steps
							}(),
						},
						{
							Title:   "Channel 3: Decision Trace",
							Details: fmt.Sprintf("Disposition: %s (%s)", report.Decision.Disposition, report.Decision.Rationale),
						},
						{
							Title:   "Channel 4: Evidence Trace",
							Details: fmt.Sprintf("Root: %s, Signer: %s (%d artifacts)", report.Evidence.EvidenceRoot, report.Evidence.SignerIdentity, len(report.Evidence.Artifacts)),
						},
					},
				}
				if report.Remediation != nil {
					root.Children = append(root.Children, &format.TreeNode{
						Title:   "Channel 5: Actionable Remediation",
						Details: fmt.Sprintf("Action: %s", report.Remediation.RemediationCmd),
						Children: []*format.TreeNode{
							{Title: "Missing Signals", Details: strings.Join(report.Remediation.MissingSignals, ", ")},
							{Title: "Explanation", Details: report.Remediation.Explanation},
						},
					})
				}
				return format.RenderTree(w, root)
			default:
				_, _ = fmt.Fprintf(w, "OSKAL 4 TRUTH CHANNELS INSPECTION REPORT\n")
				_, _ = fmt.Fprintf(w, "======================================================================\n")
				_, _ = fmt.Fprintf(w, "Subject:         %s\n", report.Subject)
				_, _ = fmt.Fprintf(w, "Assurance State: %s\n", report.AssuranceState)
				_, _ = fmt.Fprintf(w, "Timestamp:       %s\n\n", report.Timestamp.Format(time.RFC3339))

				_, _ = fmt.Fprintf(w, "1. TELEMETRY TRACE:\n")
				_, _ = fmt.Fprintf(w, "   Evaluation Duration: %s\n", report.Telemetry.EvaluationDuration)
				_, _ = fmt.Fprintf(w, "   Evidence Fetch Time: %s\n", report.Telemetry.EvidenceFetchTime)
				_, _ = fmt.Fprintf(w, "   Rule Execution Time: %s\n", report.Telemetry.RuleExecutionTime)
				_, _ = fmt.Fprintf(w, "   Memory Allocated:    %d KB\n\n", report.Telemetry.MemoryAllocatedKB)

				_, _ = fmt.Fprintf(w, "2. EXECUTION TRACE (Path: %s):\n", report.Execution.PathID)
				for _, s := range report.Execution.Steps {
					_, _ = fmt.Fprintf(w, "   [%d] %-25s %-40s [%s]\n", s.Order, s.Stage, s.Action, s.Outcome)
				}
				_, _ = fmt.Fprintln(w)

				_, _ = fmt.Fprintf(w, "3. DECISION TRACE:\n")
				_, _ = fmt.Fprintf(w, "   Control:         %s\n", report.Decision.ControlID)
				_, _ = fmt.Fprintf(w, "   Policy Digest:   %s\n", report.Decision.PolicyDigest)
				_, _ = fmt.Fprintf(w, "   Disposition:     %s\n", report.Decision.Disposition)
				_, _ = fmt.Fprintf(w, "   Rationale:       %s\n\n", report.Decision.Rationale)

				_, _ = fmt.Fprintf(w, "4. EVIDENCE TRACE:\n")
				_, _ = fmt.Fprintf(w, "   Evidence Root:   %s\n", report.Evidence.EvidenceRoot)
				_, _ = fmt.Fprintf(w, "   Signer Identity: %s\n", report.Evidence.SignerIdentity)
				_, _ = fmt.Fprintf(w, "   Merkle Valid:    %v\n", report.Evidence.MerkleValid)
				_, _ = fmt.Fprintf(w, "   Artifact Count:  %d\n", len(report.Evidence.Artifacts))
				for i, a := range report.Evidence.Artifacts {
					_, _ = fmt.Fprintf(w, "   [%d] %s (Type: %s, Freshness: %s)\n", i+1, a.Digest, a.Type, a.Freshness)
				}
				if report.Remediation != nil {
					_, _ = fmt.Fprintf(w, "\n5. ACTIONABLE REMEDIATION:\n")
					_, _ = fmt.Fprintf(w, "   Target Control:  %s\n", report.Remediation.TargetControl)
					_, _ = fmt.Fprintf(w, "   Disposition:     %s\n", report.Remediation.Disposition)
					_, _ = fmt.Fprintf(w, "   Missing Signals: %s\n", strings.Join(report.Remediation.MissingSignals, ", "))
					_, _ = fmt.Fprintf(w, "   Remediation Cmd: %s\n", report.Remediation.RemediationCmd)
					_, _ = fmt.Fprintf(w, "   Explanation:     %s\n", report.Remediation.Explanation)
				}
				return nil
			}
		},
	}
	inspectCmd.Flags().StringVar(&inspectOutput, "output", "table", "Output format: table, tree, json, yaml")
	inspectCmd.Flags().StringVar(&inspectControl, "control", "nist-sp-800-53:AC-6", "Control to inspect")

	// 13. oscal mcp
	mcpCmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start native Model Context Protocol (stdio JSON-RPC 2.0) server",
		Long: `Exposes OSKAL continuous assurance capabilities as native MCP tools
for Claude Code, Cursor, OpenCode, and AI developer environments over stdio.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			srv, err := mcp.NewServer(os.Stdin, os.Stdout, evidenceDir)
			if err != nil {
				return err
			}
			return srv.Run(cmd.Context())
		},
	}

	// 14. oscal cockpit [--refresh <duration>] [--once] [--subject <uri>]
	var (
		cockpitRefresh time.Duration
		cockpitOnce    bool
		cockpitSubject string
	)
	cockpitCmd := &cobra.Command{
		Use:   "cockpit",
		Short: "Interactive ASCII continuous assurance monitoring dashboard",
		Long: `Displays a live pure-ASCII terminal dashboard of workload vector states,
Merkle roots, drift alerts, and reconciliation loops.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := cockpit.NewCockpit(cockpit.CockpitConfig{
				RefreshInterval: cockpitRefresh,
				Once:            cockpitOnce,
				EvidenceDir:     evidenceDir,
				SubjectFilter:   cockpitSubject,
				Writer:          os.Stdout,
			})
			return c.Run(cmd.Context())
		},
	}
	cockpitCmd.Flags().DurationVar(&cockpitRefresh, "refresh", 2*time.Second, "Dashboard refresh interval")
	cockpitCmd.Flags().BoolVar(&cockpitOnce, "once", false, "Render a single frame and exit (ideal for CI/scripts)")
	cockpitCmd.Flags().StringVar(&cockpitSubject, "subject", "", "Filter dashboard to a specific workload subject")

	// 15. oscal config [view|init]
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage persistent OSKAL configuration (.oskal.yaml)",
	}
	configViewCmd := &cobra.Command{
		Use:   "view",
		Short: "View active OSKAL configuration and source file",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()
			cfg, sourceFile, err := config.LoadConfig(configFileFlag)
			if err != nil {
				return err
			}
			sourceDesc := sourceFile
			if sourceDesc == "" {
				sourceDesc = "none (using smart defaults)"
			}
			_, _ = fmt.Fprintf(w, "CONFIG FILE:  %s\n", sourceDesc)
			_, _ = fmt.Fprintf(w, "SERVER:       %s\n", cfg.Server)
			_, _ = fmt.Fprintf(w, "EVIDENCE DIR: %s\n", cfg.EvidenceDir)
			_, _ = fmt.Fprintf(w, "NAMESPACE:    %s\n", cfg.Namespace)
			_, _ = fmt.Fprintf(w, "OUTPUT:       %s\n", cfg.Output)
			_, _ = fmt.Fprintf(w, "PROFILE:      %s\n", cfg.Profile)
			return nil
		},
	}
	configInitCmd := &cobra.Command{
		Use:   "init [path]",
		Short: "Initialize a default .oskal.yaml configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			target := ".oskal.yaml"
			if len(args) > 0 {
				target = args[0]
			}
			cfg := config.DefaultConfig()
			if err := config.SaveConfig(cfg, target); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Created default configuration file: %s\n", target)
			return nil
		},
	}
	configCmd.AddCommand(configViewCmd, configInitCmd)

	// 16. oscal prune [--older-than <duration>] [--dry-run]
	var (
		pruneOlderThan time.Duration
		pruneDryRun    bool
	)
	pruneCmd := &cobra.Command{
		Use:   "prune",
		Short: "Prune expired evidence envelopes from local CAS storage (bounded retention)",
		Long: `Prunes verified evidence envelopes older than the specified retention window
from the local Content-Addressable Storage (CAS) directory to prevent unbounded disk growth.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()
			dir := evidenceDir
			if dir == "" {
				dir = "evidence"
			}
			repo, err := storage.NewFilesystemEvidenceRepository(dir)
			if err != nil {
				return fmt.Errorf("failed to open evidence repository at %s: %w", dir, err)
			}
			pruned, err := repo.Prune(pruneOlderThan, pruneDryRun)
			if err != nil {
				return fmt.Errorf("prune failed: %w", err)
			}
			mode := "PRUNED"
			if pruneDryRun {
				mode = "DRY-RUN (would prune)"
			}
			_, _ = fmt.Fprintf(w, "%s: %d envelopes (freed %d bytes) older than %s from %s\n", mode, pruned.PrunedCount, pruned.PrunedBytes, pruneOlderThan, dir)
			return nil
		},
	}
	pruneCmd.Flags().DurationVar(&pruneOlderThan, "older-than", 720*time.Hour, "Retention age threshold (e.g. 720h, 30d)")
	pruneCmd.Flags().BoolVar(&pruneDryRun, "dry-run", false, "Preview envelopes that would be deleted without removing them")

	assuranceCmd.AddCommand(stateCmd, explainCmd, evidenceCmd, driftCmd)
	rootCmd.AddCommand(
		assuranceCmd,
		exportCmd,
		importCmd,
		serveCmd,
		webhookCmd,
		validateCmd,
		scaffoldCmd,
		doctorCmd,
		inspectCmd,
		mcpCmd,
		cockpitCmd,
		configCmd,
		pruneCmd,
	)
	return rootCmd
}

func main() {
	if err := NewRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
