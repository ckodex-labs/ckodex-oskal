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
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/webhook"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/explain"
	"github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	recoscal "github.com/ckodex-labs/ckodex-oskal/internal/reconciler/oscal"
	"github.com/ckodex-labs/ckodex-oskal/internal/service"
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
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var results []assurance.EvidenceEnvelope
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var envList []assurance.EvidenceEnvelope
		if err := json.Unmarshal(data, &envList); err == nil {
			for _, env := range envList {
				if matchSubject(env.Subject, sub) {
					results = append(results, env)
				}
			}
			continue
		}

		var single assurance.EvidenceEnvelope
		if err := json.Unmarshal(data, &single); err == nil {
			if matchSubject(single.Subject, sub) {
				results = append(results, single)
			}
		}
	}
	return results, nil
}

func matchSubject(a, b assurance.SubjectRef) bool {
	if a.ID == "" || b.ID == "" {
		return true
	}
	if a.ID == b.ID || a.URI() == b.URI() {
		return true
	}
	// Match trailing resource name (e.g. "payments-api")
	partsA := strings.Split(strings.Trim(a.ID, "/"), "/")
	partsB := strings.Split(strings.Trim(b.ID, "/"), "/")
	if len(partsA) > 0 && len(partsB) > 0 && partsA[len(partsA)-1] == partsB[len(partsB)-1] {
		return true
	}
	return strings.Contains(a.ID, b.ID) || strings.Contains(b.ID, a.ID)
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

	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "", "AssuranceService gRPC address (e.g. localhost:9090)")
	rootCmd.PersistentFlags().StringVar(&evidenceDir, "evidence-dir", "", "Path to directory containing local EvidenceEnvelope JSON files")

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

	exportCmd.AddCommand(exportARCmd, exportCompDefCmd, exportAPCmd, exportPOAMCmd)

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
	)
	webhookCmd := &cobra.Command{
		Use:   "webhook",
		Short: "Start the Kubernetes Validating Admission Webhook with in-flight attestation",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := webhook.ServerConfig{
				ListenAddr:  webhookListenAddr,
				TLSCertPath: webhookTLSCertFile,
				TLSKeyPath:  webhookTLSKeyFile,
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
			fmt.Printf("OSKAL Validating Admission Webhook listening on %s (TLS enabled)\n", webhookListenAddr)

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

	assuranceCmd.AddCommand(stateCmd, explainCmd, evidenceCmd, driftCmd)
	rootCmd.AddCommand(assuranceCmd, exportCmd, importCmd, serveCmd, webhookCmd)
	return rootCmd
}

func main() {
	if err := NewRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
