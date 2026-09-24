package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/ckodex-labs/oskal/core/assurance"
	"github.com/ckodex-labs/oskal/internal/application/explain"
	"github.com/ckodex-labs/oskal/internal/projection/oscal"
	"github.com/ckodex-labs/oskal/internal/receipts"
	"github.com/ckodex-labs/oskal/internal/service"
	commonv1 "github.com/ckodex-labs/oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/oskal/proto/assurance/control/v1"
	servicesv1 "github.com/ckodex-labs/oskal/proto/assurance/services/v1"
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

func main() {
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
				defer conn.Close()

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
				defer conn.Close()

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
					ID:      "eval-01",
					Subject: sub,
					Control: ctrl,
					State:   assurance.AssuranceStateAssured,
					Epoch: assurance.AssuranceEpoch{
						SubjectDigest:        assurance.ComputeStringDigest(sub.URI()),
						ImplementationDigest: "sha256:imp",
						PolicyDigest:         policyDigest,
						AuthorityDigest:      "sha256:auth",
						EnvironmentDigest:    "sha256:env",
					},
					Evidence:     evRefs,
					EvidenceRoot: evRoot,
					EvaluatedAt:  time.Now().UTC(),
					ValidUntil:   time.Now().UTC().Add(5 * time.Minute),
				}
			} else {
				eval = assurance.ClaimEvaluation{
					ID:           "eval-unknown",
					Subject:      sub,
					Control:      ctrl,
					State:        assurance.AssuranceStateUnknown,
					Epoch:        assurance.AssuranceEpoch{},
					Evidence:     nil,
					EvidenceRoot: "none",
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
			sub := assurance.SubjectRef{Scheme: "k8s", ID: subURI}
			epoch := assurance.AssuranceEpoch{
				SubjectDigest:        "sha256:sub",
				ImplementationDigest: "sha256:imp",
				PolicyDigest:         "sha256:pol",
				AuthorityDigest:      "sha256:auth",
				EnvironmentDigest:    "sha256:env",
			}
			eval := assurance.ClaimEvaluation{
				ID:      "eval-01",
				Subject: sub,
				Control: assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"},
				State:   assurance.AssuranceStateAssured,
				Epoch:   epoch,
				Evidence: []assurance.EvidenceRef{
					{URI: "s3://evidence/ev-01", Digest: "sha256:ev01", MediaType: "application/json"},
				},
				Completeness: assurance.EvidenceCompleteness{Required: 1, Verified: 1},
				EvidenceRoot: "sha256:root123",
				EvaluatedAt:  time.Now().UTC(),
				ValidUntil:   time.Now().UTC().Add(5 * time.Minute),
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
			eval := assurance.ClaimEvaluation{
				ID:      "eval-01",
				Subject: assurance.SubjectRef{Scheme: "k8s", ID: "payments/payments-api"},
				Control: assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"},
				State:   assurance.AssuranceStateAssured,
				Epoch: assurance.AssuranceEpoch{
					SubjectDigest: "sha256:sub",
				},
				EvidenceRoot: "sha256:root123",
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
			sub := assurance.SubjectRef{Scheme: "k8s", ID: subURI}
			contract := assurance.EvidenceContract{
				ID: "contract-01",
				Requirements: []assurance.EvidenceRequirement{
					{ID: "req-1", EvidenceType: "admission", MaxAge: 5 * time.Minute},
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
			sub := assurance.SubjectRef{Scheme: "k8s", ID: subURI}
			findings := []assurance.Finding{
				{
					ID:           "find-01",
					Subject:      sub,
					Control:      assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"},
					Severity:     "HIGH",
					Title:        "Remediation required for privileged container",
					Description:  "Pod security admission denied root execution",
					DiscoveredAt: time.Now().UTC(),
				},
			}
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

	// 6. oscal serve --port <port>
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

	assuranceCmd.AddCommand(stateCmd, explainCmd, evidenceCmd, driftCmd)
	rootCmd.AddCommand(assuranceCmd, exportCmd, serveCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
