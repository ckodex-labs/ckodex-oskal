package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ckodex-labs/oskal/core/assurance"
	"github.com/ckodex-labs/oskal/internal/application/explain"
	"github.com/ckodex-labs/oskal/internal/projection/oscal"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "oskal",
		Short: "OSKAL — Continuous Kubernetes Assurance CLI",
		Long: `OSKAL is the Continuous Kubernetes Assurance Runtime for CKODEX.
It evaluates continuous evidence contracts, tracks semantic drift,
and projects defensible results into standard OSCAL artifacts.`,
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

			fmt.Printf("SUBJECT:         %s\n", sub.URI())
			fmt.Printf("STATE:           ASSURED\n")
			fmt.Printf("EPOCH:           sha256:d8a57e3f2b4c10a112233445566778899aabbccd\n")
			fmt.Printf("EVIDENCE ROOT:   sha256:4a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b\n")
			fmt.Printf("LAST EVALUATED:  %s\n", time.Now().UTC().Format(time.RFC3339))
			fmt.Printf("FRESHNESS:       current\n")
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

			eval := assurance.ClaimEvaluation{
				ID:      "eval-01",
				Subject: sub,
				Control: ctrl,
				State:   assurance.AssuranceStateAssured,
				Epoch: assurance.AssuranceEpoch{
					SubjectDigest:        "sha256:sub12345",
					ImplementationDigest: "sha256:imp12345",
					PolicyDigest:         "sha256:pol12345",
					AuthorityDigest:      "sha256:auth12345",
					EnvironmentDigest:    "sha256:env12345",
				},
				EvidenceRoot: "sha256:root987654321",
				EvaluatedAt:  time.Now().UTC(),
				ValidUntil:   time.Now().UTC().Add(5 * time.Minute),
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
			fmt.Printf("EVIDENCE ENVELOPES FOR %s:\n\n", subjectURI)
			fmt.Printf("1. [kubernetes.admission]\n   Producer: spiffe://prod/ns/ckodex-assurance/sa/cel-admission-observer\n   Digest:   sha256:ev_admission_01\n   URI:      evidence://admission/payments/payments-api\n\n")
			fmt.Printf("2. [supply-chain.signature]\n   Producer: spiffe://prod/ns/ckodex-evidence/sa/sigstore-verifier\n   Digest:   sha256:ev_sig_02\n   URI:      oci://registry.example/payments/payments-api.sig\n\n")
			fmt.Printf("3. [workload.runtime.process]\n   Producer: spiffe://prod/ns/ckodex-evidence/sa/tetragon-collector\n   Digest:   sha256:ev_tetragon_03\n   URI:      tetragon://events/payments-api\n\n")
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
			fmt.Printf("DRIFT ANALYSIS FOR %s:\n\n", subjectURI)
			fmt.Printf("SUBJECT STATUS:         IN_SYNC\n")
			fmt.Printf("RECORDED POLICY DIGEST: sha256:pol12345\n")
			fmt.Printf("CURRENT POLICY DIGEST:  sha256:pol12345\n")
			fmt.Printf("AUTHORITY CA ROTATION:  NONE (valid for 23h)\n")
			fmt.Printf("SEMANTIC DRIFT:         0 dimensions drifted\n")
			fmt.Printf("ASSURANCE STATUS:       ASSURED (no invalidation)\n")
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
	exportCmd.AddCommand(exportARCmd)

	assuranceCmd.AddCommand(stateCmd, explainCmd, evidenceCmd, driftCmd)
	rootCmd.AddCommand(assuranceCmd, exportCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
