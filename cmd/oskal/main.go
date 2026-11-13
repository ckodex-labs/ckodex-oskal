package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/mcp"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/utcp"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/webhook"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/diagnostics"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/evaluation"
	"github.com/ckodex-labs/ckodex-oskal/internal/config"
	"github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	recoscal "github.com/ckodex-labs/ckodex-oskal/internal/reconciler/oscal"
	"github.com/ckodex-labs/ckodex-oskal/internal/scaffold"
	"github.com/ckodex-labs/ckodex-oskal/internal/ui/cockpit"
	"github.com/ckodex-labs/ckodex-oskal/internal/ui/format"
	commonv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/control/v1"
	servicesv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/services/v1"
	"sigs.k8s.io/yaml"
)

var (
	version           = "v1.0.1"
	commit            = "dev"
	date              = "unknown"
	serverAddr        string
	evidenceDir       string
	tlsCAFile         string
	tlsServerName     string
	tlsClientCertFile string
	tlsClientKeyFile  string
)

func loadLocalEvidence(dir string, sub assurance.SubjectRef) ([]assurance.EvidenceEnvelope, error) {
	if dir == "" {
		return nil, nil
	}
	repo, err := storage.OpenFilesystemEvidenceRepository(dir)
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

func resolveSubjectFromArgsOrFlags(args []string, kind, name, namespace string) (assurance.SubjectRef, error) {
	if len(args) > 0 && args[0] != "" {
		return parseSubjectURI(args[0]), nil
	}
	if name != "" {
		if namespace == "" {
			return assurance.SubjectRef{}, errors.New("--subject-namespace is required with --subject-name")
		}
		if kind == "" {
			return assurance.SubjectRef{}, errors.New("--subject-kind is required with --subject-name")
		}
		return assurance.SubjectRef{
			Scheme: "k8s",
			ID:     fmt.Sprintf("%s/%s/%s", namespace, kind, name),
		}, nil
	}
	return assurance.SubjectRef{}, errors.New("must specify subject URI as positional argument or via --subject-name")
}

func evaluateLocalEnvelopes(
	sub assurance.SubjectRef,
	ctrl assurance.ControlRef,
	envelopes []assurance.EvidenceEnvelope,
	now time.Time,
) (assurance.ClaimEvaluation, string, []assurance.EvidenceEnvelope) {
	matching := make([]assurance.EvidenceEnvelope, 0, len(envelopes))
	for _, envelope := range envelopes {
		if envelope.Subject.URI() == sub.URI() {
			matching = append(matching, envelope)
		}
	}
	return evaluation.UnverifiedEvaluation(sub, ctrl, matching, now), "unknown (unverified material; no authoritative contract/epoch/producer proof)", matching
}

func splitYAMLDocuments(data []byte) [][]byte {
	normalized := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	var docs [][]byte
	var current []string
	for _, line := range lines {
		if strings.TrimSpace(line) == "---" {
			doc := strings.TrimSpace(strings.Join(current, "\n"))
			if doc != "" {
				docs = append(docs, []byte(doc))
			}
			current = nil
			continue
		}
		current = append(current, line)
	}
	if doc := strings.TrimSpace(strings.Join(current, "\n")); doc != "" {
		docs = append(docs, []byte(doc))
	}
	if len(docs) == 0 {
		return [][]byte{data}
	}
	return docs
}

func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		SilenceUsage: true,
		Use:          "oskal",
		Version:      fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		Short:        "OSKAL -- Continuous Kubernetes Assurance CLI",
		Long: `OSKAL is the Continuous Kubernetes Assurance Runtime for CKODEX.
It evaluates continuous evidence contracts, tracks semantic drift,
and projects defensible results into standard OSCAL artifacts.`,
	}

	execution := executionOptions{}
	execution.flags(rootCmd)
	var configFileFlag string
	rootCmd.PersistentFlags().StringVar(&configFileFlag, "config", "", "Path to OSKAL configuration file (default .oskal.yaml)")
	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "", "AssuranceService gRPC address (e.g. localhost:9090)")
	rootCmd.PersistentFlags().StringVar(&evidenceDir, "evidence-dir", "", "Path to directory containing local EvidenceEnvelope JSON files")
	rootCmd.PersistentFlags().StringVar(&tlsCAFile, "tls-ca-file", "", "Explicit trusted CA bundle for gRPC client connections")
	rootCmd.PersistentFlags().StringVar(&tlsServerName, "tls-server-name", "", "Exact expected gRPC server DNS name or IP SAN")
	rootCmd.PersistentFlags().StringVar(&tlsClientCertFile, "tls-client-cert-file", "", "Client certificate chain for gRPC mutual TLS")
	rootCmd.PersistentFlags().StringVar(&tlsClientKeyFile, "tls-client-key-file", "", "Private key paired with the gRPC client certificate")

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

	// 1. oscal assurance state [<subject-uri>] [--subject-kind <kind>] [--subject-name <name>] [--subject-namespace <namespace>]
	var (
		stateSubKind string
		stateSubName string
		stateSubNS   string
	)
	stateCmd := &cobra.Command{
		Use:   "state [<subject-uri>]",
		Short: "Show the current continuous assurance state for a subject",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sub, err := resolveSubjectFromArgsOrFlags(args, stateSubKind, stateSubName, stateSubNS)
			if err != nil {
				return err
			}
			scheme := sub.Scheme
			id := sub.ID

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
					fmt.Printf("QUERIED AT:  %s\n", time.Now().UTC().Format(time.RFC3339))
					fmt.Printf("FRESHNESS:       unknown\n")
					fmt.Printf("MISSING INPUTS:  authored contract, trusted producers, authoritative epoch and artifact verification\n")
					fmt.Printf("REMEDIATION:     configure authenticated observers, an authored contract, and trusted producer keys\n")
					return nil
				}

				fmt.Printf("STATE:           %s\n", resp.State.String())
				if resp.Epoch != nil {
					fmt.Printf("EPOCH:           %s\n", resp.Epoch.PolicyDigest)
				}
				fmt.Printf("EVIDENCE ROOT:   %s\n", resp.EvidenceRoot)
				fmt.Printf("QUERIED AT:  %s\n", time.Now().UTC().Format(time.RFC3339))
				fmt.Printf("FRESHNESS:       UNKNOWN (not independently established by this response)\n")
				return nil
			}

			if evidenceDir != "" {
				envelopes, err := loadLocalEvidence(evidenceDir, sub)
				if err != nil {
					return err
				}
				now := time.Now().UTC()
				ctrl := assurance.ControlRef{}
				eval, freshness, validEnvelopes := evaluateLocalEnvelopes(sub, ctrl, envelopes, now)

				fmt.Printf("SUBJECT:         %s\n", sub.URI())
				if len(validEnvelopes) == 0 {
					fmt.Printf("STATE:           UNKNOWN\n")
					if len(envelopes) > 0 {
						fmt.Printf("STATUS:          All matching evidence envelopes in %s were rejected (future-dated or invalid)\n", evidenceDir)
					} else {
						fmt.Printf("STATUS:          No matching evidence envelopes found in %s\n", evidenceDir)
					}
					fmt.Printf("EVIDENCE ROOT:   none\n")
					fmt.Printf("ANALYZED AT:  %s\n", now.Format(time.RFC3339))
					fmt.Printf("FRESHNESS:       %s\n", freshness)
					fmt.Printf("MISSING INPUTS:  authored contract, trusted producers, authoritative epoch and artifact verification\n")
					fmt.Printf("REMEDIATION:     use an authoritative binding and trusted producer verification, or --server\n")
					return nil
				}

				fmt.Printf("STATE:           %s\n", eval.State.String())
				fmt.Printf("EPOCH:           UNKNOWN\n")
				fmt.Printf("EVIDENCE ROOT:   none (unverified references only)\n")
				fmt.Printf("ANALYZED AT:  %s\n", now.Format(time.RFC3339))
				fmt.Printf("FRESHNESS:       %s\n", freshness)
				return nil
			}

			// Invariant I-02: Absence of evidence is UNKNOWN, never PASS.
			fmt.Printf("SUBJECT:         %s\n", sub.URI())
			fmt.Printf("STATE:           UNKNOWN\n")
			fmt.Printf("STATUS:          Absence of verified evidence (specify --server or --evidence-dir)\n")
			fmt.Printf("EVIDENCE ROOT:   none\n")
			fmt.Printf("ANALYZED AT:  %s\n", time.Now().UTC().Format(time.RFC3339))
			fmt.Printf("FRESHNESS:       unknown\n")
			fmt.Printf("MISSING INPUTS:  authored contract, trusted producers, authoritative epoch and artifact verification\n")
			fmt.Printf("REMEDIATION:     configure live observers and authoritative evaluation; local files are unverified material\n")
			return nil
		},
	}
	stateCmd.Flags().StringVar(&stateSubKind, "subject-kind", "", "Kubernetes resource kind (e.g. Deployment, Pod)")
	stateCmd.Flags().StringVar(&stateSubName, "subject-name", "", "Workload name")
	stateCmd.Flags().StringVar(&stateSubNS, "subject-namespace", "", "Explicit Kubernetes namespace")

	// 2. oscal assurance explain [<subject-uri>] --control <control>
	var (
		controlFlag    string
		explainSubKind string
		explainSubName string
		explainSubNS   string
	)
	explainCmd := &cobra.Command{
		Use:   "explain [<subject-uri>]",
		Short: "Explain why an assurance claim is justified or failing (Section 51)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sub, err := resolveSubjectFromArgsOrFlags(args, explainSubKind, explainSubName, explainSubNS)
			if err != nil {
				return err
			}
			scheme := sub.Scheme
			id := sub.ID

			ctrl, err := evaluation.ParseControlReference(controlFlag)
			if err != nil {
				return err
			}
			ctrlNamespace, ctrlID := ctrl.Namespace, ctrl.ID

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
					Control: &controlv1.ControlRef{Namespace: ctrlNamespace, Id: ctrlID, Version: ctrl.Version},
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

			eval, _, _ := evaluateLocalEnvelopes(sub, ctrl, envelopes, time.Now().UTC())

			_, _ = fmt.Fprint(cmd.OutOrStdout(), evaluation.UnverifiedExplanation(eval))
			return nil
		},
	}
	explainCmd.Flags().StringVar(&controlFlag, "control", "", "Target control to explain (e.g. nist-sp-800-53:AC-6)")
	explainCmd.Flags().StringVar(&explainSubKind, "subject-kind", "", "Kubernetes resource kind (e.g. Deployment, Pod)")
	explainCmd.Flags().StringVar(&explainSubName, "subject-name", "", "Workload name")
	explainCmd.Flags().StringVar(&explainSubNS, "subject-namespace", "", "Explicit Kubernetes namespace")

	// 3. oscal assurance evidence [<subject-uri>]
	var (
		evidenceSubKind string
		evidenceSubName string
		evidenceSubNS   string
		evidenceControl string
	)
	evidenceCmd := &cobra.Command{
		Use:   "evidence [<subject-uri>]",
		Short: "List supplied evidence references without inferring verification",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sub, err := resolveSubjectFromArgsOrFlags(args, evidenceSubKind, evidenceSubName, evidenceSubNS)
			if err != nil {
				return err
			}

			if evidenceDir != "" {
				envelopes, err := loadLocalEvidence(evidenceDir, sub)
				if err != nil {
					return err
				}
				now := time.Now().UTC()
				ctrl := assurance.ControlRef{}
				_, _, validEnvelopes := evaluateLocalEnvelopes(sub, ctrl, envelopes, now)
				if len(validEnvelopes) == 0 && serverAddr == "" {
					fmt.Printf("No supplied evidence envelopes found for %s in %s\n", sub.URI(), evidenceDir)
					return nil
				}
				if len(validEnvelopes) > 0 {
					fmt.Printf("SUPPLIED EVIDENCE REFERENCES FOR %s (%d total):\n\n", sub.URI(), len(validEnvelopes))
					for i, env := range validEnvelopes {
						fmt.Printf("%d. [%s]\n   ID:       %s\n   Producer: %s\n   Digest:   %s\n   URI:      %s\n   Captured: %s\n\n",
							i+1, env.ObservationType, env.ID, env.Producer.Canonical(), env.Artifact.Digest, env.Artifact.URI, env.CapturedAt.Format(time.RFC3339))
					}
					return nil
				}
			}

			if serverAddr != "" {
				ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
				defer cancel()

				control, err := evaluation.ParseControlReference(evidenceControl)
				if err != nil {
					return fmt.Errorf("remote evidence lookup requires --control: %w", err)
				}
				client, conn, err := getGRPCClient(ctx, serverAddr)
				if err != nil {
					return err
				}
				defer func() { _ = conn.Close() }()

				resp, err := client.ExplainClaim(ctx, &servicesv1.ExplainClaimRequest{
					Subject: &commonv1.SubjectRef{Scheme: sub.Scheme, Id: sub.ID},
					Control: &controlv1.ControlRef{Namespace: control.Namespace, Id: control.ID, Version: control.Version},
				})
				if err != nil {
					return fmt.Errorf("gRPC ExplainClaim failed: %w", err)
				}
				if len(resp.Evidence) == 0 {
					fmt.Printf("No supplied evidence envelopes found for %s on server %s\n", sub.URI(), serverAddr)
					return nil
				}
				fmt.Printf("SUPPLIED EVIDENCE REFERENCES FOR %s (%d total):\n\n", sub.URI(), len(resp.Evidence))
				for i, ev := range resp.Evidence {
					fmt.Printf("%d. [%s]\n   Producer: %s\n   Digest:   %s\n\n",
						i+1, ev.MediaType, ev.Uri, ev.Digest)
				}
				return nil
			}

			fmt.Printf("No supplied evidence envelopes available for %s (specify --server or --evidence-dir).\n", sub.URI())
			return nil
		},
	}
	evidenceCmd.Flags().StringVar(&evidenceControl, "control", "", "Explicit control for remote ExplainClaim evidence references")
	evidenceCmd.Flags().StringVar(&evidenceSubKind, "subject-kind", "", "Kubernetes resource kind (e.g. Deployment, Pod)")
	evidenceCmd.Flags().StringVar(&evidenceSubName, "subject-name", "", "Workload name")
	evidenceCmd.Flags().StringVar(&evidenceSubNS, "subject-namespace", "", "Explicit Kubernetes namespace")

	// 4. oscal assurance drift [<subject-uri>]
	var (
		driftSubKind string
		driftSubName string
		driftSubNS   string
	)
	driftCmd := &cobra.Command{
		Use:   "drift [<subject-uri>]",
		Short: "Detect semantic drift between observed runtime and recorded epoch",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sub, err := resolveSubjectFromArgsOrFlags(args, driftSubKind, driftSubName, driftSubNS)
			if err != nil {
				return err
			}

			if evidenceDir != "" {
				envelopes, err := loadLocalEvidence(evidenceDir, sub)
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "DRIFT ANALYSIS FOR %s:\n\nSTATUS: UNKNOWN\nSUPPLIED MATERIAL: %d envelopes\nBASELINE: no authoritative current epoch or verified baseline supplied\n", sub.URI(), len(envelopes))
				return nil
			}

			if serverAddr != "" && evidenceDir == "" {
				ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
				defer cancel()

				client, conn, err := getGRPCClient(ctx, serverAddr)
				if err != nil {
					return err
				}
				defer func() { _ = conn.Close() }()

				resp, err := client.GetAssuranceState(ctx, &servicesv1.GetAssuranceStateRequest{
					Subject: &commonv1.SubjectRef{Scheme: sub.Scheme, Id: sub.ID},
				})
				if err != nil {
					return fmt.Errorf("gRPC GetAssuranceState failed: %w", err)
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "DRIFT ANALYSIS FOR %s:\n\nSTATUS: UNKNOWN\nSERVER-REPORTED ASSURANCE: %s\nREASON: a state summary supplies no verified baseline comparison or structural drift proof\n", sub.URI(), resp.State.String())
				return nil
			}

			fmt.Printf("DRIFT ANALYSIS FOR %s:\n\n", sub.URI())
			fmt.Printf("STATUS:                 UNKNOWN (cannot establish drift without evidence or server -- specify --server or --evidence-dir)\n")
			return nil
		},
	}
	driftCmd.Flags().StringVar(&driftSubKind, "subject-kind", "", "Kubernetes resource kind (e.g. Deployment, Pod)")
	driftCmd.Flags().StringVar(&driftSubName, "subject-name", "", "Workload name")
	driftCmd.Flags().StringVar(&driftSubNS, "subject-namespace", "", "Explicit Kubernetes namespace")

	// 5. oscal assurance receipt verify
	receiptCmd := &cobra.Command{
		Use:   "receipt",
		Short: "Cryptographic receipt inspection and verification",
	}

	var (
		verifyReceiptID   string
		verifyReceiptFile string
		verifyPublicKey   string
	)
	verifyReceiptCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a receipt signature under an explicitly trusted Ed25519 public key",
		RunE: func(cmd *cobra.Command, args []string) error {
			var rcpt assurance.ControlReceipt
			var searchDirs []string
			if evidenceDir != "" {
				searchDirs = append(searchDirs, evidenceDir, filepath.Join(evidenceDir, "receipts"))
			}
			searchDirs = append(searchDirs, "evidence", filepath.Join("evidence", "receipts"))

			if verifyReceiptFile != "" {
				data, err := os.ReadFile(verifyReceiptFile)
				if err != nil {
					return fmt.Errorf("failed to read receipt file: %w", err)
				}
				if err := json.Unmarshal(data, &rcpt); err != nil {
					return fmt.Errorf("failed to parse receipt JSON: %w", err)
				}
			} else {
				if verifyReceiptID == "" && len(args) > 0 {
					verifyReceiptID = args[0]
				}
				if verifyReceiptID == "" {
					return errors.New("must specify --receipt-id or --receipt-file")
				}

				var candidatePaths []string
				if strings.HasSuffix(verifyReceiptID, ".json") {
					candidatePaths = append(candidatePaths, verifyReceiptID)
				}
				for _, d := range searchDirs {
					candidatePaths = append(candidatePaths,
						filepath.Join(d, verifyReceiptID+".json"),
						filepath.Join(d, "rcpt-"+verifyReceiptID+".json"),
					)
				}

				found := false
				for _, p := range candidatePaths {
					data, err := os.ReadFile(p)
					if err != nil {
						continue
					}
					if err := json.Unmarshal(data, &rcpt); err != nil {
						return fmt.Errorf("failed to parse receipt from %s: %w", p, err)
					}
					found = true
					break
				}
				if !found {
					return fmt.Errorf("[FAIL] receipt %q not found on disk (searched %v)", verifyReceiptID, searchDirs)
				}
			}

			idDisplay := verifyReceiptID
			if idDisplay == "" {
				idDisplay = "rcpt-" + rcpt.Control.ID
			}

			pubKeyHex := strings.TrimSpace(verifyPublicKey)
			if pubKeyHex == "" {
				return fmt.Errorf("--public-key is required from trusted custody; a key stored beside the receipt is not an authority anchor")
			}
			if len(pubKeyHex) != 64 {
				raw, err := readBoundedFile(pubKeyHex, 4096)
				if err != nil {
					return err
				}
				pubKeyHex = strings.TrimSpace(string(raw))
			}

			valid, err := receipts.VerifyIndependentReceipt(rcpt, pubKeyHex)
			if err != nil || !valid {
				return fmt.Errorf("[FAIL] Receipt %s cryptographic verification failed: valid=%v, err=%v", idDisplay, valid, err)
			}

			fmt.Printf("[VERIFIED] Receipt %s is cryptographically valid.\n", idDisplay)
			fmt.Printf("Signed evaluator claim: %s\n", rcpt.Evaluator.Canonical())
			fmt.Printf("Signed evidence digest: %s\n", rcpt.EvidenceRoot)
			fmt.Printf("Scope: signature under the supplied key; source observations, identity binding and assurance decision are not independently verified.\n")
			return nil
		},
	}
	verifyReceiptCmd.Flags().StringVar(&verifyReceiptID, "receipt-id", "", "ID of the receipt to verify")
	verifyReceiptCmd.Flags().StringVar(&verifyReceiptFile, "receipt-file", "", "Path to raw ControlReceipt JSON file")
	verifyReceiptCmd.Flags().StringVar(&verifyPublicKey, "public-key", "", "Ed25519 public key hex or path to .pub file")
	receiptCmd.AddCommand(verifyReceiptCmd)

	recordCmd := newRecordCommand()
	exportCmd := newExportCommand()

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

	serveCmd := newGRPCServeCommand()

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
				if err := format.RenderStructured(w, report, outFormat); err != nil {
					return err
				}
				return doctorResult(report)
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
				return doctorResult(report)
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
			ctrl, err := evaluation.ParseControlReference(inspectControl)
			if err != nil {
				return err
			}

			var envelopes []assurance.EvidenceEnvelope
			if evidenceDir != "" {
				envelopes, err = loadLocalEvidence(evidenceDir, sub)
				if err != nil {
					return err
				}
			}
			if len(envelopes) == 0 && serverAddr != "" {
				return fmt.Errorf("remote ExplainClaim supplies references, not canonical observations; use assurance explain with --server, or inspect a local evidence store with --evidence-dir")
			}

			now := time.Now().UTC()
			eval, _, validEnvelopes := evaluateLocalEnvelopes(sub, ctrl, envelopes, now)

			report := diagnostics.InspectSubject(cmd.Context(), sub, eval, validEnvelopes)

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
				_, _ = fmt.Fprintf(w, "   Root Consistency: %s\n", report.Evidence.RootConsistency)
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
	inspectCmd.Flags().StringVar(&inspectControl, "control", "", "Control to inspect")

	// 13. oscal mcp
	mcpCmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start native Model Context Protocol (stdio JSON-RPC 2.0) server",
		Long: `Exposes OSKAL continuous assurance capabilities as native MCP tools
for Claude Code, Cursor, OpenCode, and AI developer environments over stdio.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			runtime, err := configureExecution(cmd.Context(), execution, false)
			if err != nil {
				return err
			}
			defer runtime.close()
			srv, err := mcp.NewServerWithBroker(cmd.InOrStdin(), cmd.OutOrStdout(), evidenceDir, runtime.broker)
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
		Short: "Read-only ASCII archive inventory with explicit unknown assurance",
		Long: `Displays archived material counts without inferring current assurance,
producer trust, freshness, drift, or live enforcement.`,
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
			repo, err := storage.OpenFilesystemEvidenceRepository(dir)
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

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print OSKAL CLI version and build metadata",
		Run: func(cmd *cobra.Command, args []string) {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "oskal %s (commit: %s, built: %s)\n", version, commit, date)
		},
	}

	// 17. oscal utcp [manual|validate|search|call|serve|sdk-config]
	utcpCmd := &cobra.Command{
		Use:   "utcp",
		Short: "Universal Tool Calling Protocol (UTCP v1.0.1) manual, discovery, and multi-SDK operations",
		Long: `Provides full Universal Tool Calling Protocol (UTCP) support compatible with:
  - utcp-specification (https://github.com/universal-tool-calling-protocol/utcp-specification)
  - utcp-mcp           (https://github.com/universal-tool-calling-protocol/utcp-mcp)
  - go-utcp            (https://github.com/universal-tool-calling-protocol/go-utcp)
  - rs-utcp            (https://github.com/universal-tool-calling-protocol/rs-utcp)
  - typescript-utcp    (https://github.com/universal-tool-calling-protocol/typescript-utcp)
  - python-utcp        (https://github.com/universal-tool-calling-protocol/python-utcp)`,
	}

	var (
		utcpTransport string
		utcpBaseURL   string
		utcpGRPCAddr  string
		utcpBinary    string
		utcpOutput    string
	)
	utcpManualCmd := &cobra.Command{
		Use:   "manual",
		Short: "Export the OSKAL UTCP v1.0.1 manual (JSON or YAML)",
		RunE: func(cmd *cobra.Command, args []string) error {
			m := utcp.BuildOSKALManual(utcp.ManualOptions{
				PrimaryTransport: utcpTransport,
				BaseURL:          utcpBaseURL,
				GRPCAddr:         utcpGRPCAddr,
				BinaryPath:       utcpBinary,
			})
			if strings.EqualFold(utcpOutput, "yaml") {
				out, err := yaml.Marshal(m)
				if err != nil {
					return err
				}
				_, _ = fmt.Fprint(cmd.OutOrStdout(), string(out))
				return nil
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(m)
		},
	}
	utcpManualCmd.Flags().StringVar(&utcpTransport, "transport", "cli", "Primary call_template_type: cli, http, grpc, mcp")
	utcpManualCmd.Flags().StringVar(&utcpBaseURL, "base-url", "http://localhost:8090", "Base HTTP URL for http call templates")
	utcpManualCmd.Flags().StringVar(&utcpGRPCAddr, "grpc-addr", "localhost:9090", "gRPC server address for grpc call templates")
	utcpManualCmd.Flags().StringVar(&utcpBinary, "binary", "oskal", "CLI binary name or path for cli/mcp call templates")
	utcpManualCmd.Flags().StringVar(&utcpOutput, "output", "json", "Output format: json or yaml")

	utcpValidateCmd := &cobra.Command{
		Use:   "validate <manual-file>",
		Short: "Validate a UTCP manual against utcp-specification v1.0.1 and CKODEX invariants",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to read UTCP manual file %s: %w", args[0], err)
			}
			var m utcp.UTCPManual
			if err := yaml.Unmarshal(raw, &m); err != nil {
				return fmt.Errorf("failed to parse UTCP manual: %w", err)
			}
			if err := utcp.ValidateManual(m); err != nil {
				return fmt.Errorf("[FAIL] UTCP manual validation failed: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "[PASS] UTCP manual %s conforms to utcp-specification v%s (%d tools verified)\n", args[0], m.UTCPVersion, len(m.Tools))
			return nil
		},
	}

	var (
		utcpSearchTag   string
		utcpSearchLimit int
	)
	utcpSearchCmd := &cobra.Command{
		Use:   "search [query]",
		Short: "Search OSKAL UTCP tools by keyword and tag",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			q := ""
			if len(args) > 0 {
				q = args[0]
			}
			reg, err := utcp.NewRegistry(evidenceDir, nil)
			if err != nil {
				return err
			}
			var tags []string
			if utcpSearchTag != "" {
				tags = append(tags, utcpSearchTag)
			}
			matches := reg.SearchTools(q, tags, utcpSearchLimit)
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]interface{}{
				"tools": matches,
				"count": len(matches),
			})
		},
	}
	utcpSearchCmd.Flags().StringVar(&utcpSearchTag, "tag", "", "Optional tag filter")
	utcpSearchCmd.Flags().IntVar(&utcpSearchLimit, "limit", 10, "Maximum results")

	runListTools := func(cmd *cobra.Command, _ []string) error {
		reg, err := utcp.NewRegistry(evidenceDir, nil)
		if err != nil {
			return err
		}
		tools := reg.ListTools()
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]interface{}{
			"tools": tools,
			"count": len(tools),
		})
	}

	utcpListToolsCmd := &cobra.Command{
		Use:   "list-tools",
		Short: "List all registered OSKAL UTCP tools (compatible with go-utcp CLI discovery)",
		RunE:  runListTools,
	}

	topListToolsCmd := &cobra.Command{
		Use:    "list-tools",
		Short:  "List all registered OSKAL UTCP tools",
		Hidden: true,
		RunE:   runListTools,
	}

	var utcpCallArgs string
	runUTCPCall := func(cmd *cobra.Command, rawArgs []string) error {
		var posArgs []string
		flagArgs := make(map[string]interface{})
		explicitArgsJSON := ""
		leaseID := ""
		prevReceiptHash := ""

		explicitServer := false
		explicitEvidenceDir := false
		explicitConfig := false

		for i := 0; i < len(rawArgs); i++ {
			tok := rawArgs[i]
			if tok == "-h" || tok == "--help" {
				return cmd.Help()
			}
			if !strings.HasPrefix(tok, "-") || tok == "-" {
				posArgs = append(posArgs, tok)
				continue
			}

			trimmed := strings.TrimLeft(tok, "-")
			key := trimmed
			val := ""
			hasInlineVal := false
			if eqIdx := strings.IndexByte(trimmed, '='); eqIdx >= 0 {
				key = trimmed[:eqIdx]
				val = trimmed[eqIdx+1:]
				hasInlineVal = true
			} else if i+1 < len(rawArgs) && (!strings.HasPrefix(rawArgs[i+1], "-") || rawArgs[i+1] == "-") {
				val = rawArgs[i+1]
				i++
			} else {
				val = "true"
			}

			switch key {
			case "args":
				explicitArgsJSON = val
			case "evidence-dir":
				evidenceDir = val
				explicitEvidenceDir = true
			case "server":
				serverAddr = val
				explicitServer = true
			case "config":
				configFileFlag = val
				explicitConfig = true
			case "tls-ca-file":
				tlsCAFile = val
			case "tls-server-name":
				tlsServerName = val
			case "tls-client-cert-file":
				tlsClientCertFile = val
			case "tls-client-key-file":
				tlsClientKeyFile = val
			case "projection-context":
				if strings.HasPrefix(val, "UTCP_ARG_") && strings.HasSuffix(val, "_UTCP_END") {
					continue
				}
				var raw []byte
				if strings.HasPrefix(strings.TrimSpace(val), "{") {
					raw = []byte(val)
				} else {
					var err error
					raw, err = readBoundedFile(val, oscal.MaxProjectionContextBytes)
					if err != nil {
						return err
					}
				}
				context, err := oscal.DecodeProjectionContext(raw)
				if err != nil {
					return err
				}
				flagArgs["projection_context"] = context
			case "lease-kubeconfig":
				execution.kubeconfig = val
			case "workload-api":
				execution.address = val
			case "spiffe-id":
				execution.ownID = val
			case "allowed-peer-id":
				return fmt.Errorf("--allowed-peer-id is only meaningful for an HTTP server")
			case "lease-id", "lease_id":
				leaseID = val
			case "prev-receipt-hash", "prev_receipt_hash":
				prevReceiptHash = val
			default:
				if strings.HasPrefix(val, "UTCP_ARG_") && strings.HasSuffix(val, "_UTCP_END") {
					continue
				}
				var decoded interface{} = val
				if !hasInlineVal && (strings.HasPrefix(val, "{") || strings.HasPrefix(val, "[")) {
					var js interface{}
					if json.Unmarshal([]byte(val), &js) == nil {
						decoded = js
					}
				}
				flagArgs[key] = decoded
				if strings.Contains(key, "-") {
					underKey := strings.ReplaceAll(key, "-", "_")
					if _, exists := flagArgs[underKey]; !exists {
						flagArgs[underKey] = decoded
					}
				}
			}
		}

		if explicitConfig && configFileFlag != "" {
			cfg, _, err := config.LoadConfig(configFileFlag)
			if err != nil {
				return err
			}
			if !explicitServer && cfg.Server != "" {
				serverAddr = cfg.Server
			}
			if !explicitEvidenceDir && cfg.EvidenceDir != "" {
				evidenceDir = cfg.EvidenceDir
			}
		}

		if len(posArgs) < 1 || len(posArgs) > 2 {
			return fmt.Errorf("expected 1 or 2 positional arguments (<tool-name> or <provider-name> <tool-name>), got %d", len(posArgs))
		}
		toolName := posArgs[0]
		if len(posArgs) == 2 {
			toolName = posArgs[0] + "." + posArgs[1]
		}

		parsedArgs := make(map[string]interface{})
		if strings.TrimSpace(explicitArgsJSON) != "" {
			if err := json.Unmarshal([]byte(explicitArgsJSON), &parsedArgs); err != nil {
				return fmt.Errorf("invalid --args JSON: %w", err)
			}
		} else {
			inReader := cmd.InOrStdin()
			shouldReadStdin := false
			if f, ok := inReader.(*os.File); ok {
				if st, err := f.Stat(); err == nil && (st.Mode()&os.ModeCharDevice) == 0 {
					shouldReadStdin = true
				}
			} else if inReader != nil {
				shouldReadStdin = true
			}
			if shouldReadStdin {
				stdinBytes, err := io.ReadAll(io.LimitReader(inReader, 4<<20))
				if err == nil && len(bytes.TrimSpace(stdinBytes)) > 0 {
					if err := json.Unmarshal(bytes.TrimSpace(stdinBytes), &parsedArgs); err != nil {
						return fmt.Errorf("invalid stdin JSON arguments: %w", err)
					}
				}
			}
		}

		for k, v := range flagArgs {
			parsedArgs[k] = v
		}

		runtime, err := configureExecution(cmd.Context(), execution, false)
		if err != nil {
			return err
		}
		defer runtime.close()
		reg, err := utcp.NewRegistry(evidenceDir, runtime.broker)
		if err != nil {
			return err
		}
		res, err := reg.CallTool(cmd.Context(), toolName, parsedArgs, leaseID, prevReceiptHash)

		if err != nil {
			return err
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}

	utcpCallCmd := &cobra.Command{
		Use:                "call [<provider-name>] <tool-name>",
		Short:              "Execute an OSKAL UTCP tool directly via flags, --args JSON, or stdin JSON",
		DisableFlagParsing: true,
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		RunE:               runUTCPCall,
	}
	utcpCallCmd.Flags().StringVar(&utcpCallArgs, "args", "{}", "JSON object of tool arguments")

	topCallCmd := &cobra.Command{
		Use:                "call [<provider-name>] <tool-name>",
		Short:              "Execute an OSKAL UTCP tool directly",
		Hidden:             true,
		DisableFlagParsing: true,
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		RunE:               runUTCPCall,
	}

	var (
		utcpServeAddr    string
		utcpServeBaseURL string
	)
	utcpServeCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start native UTCP HTTP discovery (GET /utcp) and tool execution server",
		RunE: func(cmd *cobra.Command, args []string) error {
			runtime, err := configureExecution(cmd.Context(), execution, true)
			if err != nil {
				return err
			}
			defer runtime.close()
			reg, err := utcp.NewRegistry(evidenceDir, runtime.broker)
			if err != nil {
				return err
			}
			httpSrv := utcp.NewHTTPServer(reg, utcpServeBaseURL)
			srv := &http.Server{
				Addr:              utcpServeAddr,
				Handler:           httpSrv.Handler(),
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       15 * time.Second,
				WriteTimeout:      30 * time.Second,
				IdleTimeout:       60 * time.Second,
				MaxHeaderBytes:    1 << 20,
			}
			if runtime.identity != nil {
				tlsConfig, err := runtime.identity.TLSServerConfig(cmd.Context(), execution.allowedPeers)
				if err != nil {
					return err
				}
				srv.TLSConfig = tlsConfig
			} else {
				host, _, err := net.SplitHostPort(utcpServeAddr)
				if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
					return fmt.Errorf("plaintext read-only UTCP must bind a loopback address; non-loopback access requires SPIFFE mTLS")
				}
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Starting OSKAL UTCP HTTP Server on %s (discovery: %s/utcp)\n", utcpServeAddr, strings.TrimRight(utcpServeBaseURL, "/"))

			stopCh := make(chan os.Signal, 1)
			signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)
			defer signal.Stop(stopCh)

			listener, err := net.Listen("tcp", utcpServeAddr)
			if err != nil {
				return err
			}
			limited := newLimitedListener(listener, utcp.MaxHTTPConcurrentRequests)
			defer func() { _ = limited.Close() }()
			errCh := make(chan error, 1)
			go func() {
				var serveErr error
				if srv.TLSConfig != nil {
					serveErr = srv.ServeTLS(limited, "", "")
				} else {
					serveErr = srv.Serve(limited)
				}
				if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
					errCh <- serveErr
				} else {
					errCh <- nil
				}
			}()

			select {
			case <-stopCh:
			case <-cmd.Context().Done():
			case serveErr := <-errCh:
				return serveErr
			}

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return srv.Shutdown(shutdownCtx)
		},
	}
	utcpServeCmd.Flags().StringVar(&utcpServeAddr, "addr", "127.0.0.1:8090", "Listen address for UTCP HTTP server")
	utcpServeCmd.Flags().StringVar(&utcpServeBaseURL, "base-url", "http://localhost:8090", "Public base URL advertised in /utcp manual")

	var utcpSDKLang string
	utcpSDKConfigCmd := &cobra.Command{
		Use:   "sdk-config",
		Short: "Generate UTCP provider configs and client snippets for go-utcp, rs-utcp, typescript-utcp, python-utcp, and utcp-mcp",
		RunE: func(cmd *cobra.Command, args []string) error {
			bundles := utcp.GenerateSDKConfigs(utcpBaseURL, utcpBinary)
			var filtered []utcp.SDKBundle
			for _, b := range bundles {
				if utcpSDKLang == "" || utcpSDKLang == "all" || strings.EqualFold(b.Language, utcpSDKLang) {
					filtered = append(filtered, b)
				}
			}
			if len(filtered) == 0 {
				return fmt.Errorf("unknown UTCP SDK target '%s' (valid: all, go, rust, typescript, python, utcp-mcp)", utcpSDKLang)
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(filtered)
		},
	}
	utcpSDKConfigCmd.Flags().StringVar(&utcpSDKLang, "lang", "all", "Target SDK language: all, go, rust, typescript, python, utcp-mcp")
	utcpSDKConfigCmd.Flags().StringVar(&utcpBaseURL, "base-url", "http://localhost:8090", "Base UTCP HTTP endpoint URL")
	utcpSDKConfigCmd.Flags().StringVar(&utcpBinary, "binary", "oskal", "OSKAL binary path")

	utcpCmd.AddCommand(utcpManualCmd, utcpValidateCmd, utcpSearchCmd, utcpListToolsCmd, utcpCallCmd, utcpServeCmd, utcpSDKConfigCmd)

	assuranceCmd.AddCommand(newBindingEvaluationCommand(), stateCmd, explainCmd, evidenceCmd, driftCmd, receiptCmd)
	rootCmd.AddCommand(
		newIdentityCommand(), newVerifyCommand(),
		assuranceCmd,
		recordCmd,
		exportCmd,
		importCmd,
		serveCmd,
		webhookCmd,
		validateCmd,
		scaffoldCmd,
		doctorCmd,
		inspectCmd,
		mcpCmd,
		utcpCmd,
		topListToolsCmd,
		topCallCmd,
		cockpitCmd,
		configCmd,
		pruneCmd,
		versionCmd,
	)
	return rootCmd
}

func main() {
	if err := NewRootCommand().Execute(); err != nil {
		os.Exit(commandExitCode(err))
	}
}
