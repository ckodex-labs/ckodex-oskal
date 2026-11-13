package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

func newRecordCommand() *cobra.Command {
	var file, namespace string
	record := &cobra.Command{Use: "record", Short: "Store explicitly labelled untrusted source material"}
	manifest := &cobra.Command{Use: "manifest", Short: "Store exact manifest bytes without asserting Kubernetes admission or compliance", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		raw, err := readBoundedFile(file, maxBackendDocumentBytes)
		if err != nil {
			return err
		}
		documents := splitYAMLDocuments(raw)
		if len(documents) != 1 {
			return fmt.Errorf("record manifest requires one explicit resource per file")
		}
		encoded, err := yaml.YAMLToJSONStrict(raw)
		if err != nil {
			return fmt.Errorf("manifest YAML: %w", err)
		}
		var object struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Metadata   struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(encoded, &object); err != nil {
			return err
		}
		if object.APIVersion == "" || object.Kind == "" || object.Metadata.Name == "" {
			return fmt.Errorf("manifest must declare apiVersion, kind, and metadata.name; no workload identity is inferred")
		}
		declaredNamespace := object.Metadata.Namespace
		if namespace != "" {
			if declaredNamespace != "" && namespace != declaredNamespace {
				return fmt.Errorf("--namespace conflicts with declared manifest namespace")
			}
			declaredNamespace = namespace
		}
		if declaredNamespace == "" {
			return fmt.Errorf("manifest must declare metadata.namespace or --namespace explicitly; this command records namespaced workload material")
		}
		if evidenceDir == "" {
			return fmt.Errorf("--evidence-dir is required for recording material")
		}
		absolute, err := filepath.Abs(file)
		if err != nil {
			return err
		}
		hash := assurance.ComputeDigest(raw)
		subject := assurance.SubjectRef{Scheme: "k8s", ID: declaredNamespace + "/" + object.Kind + "/" + object.Metadata.Name, Attributes: map[string]string{"identity-source": "untrusted-manifest-declaration", "source-file": absolute}}
		material := assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/material/v1", ID: "manifest-" + strings.TrimPrefix(hash, "sha256:"), Subject: subject, ObservationType: "manifest.observed", CapturedAt: time.Now().UTC(), Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(hash, "sha256:"), Digest: hash, MediaType: "application/yaml"}, IntegrityDigest: hash}
		repository, err := storage.NewFilesystemEvidenceRepository(evidenceDir)
		if err != nil {
			return err
		}
		stored, err := repository.Put(cmd.Context(), material, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		return emitBackendResult(cmd, map[string]any{"status": "RECORDED_UNTRUSTED", "subject": subject.URI(), "material": stored, "artifact": material.Artifact, "authority": "UNKNOWN", "admission": "NOT_ASSESSED", "scope": "manifest bytes and declared identity only; no runtime observation, admission decision, control satisfaction, or signed receipt"}, 0, "")
	}}
	manifest.Flags().StringVar(&file, "file", "", "Single Kubernetes manifest file")
	manifest.Flags().StringVar(&namespace, "namespace", "", "Explicit declared namespace when omitted from the manifest")
	retired := &cobra.Command{Use: "admission", Short: "Retired: a local file cannot establish an admission decision", RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("record admission is retired: local manifest validation is not Kubernetes admission evidence; use record manifest --file <path> --evidence-dir <path> for untrusted material, or a real admission observer")
	}}
	retired.Flags().String("file", "", "Retired file-only admission input")
	record.AddCommand(manifest, retired)
	return record
}
