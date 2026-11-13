package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	assurancev1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/evaluation"
	"github.com/ckodex-labs/ckodex-oskal/internal/verifier"
)

type bindingEvaluationOptions struct{ kubeconfig, namespace, binding, keys, authority string }

func (o *bindingEvaluationOptions) flags(command *cobra.Command, persistent bool) {
	flags := command.Flags()
	if persistent {
		flags = command.PersistentFlags()
	}
	flags.StringVar(&o.kubeconfig, "kubeconfig", "", "Explicit kubeconfig for authoritative workload and contract queries")
	flags.StringVar(&o.namespace, "namespace", "", "Explicit namespace of the actual ControlBinding")
	flags.StringVar(&o.binding, "binding", "", "Actual ControlBinding name")
	flags.StringVar(&o.keys, "trusted-evidence-keys", "", "Trusted producer URI -> Ed25519 public-key hex JSON object from trusted custody")
	flags.StringVar(&o.authority, "authority-digest", "", "Explicit SHA-256 pin of the operator's trusted authority snapshot")
}
func (o bindingEvaluationOptions) requested() bool {
	return o.kubeconfig != "" || o.namespace != "" || o.binding != "" || o.keys != "" || o.authority != ""
}

func loadTrustedEvidenceVerifier(path string) (*verifier.DefaultEvidenceVerifier, error) {
	data, err := readBoundedFile(path, 1<<20)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("trusted evidence keys must be one JSON object")
	}
	verified := verifier.NewDefaultEvidenceVerifier()
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		producer, ok := token.(string)
		if !ok || seen[producer] || len(seen) >= 128 {
			return nil, fmt.Errorf("trusted evidence keys require 1 to 128 unique producer URIs")
		}
		seen[producer] = true
		identity, err := url.Parse(producer)
		if err != nil || identity.Scheme == "" || identity.Host == "" || identity.User != nil || identity.RawQuery != "" || identity.Fragment != "" || strings.ContainsAny(producer, "*|\r\n") {
			return nil, fmt.Errorf("producer trust requires exact identity URIs")
		}
		var keyHex string
		if err := decoder.Decode(&keyHex); err != nil {
			return nil, err
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("producer %s requires a 32-byte Ed25519 public key in hex", producer)
		}
		verified.RegisterPublicKey(producer, ed25519.PublicKey(key))
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF || len(seen) == 0 {
		return nil, fmt.Errorf("trusted evidence keys must be one nonempty JSON object")
	}
	return verified, nil
}

func evaluateBinding(ctx context.Context, o bindingEvaluationOptions) (binding.Context, []assurance.ClaimEvaluation, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if o.kubeconfig == "" || o.namespace == "" || o.binding == "" || o.keys == "" || o.authority == "" || evidenceDir == "" {
		return binding.Context{}, nil, fmt.Errorf("authoritative evaluation requires --kubeconfig, --namespace, --binding, --trusted-evidence-keys, --authority-digest and --evidence-dir; no ambient credentials or trust defaults are used")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", o.kubeconfig)
	if err != nil {
		return binding.Context{}, nil, err
	}
	cfg.Timeout = binding.ResolutionTimeout
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, assurancev1.AddToScheme} {
		if err := add(scheme); err != nil {
			return binding.Context{}, nil, err
		}
	}
	reader, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return binding.Context{}, nil, err
	}
	resolver, err := binding.NewResolver(reader).WithAuthorityDigest(o.authority)
	if err != nil {
		return binding.Context{}, nil, err
	}
	current, err := resolver.ContextForBinding(ctx, o.namespace, o.binding)
	if err != nil {
		return current, nil, err
	}
	archive, err := storage.OpenFilesystemEvidenceRepository(evidenceDir)
	if err != nil {
		return current, nil, err
	}
	trusted, err := loadTrustedEvidenceVerifier(o.keys)
	if err != nil {
		return current, nil, err
	}
	evaluator, err := evaluation.NewEvaluator(archive, trusted)
	if err != nil {
		return current, nil, err
	}
	results := make([]assurance.ClaimEvaluation, 0, len(current.Controls))
	for _, control := range current.Controls {
		result, err := evaluator.Evaluate(ctx, assurance.Claim{ID: current.BindingName + "-" + control.Canonical(), Subject: current.Subject, Control: control}, current.Contract, current.Epoch)
		results = append(results, result)
		if err != nil {
			return current, results, err
		}
	}
	return current, results, nil
}

func newBindingEvaluationCommand() *cobra.Command {
	options := bindingEvaluationOptions{}
	command := &cobra.Command{Use: "evaluate", Short: "Verify stored signed evidence against an actual Kubernetes binding and explicit trust", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		current, results, err := evaluateBinding(cmd.Context(), options)
		status, code := "VERIFIED", 0
		reason := ""
		if err != nil {
			status, code, reason = "UNKNOWN", 2, err.Error()
		}
		for _, result := range results {
			if result.State == assurance.AssuranceStateFailed {
				status, code = "FAILED", 3
			}
			if result.State == assurance.AssuranceStateUnknown && code != 3 {
				status, code = "UNKNOWN", 2
			}
		}
		if len(results) == 0 && code == 0 {
			status, code = "UNKNOWN", 2
		}
		output := map[string]any{"status": status, "context": current, "evaluations": results, "scope": "authoritative current configuration plus stored signed evidence; live source availability and overall policy admission are not established"}
		if reason != "" {
			output["reason"] = reason
		}
		return emitBackendResult(cmd, output, code, "binding evaluation returned "+status)
	}}
	options.flags(command, false)
	return command
}
