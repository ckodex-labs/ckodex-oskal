// Command demo exercises OSKAL reconciliation using a real, disposable Kind API.
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
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/reconcile"
)

func main() {
	started := time.Now()
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "demo accepts no arguments; run make demo from the repository root")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Demo failed after %s: %v\nInspect retained artifacts printed above before retrying.\n", time.Since(started).Round(time.Millisecond), err)
		os.Exit(1)
	}
}

func command(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", args[0], err)
	}
	return nil
}

// eligibleEvidence reads the source before each explicit reconciliation. Historical CAS data is
// retained for audit, but cannot establish current source availability.
func eligibleEvidence(ctx context.Context, endpoint string) ([]assurance.EvidenceEnvelope, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/api/v1/nodes", nil)
	if err != nil {
		return nil, nil, err
	}
	hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer hc.CloseIdleConnections()
	res, err := hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("node API returned %s", res.Status)
	}
	const limit = 4 << 20
	raw, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > limit {
		return nil, nil, fmt.Errorf("node API response exceeds %d bytes", limit)
	}
	var nodes corev1.NodeList
	if err := json.Unmarshal(raw, &nodes); err != nil {
		return nil, nil, err
	}
	if len(nodes.Items) != 1 {
		return nil, nil, fmt.Errorf("expected one fresh Kind node, found %d", len(nodes.Items))
	}
	node := nodes.Items[0]
	subject := nodeSubject(node)
	for _, condition := range node.Status.Conditions {
		if condition.Type != corev1.NodeReady || condition.Status != corev1.ConditionTrue {
			continue
		}
		digest := assurance.ComputeDigest(raw)
		env := assurance.EvidenceEnvelope{
			Schema: "assurance.ckodex.io/evidence/v1alpha1", ID: "node-ready-" + node.ResourceVersion,
			Subject: subject, ObservationType: "kubernetes.api.node-ready", CapturedAt: time.Now().UTC(),
			Producer:        assurance.AuthorityRef{Scheme: "local", Subject: "demo/api-observer"},
			Artifact:        assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(digest, "sha256:"), Digest: digest, MediaType: "application/json"},
			IntegrityDigest: digest, Epoch: assurance.AssuranceEpoch{SubjectDigest: subject.Digest()},
			ControlRefs: []assurance.ControlRef{{Namespace: "demo", ID: "api-node-ready"}},
		}
		return []assurance.EvidenceEnvelope{env}, raw, nil
	}
	return nil, raw, fmt.Errorf("API does not report Node Ready=True")
}

func nodeSubject(node corev1.Node) assurance.SubjectRef {
	return assurance.SubjectRef{Scheme: "k8s", ID: "Node/" + node.Name, Attributes: map[string]string{"uid": string(node.UID), "name": node.Name, "kind": "Node"}}
}

type nodeResolver struct{ client client.Client }

func (r nodeResolver) ResolveSubject(ctx context.Context, uri string) (assurance.SubjectRef, error) {
	const prefix = "k8s://default/Node/"
	if !strings.HasPrefix(uri, prefix) {
		return assurance.SubjectRef{}, fmt.Errorf("unsupported demo subject %q", uri)
	}
	var node corev1.Node
	if err := r.client.Get(ctx, types.NamespacedName{Name: strings.TrimPrefix(uri, prefix)}, &node); err != nil {
		return assurance.SubjectRef{}, err
	}
	return nodeSubject(node), nil
}

func (r nodeResolver) ComputeSubjectDigest(_ context.Context, subject assurance.SubjectRef) (string, error) {
	return subject.Digest(), nil
}

func run(ctx context.Context) error {
	started := time.Now()
	for _, tool := range []string{"kind", "kubectl", "docker"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("install %s and retry: %w", tool, err)
		}
	}
	if err := command(ctx, "docker", "info", "--format", "{{.ServerVersion}}"); err != nil {
		return fmt.Errorf("start Docker and retry: %w", err)
	}
	dir, err := os.MkdirTemp("", "oskal-demo-")
	if err != nil {
		return err
	}
	name := fmt.Sprintf("oskal-demo-%d", time.Now().UnixNano())
	kubeconfig := filepath.Join(dir, "kubeconfig")
	fmt.Printf("OSKAL checks a real Kubernetes API observation, then reports UNKNOWN when its source stops.\nCluster: %s\nArtifacts: %s\n", name, dir)
	fmt.Println("Scope: local OSKAL reconciler and CRDs; API evidence only, unsigned and not hardware-attested.")
	fmt.Fprintf(os.Stderr, "Cluster retained. Cleanup after review: kind delete cluster --name %s\n", name)
	if err := command(ctx, "kind", "create", "cluster", "--name", name, "--kubeconfig", kubeconfig, "--wait", "90s", "--retain"); err != nil {
		return err
	}
	if err := command(ctx, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "config/crd/bases/"); err != nil {
		return err
	}
	if err := command(ctx, "kubectl", "--kubeconfig", kubeconfig, "wait", "--for=condition=Established", "--timeout=30s", "crd", "--all"); err != nil {
		return err
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return err
	}
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		return err
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		return err
	}
	kc, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	nodeName := name + "-control-plane"
	var node corev1.Node
	if err := kc.Get(ctx, types.NamespacedName{Name: nodeName}, &node); err != nil {
		return err
	}
	key := types.NamespacedName{Namespace: "default", Name: nodeName + "-binding"}
	objects := []client.Object{
		&api.EvidenceContract{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: "current-api"}, Spec: api.EvidenceContractSpec{
			Requirements:              []api.ContractRequirement{{ID: "current-node-read", Type: "kubernetes.api.node-ready", Required: true, Freshness: metav1.Duration{Duration: time.Minute}, AcceptedProducers: []string{"local://demo/api-observer"}}},
			OnMissingRequiredEvidence: api.MissingEvidencePolicy{State: "Unknown"},
		}},
		&api.ControlBinding{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}, Spec: api.ControlBindingSpec{
			Controls:     []api.ControlBindingItem{{Canonical: api.CanonicalControlRef{Namespace: "demo", ID: "api-node-ready"}}},
			Subjects:     api.SubjectSelector{Kinds: []string{"Node"}},
			Requirements: []api.RequirementBinding{{ID: "current-node-read", EvidenceContract: "current-api", Implementations: []api.ImplementationBindingRef{}}},
		}},
		&api.AssuranceState{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: "node-evidence-state"}, Spec: api.AssuranceStateSpec{SubjectRef: api.StateSubjectRef{APIVersion: "v1", Kind: "Node", Name: node.Name, UID: string(node.UID)}}},
	}
	for _, object := range objects {
		if err := kc.Create(ctx, object); err != nil {
			return err
		}
	}
	// The proxy is the actual evidence transport. Its kubeconfig is isolated from
	// the user's context. Stopping it never stops the assessor's direct API client.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return err
	}
	proxy := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfig, "proxy", "--address=127.0.0.1", fmt.Sprintf("--port=%d", port))
	proxy.Stdout, proxy.Stderr = os.Stderr, os.Stderr
	if err := proxy.Start(); err != nil {
		return err
	}
	waited := false
	defer func() {
		if !waited {
			_ = proxy.Process.Kill()
			_ = proxy.Wait()
		}
	}()
	endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
	var envs []assurance.EvidenceEnvelope
	var raw []byte
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		envs, raw, err = eligibleEvidence(ctx, endpoint)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	if err != nil {
		return fmt.Errorf("read evidence source: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node-response.json"), raw, 0600); err != nil {
		return err
	}
	archive, err := storage.NewFilesystemEvidenceRepository(filepath.Join(dir, "evidence"))
	if err != nil {
		return err
	}
	for _, env := range envs {
		if _, err := archive.Put(ctx, env, bytes.NewReader(raw)); err != nil {
			return err
		}
	}
	// The demo intentionally evaluates current reads only. The archive is never
	// used as a substitute for a successful read from a stopped source.
	evaluator := &reconcile.ContractEvaluator{EvidenceSource: envs}
	r := &reconcile.ControlBindingReconciler{Client: kc, Scheme: scheme, Log: logr.Discard(), ClaimEvaluator: evaluator, SubjectResolver: nodeResolver{client: kc}}
	if err := assess(ctx, r, kc, key, dir, "before", "ASSURED"); err != nil {
		return err
	}
	if err := proxy.Process.Kill(); err != nil {
		return err
	}
	_ = proxy.Wait() // Termination by our signal is expected; confirm the source is unreachable below.
	waited = true
	envs, _, sourceErr := eligibleEvidence(ctx, endpoint)
	if !errors.Is(sourceErr, syscall.ECONNREFUSED) {
		return fmt.Errorf("expected connection refused from stopped source; got %v", sourceErr)
	}
	fmt.Fprintf(os.Stderr, "Evidence transport stopped: %v\n", sourceErr)
	evaluator.EvidenceSource = envs
	if err := assess(ctx, r, kc, key, dir, "after", "UNKNOWN"); err != nil {
		return err
	}
	fmt.Printf("Earlier evidence retained in %s\nElapsed: %s\n", filepath.Join(dir, "evidence"), time.Since(started).Round(time.Millisecond))
	return nil
}

func assess(ctx context.Context, r *reconcile.ControlBindingReconciler, kc client.Client, key types.NamespacedName, dir, phase, expected string) error {
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		return err
	}
	var state api.AssuranceState
	if err := kc.Get(ctx, types.NamespacedName{Namespace: key.Namespace, Name: "node-evidence-state"}, &state); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, phase+".json"), raw, 0600); err != nil {
		return err
	}
	if len(state.Status.Controls) != 1 || state.Status.Controls[0].ID != "api-node-ready" || state.Status.Controls[0].State != expected || state.Status.State != expected {
		return fmt.Errorf("%s: expected control %s; got %+v", phase, expected, state.Status.Controls)
	}
	if expected == "UNKNOWN" && state.Status.EvidenceRoot != "" {
		return fmt.Errorf("UNKNOWN retained an active evidence root")
	}
	if expected == "ASSURED" && state.Status.EvidenceRoot == "" {
		return fmt.Errorf("ASSURED is missing its evidence root")
	}
	label := state.Status.Controls[0].State
	if label == "ASSURED" {
		label = "PASS (OSKAL control state ASSURED)"
	}
	fmt.Printf("%s: demo:api-node-ready = %s; %s\n", phase, label, state.Status.Controls[0].EvidenceSummary)
	return nil
}
