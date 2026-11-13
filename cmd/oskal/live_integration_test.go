package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	assurancev1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/workcell"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

func TestRealCLIBindingAndLease(t *testing.T) {
	kubeconfig := os.Getenv("OSKAL_CLI_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("set OSKAL_CLI_KUBECONFIG to an explicitly authorized test API")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Timeout = 10 * time.Second
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, assurancev1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	api, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := workcell.NewKubernetesPrincipal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := identity.AuthenticatedPrincipal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("oskal-cli-%d", time.Now().UnixNano())}}
	if err := api.Create(ctx, namespace); err != nil {
		t.Fatal(err)
	}
	t.Logf("retained actual API namespace=%s UID=%s actor=%s", namespace.Name, namespace.UID, actor)
	binary := buildCLI(t)
	directory := os.Getenv("OSKAL_CLI_EVIDENCE_DIR")
	if directory == "" {
		directory = t.TempDir()
	} else {
		directory = filepath.Join(directory, namespace.Name)
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	producer := assurance.AuthorityRef{Scheme: "kubernetes-user", Subject: url.PathEscape(actor)}
	signer, err := receipts.LoadOrCreateReceiptManager(producer, filepath.Join(directory, "signer"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := hex.DecodeString(signer.PublicKey())
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("invalid actual signing key")
	}
	authority := assurance.ComputeDigest(publicKey)
	controls := []assurancev1.ControlBindingItem{{Canonical: assurancev1.CanonicalControlRef{Namespace: "cli-test", ID: "api-observation"}}}
	zero := int32(0)
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "observed", Namespace: namespace.Name}, Spec: appsv1.DeploymentSpec{Replicas: &zero, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "observed"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "observed"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "pause", Image: "registry.k8s.io/pause:3.10"}}}}}}
	if err := api.Create(ctx, deployment); err != nil {
		t.Fatal(err)
	}
	contract := &assurancev1.EvidenceContract{ObjectMeta: metav1.ObjectMeta{Name: "api-observation", Namespace: namespace.Name}, Spec: assurancev1.EvidenceContractSpec{Requirements: []assurancev1.ContractRequirement{{ID: "actual-api-object", Type: "kubernetes.deployment.read", Required: true, Freshness: metav1.Duration{Duration: 5 * time.Minute}, AcceptedProducers: []string{producer.Canonical()}}}, OnMissingRequiredEvidence: assurancev1.MissingEvidencePolicy{State: "Unknown"}}}
	if err := api.Create(ctx, contract); err != nil {
		t.Fatal(err)
	}
	cb := &assurancev1.ControlBinding{ObjectMeta: metav1.ObjectMeta{Name: "observed-binding", Namespace: namespace.Name}, Spec: assurancev1.ControlBindingSpec{Controls: controls, Subjects: assurancev1.SubjectSelector{Kinds: []string{"Deployment"}, APIGroups: []string{"apps"}}, Requirements: []assurancev1.RequirementBinding{{ID: "actual-api-object", EvidenceContract: contract.Name, Implementations: []assurancev1.ImplementationBindingRef{}}}}}
	if err := api.Create(ctx, cb); err != nil {
		t.Fatal(err)
	}
	resolver, err := binding.NewResolver(api).WithAuthorityDigest(authority)
	if err != nil {
		t.Fatal(err)
	}
	current, err := resolver.ContextForBinding(ctx, namespace.Name, cb.Name)
	if err != nil {
		t.Fatal(err)
	}
	var observed appsv1.Deployment
	if err := api.Get(ctx, client.ObjectKeyFromObject(deployment), &observed); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	hash := assurance.ComputeDigest(payload)
	envelope := assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/evidence/v1alpha1", ID: "actual-api-read", Subject: current.Subject, ObservationType: "kubernetes.deployment.read", CapturedAt: time.Now().UTC(), Producer: producer, Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(hash, "sha256:"), Digest: hash, MediaType: "application/json"}, IntegrityDigest: hash, Epoch: current.Epoch, ControlRefs: current.Controls}
	signed, err := signer.SignEvidence(ctx, envelope)
	if err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(directory, "store")
	archive, err := storage.NewFilesystemEvidenceRepository(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Put(ctx, signed, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "trusted-producers.json")
	keyBytes, err := json.Marshal(map[string]string{producer.Canonical(): signer.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"assurance", "evaluate", "--kubeconfig", kubeconfig, "--namespace", namespace.Name, "--binding", cb.Name, "--trusted-evidence-keys", keyPath, "--authority-digest", authority, "--evidence-dir", storePath}
	result := runCLIJSON(t, binary, 0, args...)
	if result["status"] != "VERIFIED" {
		t.Fatalf("actual signed API observation did not verify: %+v", result)
	}
	// Ordinary offline analysis of the same bytes does not inherit this explicit trust.
	offline := runCLIJSON(t, binary, 0, "utcp", "call", "get_assurance_state", "--subject", current.Subject.URI(), "--evidence-dir", storePath)
	if offline["output"].(map[string]any)["state"] != "UNKNOWN" {
		t.Fatal("explicit trust leaked into offline material analysis")
	}
	// A real changed binding configuration invalidates the signed candidate epoch.
	var changed assurancev1.ControlBinding
	if err := api.Get(ctx, client.ObjectKeyFromObject(cb), &changed); err != nil {
		t.Fatal(err)
	}
	changed.Spec.Requirements[0].Implementations = []assurancev1.ImplementationBindingRef{{Purpose: "informational", Provider: "kubernetes-api", Ref: assurancev1.ImplementationTargetRef{Name: deployment.Name, Namespace: namespace.Name}}}
	if err := api.Update(ctx, &changed); err != nil {
		t.Fatal(err)
	}
	result = runCLIJSON(t, binary, 2, args...)
	if result["status"] != "UNKNOWN" {
		t.Fatal("old signed epoch survived actual binding drift")
	}
	createLease := func(name, principal string) *assurancev1.CapabilityLease {
		t.Helper()
		lease := &assurancev1.CapabilityLease{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace.Name}, Spec: assurancev1.CapabilityLeaseSpec{Principal: principal, Scope: "utcp://registry/tool/oskal.run_doctor", AllowedCapabilities: []string{"utcp:run-doctor"}, MaxTurns: 1, TTL: metav1.Duration{Duration: time.Hour}}}
		if err := api.Create(ctx, lease); err != nil {
			t.Fatal(err)
		}
		issued := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
		expires := metav1.NewTime(issued.Add(time.Hour))
		lease.Status = assurancev1.CapabilityLeaseStatus{Phase: "Active", IssuedAt: &issued, ExpiresAt: &expires, ObservedGeneration: lease.Generation}
		if err := api.Status().Update(ctx, lease); err != nil {
			t.Fatal(err)
		}
		return lease
	}
	lease := createLease("cli-diagnostic", actor)
	leaseID := namespace.Name + "/" + lease.Name + "/" + string(lease.UID)
	result = runCLIJSON(t, binary, 0, "utcp", "call", "run_doctor", "--lease-kubeconfig", kubeconfig, "--lease-id", leaseID)
	if result["receipt"] == nil {
		t.Fatal("actual governed CLI effect produced no execution receipt")
	}
	var completed assurancev1.CapabilityLease
	if err := api.Get(ctx, client.ObjectKeyFromObject(lease), &completed); err != nil {
		t.Fatal(err)
	}
	if completed.Status.CurrentTurn != 1 || completed.Status.PendingExecution != nil || len(completed.Status.ExecutionHistory) != 1 {
		t.Fatalf("actual lease did not reserve/complete: %+v", completed.Status)
	}
	denied := createLease("wrong-principal", "different-principal")
	wrong := exec.Command(binary, "utcp", "call", "run_doctor", "--lease-kubeconfig", kubeconfig, "--lease-id", namespace.Name+"/"+denied.Name+"/"+string(denied.UID), "--args", `{"principal":"different-principal"}`)
	if output, err := wrong.CombinedOutput(); err == nil {
		t.Fatalf("request principal overrode actual SelfSubjectReview: %s", output)
	}
	completed = assurancev1.CapabilityLease{}
	if err := api.Get(ctx, client.ObjectKeyFromObject(denied), &completed); err != nil {
		t.Fatal(err)
	}
	if completed.Status.CurrentTurn != 0 {
		t.Fatal("wrong authenticated principal consumed a turn")
	}
	t.Logf("VERIFIED actual CLI signed-observation evaluation, epoch drift UNKNOWN, SelfSubjectReview principal, durable completion, and claimed-principal denial; evidence=%s", directory)
}
