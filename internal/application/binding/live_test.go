package binding_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	kubeadapter "github.com/ckodex-labs/ckodex-oskal/internal/adapters/kubernetes"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

// This test requires real controller-created Pod ownership from an explicitly
// selected API. It retains its uniquely named namespace for independent review.
// Captured facts are real Pod API observations; runtime source execution is not
// asserted by this attribution test.
func TestLiveBindingContext(t *testing.T) {
	kubeconfig := os.Getenv("OSKAL_BINDING_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("set OSKAL_BINDING_KUBECONFIG to an explicitly authorized test cluster")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Timeout = 10 * time.Second
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, assurancev1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	api, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	resolver := binding.NewResolver(api)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("oskal-binding-%d", time.Now().UnixNano()), Labels: map[string]string{"owner": "binding-test"}}}
	if err := api.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	t.Logf("retained namespace=%s UID=%s", ns.Name, ns.UID)
	// Explicit ServiceAccount avoids depending on default-SA controller recovery.
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "binding-test", Namespace: ns.Name}}
	if err := api.Create(ctx, serviceAccount); err != nil {
		t.Fatal(err)
	}

	replicas := int32(1)
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: ns.Name, Labels: map[string]string{"app": "workload"}}, Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "workload"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "workload"}}, Spec: corev1.PodSpec{ServiceAccountName: "binding-test", Containers: []corev1.Container{{Name: "pause", Image: "registry.k8s.io/pause:3.10"}}}}}}
	if err := api.Create(ctx, deployment); err != nil {
		t.Fatal(err)
	}
	contract := &assurancev1alpha1.EvidenceContract{ObjectMeta: metav1.ObjectMeta{Name: "runtime", Namespace: ns.Name}, Spec: assurancev1alpha1.EvidenceContractSpec{Requirements: []assurancev1alpha1.ContractRequirement{{ID: "pod-observation", Type: "kubernetes.pod.read", Required: true, Freshness: metav1.Duration{Duration: 5 * time.Minute}}}, OnMissingRequiredEvidence: assurancev1alpha1.MissingEvidencePolicy{State: "Unknown"}}}
	if err := api.Create(ctx, contract); err != nil {
		t.Fatal(err)
	}
	cb := &assurancev1alpha1.ControlBinding{ObjectMeta: metav1.ObjectMeta{Name: "workload-binding", Namespace: ns.Name}, Spec: assurancev1alpha1.ControlBindingSpec{Controls: []assurancev1alpha1.ControlBindingItem{{Canonical: assurancev1alpha1.CanonicalControlRef{Namespace: "ckodex", ID: "runtime-observation", Version: "v1"}}}, Subjects: assurancev1alpha1.SubjectSelector{Kinds: []string{"Deployment"}, APIGroups: []string{"apps"}, LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "workload"}}, NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"owner": "binding-test"}}}, Requirements: []assurancev1alpha1.RequirementBinding{{ID: "runtime", EvidenceContract: "runtime", Implementations: []assurancev1alpha1.ImplementationBindingRef{}}}}}
	if err := api.Create(ctx, cb); err != nil {
		t.Fatal(err)
	}
	var pod corev1.Pod
	deadline := time.Now().Add(30 * time.Second)
	for {
		var pods corev1.PodList
		if err := api.List(ctx, &pods, client.InNamespace(ns.Name), client.MatchingLabels{"app": "workload"}); err != nil {
			t.Fatal(err)
		}
		if len(pods.Items) > 0 {
			pod = pods.Items[0]
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real Deployment controller did not create a Pod")
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}

	base, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
	if err != nil {
		t.Fatal(err)
	}
	if base.Subject.Attributes["uid"] != string(deployment.UID) || base.Epoch.SubjectDigest != kubeadapter.ComputeDeploymentDigest(deployment) || base.Epoch.AuthorityDigest != "" {
		t.Fatalf("context did not bind actual spec/UID or invented authority: %+v", base)
	}
	payload, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	event := ports.CapturedEvent{Subject: kubeadapter.BuildPodSubjectRef(&pod), Type: "kubernetes.pod.read", CapturedAt: time.Now().UTC(), Payload: payload, MediaType: "application/json"}
	subject, epoch, err := resolver.ResolveCapture(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	if subject.URI() != base.Subject.URI() || epoch != base.Epoch {
		t.Fatalf("capture and evaluator context diverged: %s %+v vs %s %+v", subject.URI(), epoch, base.Subject.URI(), base.Epoch)
	}
	t.Logf("VERIFIED controller-created API ownership attribution: real Pod UID %s -> ReplicaSet -> Deployment UID %s; subject=%s epoch=%s", pod.UID, deployment.UID, subject.URI(), epoch.CompositeDigest())
	t.Run("explicit-authority-snapshot", func(t *testing.T) {
		declared := assurance.ComputeStringDigest("binding-test-configuration:" + string(ns.UID))
		configured, err := resolver.WithAuthorityDigest(declared)
		if err != nil {
			t.Fatal(err)
		}
		contextWithAuthority, err := configured.ContextForBinding(ctx, ns.Name, cb.Name)
		if err != nil {
			t.Fatal(err)
		}
		_, captureEpoch, err := configured.ResolveCapture(ctx, event)
		if err != nil {
			t.Fatal(err)
		}
		if captureEpoch != contextWithAuthority.Epoch || captureEpoch.AuthorityDigest != declared {
			t.Fatal("explicit caller authority snapshot is not shared by capture/evaluation")
		}
	})

	assertDenied := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("expected authoritative resolution error")
		}
		t.Logf("VERIFIED rejection: %v", err)
	}
	updateBinding := func(t *testing.T, change func(*assurancev1alpha1.ControlBinding)) func() {
		t.Helper()
		var current assurancev1alpha1.ControlBinding
		if err := api.Get(ctx, client.ObjectKeyFromObject(cb), &current); err != nil {
			t.Fatal(err)
		}
		old := current.DeepCopy().Spec
		change(&current)
		if err := api.Update(ctx, &current); err != nil {
			t.Fatal(err)
		}
		return func() {
			var fresh assurancev1alpha1.ControlBinding
			if err := api.Get(ctx, client.ObjectKeyFromObject(cb), &fresh); err != nil {
				t.Fatal(err)
			}
			fresh.Spec = old
			if err := api.Update(ctx, &fresh); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("missing-contract", func(t *testing.T) {
		restore := updateBinding(t, func(b *assurancev1alpha1.ControlBinding) { b.Spec.Requirements[0].EvidenceContract = "absent" })
		defer restore()
		_, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
		assertDenied(t, err)
	})
	t.Run("missing-workload", func(t *testing.T) {
		_, err := resolver.ContextForSubject(ctx, assurance.SubjectRef{Scheme: "k8s", ID: ns.Name + "/Deployment/absent"})
		assertDenied(t, err)
	})
	t.Run("UID-less-creation-precision-hold", func(t *testing.T) {
		uncertain := event
		uncertain.Subject = assurance.SubjectRef{Scheme: event.Subject.Scheme, ID: event.Subject.ID}
		uncertain.CapturedAt = pod.CreationTimestamp.Time
		uncertain.MediaType = "application/vnd.cilium.flow+json"
		_, _, err := resolver.ResolveCapture(ctx, uncertain)
		assertDenied(t, err)
		if !strings.Contains(err.Error(), "precision window") {
			t.Fatalf("wrong rejection for ambiguous creation timestamp: %v", err)
		}
	})
	t.Run("wrong-captured-UID", func(t *testing.T) {
		wrong := event
		wrong.Subject = assurance.SubjectRef{Scheme: event.Subject.Scheme, ID: event.Subject.ID, Attributes: map[string]string{"uid": "incorrect-uid"}}
		_, _, err := resolver.ResolveCapture(ctx, wrong)
		assertDenied(t, err)
	})
	t.Run("label-mismatch", func(t *testing.T) {
		restore := updateBinding(t, func(b *assurancev1alpha1.ControlBinding) {
			b.Spec.Subjects.LabelSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": "absent"}}
		})
		defer restore()
		_, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
		assertDenied(t, err)
		_, _, err = resolver.ResolveCapture(ctx, event)
		assertDenied(t, err)
	})
	t.Run("namespace-label-mismatch", func(t *testing.T) {
		restore := updateBinding(t, func(b *assurancev1alpha1.ControlBinding) {
			b.Spec.Subjects.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"owner": "another-test"}}
		})
		defer restore()
		_, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
		assertDenied(t, err)
	})
	t.Run("API-group-mismatch", func(t *testing.T) {
		restore := updateBinding(t, func(b *assurancev1alpha1.ControlBinding) { b.Spec.Subjects.APIGroups = []string{""} })
		defer restore()
		_, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
		assertDenied(t, err)
	})
	t.Run("ambiguous-bindings", func(t *testing.T) {
		another := cb.DeepCopy()
		another.ResourceVersion = ""
		another.UID = ""
		another.Name = "another-binding"
		another.CreationTimestamp = metav1.Time{}
		if err := api.Create(ctx, another); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := api.Delete(ctx, another); err != nil {
				t.Fatal(err)
			}
		}()
		_, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
		assertDenied(t, err)
	})
	t.Run("ambiguous-subjects", func(t *testing.T) {
		another := deployment.DeepCopy()
		another.ResourceVersion = ""
		another.UID = ""
		another.Name = "another-workload"
		another.CreationTimestamp = metav1.Time{}
		zero := int32(0)
		another.Spec.Replicas = &zero
		if err := api.Create(ctx, another); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := api.Delete(ctx, another); err != nil {
				t.Fatal(err)
			}
		}()
		_, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
		assertDenied(t, err)
		_, _, err = resolver.ResolveCapture(ctx, event)
		assertDenied(t, err)
	})
	t.Run("conflicting-contract-requirement", func(t *testing.T) {
		another := contract.DeepCopy()
		another.ResourceVersion = ""
		another.UID = ""
		another.Name = "conflicting"
		another.CreationTimestamp = metav1.Time{}
		another.Spec.Requirements[0].Type = "different.actual.configuration"
		if err := api.Create(ctx, another); err != nil {
			t.Fatal(err)
		}
		restore := updateBinding(t, func(b *assurancev1alpha1.ControlBinding) {
			b.Spec.Requirements = append(b.Spec.Requirements, assurancev1alpha1.RequirementBinding{ID: "conflict", EvidenceContract: another.Name, Implementations: []assurancev1alpha1.ImplementationBindingRef{}})
		})
		defer restore()
		_, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
		assertDenied(t, err)
	})
	t.Run("full-spec-epoch-drift", func(t *testing.T) {
		var fresh appsv1.Deployment
		if err := api.Get(ctx, client.ObjectKeyFromObject(deployment), &fresh); err != nil {
			t.Fatal(err)
		}
		fresh.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "BINDING_TEST_REVISION", Value: "two"}}
		if err := api.Update(ctx, &fresh); err != nil {
			t.Fatal(err)
		}
		updated, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
		if err != nil {
			t.Fatal(err)
		}
		if updated.Epoch.SubjectDigest == base.Epoch.SubjectDigest {
			t.Fatal("non-image full spec change did not invalidate subject epoch")
		}
		t.Logf("VERIFIED full-spec subject drift %s -> %s", base.Epoch.SubjectDigest, updated.Epoch.SubjectDigest)
		_, _, err = resolver.ResolveCapture(ctx, event)
		assertDenied(t, err)

	})
	t.Run("contract-and-policy-epoch-drift", func(t *testing.T) {
		before, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
		if err != nil {
			t.Fatal(err)
		}
		var fresh assurancev1alpha1.EvidenceContract
		if err := api.Get(ctx, client.ObjectKeyFromObject(contract), &fresh); err != nil {
			t.Fatal(err)
		}
		fresh.Spec.Requirements[0].Freshness.Duration = 2 * time.Minute
		if err := api.Update(ctx, &fresh); err != nil {
			t.Fatal(err)
		}
		after, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
		if err != nil {
			t.Fatal(err)
		}
		if before.Epoch.PolicyDigest == after.Epoch.PolicyDigest || after.Contract.Requirements[0].MaxAge != 2*time.Minute {
			t.Fatal("contract change did not change effective policy epoch")
		}
		policy := &assurancev1alpha1.AssurancePolicy{ObjectMeta: metav1.ObjectMeta{Name: "bounded", Namespace: ns.Name}, Spec: assurancev1alpha1.AssurancePolicySpec{RequiredState: "Assured", Evidence: assurancev1alpha1.PolicyEvidenceConfig{RequireFresh: true}, Behavior: assurancev1alpha1.PolicyBehaviorConfig{UnknownIsViolation: true}, Freshness: assurancev1alpha1.PolicyFreshnessConfig{MaxEvaluationAge: metav1.Duration{Duration: time.Minute}}}}
		if err := api.Create(ctx, policy); err != nil {
			t.Fatal(err)
		}
		withPolicy, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
		if err != nil {
			t.Fatal(err)
		}
		if withPolicy.Epoch.PolicyDigest == after.Epoch.PolicyDigest || withPolicy.Contract.Requirements[0].MaxAge != time.Minute || withPolicy.Contract.OnMissingRequiredState != assurance.AssuranceStateFailed {
			t.Fatal("namespace policy did not change actual epoch/effective obligations")
		}
		t.Logf("VERIFIED contract+policy epoch drift %s -> %s -> %s", before.Epoch.PolicyDigest, after.Epoch.PolicyDigest, withPolicy.Epoch.PolicyDigest)
	})
	t.Run("namespace-label-epoch-drift", func(t *testing.T) {
		before, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
		if err != nil {
			t.Fatal(err)
		}
		var fresh corev1.Namespace
		if err := api.Get(ctx, client.ObjectKey{Name: ns.Name}, &fresh); err != nil {
			t.Fatal(err)
		}
		fresh.Labels["revision"] = "two"
		if err := api.Update(ctx, &fresh); err != nil {
			t.Fatal(err)
		}
		after, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
		if err != nil {
			t.Fatal(err)
		}
		if before.Epoch.EnvironmentDigest == after.Epoch.EnvironmentDigest {
			t.Fatal("namespace label drift did not invalidate environment epoch")
		}
	})
	t.Run("name-reuse-and-direct-Pod", func(t *testing.T) {
		direct := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "direct", Namespace: ns.Name}, Spec: corev1.PodSpec{ServiceAccountName: "binding-test", Containers: []corev1.Container{{Name: "pause", Image: "registry.k8s.io/pause:3.10"}}}}
		if err := api.Create(ctx, direct); err != nil {
			t.Fatal(err)
		}
		podBinding := cb.DeepCopy()
		podBinding.ResourceVersion = ""
		podBinding.UID = ""
		podBinding.Name = "direct-binding"
		podBinding.CreationTimestamp = metav1.Time{}
		podBinding.Spec.Subjects = assurancev1alpha1.SubjectSelector{Kinds: []string{"Pod"}, APIGroups: []string{""}}
		if err := api.Create(ctx, podBinding); err != nil {
			t.Fatal(err)
		}
		old := ports.CapturedEvent{Subject: kubeadapter.BuildPodSubjectRef(direct), CapturedAt: time.Now().UTC(), MediaType: "application/json"}
		expected, err := resolver.ContextForBinding(ctx, ns.Name, podBinding.Name)
		if err != nil {
			t.Fatal(err)
		}
		actual, currentEpoch, err := resolver.ResolveCapture(ctx, old)
		if err != nil || actual.URI() != expected.Subject.URI() || currentEpoch != expected.Epoch {
			t.Fatalf("direct Pod capture disagrees with evaluator: %v", err)
		}
		if err := api.Delete(ctx, direct, client.GracePeriodSeconds(0)); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			var gone corev1.Pod
			err := api.Get(ctx, client.ObjectKeyFromObject(direct), &gone)
			if client.IgnoreNotFound(err) == nil && err != nil {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if time.Now().After(deadline) {
				t.Fatal("direct Pod deletion did not complete")
			}
			time.Sleep(100 * time.Millisecond)
		}
		time.Sleep(1100 * time.Millisecond)
		replacement := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: direct.Name, Namespace: ns.Name}, Spec: direct.Spec}
		if err := api.Create(ctx, replacement); err != nil {
			t.Fatal(err)
		}
		if replacement.UID == direct.UID {
			t.Fatal("real API reused a Pod UID")
		}
		_, _, err = resolver.ResolveCapture(ctx, old)
		assertDenied(t, err)
		old.Subject.Attributes = nil
		old.MediaType = "application/vnd.cilium.flow+json"
		_, _, err = resolver.ResolveCapture(ctx, old)
		assertDenied(t, err)
		t.Logf("VERIFIED actual Pod name reuse: oldUID=%s newUID=%s oldCapture=%s newCreation=%s", direct.UID, replacement.UID, old.CapturedAt, replacement.CreationTimestamp.Time)
	})
	t.Run("unreachable-API", func(t *testing.T) {
		unreachable := *cfg
		unreachable.Host = "https://127.0.0.1:1"
		unreachable.Timeout = time.Second
		offline, err := client.New(&unreachable, client.Options{Scheme: scheme})
		if err != nil {
			t.Fatal(err)
		}
		_, err = binding.NewResolver(offline).ContextForBinding(ctx, ns.Name, cb.Name)
		assertDenied(t, err)
	})
	// Retain a portable record of real API facts and the originally matched context.
	if evidenceDir := os.Getenv("OSKAL_BINDING_EVIDENCE_DIR"); evidenceDir != "" {
		if err := os.MkdirAll(evidenceDir, 0700); err != nil {
			t.Fatal(err)
		}
		record := struct {
			Namespace                           string
			NamespaceUID, DeploymentUID, PodUID types.UID
			Context                             binding.Context
		}{ns.Name, ns.UID, deployment.UID, pod.UID, base}
		data, err := json.MarshalIndent(record, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(evidenceDir, ns.Name+".json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		t.Logf("retained API evidence=%s", path)
	}
}

func TestUnsupportedAndAmbiguousURIsFailClosed(t *testing.T) {
	for _, uri := range []string{"k8s://workload", "k8s://ns/workload", "k8s://cluster/ns/Deployment/workload", "k8s://ns/Constraint/violation", "k8s://ns/Pod/workload/extra", "k8s://ns/Pod/workload?other=target"} {
		if _, _, _, err := binding.ParseSubjectURI(uri); err == nil {
			t.Errorf("accepted unsupported or ambiguous URI %s", uri)
		}
	}
	for _, uri := range []string{"k8s://ns/Deployment/workload", "k8s://ns/Pod/workload"} {
		if _, _, _, err := binding.ParseSubjectURI(uri); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := binding.ParseSubjectURI(strings.Repeat("a", 100)); err == nil {
		t.Fatal("accepted invalid subject URI")
	}
}

func TestAuthorityDigestRequiresActualCanonicalSnapshot(t *testing.T) {
	resolver := binding.NewResolver(nil)
	for _, input := range []string{"", "sha256:abc", strings.Repeat("f", 64), "sha256:" + strings.Repeat("z", 64), "sha256:" + strings.Repeat("A", 64)} {
		if _, err := resolver.WithAuthorityDigest(input); err == nil {
			t.Errorf("accepted invalid authority digest %q", input)
		}
	}
	if _, err := resolver.WithAuthorityDigest(assurance.ComputeStringDigest("explicit domain input")); err != nil {
		t.Fatal(err)
	}
}
