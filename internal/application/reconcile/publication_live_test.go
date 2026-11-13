package reconcile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	api "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/evaluation"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/ingestion"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/ckodex-labs/ckodex-oskal/internal/verifier"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Real API, real immutable CAS, Ed25519 and evaluator. This records API facts;
// it does not claim these facts are runtime process or network sensor evidence.
func TestLivePublicationGuards(t *testing.T) {
	path := os.Getenv("OSKAL_PUBLICATION_KUBECONFIG")
	if path == "" {
		t.Skip("requires explicitly owned Kubernetes API")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	must(t, err)
	cfg.Timeout = 5 * time.Second
	scheme := runtime.NewScheme()
	must(t, corev1.AddToScheme(scheme))
	must(t, appsv1.AddToScheme(scheme))
	must(t, api.AddToScheme(scheme))
	k, err := client.NewWithWatch(cfg, client.Options{Scheme: scheme})
	must(t, err)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("oskal-publication-%d", time.Now().UnixNano())}}
	must(t, k.Create(ctx, ns))
	t.Logf("retained namespace %s UID %s", ns.Name, ns.UID)
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "publication", Namespace: ns.Name}}
	must(t, k.Create(ctx, sa))
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: ns.Name, Labels: map[string]string{"publication": "bound"}}, Spec: corev1.PodSpec{ServiceAccountName: sa.Name, NodeName: "publication-unscheduled", Containers: []corev1.Container{{Name: "pause", Image: "registry.k8s.io/pause:3.10"}}}}
	must(t, k.Create(ctx, pod))
	producer := assurance.AuthorityRef{Scheme: "local", Subject: "publication-api-test"}
	signer, err := receipts.NewReceiptManager(producer)
	must(t, err)
	archive, err := storage.NewFilesystemEvidenceRepository(t.TempDir())
	must(t, err)
	candidates, err := collection.NewCandidates(archive, []collection.SourceConfig{{ID: "pod-api", Producer: producer, Signer: signer}}, 32)
	must(t, err)
	session, err := candidates.BeginSession("pod-api")
	must(t, err)
	key, err := hex.DecodeString(signer.PublicKey())
	must(t, err)
	v := verifier.NewDefaultEvidenceVerifier()
	v.RegisterPublicKey(producer.Canonical(), ed25519.PublicKey(key))
	evaluator, err := evaluation.NewEvaluator(candidates, v)
	must(t, err)
	resolver, err := binding.NewResolver(k).WithAuthorityDigest(assurance.ComputeDigest(key))
	must(t, err)
	ec := &api.EvidenceContract{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: ns.Name}, Spec: api.EvidenceContractSpec{Requirements: []api.ContractRequirement{{ID: "read", Type: "kubernetes.pod.read", Required: true, Freshness: metav1.Duration{Duration: time.Minute}, AcceptedProducers: []string{producer.Canonical()}}}, OnMissingRequiredEvidence: api.MissingEvidencePolicy{State: "Unknown"}}}
	must(t, k.Create(ctx, ec))
	cb := &api.ControlBinding{ObjectMeta: metav1.ObjectMeta{Name: "pod-binding", Namespace: ns.Name}, Spec: api.ControlBindingSpec{Controls: []api.ControlBindingItem{{Canonical: api.CanonicalControlRef{Namespace: "ckodex", ID: "pod-read", Version: "v1"}}}, Subjects: api.SubjectSelector{Kinds: []string{"Pod"}, LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"publication": "bound"}}}, Requirements: []api.RequirementBinding{{ID: "read", EvidenceContract: "api", Implementations: []api.ImplementationBindingRef{}}}}}
	must(t, k.Create(ctx, cb))
	r := &LiveControlReconciler{Client: k, Reader: k, Scheme: scheme, Resolver: resolver, Evaluator: evaluator, Signer: signer, Receipts: archive, Interval: time.Second, Sources: candidates}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cb)}
	observe := func(p *corev1.Pod) binding.Context {
		t.Helper()
		resolved, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
		must(t, err)
		raw, err := json.Marshal(p)
		must(t, err)
		digest := assurance.ComputeDigest(raw)
		_, err = session.Repository().Put(ctx, assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/evidence/v1alpha1", ID: "pod-" + strings.TrimPrefix(resolved.Epoch.CompositeDigest(), "sha256:"), Subject: resolved.Subject, ObservationType: "kubernetes.pod.read", CapturedAt: time.Now().UTC(), Producer: producer, Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(digest, "sha256:"), Digest: digest, MediaType: "application/json"}, IntegrityDigest: digest, Epoch: resolved.Epoch, ControlRefs: resolved.Controls}, bytes.NewReader(raw))
		must(t, err)
		return resolved
	}
	readState := func() api.AssuranceState {
		t.Helper()
		var s api.AssuranceState
		must(t, k.Get(ctx, req.NamespacedName, &s))
		return s
	}
	run := func() { t.Helper(); _, err := r.Reconcile(ctx, req); must(t, err) }
	observe(pod)
	run()
	if s := readState(); s.Status.State != "VERIFIED" {
		t.Fatalf("without policy got %s", s.Status.State)
	}
	must(t, k.Get(ctx, req.NamespacedName, cb))
	if cb.Status.Conditions[0].Status == metav1.ConditionTrue {
		t.Fatal("policy-free evaluation became Ready")
	}
	policy := &api.AssurancePolicy{ObjectMeta: metav1.ObjectMeta{Name: "explicit", Namespace: ns.Name}, Spec: api.AssurancePolicySpec{RequiredState: "Assured", Evidence: api.PolicyEvidenceConfig{RequireFresh: true}, Behavior: api.PolicyBehaviorConfig{FailOnConfirmedViolation: true}, Freshness: api.PolicyFreshnessConfig{MaxEvaluationAge: metav1.Duration{Duration: time.Minute}}}}
	must(t, k.Create(ctx, policy))
	observe(pod)
	run()
	old := readState()
	if old.Status.State != "ASSURED" {
		t.Fatalf("explicit policy got %s", old.Status.State)
	}
	watch, err := k.Watch(ctx, &api.AssuranceStateList{}, client.InNamespace(ns.Name), &client.ListOptions{Raw: &metav1.ListOptions{ResourceVersion: old.ResourceVersion}})
	must(t, err)
	defer watch.Stop()
	pod.Labels["publication"] = "retired"
	must(t, k.Update(ctx, pod))
	second := pod.DeepCopy()
	second.ObjectMeta = metav1.ObjectMeta{Name: "second", Namespace: ns.Name, Labels: map[string]string{"publication": "bound"}}
	second.Status = corev1.PodStatus{}
	must(t, k.Create(ctx, second))
	observe(second)
	run()
	final := readState()
	if final.Spec.SubjectRef.UID != string(second.UID) || final.Status.State != "ASSURED" {
		t.Fatal("retarget failed")
	}
	sawRetraction := false
	for {
		select {
		case event := <-watch.ResultChan():
			s, ok := event.Object.(*api.AssuranceState)
			if !ok {
				t.Fatalf("unexpected watch object %T", event.Object)
			}
			if s.Status.State == "UNKNOWN" {
				sawRetraction = true
			}
			if s.Spec.SubjectRef.UID == string(second.UID) && !sawRetraction {
				t.Fatal("replacement UID visible before old standing retracted")
			}
			if s.Spec.SubjectRef.UID == string(second.UID) && s.Status.State == "ASSURED" && s.Status.EvidenceRoot == old.Status.EvidenceRoot {
				t.Fatal("replacement inherited old evidence root")
			}
			if s.ResourceVersion == final.ResourceVersion {
				goto observed
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
observed:
	expected, err := resolver.ContextForBinding(ctx, ns.Name, cb.Name)
	must(t, err)
	revision := candidates.Revision()
	must(t, k.Get(ctx, req.NamespacedName, cb))
	before := cb.DeepCopy()
	cb.Spec.Requirements[0].ID = "changed"
	must(t, k.Update(ctx, cb))
	if err := r.current(ctx, before, expected, revision); err == nil {
		t.Fatal("binding drift admitted")
	}
	if err := r.publishUnknown(ctx, before, "binding changed"); err == nil {
		t.Fatal("stale condition unexpectedly accepted")
	}
	if s := readState(); s.Status.State != "UNKNOWN" || s.Status.EvidenceRoot != "" {
		t.Fatal("stale condition guard prevented retraction")
	}
	observe(second)
	run()
	expected, err = resolver.ContextForBinding(ctx, ns.Name, cb.Name)
	must(t, err)
	revision = candidates.Revision()
	must(t, session.End("test source shutdown"))
	if err := r.current(ctx, cb, expected, revision); err == nil {
		t.Fatal("source shutdown admitted")
	}
	run()
	if s := readState(); s.Status.State == "ASSURED" {
		t.Fatal("unavailable source retained assurance")
	}
	// The unsupported owner is a real API object, with a real UID. No runtime
	// activity is claimed by this API attribution test.
	ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "unbound", Namespace: ns.Name, Labels: map[string]string{"app": "unbound"}}, Spec: appsv1.DaemonSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "unbound"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "unbound"}}, Spec: corev1.PodSpec{ServiceAccountName: sa.Name, Containers: []corev1.Container{{Name: "pause", Image: "registry.k8s.io/pause:3.10"}}}}}}
	must(t, k.Create(ctx, ds))
	var owned *corev1.Pod
	for owned == nil {
		var pods corev1.PodList
		must(t, k.List(ctx, &pods, client.InNamespace(ns.Name), client.MatchingLabels{"app": "unbound"}))
		for i := range pods.Items {
			if owner := metav1.GetControllerOf(&pods.Items[i]); owner != nil && owner.UID == ds.UID {
				owned = &pods.Items[i]
				break
			}
		}
		if owned == nil {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	event := ports.CapturedEvent{Subject: binding.PodSubject(owned), Type: "kubernetes.pod.read", CapturedAt: time.Now().UTC(), Producer: producer, Payload: []byte(`{"read":true}`), MediaType: "application/json"}
	if _, _, err := resolver.ResolveCapture(ctx, event); !errors.Is(err, ports.ErrNotApplicable) {
		t.Fatalf("unbound owner: %v", err)
	}
	writer := &ingestion.Writer{Repository: archive, Resolver: resolver}
	must(t, writer.WriteCapturedEvent(ctx, event))
	ignored, err := archive.ListBySubject(ctx, event.Subject)
	must(t, err)
	if len(ignored) != 0 {
		t.Fatal("out-of-scope capture was stored")
	}
	direct := cb.DeepCopy()
	direct.ObjectMeta = metav1.ObjectMeta{Name: "unbound-binding", Namespace: ns.Name}
	direct.Spec.Subjects = api.SubjectSelector{Kinds: []string{"Pod"}, LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "unbound"}}}
	direct.Status = api.ControlBindingStatus{}
	must(t, k.Create(ctx, direct))
	if _, _, err := resolver.ResolveCapture(ctx, event); err != nil {
		t.Fatalf("direct Pod binding ignored: %v", err)
	}
	direct.Spec.Subjects.Kinds = []string{"DaemonSet"}
	must(t, k.Update(ctx, direct))
	if _, _, err := resolver.ResolveCapture(ctx, event); err == nil || errors.Is(err, ports.ErrNotApplicable) {
		t.Fatalf("configured unsupported owner was ignored: %v", err)
	}
	t.Log("verified policy gating, watch-observed retarget retraction, binding/source drift, and direct/unbound/unsupported Pod attribution")
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
