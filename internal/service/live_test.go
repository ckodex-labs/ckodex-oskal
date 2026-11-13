package service_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	api "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/evaluation"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/ckodex-labs/ckodex-oskal/internal/service"
	"github.com/ckodex-labs/ckodex-oskal/internal/verifier"
	"github.com/ckodex-labs/ckodex-oskal/pkg/oskal"
	commonv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/control/v1"
	servicesv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/services/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestLiveBindingAssessmentOverTLSAndSDK(t *testing.T) {
	path := os.Getenv("OSKAL_SERVICE_KUBECONFIG")
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
	k, err := client.New(cfg, client.Options{Scheme: scheme})
	must(t, err)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("oskal-service-%d", time.Now().UnixNano())}}
	must(t, k.Create(ctx, ns))
	t.Logf("retained namespace %s UID %s", ns.Name, ns.UID)
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "service-test", Namespace: ns.Name}}
	must(t, k.Create(ctx, sa))
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "observed", Namespace: ns.Name}, Spec: corev1.PodSpec{ServiceAccountName: sa.Name, NodeName: "service-unscheduled", Containers: []corev1.Container{{Name: "pause", Image: "registry.k8s.io/pause:3.10"}}}}
	must(t, k.Create(ctx, pod))
	producer := assurance.AuthorityRef{Scheme: "local", Subject: "service-api-test"}
	wrongProducer := assurance.AuthorityRef{Scheme: "local", Subject: "unaccepted-api-reader"}
	signer, err := receipts.NewReceiptManager(producer)
	must(t, err)
	wrongSigner, err := receipts.NewReceiptManager(wrongProducer)
	must(t, err)
	archive, err := storage.NewFilesystemEvidenceRepository(t.TempDir())
	must(t, err)
	candidates, err := collection.NewCandidates(archive, []collection.SourceConfig{{ID: "api", Producer: producer, Signer: signer}, {ID: "wrong-producer", Producer: wrongProducer, Signer: wrongSigner}}, 32)
	must(t, err)
	session, err := candidates.BeginSession("api")
	must(t, err)
	wrongSession, err := candidates.BeginSession("wrong-producer")
	must(t, err)
	v := verifier.NewDefaultEvidenceVerifier()
	for _, pair := range []struct {
		producer assurance.AuthorityRef
		signer   *receipts.ReceiptManager
	}{{producer, signer}, {wrongProducer, wrongSigner}} {
		key, err := hex.DecodeString(pair.signer.PublicKey())
		must(t, err)
		v.RegisterPublicKey(pair.producer.Canonical(), ed25519.PublicKey(key))
	}
	evaluator, err := evaluation.NewEvaluator(candidates, v)
	must(t, err)
	key, err := hex.DecodeString(signer.PublicKey())
	must(t, err)
	resolver, err := binding.NewResolver(k).WithAuthorityDigest(assurance.ComputeDigest(key))
	must(t, err)
	ec := &api.EvidenceContract{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: ns.Name}, Spec: api.EvidenceContractSpec{Requirements: []api.ContractRequirement{{ID: "read", Type: "kubernetes.pod.read", Required: true, Freshness: metav1.Duration{Duration: time.Minute}, AcceptedProducers: []string{producer.Canonical()}}}, OnMissingRequiredEvidence: api.MissingEvidencePolicy{State: "Unknown"}}}
	must(t, k.Create(ctx, ec))
	cb := &api.ControlBinding{ObjectMeta: metav1.ObjectMeta{Name: "observed-binding", Namespace: ns.Name}, Spec: api.ControlBindingSpec{Controls: []api.ControlBindingItem{{Canonical: api.CanonicalControlRef{Namespace: "ckodex", ID: "api-read", Version: "v1"}}}, Subjects: api.SubjectSelector{Kinds: []string{"Pod"}}, Requirements: []api.RequirementBinding{{ID: "read", EvidenceContract: "api", Implementations: []api.ImplementationBindingRef{}}}}}
	must(t, k.Create(ctx, cb))
	config := service.EvaluationConfig{Resolver: resolver, Evaluator: evaluator, Sources: candidates}
	server, err := service.NewServerWithEvaluation(signer, config)
	must(t, err)
	rpc, sdk := serveTLS(t, server)
	sdkConfig, err := oskal.NewEvaluationConfig(k, assurance.ComputeDigest(key), candidates, v)
	must(t, err)
	embedded, err := oskal.NewInProcessClientWithEvaluation(sdkConfig)
	must(t, err)
	subject := binding.PodSubject(pod)
	wireSubject := &commonv1.SubjectRef{Scheme: subject.Scheme, Id: subject.ID, Attributes: subject.Attributes}
	control := assurance.ControlRef{Namespace: "ckodex", ID: "api-read", Version: "v1"}
	wireControl := &controlv1.ControlRef{Namespace: control.Namespace, Id: control.ID, Version: control.Version}
	request := &servicesv1.EvaluateSubjectRequest{Subject: wireSubject, Controls: []*controlv1.ControlRef{wireControl}}
	observe := func(source *collection.Session, authority assurance.AuthorityRef) (binding.Context, assurance.EvidenceRef, time.Time) {
		t.Helper()
		resolved, err := resolver.ContextForSubject(ctx, subject)
		must(t, err)
		raw, err := json.Marshal(pod)
		must(t, err)
		digest := assurance.ComputeDigest(raw)
		captured := time.Now().UTC()
		ref, err := source.Repository().Put(ctx, assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/evidence/v1alpha1", ID: "api-" + strings.TrimPrefix(resolved.Epoch.CompositeDigest(), "sha256:"), Subject: resolved.Subject, ObservationType: "kubernetes.pod.read", CapturedAt: captured, Producer: authority, Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(digest, "sha256:"), Digest: digest, MediaType: "application/json"}, IntegrityDigest: digest, Epoch: resolved.Epoch, ControlRefs: resolved.Controls}, bytes.NewReader(raw))
		must(t, err)
		return resolved, ref, captured
	}
	observe(wrongSession, wrongProducer)
	rejected, err := rpc.EvaluateSubject(ctx, request)
	must(t, err)
	if rejected.SummaryState != commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN {
		t.Fatal("valid signature from unaccepted producer promoted")
	}
	resolved, _, captured := observe(session, producer)
	verified, err := rpc.EvaluateSubject(ctx, request)
	must(t, err)
	if verified.SummaryState != commonv1.AssuranceState_ASSURANCE_STATE_VERIFIED {
		t.Fatalf("without policy: %v", verified)
	}
	e := verified.Evaluations[0]
	if e.Subject.Attributes["uid"] != string(pod.UID) || e.Control.Version != "v1" || e.Epoch.SubjectDigest != resolved.Epoch.SubjectDigest || e.Epoch.PolicyDigest != resolved.Epoch.PolicyDigest || e.Epoch.AuthorityDigest != resolved.Epoch.AuthorityDigest || !e.ValidUntil.AsTime().Equal(captured.Add(time.Minute)) || len(e.Evidence) != 1 {
		t.Fatalf("wire changed metadata: %v", e)
	}
	for _, consumer := range []oskal.Client{sdk, embedded} {
		result, err := consumer.EvaluateSubject(ctx, subject, []assurance.ControlRef{control})
		must(t, err)
		got := result.Evaluations[0]
		if result.SummaryState != assurance.AssuranceStateVerified || got.Epoch != resolved.Epoch || !reflect.DeepEqual(got.Subject.Attributes, resolved.Subject.Attributes) || got.Control != control || len(got.Evidence) != 1 || got.Evidence[0].URI != e.Evidence[0].Uri || !got.ValidUntil.Equal(captured.Add(time.Minute)) || len(got.Trace) == 0 || !result.EvaluatedAt.Equal(got.EvaluatedAt) {
			t.Fatalf("SDK changed evaluation: %+v", result)
		}
	}
	explanation, err := rpc.ExplainClaim(ctx, &servicesv1.ExplainClaimRequest{Subject: wireSubject, Control: wireControl})
	must(t, err)
	if len(explanation.Implementations) != 0 || len(explanation.AtomicRequirements) != 0 || len(explanation.Evidence) != 1 || explanation.Evidence[0].Uri != e.Evidence[0].Uri {
		t.Fatal("explanation fabricated provenance or replaced artifact URI")
	}
	policy := &api.AssurancePolicy{ObjectMeta: metav1.ObjectMeta{Name: "explicit", Namespace: ns.Name}, Spec: api.AssurancePolicySpec{RequiredState: "Assured", Evidence: api.PolicyEvidenceConfig{RequireFresh: true}, Behavior: api.PolicyBehaviorConfig{FailOnConfirmedViolation: true}, Freshness: api.PolicyFreshnessConfig{MaxEvaluationAge: metav1.Duration{Duration: time.Minute}}}}
	must(t, k.Create(ctx, policy))
	changed, err := rpc.EvaluateSubject(ctx, request)
	must(t, err)
	if changed.SummaryState != commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN {
		t.Fatal("policy epoch reused old evidence")
	}
	observe(session, producer)
	assured, err := rpc.EvaluateSubject(ctx, request)
	must(t, err)
	if assured.SummaryState != commonv1.AssuranceState_ASSURANCE_STATE_ASSURED {
		t.Fatalf("explicit policy: %v", assured)
	}
	state, err := rpc.GetAssuranceState(ctx, &servicesv1.GetAssuranceStateRequest{Subject: wireSubject})
	must(t, err)
	if state.State != commonv1.AssuranceState_ASSURANCE_STATE_ASSURED || len(state.Evaluations) != 1 {
		t.Fatal("summary bypassed bound evaluation")
	}
	invalid := &servicesv1.EvaluateSubjectRequest{Subject: wireSubject, Controls: []*controlv1.ControlRef{{Namespace: "ckodex", Id: "unbound"}}}
	if _, err := rpc.EvaluateSubject(ctx, invalid); err == nil {
		t.Fatal("unbound control admitted")
	}
	wrongUID := subject
	wrongUID.Attributes = map[string]string{"uid": "wrong"}
	if _, err := sdk.EvaluateSubject(ctx, wrongUID, []assurance.ControlRef{control}); err == nil {
		t.Fatal("SDK discarded UID before resolution")
	}
	must(t, session.End("actual source ended"))
	ended, err := rpc.EvaluateSubject(ctx, request)
	must(t, err)
	if ended.SummaryState != commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN {
		t.Fatal("source shutdown retained standing")
	}
	t.Log("verified mTLS rejection, wrong-producer exclusion, policy-free VERIFIED, explicit-policy ASSURED, epoch/source invalidation and exact SDK/in-process mappings")
}
