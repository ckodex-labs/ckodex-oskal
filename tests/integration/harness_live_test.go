package integration

import (
	"context"
	"os"
	"testing"
	"time"

	api "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/reconcile"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The always-on harness above asserts the same negative invariant. This test
// additionally proves actual API validation and status-subresource persistence.
func TestControllerReconciliationRealAPIMissingEvidence(t *testing.T) {
	kubeconfig := os.Getenv("OSKAL_INTEGRATION_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("explicit isolated OSKAL_INTEGRATION_KUBECONFIG with OSKAL CRDs required")
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	config.Timeout = 5 * time.Second
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	connection, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "oskal-ci-compat-"}}
	if err := connection.Create(ctx, namespace); err != nil {
		t.Fatal(err)
	}
	t.Logf("retained isolated namespace %s UID %s", namespace.Name, namespace.UID)
	contract := &api.EvidenceContract{ObjectMeta: metav1.ObjectMeta{Name: "current-evidence", Namespace: namespace.Name}, Spec: api.EvidenceContractSpec{
		Requirements:              []api.ContractRequirement{{ID: "current-observation", Type: "admission", Required: true, Freshness: metav1.Duration{Duration: time.Minute}, AcceptedProducers: []string{"local://ci-explicit-source"}}},
		OnMissingRequiredEvidence: api.MissingEvidencePolicy{State: "Unknown"},
	}}
	if err := connection.Create(ctx, contract); err != nil {
		t.Fatal(err)
	}
	binding := &api.ControlBinding{ObjectMeta: metav1.ObjectMeta{Name: "requires-evidence", Namespace: namespace.Name}, Spec: api.ControlBindingSpec{
		Controls:     []api.ControlBindingItem{{Canonical: api.CanonicalControlRef{Namespace: "example", ID: "current-observation"}}},
		Subjects:     api.SubjectSelector{Kinds: []string{"Pod"}},
		Requirements: []api.RequirementBinding{{ID: "current-observation", EvidenceContract: contract.Name, Implementations: []api.ImplementationBindingRef{}}},
	}}
	if err := connection.Create(ctx, binding); err != nil {
		t.Fatal(err)
	}
	controller := &reconcile.ControlBindingReconciler{Client: connection, Scheme: scheme, Log: ctrl.Log.WithName("real-api-ci-compatibility"), ClaimEvaluator: &reconcile.ContractEvaluator{}}
	key := client.ObjectKeyFromObject(binding)
	if _, err := controller.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	var observed api.ControlBinding
	if err := connection.Get(ctx, key, &observed); err != nil {
		t.Fatal(err)
	}
	if observed.UID == "" || observed.UID != binding.UID || observed.Status.ObservedGeneration != observed.Generation {
		t.Fatalf("status did not bind the actual API object: %+v", observed.Status)
	}
	for _, condition := range observed.Status.Conditions {
		if condition.Type == "Ready" {
			if condition.Status != metav1.ConditionFalse || condition.Reason != "UNKNOWN" {
				t.Fatalf("missing evidence acquired standing through the real API: %+v", condition)
			}
			t.Logf("actual status UID=%s generation=%d Ready=%s reason=%s", observed.UID, observed.Generation, condition.Status, condition.Reason)
			return
		}
	}
	t.Fatal("actual API status omitted Ready condition")
}
