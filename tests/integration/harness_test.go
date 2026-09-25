package integration

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/reconcile"
)

func TestControllerReconciliationHarness(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add client-go scheme: %v", err)
	}
	if err := assurancev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add assurance scheme: %v", err)
	}

	binding := &assurancev1alpha1.ControlBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "restricted-container",
			Namespace: "payments",
		},
		Spec: assurancev1alpha1.ControlBindingSpec{
			Controls: []assurancev1alpha1.ControlBindingItem{
				{
					Canonical: assurancev1alpha1.CanonicalControlRef{
						Namespace: "ckodex",
						ID:        "container.least-privilege",
					},
					Mappings: []assurancev1alpha1.FrameworkMapping{
						{Framework: "nist-sp-800-53", Control: "AC-6"},
					},
				},
			},
			Subjects: assurancev1alpha1.SubjectSelector{
				Kinds: []string{"Deployment"},
			},
			Requirements: []assurancev1alpha1.RequirementBinding{
				{
					ID: "non-root",
					Implementations: []assurancev1alpha1.ImplementationBindingRef{
						{
							Purpose:  "preventive",
							Provider: "kubernetes-validating-admission",
							Ref: assurancev1alpha1.ImplementationTargetRef{
								Name: "workloads-non-root",
							},
						},
					},
					EvidenceContract: "workload-least-privilege",
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&assurancev1alpha1.ControlBinding{}, &assurancev1alpha1.AssuranceState{}).
		WithObjects(binding).
		Build()

	reconciler := &reconcile.ControlBindingReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		Log:            ctrl.Log.WithName("test-controller"),
		ClaimEvaluator: &reconcile.ContractEvaluator{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "restricted-container",
			Namespace: "payments",
		},
	}

	res, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	if res.RequeueAfter != 5*time.Minute {
		t.Errorf("expected RequeueAfter to be 5m, got %v", res.RequeueAfter)
	}

	// Verify status updated with condition
	var updatedBinding assurancev1alpha1.ControlBinding
	if err := fakeClient.Get(ctx, req.NamespacedName, &updatedBinding); err != nil {
		t.Fatalf("failed to get updated binding: %v", err)
	}

	if len(updatedBinding.Status.Conditions) == 0 {
		t.Fatalf("expected Ready condition on updated binding status")
	}

	readyCond := updatedBinding.Status.Conditions[0]
	if readyCond.Type != "Ready" || readyCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Ready=True condition, got %v", readyCond)
	}
}

func TestAssuranceStateReconcilerHarness(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = assurancev1alpha1.AddToScheme(scheme)

	state := &assurancev1alpha1.AssuranceState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "payments-api",
			Namespace: "payments",
		},
		Spec: assurancev1alpha1.AssuranceStateSpec{
			SubjectRef: assurancev1alpha1.StateSubjectRef{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       "payments-api",
			},
		},
		Status: assurancev1alpha1.AssuranceStateStatus{
			State: "Assured",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(state).
		Build()

	reconciler := &reconcile.AssuranceStateReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Log:    ctrl.Log.WithName("test-state-controller"),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "payments-api",
			Namespace: "payments",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("state reconciler failed: %v", err)
	}
}

func TestContractEvaluatorHonestAssurance(t *testing.T) {
	evaluator := &reconcile.ContractEvaluator{}
	claim := assurance.Claim{
		ID:      "claim-01",
		Subject: assurance.SubjectRef{Scheme: "k8s", ID: "payments/Deployment/payments-api"},
		Control: assurance.ControlRef{Namespace: "ckodex", ID: "container.least-privilege"},
	}
	contract := assurance.EvidenceContract{
		ID: "contract-01",
		Requirements: []assurance.EvidenceRequirement{
			{ID: "req-1", EvidenceType: "admission", Required: true},
		},
		OnMissingRequiredState: assurance.AssuranceStateUnknown,
	}
	epoch := assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeStringDigest("payments/Deployment/payments-api")}

	eval, err := evaluator.Evaluate(context.Background(), claim, contract, epoch)
	if err != nil {
		t.Fatalf("evaluator failed: %v", err)
	}

	if eval.State != assurance.AssuranceStateUnknown {
		t.Fatalf("expected state UNKNOWN for empty evidence, got %s", eval.State)
	}
}
