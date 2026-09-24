package reconcile

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	assurancev1alpha1 "github.com/ckodex-labs/oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/oskal/core/assurance"
	"github.com/ckodex-labs/oskal/internal/ports"
)

// ControlBindingReconciler reconciles ControlBinding objects and updates AssuranceState projections.
type ControlBindingReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Log               logr.Logger
	ControlResolver   ports.ControlResolver
	SubjectResolver   ports.SubjectResolver
	ClaimEvaluator    ports.ClaimEvaluator
	EvidenceRepo      ports.EvidenceRepository
	ReceiptSigner     ports.ReceiptSigner
}

// +kubebuilder:rbac:groups=assurance.ckodex.io,resources=controlbindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=assurance.ckodex.io,resources=controlbindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=assurance.ckodex.io,resources=controlbindings/finalizers,verbs=update
// +kubebuilder:rbac:groups=assurance.ckodex.io,resources=assurancestates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=assurance.ckodex.io,resources=assurancestates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments;daemonsets;statefulsets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods;namespaces;serviceaccounts,verbs=get;list;watch

func (r *ControlBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("controlbinding", req.NamespacedName)

	var binding assurancev1alpha1.ControlBinding
	if err := r.Get(ctx, req.NamespacedName, &binding); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("ControlBinding resource not found; ignoring deleted object")
			return ctrl.Result{}, nil
		}
		log.Error(err, "unable to fetch ControlBinding")
		return ctrl.Result{}, err
	}

	log.Info("Reconciling ControlBinding", "controlsCount", len(binding.Spec.Controls), "requirementsCount", len(binding.Spec.Requirements))

	// Reconcile status conditions
	binding.Status.ObservedGeneration = binding.Generation
	metaCondition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "Reconciled",
		Message:            fmt.Sprintf("Binding configured with %d controls", len(binding.Spec.Controls)),
	}

	// Update condition in slice
	updated := false
	for i, c := range binding.Status.Conditions {
		if c.Type == metaCondition.Type {
			binding.Status.Conditions[i] = metaCondition
			updated = true
			break
		}
	}
	if !updated {
		binding.Status.Conditions = append(binding.Status.Conditions, metaCondition)
	}

	if err := r.Status().Update(ctx, &binding); err != nil {
		log.Error(err, "unable to update ControlBinding status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ControlBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&assurancev1alpha1.ControlBinding{}).
		Complete(r)
}

// AssuranceStateReconciler reconciles AssuranceState objects.
type AssuranceStateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

func (r *AssuranceStateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("assurancestate", req.NamespacedName)

	var state assurancev1alpha1.AssuranceState
	if err := r.Get(ctx, req.NamespacedName, &state); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	log.Info("Observed AssuranceState projection", "subject", state.Spec.SubjectRef.Name, "state", state.Status.State)
	return ctrl.Result{}, nil
}

func (r *AssuranceStateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&assurancev1alpha1.AssuranceState{}).
		Complete(r)
}

// DefaultMockEvaluator provides a default ClaimEvaluator satisfying ports.ClaimEvaluator for standalone testing.
type DefaultMockEvaluator struct{}

func (e *DefaultMockEvaluator) Evaluate(ctx context.Context, claim assurance.Claim, contract assurance.EvidenceContract, currentEpoch assurance.AssuranceEpoch) (assurance.ClaimEvaluation, error) {
	now := time.Now()
	res := contract.Evaluate(nil, currentEpoch, now)
	return assurance.ClaimEvaluation{
		ID:           fmt.Sprintf("eval-%s", claim.ID),
		Control:      claim.Control,
		Subject:      claim.Subject,
		State:        res.State,
		Vector:       assurance.NewDefaultAssuranceVector(),
		Epoch:        currentEpoch,
		Completeness: res.Completeness,
		EvaluatedAt:  now,
		ValidUntil:   now.Add(5 * time.Minute),
	}, nil
}
