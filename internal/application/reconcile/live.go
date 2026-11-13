package reconcile

import (
	"context"
	"fmt"
	"time"

	api "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// LiveControlReconciler publishes evaluations of real, coherently resolved
// Kubernetes bindings. It never substitutes a guessed subject or contract.
type LiveControlReconciler struct {
	Client    client.Client
	Reader    client.Reader
	Scheme    *runtime.Scheme
	Resolver  *binding.Resolver
	Evaluator ports.ClaimEvaluator
	Signer    ports.ReceiptSigner
	Receipts  ports.ReceiptRepository
	Interval  time.Duration
}

func (r *LiveControlReconciler) Reconcile(parent context.Context, req ctrl.Request) (ctrl.Result, error) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	if r.Client == nil || r.Reader == nil || r.Resolver == nil || r.Evaluator == nil || r.Signer == nil || r.Receipts == nil || r.Interval <= 0 {
		return ctrl.Result{}, fmt.Errorf("live evaluation requires an authoritative reader, binding resolver, verifier, durable receipt store and positive interval")
	}
	var object api.ControlBinding
	if err := r.Reader.Get(ctx, req.NamespacedName, &object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	resolved, err := r.Resolver.ContextForBinding(ctx, req.Namespace, req.Name)
	if err != nil {
		if statusErr := r.publishUnknown(ctx, &object, err.Error()); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		return ctrl.Result{RequeueAfter: r.Interval}, nil
	}
	if resolved.BindingUID != object.UID || len(resolved.Controls) == 0 || len(resolved.Controls) > 256 {
		return ctrl.Result{}, fmt.Errorf("binding changed or exceeds the 256-control evaluation bound; re-read the binding")
	}
	state := assurance.AssuranceStateAssured
	var summaryEvidence []assurance.EvidenceRef
	var evaluations []assurance.ClaimEvaluation
	var controls []api.ControlStatus
	for _, control := range resolved.Controls {
		claim := assurance.Claim{ID: string(object.UID) + "/" + control.Canonical(), Subject: resolved.Subject, Control: control}
		evaluation, err := r.Evaluator.Evaluate(ctx, claim, resolved.Contract, resolved.Epoch)
		if err != nil {
			if statusErr := r.publishUnknown(ctx, &object, "evaluation failed: "+err.Error()); statusErr != nil {
				return ctrl.Result{}, statusErr
			}
			return ctrl.Result{RequeueAfter: r.Interval}, nil
		}
		if evaluation.State == assurance.AssuranceStateVerified {
			evaluation.State = assurance.AssuranceStateAssured
		}
		state = combineLiveStates(state, evaluation.State)
		summaryEvidence = append(summaryEvidence, evaluation.Evidence...)
		receipt := assurance.ControlReceipt{Subject: resolved.Subject, Control: control, State: evaluation.State, Epoch: evaluation.Epoch, EvidenceRoot: evaluation.EvidenceRoot, EvaluatedAt: evaluation.EvaluatedAt}
		signed, err := r.Signer.SignReceipt(ctx, receipt)
		if err != nil {
			return ctrl.Result{}, r.receiptFailure(ctx, &object, err)
		}
		reference, err := r.Receipts.PutReceipt(ctx, signed)
		if err != nil {
			return ctrl.Result{}, r.receiptFailure(ctx, &object, err)
		}
		controls = append(controls, api.ControlStatus{ID: control.ID, State: evaluation.State.String(), EvidenceSummary: evaluation.Completeness.Summary(), ReceiptRef: reference, Completeness: evaluation.Completeness})
		evaluations = append(evaluations, evaluation)
	}
	root := ""
	if state == assurance.AssuranceStateAssured {
		root = receipts.ComputeEvidenceRoot(summaryEvidence)
	}
	if err := r.publish(ctx, &object, resolved, state, root, controls, evaluations); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: r.Interval}, nil
}

func combineLiveStates(current, next assurance.AssuranceState) assurance.AssuranceState {
	if current == assurance.AssuranceStateFailed || next == assurance.AssuranceStateFailed {
		return assurance.AssuranceStateFailed
	}
	if current == assurance.AssuranceStateUnknown || next == assurance.AssuranceStateUnknown || next == assurance.AssuranceStateUnspecified {
		return assurance.AssuranceStateUnknown
	}
	if current == assurance.AssuranceStateStale || next == assurance.AssuranceStateStale {
		return assurance.AssuranceStateStale
	}
	if next != assurance.AssuranceStateAssured && next != assurance.AssuranceStateVerified {
		return assurance.AssuranceStateUnknown
	}
	return current
}

func (r *LiveControlReconciler) receiptFailure(ctx context.Context, object *api.ControlBinding, cause error) error {
	if err := r.publishUnknown(ctx, object, "durable receipt failed: "+cause.Error()); err != nil {
		return fmt.Errorf("receipt failed: %v; publishing UNKNOWN also failed: %w", cause, err)
	}
	return fmt.Errorf("persist evaluation receipt before publishing standing: %w", cause)
}

func (r *LiveControlReconciler) condition(ctx context.Context, object *api.ControlBinding, state assurance.AssuranceState, reason string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var latest api.ControlBinding
		if err := r.Reader.Get(ctx, client.ObjectKeyFromObject(object), &latest); err != nil {
			return err
		}
		if latest.UID != object.UID || latest.Generation != object.Generation {
			return fmt.Errorf("binding identity or generation changed during evaluation")
		}
		ready := metav1.ConditionFalse
		if state == assurance.AssuranceStateAssured {
			ready = metav1.ConditionTrue
		}
		latest.Status.ObservedGeneration = object.Generation
		latest.Status.Conditions = upsertCondition(latest.Status.Conditions, metav1.Condition{Type: "Ready", Status: ready, Reason: state.String(), Message: reason, ObservedGeneration: object.Generation, LastTransitionTime: metav1.Now()})
		return r.Client.Status().Update(ctx, &latest)
	})
}

func (r *LiveControlReconciler) publishUnknown(ctx context.Context, object *api.ControlBinding, reason string) error {
	if err := r.condition(ctx, object, assurance.AssuranceStateUnknown, reason); err != nil {
		return err
	}
	var states api.AssuranceStateList
	if err := r.Reader.List(ctx, &states, client.InNamespace(object.Namespace), client.MatchingLabels{"assurance.ckodex.io/binding-uid": string(object.UID)}, client.Limit(257)); err != nil {
		return err
	}
	if len(states.Items) > 256 || states.Continue != "" {
		return fmt.Errorf("associated assurance states exceed the 256-object bound")
	}
	for _, state := range states.Items {
		key := client.ObjectKeyFromObject(&state)
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var latest api.AssuranceState
			if err := r.Reader.Get(ctx, key, &latest); err != nil {
				return err
			}
			latest.Status.State = assurance.AssuranceStateUnknown.String()
			latest.Status.EvidenceRoot = ""
			for i := range latest.Status.Controls {
				latest.Status.Controls[i].State = assurance.AssuranceStateUnknown.String()
				latest.Status.Controls[i].EvidenceSummary = reason
				latest.Status.Controls[i].ReceiptRef = ""
				latest.Status.Controls[i].Completeness = assurance.EvidenceCompleteness{Required: latest.Status.Controls[i].Completeness.Required, Missing: latest.Status.Controls[i].Completeness.Required}
			}
			latest.Status.ValidUntil = nil
			latest.Status.Epoch = api.StateEpoch{}
			latest.Status.EvaluatedAt = &metav1.Time{Time: time.Now().UTC()}
			return r.Client.Status().Update(ctx, &latest)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (r *LiveControlReconciler) publish(ctx context.Context, object *api.ControlBinding, resolved binding.Context, standing assurance.AssuranceState, root string, controls []api.ControlStatus, evaluations []assurance.ClaimEvaluation) error {
	key := client.ObjectKey{Namespace: object.Namespace, Name: object.Name}
	var state api.AssuranceState
	if err := r.Reader.Get(ctx, key, &state); err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		state.ObjectMeta = metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name, Labels: map[string]string{"assurance.ckodex.io/binding-uid": string(object.UID)}}
		state.Spec.SubjectRef = stateSubject(resolved.Subject)
		if err := controllerutil.SetControllerReference(object, &state, r.Scheme); err != nil {
			return err
		}
		if err := r.Client.Create(ctx, &state); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var latest api.AssuranceState
		if err := r.Reader.Get(ctx, key, &latest); err != nil {
			return err
		}
		if latest.Labels["assurance.ckodex.io/binding-uid"] != string(object.UID) {
			return fmt.Errorf("assurance state is owned by a different binding; inspect it before replacement")
		}
		if latest.Spec.SubjectRef != stateSubject(resolved.Subject) {
			latest.Spec.SubjectRef = stateSubject(resolved.Subject)
			if err := r.Client.Update(ctx, &latest); err != nil {
				return err
			}
		}
		latest.Status.State = standing.String()
		latest.Status.EvidenceRoot = root
		latest.Status.Controls = controls
		latest.Status.Epoch = api.StateEpoch{Subject: resolved.Epoch.SubjectDigest, Policy: resolved.Epoch.PolicyDigest, Implementation: resolved.Epoch.ImplementationDigest, Authority: resolved.Epoch.AuthorityDigest, Environment: resolved.Epoch.EnvironmentDigest, Composite: resolved.Epoch.CompositeDigest()}
		latest.Status.EvaluatedAt = nil
		latest.Status.ValidUntil = nil
		for _, evaluation := range evaluations {
			if latest.Status.EvaluatedAt == nil || evaluation.EvaluatedAt.Before(latest.Status.EvaluatedAt.Time) {
				latest.Status.EvaluatedAt = &metav1.Time{Time: evaluation.EvaluatedAt}
			}
			if !evaluation.ValidUntil.IsZero() && (latest.Status.ValidUntil == nil || evaluation.ValidUntil.Before(latest.Status.ValidUntil.Time)) {
				latest.Status.ValidUntil = &metav1.Time{Time: evaluation.ValidUntil}
			}
		}
		return r.Client.Status().Update(ctx, &latest)
	}); err != nil {
		return err
	}
	return r.condition(ctx, object, standing, "Resolved current workload, policy and evidence; "+standing.String())
}

func stateSubject(subject assurance.SubjectRef) api.StateSubjectRef {
	version := "v1"
	if subject.Attributes["kind"] == "Deployment" {
		version = "apps/v1"
	}
	return api.StateSubjectRef{APIVersion: version, Kind: subject.Attributes["kind"], Namespace: subject.Attributes["namespace"], Name: subject.Attributes["name"], UID: subject.Attributes["uid"]}
}

func (r *LiveControlReconciler) SetupWithManager(manager ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(manager).For(&api.ControlBinding{}).Complete(r)
}
