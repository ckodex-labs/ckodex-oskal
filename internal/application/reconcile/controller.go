package reconcile

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/spire"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
)

// ControlBindingReconciler reconciles ControlBinding objects and updates AssuranceState projections.
type ControlBindingReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	Log             logr.Logger
	ControlResolver ports.ControlResolver
	SubjectResolver ports.SubjectResolver
	ClaimEvaluator  ports.ClaimEvaluator
	EvidenceRepo    ports.EvidenceRepository
	ReceiptSigner   ports.ReceiptSigner
	SVIDValidator   *spire.SVIDValidator
}

// +kubebuilder:rbac:groups=assurance.ckodex.io,resources=controlbindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=assurance.ckodex.io,resources=controlbindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=assurance.ckodex.io,resources=controlbindings/finalizers,verbs=update
// +kubebuilder:rbac:groups=assurance.ckodex.io,resources=assurancestates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=assurance.ckodex.io,resources=assurancestates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments;daemonsets;statefulsets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods;namespaces;serviceaccounts,verbs=get;list;watch

func (r *ControlBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ctx, span := telemetry.StartEvaluationSpan(ctx, req.Name, req.Namespace)
	defer span.End()

	timer := prometheus.NewTimer(telemetry.EvaluationDurationSeconds.WithLabelValues(req.Name))
	defer timer.ObserveDuration()

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

	// Detect generation drift if object was updated
	if binding.Status.ObservedGeneration != 0 && binding.Status.ObservedGeneration != binding.Generation {
		telemetry.RecordDriftInvalidation(binding.Name, "generation_drift")
	}

	// Determine honest assurance state via ClaimEvaluator
	targetState := assurance.AssuranceStateUnknown
	var evidenceRoot string
	var evalResult assurance.ClaimEvaluation

	if r.ClaimEvaluator != nil && len(binding.Spec.Controls) > 0 {
		ctrlRef := assurance.ControlRef{
			Namespace: binding.Spec.Controls[0].Canonical.Namespace,
			ID:        binding.Spec.Controls[0].Canonical.ID,
		}
		subRef := assurance.SubjectRef{
			Scheme: "k8s",
			ID:     fmt.Sprintf("%s/%s", binding.Namespace, binding.Name),
		}
		claim := assurance.Claim{
			ID:      fmt.Sprintf("claim-%s", binding.Name),
			Subject: subRef,
			Control: ctrlRef,
		}

		// Build contract from referenced EvidenceContract CRD or directly from binding requirements
		var contract assurance.EvidenceContract
		if len(binding.Spec.Requirements) > 0 && binding.Spec.Requirements[0].EvidenceContract != "" {
			var ecCRD assurancev1alpha1.EvidenceContract
			ecKey := client.ObjectKey{Namespace: binding.Namespace, Name: binding.Spec.Requirements[0].EvidenceContract}
			if err := r.Get(ctx, ecKey, &ecCRD); err == nil {
				var reqs []assurance.EvidenceRequirement
				for _, cr := range ecCRD.Spec.Requirements {
					maxAge := cr.Freshness.Duration
					if maxAge <= 0 {
						maxAge = 24 * time.Hour
					}
					reqs = append(reqs, assurance.EvidenceRequirement{
						ID:                cr.ID,
						EvidenceType:      cr.Type,
						Required:          cr.Required,
						MaxAge:            maxAge,
						AcceptedProducers: cr.AcceptedProducers,
					})
				}
				missingState := assurance.AssuranceStateUnknown
				if ecCRD.Spec.OnMissingRequiredEvidence.State == "Failed" {
					missingState = assurance.AssuranceStateFailed
				}
				contract = assurance.EvidenceContract{
					ID:                     ecCRD.Name,
					Requirements:           reqs,
					OnMissingRequiredState: missingState,
				}
			}
		}

		if len(contract.Requirements) == 0 {
			var reqs []assurance.EvidenceRequirement
			for _, req := range binding.Spec.Requirements {
				reqs = append(reqs, assurance.EvidenceRequirement{
					ID:           req.ID,
					EvidenceType: "admission",
					Required:     true,
					MaxAge:       24 * time.Hour,
				})
			}
			contract = assurance.EvidenceContract{
				ID:                     fmt.Sprintf("contract-%s", binding.Name),
				Requirements:           reqs,
				OnMissingRequiredState: assurance.AssuranceStateUnknown,
			}
		}

		currentEpoch := assurance.AssuranceEpoch{
			SubjectDigest: assurance.ComputeStringDigest(subRef.URI()),
		}

		if ce, ok := r.ClaimEvaluator.(*ContractEvaluator); ok && ce.EvidenceRepo == nil && r.EvidenceRepo != nil {
			ce.EvidenceRepo = r.EvidenceRepo
		}

		eval, err := r.ClaimEvaluator.Evaluate(ctx, claim, contract, currentEpoch)
		if err == nil {
			evalResult = eval
			targetState = eval.State
			if targetState == assurance.AssuranceStateVerified {
				targetState = assurance.AssuranceStateAssured
			}
			evidenceRoot = eval.EvidenceRoot
		}
	}

	// Reconcile status conditions
	binding.Status.ObservedGeneration = binding.Generation
	statusMsg := fmt.Sprintf("Binding configured with %d controls; evaluated state: %s", len(binding.Spec.Controls), targetState)
	if evidenceRoot != "" {
		statusMsg = fmt.Sprintf("%s; evidenceRoot: %s", statusMsg, evidenceRoot)
	}
	metaCondition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             targetState.String(),
		Message:            statusMsg,
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

	// Update any associated AssuranceState CRDs in this namespace
	var stateList assurancev1alpha1.AssuranceStateList
	if err := r.List(ctx, &stateList, client.InNamespace(binding.Namespace)); err == nil {
		cleanBindingName := strings.TrimSuffix(binding.Name, "-binding")
		for _, item := range stateList.Items {
			if item.Spec.SubjectRef.Name == binding.Name ||
				item.Spec.SubjectRef.Name == cleanBindingName ||
				item.Name == binding.Name ||
				item.Name == cleanBindingName ||
				item.Name == cleanBindingName+"-state" {
				stateCopy := item
				stateCopy.Status.State = targetState.String()
				stateCopy.Status.EvidenceRoot = evidenceRoot
				if !evalResult.EvaluatedAt.IsZero() {
					stateCopy.Status.EvaluatedAt = &metav1.Time{Time: evalResult.EvaluatedAt}
					stateCopy.Status.ValidUntil = &metav1.Time{Time: evalResult.ValidUntil}
					stateCopy.Status.Epoch = assurancev1alpha1.StateEpoch{
						Subject:        evalResult.Epoch.SubjectDigest,
						Policy:         evalResult.Epoch.PolicyDigest,
						Implementation: evalResult.Epoch.ImplementationDigest,
						Authority:      evalResult.Epoch.AuthorityDigest,
						Environment:    evalResult.Epoch.EnvironmentDigest,
						Composite:      evalResult.Epoch.CompositeDigest(),
					}
				}
				var ctrlStatuses []assurancev1alpha1.ControlStatus
				for _, c := range binding.Spec.Controls {
					ctrlStatuses = append(ctrlStatuses, assurancev1alpha1.ControlStatus{
						ID:              c.Canonical.ID,
						State:           targetState.String(),
						EvidenceSummary: fmt.Sprintf("Verified %d/%d requirements", evalResult.Completeness.Verified, evalResult.Completeness.Required),
					})
				}
				stateCopy.Status.Controls = ctrlStatuses
				_ = r.Status().Update(ctx, &stateCopy)
			}
		}
	}

	// Emit truthful telemetry metrics reflecting verified state (never fabricated PASS)
	telemetry.RecordAssuranceState(binding.Namespace, binding.Name, targetState.String(), fmt.Sprintf("%d", binding.Generation), true)

	if r.ReceiptSigner != nil && targetState == assurance.AssuranceStateAssured {
		telemetry.RecordReceiptIssued(binding.Name, "VALID")
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
	telemetry.RecordAssuranceState(state.Namespace, state.Name, string(state.Status.State), fmt.Sprintf("%d", state.Generation), true)
	return ctrl.Result{}, nil
}

func (r *AssuranceStateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&assurancev1alpha1.AssuranceState{}).
		Complete(r)
}

// ContractEvaluator provides deterministic claim evaluation satisfying ports.ClaimEvaluator.
type ContractEvaluator struct {
	EvidenceSource []assurance.EvidenceEnvelope
	EvidenceRepo   ports.EvidenceRepository
}

func (e *ContractEvaluator) Evaluate(ctx context.Context, claim assurance.Claim, contract assurance.EvidenceContract, currentEpoch assurance.AssuranceEpoch) (assurance.ClaimEvaluation, error) {
	now := time.Now().UTC()
	source := e.EvidenceSource
	if len(source) == 0 && e.EvidenceRepo != nil {
		if envs, err := e.EvidenceRepo.ListBySubject(ctx, claim.Subject); err == nil {
			source = envs
		}
	}
	res := contract.Evaluate(source, currentEpoch, now)

	vec := assurance.NewDefaultAssuranceVector()
	var evidenceRefs []assurance.EvidenceRef
	var evidenceDigests []string

	for _, v := range res.VerifiedEvidences {
		ref := assurance.EvidenceRef{
			URI:       v.Artifact.URI,
			Digest:    v.Artifact.Digest,
			MediaType: v.Artifact.MediaType,
		}
		evidenceRefs = append(evidenceRefs, ref)
		if v.Artifact.Digest != "" {
			evidenceDigests = append(evidenceDigests, v.Artifact.Digest)
		} else if v.ID != "" {
			evidenceDigests = append(evidenceDigests, assurance.ComputeStringDigest(v.ID))
		}
	}

	evidenceRoot := ""
	if len(evidenceDigests) > 0 {
		evidenceRoot = assurance.CanonicalDigestList(evidenceDigests)
	}

	switch res.State {
	case assurance.AssuranceStateAssured, assurance.AssuranceStateVerified:
		vec.Applicability = assurance.ValencePositive
		vec.Conformance = assurance.ValencePositive
		vec.Completeness = assurance.ValencePositive
		vec.Freshness = assurance.ValencePositive
	case assurance.AssuranceStateFailed:
		vec.Conformance = assurance.ValenceNegative
		vec.Coherence = assurance.CoherenceDecoherent
	}

	return assurance.ClaimEvaluation{
		ID:           fmt.Sprintf("eval-%s", claim.ID),
		Control:      claim.Control,
		Subject:      claim.Subject,
		State:        res.State,
		Vector:       vec,
		Epoch:        currentEpoch,
		Evidence:     evidenceRefs,
		Completeness: res.Completeness,
		EvidenceRoot: evidenceRoot,
		EvaluatedAt:  now,
		ValidUntil:   now.Add(5 * time.Minute),
	}, nil
}
