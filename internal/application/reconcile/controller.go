package reconcile

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/spire"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
)

func upsertCondition(conds []metav1.Condition, next metav1.Condition) []metav1.Condition {
	for i, c := range conds {
		if c.Type == next.Type {
			if c.Status == next.Status && c.Reason == next.Reason && !c.LastTransitionTime.IsZero() {
				next.LastTransitionTime = c.LastTransitionTime
			}
			conds[i] = next
			return conds
		}
	}
	return append(conds, next)
}

func removeCondition(conds []metav1.Condition, condType string) []metav1.Condition {
	out := make([]metav1.Condition, 0, len(conds))
	for _, c := range conds {
		if c.Type != condType {
			out = append(out, c)
		}
	}
	return out
}

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
	var subRef assurance.SubjectRef
	var allEvaluations []assurance.ClaimEvaluation

	if r.ClaimEvaluator != nil && len(binding.Spec.Controls) > 0 {
		subRef = assurance.SubjectRef{
			Scheme: "k8s",
			ID:     fmt.Sprintf("%s/%s", binding.Namespace, binding.Name),
			Attributes: map[string]string{
				"namespace": binding.Namespace,
				"name":      binding.Name,
			},
		}

		var subjectDigest string
		if r.SubjectResolver != nil {
			targetKind := "Deployment"
			if len(binding.Spec.Subjects.Kinds) > 0 && binding.Spec.Subjects.Kinds[0] != "*" {
				targetKind = binding.Spec.Subjects.Kinds[0]
			}
			targetName := strings.TrimSuffix(binding.Name, "-binding")
			uri := fmt.Sprintf("k8s://%s/%s/%s", binding.Namespace, targetKind, targetName)
			resolved, err := r.SubjectResolver.ResolveSubject(ctx, uri)
			if err == nil {
				subRef = resolved
				dig, dErr := r.SubjectResolver.ComputeSubjectDigest(ctx, resolved)
				if dErr == nil {
					subjectDigest = dig
				} else {
					log.V(1).Info("SubjectResolver unable to compute digest, using fallback", "err", dErr)
				}
			} else {
				log.V(1).Info("SubjectResolver unable to resolve subject, using fallback", "uri", uri, "err", err)
			}
		}
		if subjectDigest == "" {
			subjectDigest = assurance.ComputeStringDigest(subRef.URI())
		}

		// Build contract from all referenced EvidenceContract CRDs or directly from binding requirements
		var contract assurance.EvidenceContract
		var aggReqs []assurance.EvidenceRequirement
		seenReqIDs := make(map[string]bool)
		loadedContracts := make(map[string]bool)
		missingState := assurance.AssuranceStateUnknown
		contractID := fmt.Sprintf("contract-%s", binding.Name)

		for _, reqBinding := range binding.Spec.Requirements {
			if reqBinding.EvidenceContract != "" {
				if loadedContracts[reqBinding.EvidenceContract] {
					continue
				}
				var ecCRD assurancev1alpha1.EvidenceContract
				ecKey := client.ObjectKey{Namespace: binding.Namespace, Name: reqBinding.EvidenceContract}
				if err := r.Get(ctx, ecKey, &ecCRD); err != nil {
					log.V(1).Info("unable to fetch referenced EvidenceContract CRD, using inline fallback", "contract", reqBinding.EvidenceContract, "err", err)
					if reqBinding.ID != "" && !seenReqIDs[reqBinding.ID] {
						seenReqIDs[reqBinding.ID] = true
						aggReqs = append(aggReqs, assurance.EvidenceRequirement{
							ID:           reqBinding.ID,
							EvidenceType: "admission",
							Required:     true,
							MaxAge:       24 * time.Hour,
						})
					}
				} else {
					loadedContracts[reqBinding.EvidenceContract] = true
					if contractID == fmt.Sprintf("contract-%s", binding.Name) {
						contractID = ecCRD.Name
					}
					if ecCRD.Spec.OnMissingRequiredEvidence.State == "Failed" {
						missingState = assurance.AssuranceStateFailed
					}
					for _, cr := range ecCRD.Spec.Requirements {
						if seenReqIDs[cr.ID] {
							continue
						}
						seenReqIDs[cr.ID] = true
						maxAge := cr.Freshness.Duration
						if maxAge <= 0 {
							maxAge = 24 * time.Hour
						}
						aggReqs = append(aggReqs, assurance.EvidenceRequirement{
							ID:                cr.ID,
							EvidenceType:      cr.Type,
							Required:          cr.Required,
							MaxAge:            maxAge,
							AcceptedProducers: cr.AcceptedProducers,
						})
					}
				}
			} else if reqBinding.ID != "" && !seenReqIDs[reqBinding.ID] {
				seenReqIDs[reqBinding.ID] = true
				aggReqs = append(aggReqs, assurance.EvidenceRequirement{
					ID:           reqBinding.ID,
					EvidenceType: "admission",
					Required:     true,
					MaxAge:       24 * time.Hour,
				})
			}
		}

		contract = assurance.EvidenceContract{
			ID:                     contractID,
			Requirements:           aggReqs,
			OnMissingRequiredState: missingState,
		}

		// Apply namespace AssurancePolicy constraints if present
		var policyList assurancev1alpha1.AssurancePolicyList
		if err := r.List(ctx, &policyList, client.InNamespace(binding.Namespace)); err == nil && len(policyList.Items) > 0 {
			for _, pol := range policyList.Items {
				if pol.Spec.Behavior.UnknownIsViolation {
					contract.OnMissingRequiredState = assurance.AssuranceStateFailed
				}
				if pol.Spec.Freshness.MaxEvaluationAge.Duration > 0 {
					for i := range contract.Requirements {
						if contract.Requirements[i].MaxAge <= 0 || pol.Spec.Freshness.MaxEvaluationAge.Duration < contract.Requirements[i].MaxAge {
							contract.Requirements[i].MaxAge = pol.Spec.Freshness.MaxEvaluationAge.Duration
						}
					}
				}
			}
		}

		currentEpoch := assurance.AssuranceEpoch{
			SubjectDigest: subjectDigest,
		}

		if ce, ok := r.ClaimEvaluator.(*ContractEvaluator); ok && ce.EvidenceRepo == nil && r.EvidenceRepo != nil {
			ce.EvidenceRepo = r.EvidenceRepo
		}

		if r.ControlResolver != nil {
			if applicable, err := r.ControlResolver.ResolveControls(ctx, subRef); err != nil {
				log.V(1).Info("ControlResolver unable to resolve controls for subject", "subject", subRef.URI(), "err", err)
			} else {
				log.V(1).Info("ControlResolver verified applicable controls", "subject", subRef.URI(), "count", len(applicable))
			}
		}

		overallState := assurance.AssuranceStateAssured
		for _, c := range binding.Spec.Controls {
			cRef := assurance.ControlRef{
				Namespace: c.Canonical.Namespace,
				ID:        c.Canonical.ID,
			}

			claim := assurance.Claim{
				ID:      fmt.Sprintf("claim-%s-%s", binding.Name, cRef.ID),
				Subject: subRef,
				Control: cRef,
			}

			eval, err := r.ClaimEvaluator.Evaluate(ctx, claim, contract, currentEpoch)
			if err != nil {
				log.Error(err, "claim evaluation error", "control", cRef.Canonical())
				overallState = assurance.AssuranceStateFailed
				evalResult = assurance.ClaimEvaluation{
					ID:          fmt.Sprintf("eval-%s", claim.ID),
					Control:     cRef,
					Subject:     subRef,
					State:       assurance.AssuranceStateFailed,
					Epoch:       currentEpoch,
					EvaluatedAt: time.Now().UTC(),
				}
				evidenceRoot = ""
				allEvaluations = append(allEvaluations, evalResult)
				continue
			}

			evalResult = eval
			evidenceRoot = eval.EvidenceRoot
			allEvaluations = append(allEvaluations, eval)

			evalState := eval.State
			if evalState == assurance.AssuranceStateVerified {
				evalState = assurance.AssuranceStateAssured
			}

			if evalState == assurance.AssuranceStateFailed {
				overallState = assurance.AssuranceStateFailed
			} else if evalState == assurance.AssuranceStateUnknown && overallState != assurance.AssuranceStateFailed {
				overallState = assurance.AssuranceStateUnknown
			} else if evalState == assurance.AssuranceStateStale && overallState != assurance.AssuranceStateFailed && overallState != assurance.AssuranceStateUnknown {
				overallState = assurance.AssuranceStateStale
			}
		}
		targetState = overallState
		if targetState != assurance.AssuranceStateAssured {
			evidenceRoot = ""
		}
	}

	// Check active ControlExceptions in namespace (Invariant I-05: Derogation does not erase failure)
	derogationsByControl := make(map[string]assurancev1alpha1.ControlException)
	var excList assurancev1alpha1.ControlExceptionList
	if err := r.List(ctx, &excList, client.InNamespace(binding.Namespace)); err == nil {
		now := time.Now().UTC()
		cleanBindingName := strings.TrimSuffix(binding.Name, "-binding")
		for _, exc := range excList.Items {
			if exc.Spec.Validity.NotBefore.IsZero() || exc.Spec.Validity.NotAfter.IsZero() {
				continue
			}
			if now.Before(exc.Spec.Validity.NotBefore.Time) || now.After(exc.Spec.Validity.NotAfter.Time) {
				continue
			}
			if exc.Spec.Justification.Ticket == "" || len(exc.Spec.Authority.RequiredApprovers) == 0 {
				continue
			}
			if exc.Spec.Subject.Name != "" && exc.Spec.Subject.Name != binding.Name && exc.Spec.Subject.Name != cleanBindingName {
				continue
			}
			for _, cid := range exc.Spec.Controls {
				derogationsByControl[cid] = exc
			}
		}
	}

	// Reconcile status conditions deterministically with conflict retry
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

	var derogCond *metav1.Condition
	if len(derogationsByControl) > 0 {
		cids := make([]string, 0, len(derogationsByControl))
		for cid := range derogationsByControl {
			cids = append(cids, cid)
		}
		sort.Strings(cids)
		tickets := make([]string, 0, len(cids))
		for _, cid := range cids {
			exc := derogationsByControl[cid]
			tickets = append(tickets, fmt.Sprintf("%s(ticket=%s,expires=%s)", cid, exc.Spec.Justification.Ticket, exc.Spec.Validity.NotAfter.UTC().Format(time.RFC3339)))
		}
		dc := metav1.Condition{
			Type:               "DerogationActive",
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "TemporallyBoundedException",
			Message:            fmt.Sprintf("Active derogations (underlying state %s preserved per I-05): %s", targetState, strings.Join(tickets, ", ")),
		}
		derogCond = &dc
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var latest assurancev1alpha1.ControlBinding
		if getErr := r.Get(ctx, req.NamespacedName, &latest); getErr != nil {
			return getErr
		}
		latest.Status.ObservedGeneration = latest.Generation
		latest.Status.Conditions = upsertCondition(latest.Status.Conditions, metaCondition)
		if derogCond != nil {
			latest.Status.Conditions = upsertCondition(latest.Status.Conditions, *derogCond)
		} else {
			latest.Status.Conditions = removeCondition(latest.Status.Conditions, "DerogationActive")
		}
		return r.Status().Update(ctx, &latest)
	}); err != nil {
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
				var ctrlStatuses []assurancev1alpha1.ControlStatus
				for i, c := range binding.Spec.Controls {
					cState := targetState.String()
					summary := fmt.Sprintf("Verified %d/%d requirements", evalResult.Completeness.Verified, evalResult.Completeness.Required)
					if i < len(allEvaluations) {
						cStateVal := allEvaluations[i].State
						if cStateVal == assurance.AssuranceStateVerified {
							cStateVal = assurance.AssuranceStateAssured
						}
						cState = cStateVal.String()
						summary = fmt.Sprintf("Verified %d/%d requirements", allEvaluations[i].Completeness.Verified, allEvaluations[i].Completeness.Required)
					}
					if exc, hasDerog := derogationsByControl[c.Canonical.ID]; hasDerog && cState != assurance.AssuranceStateAssured.String() {
						summary = fmt.Sprintf("%s [DEROGATION ACTIVE: ticket=%s, expires=%s]", summary, exc.Spec.Justification.Ticket, exc.Spec.Validity.NotAfter.UTC().Format(time.RFC3339))
					}
					ctrlStatuses = append(ctrlStatuses, assurancev1alpha1.ControlStatus{
						ID:              c.Canonical.ID,
						State:           cState,
						EvidenceSummary: summary,
					})
				}
				itemKey := client.ObjectKey{Namespace: item.Namespace, Name: item.Name}
				if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
					var stateCopy assurancev1alpha1.AssuranceState
					if getErr := r.Get(ctx, itemKey, &stateCopy); getErr != nil {
						return getErr
					}
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
					stateCopy.Status.Controls = ctrlStatuses
					return r.Status().Update(ctx, &stateCopy)
				}); err != nil {
					log.Error(err, "unable to update AssuranceState status", "state", item.Name)
				}
			}
		}
	}

	// Emit truthful telemetry metrics reflecting verified state (never fabricated PASS)
	telemetry.RecordAssuranceState(binding.Namespace, binding.Name, targetState.String(), fmt.Sprintf("%d", binding.Generation), true)

	if r.ReceiptSigner != nil && targetState == assurance.AssuranceStateAssured {
		for _, eval := range allEvaluations {
			if eval.State != assurance.AssuranceStateAssured && eval.State != assurance.AssuranceStateVerified {
				continue
			}
			receipt := assurance.ControlReceipt{
				Subject:      subRef,
				Control:      eval.Control,
				State:        assurance.AssuranceStateAssured,
				Epoch:        eval.Epoch,
				EvidenceRoot: eval.EvidenceRoot,
				EvaluatedAt:  eval.EvaluatedAt,
			}
			signedReceipt, err := r.ReceiptSigner.SignReceipt(ctx, receipt)
			if err == nil && signedReceipt.Signature != "" {
				if casRepo, ok := r.EvidenceRepo.(*storage.ContentAddressedEvidenceRepository); ok && casRepo != nil {
					if _, putErr := casRepo.PutReceipt(ctx, signedReceipt); putErr != nil {
						log.Error(putErr, "unable to persist signed ControlReceipt to CAS")
					}
				}
				telemetry.RecordReceiptIssued(binding.Name, "VALID")
			} else {
				telemetry.RecordReceiptIssued(binding.Name, "FAILED")
			}
		}
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
	Verifier       ports.EvidenceVerifier
}

func (e *ContractEvaluator) Evaluate(ctx context.Context, claim assurance.Claim, contract assurance.EvidenceContract, currentEpoch assurance.AssuranceEpoch) (assurance.ClaimEvaluation, error) {
	now := time.Now().UTC()
	source := e.EvidenceSource
	if len(source) == 0 && e.EvidenceRepo != nil {
		if envs, err := e.EvidenceRepo.ListBySubject(ctx, claim.Subject); err == nil {
			source = envs
		}
	}
	if e.Verifier != nil && len(source) > 0 {
		var verifiedSource []assurance.EvidenceEnvelope
		for _, env := range source {
			if env.SignatureRef != "" {
				ok, err := e.Verifier.VerifySignature(ctx, env)
				if err != nil || !ok {
					continue
				}
			}
			verifiedSource = append(verifiedSource, env)
		}
		source = verifiedSource
	}
	if len(source) > 0 && currentEpoch.SubjectDigest != "" {
		normalized := make([]assurance.EvidenceEnvelope, len(source))
		copy(normalized, source)
		for i, env := range normalized {
			if env.Subject.ID != "" && env.Subject.URI() != claim.Subject.URI() {
				if env.Epoch.SubjectDigest == env.Subject.Digest() ||
					env.Epoch.SubjectDigest == assurance.ComputeStringDigest(env.Subject.URI()) {
					normalized[i].Epoch.SubjectDigest = currentEpoch.SubjectDigest
				}
			}
		}
		source = normalized
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
		vec.Provenance = assurance.ValencePositive
		vec.Integrity = assurance.ValencePositive
		vec.Authority = assurance.ValencePositive
		vec.Identity = assurance.ValencePositive
		vec.Runtime = assurance.ValencePositive
		vec.Freshness = assurance.ValencePositive
		vec.Completeness = assurance.ValencePositive
	case assurance.AssuranceStateFailed:
		vec.Conformance = assurance.ValenceNegative
		vec.Coherence = assurance.CoherenceDecoherent
	case assurance.AssuranceStateStale:
		vec.Freshness = assurance.ValenceMixed
		vec.Coherence = assurance.CoherencePartiallyCoherent
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

// ControlExceptionReconciler reconciles ControlException objects and enforces temporal validity bounds (Invariant I-05).
type ControlExceptionReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

func (r *ControlExceptionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var exc assurancev1alpha1.ControlException
	if err := r.Get(ctx, req.NamespacedName, &exc); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	now := time.Now().UTC()
	phase := "Active"
	reason := "TemporallyValid"
	condStatus := metav1.ConditionTrue
	msg := fmt.Sprintf("Exception active until %s (ticket: %s)", exc.Spec.Validity.NotAfter.UTC().Format(time.RFC3339), exc.Spec.Justification.Ticket)

	if exc.Spec.Validity.NotBefore.IsZero() || exc.Spec.Validity.NotAfter.IsZero() ||
		exc.Spec.Justification.Ticket == "" || len(exc.Spec.Authority.RequiredApprovers) == 0 {
		phase = "Invalid"
		reason = "MissingMandatoryFields"
		condStatus = metav1.ConditionFalse
		msg = "ControlException requires non-zero validity bounds, justification ticket, and required approvers (Invariant I-05)"
	} else if now.After(exc.Spec.Validity.NotAfter.Time) || now.Before(exc.Spec.Validity.NotBefore.Time) {
		phase = "Expired"
		reason = "OutOfBounds"
		condStatus = metav1.ConditionFalse
		msg = fmt.Sprintf("ControlException outside validity window [%s, %s]", exc.Spec.Validity.NotBefore.UTC().Format(time.RFC3339), exc.Spec.Validity.NotAfter.UTC().Format(time.RFC3339))
	}

	excCond := metav1.Condition{
		Type:               "Ready",
		Status:             condStatus,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            msg,
	}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var latest assurancev1alpha1.ControlException
		if getErr := r.Get(ctx, req.NamespacedName, &latest); getErr != nil {
			return getErr
		}
		latest.Status.Phase = phase
		latest.Status.ObservedGeneration = latest.Generation
		latest.Status.Conditions = upsertCondition(latest.Status.Conditions, excCond)
		return r.Status().Update(ctx, &latest)
	}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

func (r *ControlExceptionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&assurancev1alpha1.ControlException{}).
		Complete(r)
}

// AssurancePolicyReconciler reconciles AssurancePolicy objects.
type AssurancePolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

func (r *AssurancePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pol assurancev1alpha1.AssurancePolicy
	if err := r.Get(ctx, req.NamespacedName, &pol); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	polCond := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "PolicyActive",
		Message:            fmt.Sprintf("AssurancePolicy active (requiredState=%s, unknownIsViolation=%v)", pol.Spec.RequiredState, pol.Spec.Behavior.UnknownIsViolation),
	}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var latest assurancev1alpha1.AssurancePolicy
		if getErr := r.Get(ctx, req.NamespacedName, &latest); getErr != nil {
			return getErr
		}
		latest.Status.ObservedGeneration = latest.Generation
		latest.Status.Conditions = upsertCondition(latest.Status.Conditions, polCond)
		return r.Status().Update(ctx, &latest)
	}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *AssurancePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&assurancev1alpha1.AssurancePolicy{}).
		Complete(r)
}

// CapabilityLeaseReconciler reconciles CapabilityLease objects for bounded AI workcell execution.
type CapabilityLeaseReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Log           logr.Logger
	ReceiptSigner ports.ReceiptSigner
	EvidenceRepo  ports.EvidenceRepository
}

func (r *CapabilityLeaseReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var lease assurancev1alpha1.CapabilityLease
	if err := r.Get(ctx, req.NamespacedName, &lease); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	now := metav1.Now()
	issuedAt := lease.Status.IssuedAt
	if issuedAt == nil {
		issuedAt = &now
	}
	expiresAt := lease.Status.ExpiresAt
	if expiresAt == nil && lease.Spec.TTL.Duration > 0 {
		exp := metav1.NewTime(issuedAt.Add(lease.Spec.TTL.Duration))
		expiresAt = &exp
	}

	phase := "Active"
	if lease.Status.RevocationReason != "" {
		phase = "Revoked"
	} else if expiresAt != nil && now.After(expiresAt.Time) {
		phase = "Expired"
	} else if lease.Spec.MaxTurns > 0 && lease.Status.CurrentTurn >= lease.Spec.MaxTurns {
		phase = "Exhausted"
	}

	lastReceiptHash := lease.Status.LastReceiptHash
	if phase == "Active" && r.ReceiptSigner != nil {
		sub := assurance.SubjectRef{
			Scheme: "k8s",
			ID:     fmt.Sprintf("%s/CapabilityLease/%s", lease.Namespace, lease.Name),
		}
		rcpt := assurance.ControlReceipt{
			Subject:      sub,
			Control:      assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"},
			State:        assurance.AssuranceStateAssured,
			Epoch:        assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeStringDigest(fmt.Sprintf("%s|%d|%d", sub.URI(), lease.Generation, lease.Status.CurrentTurn))},
			EvidenceRoot: assurance.ComputeStringDigest(strings.Join(lease.Spec.AllowedCapabilities, ",")),
			EvaluatedAt:  now.UTC(),
		}
		if signed, err := r.ReceiptSigner.SignReceipt(ctx, rcpt); err == nil {
			lastReceiptHash = signed.Digest()
			if casRepo, ok := r.EvidenceRepo.(*storage.ContentAddressedEvidenceRepository); ok && casRepo != nil {
				_, _ = casRepo.PutReceipt(ctx, signed)
			}
		}
	}

	leaseCond := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: now,
		Reason:             phase,
		Message:            fmt.Sprintf("CapabilityLease for %s in phase %s (turn %d/%d)", lease.Spec.Principal, phase, lease.Status.CurrentTurn, lease.Spec.MaxTurns),
	}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var latest assurancev1alpha1.CapabilityLease
		if getErr := r.Get(ctx, req.NamespacedName, &latest); getErr != nil {
			return getErr
		}
		if latest.Status.IssuedAt == nil {
			latest.Status.IssuedAt = issuedAt
		}
		if latest.Status.ExpiresAt == nil && expiresAt != nil {
			latest.Status.ExpiresAt = expiresAt
		}
		latest.Status.LastReceiptHash = lastReceiptHash
		latest.Status.Phase = phase
		latest.Status.ObservedGeneration = latest.Generation
		latest.Status.Conditions = upsertCondition(latest.Status.Conditions, leaseCond)
		return r.Status().Update(ctx, &latest)
	}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
}

func (r *CapabilityLeaseReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&assurancev1alpha1.CapabilityLease{}).
		Complete(r)
}
