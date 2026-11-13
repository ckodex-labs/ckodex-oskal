package reconcile

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/spire"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/ckodex-labs/ckodex-oskal/internal/verifier"
)

func TestContractEvaluator_Unit(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "payments/payments-api"}
	ctrlRef := assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
	epoch := assurance.AssuranceEpoch{
		SubjectDigest: assurance.ComputeStringDigest(sub.URI()),
	}

	claim := assurance.Claim{
		ID:      "claim-01",
		Subject: sub,
		Control: ctrlRef,
	}

	contract := assurance.EvidenceContract{
		ID: "contract-ac6",
		Requirements: []assurance.EvidenceRequirement{
			{ID: "req-1", EvidenceType: "admission", Required: true, MaxAge: 5 * time.Minute},
		},
		OnMissingRequiredState: assurance.AssuranceStateUnknown,
	}

	// 1. Missing evidence -> UNKNOWN
	evaluatorMissing := &ContractEvaluator{EvidenceSource: nil}
	evalResMissing, err := evaluatorMissing.Evaluate(ctx, claim, contract, epoch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evalResMissing.State != assurance.AssuranceStateUnknown {
		t.Fatalf("expected UNKNOWN state on missing evidence, got %s", evalResMissing.State)
	}

	// 2. Present fresh evidence -> ASSURED
	ev := assurance.EvidenceEnvelope{
		ObservationType: "admission",
		CapturedAt:      now,
		Epoch:           epoch,
	}
	evaluatorPresent := &ContractEvaluator{EvidenceSource: []assurance.EvidenceEnvelope{ev}}
	evalResPresent, err := evaluatorPresent.Evaluate(ctx, claim, contract, epoch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evalResPresent.State != assurance.AssuranceStateAssured && evalResPresent.State != assurance.AssuranceStateVerified {
		t.Fatalf("expected ASSURED/VERIFIED on fresh evidence, got %s", evalResPresent.State)
	}
	if evalResPresent.Vector.Conformance != assurance.ValencePositive {
		t.Fatalf("expected positive conformance in vector state, got %s", evalResPresent.Vector.Conformance)
	}
	if evalResPresent.Vector.Resolve(assurance.VectorResolutionPolicy{RequireFresh: true}) != assurance.AssuranceStateAssured {
		t.Fatalf("expected evalResPresent.Vector.Resolve() == ASSURED, got %s", evalResPresent.Vector.Resolve(assurance.VectorResolutionPolicy{RequireFresh: true}))
	}

	// 3. Failed contract state
	contractFailing := assurance.EvidenceContract{
		ID: "contract-failing",
		Requirements: []assurance.EvidenceRequirement{
			{ID: "req-fail", EvidenceType: "untrusted-type", Required: true},
		},
		OnMissingRequiredState: assurance.AssuranceStateFailed,
	}
	evalResFailed, err := evaluatorPresent.Evaluate(ctx, claim, contractFailing, epoch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evalResFailed.State != assurance.AssuranceStateFailed {
		t.Fatalf("expected FAILED state, got %s", evalResFailed.State)
	}
}

func TestControlBindingReconciler_Reconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add client-go scheme: %v", err)
	}
	if err := assurancev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add assurance scheme: %v", err)
	}

	binding := &assurancev1alpha1.ControlBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "payments-binding",
			Namespace:  "payments",
			Generation: 1,
		},
		Spec: assurancev1alpha1.ControlBindingSpec{
			Controls: []assurancev1alpha1.ControlBindingItem{
				{
					Canonical: assurancev1alpha1.CanonicalControlRef{Namespace: "ckodex", ID: "least-privilege"},
				},
			},
			Requirements: []assurancev1alpha1.RequirementBinding{
				{ID: "req-1"},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(binding).
		WithStatusSubresource(binding).
		Build()

	reconciler := &ControlBindingReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		Log:            logr.Discard(),
		ClaimEvaluator: &ContractEvaluator{},
	}

	// 1. Successful reconciliation
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "payments", Name: "payments-binding"}}
	res, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}
	if res.RequeueAfter != 5*time.Minute {
		t.Fatalf("expected 5 minute requeue, got %v", res.RequeueAfter)
	}

	var updated assurancev1alpha1.ControlBinding
	if err := fakeClient.Get(context.Background(), req.NamespacedName, &updated); err != nil {
		t.Fatalf("failed to get updated binding: %v", err)
	}
	if len(updated.Status.Conditions) == 0 {
		t.Fatal("expected status conditions to be populated")
	}
	if updated.Status.Conditions[0].Reason != "UNKNOWN" {
		t.Fatalf("expected UNKNOWN reason when no evidence is supplied, got: %s", updated.Status.Conditions[0].Reason)
	}

	// 2. Not found reconciliation (clean ignore)
	notFoundReq := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "payments", Name: "deleted-binding"}}
	_, errNotFound := reconciler.Reconcile(context.Background(), notFoundReq)
	if errNotFound != nil {
		t.Fatalf("expected nil error on deleted object, got %v", errNotFound)
	}
}

func TestAssuranceStateReconciler_Reconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := assurancev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add assurance scheme: %v", err)
	}

	stateObj := &assurancev1alpha1.AssuranceState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "payments-state",
			Namespace: "payments",
		},
		Spec: assurancev1alpha1.AssuranceStateSpec{
			SubjectRef: assurancev1alpha1.StateSubjectRef{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       "payments-api",
				Namespace:  "payments",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(stateObj).
		WithStatusSubresource(stateObj).
		Build()

	reconciler := &AssuranceStateReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Log:    logr.Discard(),
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "payments", Name: "payments-state"}}
	res, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}
	if res != (ctrl.Result{}) {
		t.Fatalf("expected empty result, got %v", res)
	}

	// Not found
	notFoundReq := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "payments", Name: "missing-state"}}
	_, errNotFound := reconciler.Reconcile(context.Background(), notFoundReq)
	if errNotFound != nil {
		t.Fatalf("expected nil error on missing object, got: %v", errNotFound)
	}
}

func TestControlBindingReconciler_WithSVIDValidator(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = assurancev1alpha1.AddToScheme(scheme)

	binding := &assurancev1alpha1.ControlBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "identity-binding",
			Namespace:  "payments",
			Generation: 1,
		},
		Spec: assurancev1alpha1.ControlBindingSpec{
			Controls: []assurancev1alpha1.ControlBindingItem{
				{
					Canonical: assurancev1alpha1.CanonicalControlRef{
						Namespace: "nist-sp-800-53",
						ID:        "IA-2",
					},
				},
			},
			Requirements: []assurancev1alpha1.RequirementBinding{
				{
					ID:               "req-identity",
					EvidenceContract: "contract-identity",
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(binding).
		WithStatusSubresource(binding).
		Build()

	bundle := spire.NewTrustBundle()
	validator := spire.NewSVIDValidator(bundle, assurance.AuthorityRef{
		Scheme:  "spiffe",
		Subject: "prod/ns/security/sa/reconciler",
	})

	reconciler := &ControlBindingReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		Log:            logr.Discard(),
		ClaimEvaluator: &ContractEvaluator{},
		SVIDValidator:  validator,
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "payments", Name: "identity-binding"}}
	res, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}
	if res.RequeueAfter != 5*time.Minute {
		t.Fatalf("expected requeue after 5m, got: %v", res.RequeueAfter)
	}
}

func TestControlBindingReconciler_ClosedLoopWithEvidenceRepo(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = assurancev1alpha1.AddToScheme(scheme)

	repo := storage.NewMemoryEvidenceRepository()

	// 1. Ingest verified admission evidence into EvidenceRepository
	subRef := assurance.SubjectRef{
		Scheme: "k8s",
		ID:     "payments/Pod/payments-api-7b89f-abcd",
	}
	epoch := assurance.AssuranceEpoch{
		SubjectDigest:        assurance.ComputeStringDigest("k8s://payments/payments-api-binding"),
		ImplementationDigest: assurance.ComputeStringDigest("kubernetes:validating-webhook"),
		AuthorityDigest:      assurance.ComputeStringDigest("k8s:admission-controller://ckodex-system/oskal-webhook"),
		EnvironmentDigest:    assurance.ComputeStringDigest("cluster:kubernetes"),
	}
	env := assurance.EvidenceEnvelope{
		Schema:          "https://schema.ckodex.io/evidence/v1/envelope.json",
		ID:              "env-admission-001",
		ObservationType: "kubernetes.admission",
		Subject:         subRef,
		Producer: assurance.AuthorityRef{
			Scheme:  "k8s:admission-controller",
			Subject: "ckodex-system/oskal-webhook",
		},
		Epoch: epoch,
		Artifact: assurance.EvidenceRef{
			URI:       "k8s://payments/Pod/payments-api-7b89f-abcd",
			Digest:    "sha256:abcd0123ef456789abcd0123ef456789abcd0123ef456789abcd0123ef456789",
			MediaType: "application/json",
		},
		CapturedAt: time.Now().UTC(),
	}
	if _, err := repo.Put(ctx, env, nil); err != nil {
		t.Fatalf("failed to store evidence: %v", err)
	}

	// 2. Setup EvidenceContract CRD
	contractCRD := &assurancev1alpha1.EvidenceContract{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "payments-contract",
			Namespace: "payments",
		},
		Spec: assurancev1alpha1.EvidenceContractSpec{
			Requirements: []assurancev1alpha1.ContractRequirement{
				{
					ID:        "req-ac-6",
					Type:      "admission",
					Required:  true,
					Freshness: metav1.Duration{Duration: 24 * time.Hour},
					AcceptedProducers: []string{
						"k8s:admission-controller://ckodex-system/oskal-webhook",
					},
				},
			},
		},
	}

	// 3. Setup ControlBinding CRD referencing the contract
	binding := &assurancev1alpha1.ControlBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "payments-api-binding",
			Namespace:  "payments",
			Generation: 1,
		},
		Spec: assurancev1alpha1.ControlBindingSpec{
			Controls: []assurancev1alpha1.ControlBindingItem{
				{
					Canonical: assurancev1alpha1.CanonicalControlRef{
						Namespace: "nist-sp-800-53",
						ID:        "AC-6",
					},
				},
			},
			Requirements: []assurancev1alpha1.RequirementBinding{
				{
					ID:               "req-ac-6",
					EvidenceContract: "payments-contract",
				},
			},
		},
	}

	// 4. Setup AssuranceState projection CRD
	stateCRD := &assurancev1alpha1.AssuranceState{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "payments-api-state",
			Namespace: "payments",
		},
		Spec: assurancev1alpha1.AssuranceStateSpec{
			SubjectRef: assurancev1alpha1.StateSubjectRef{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       "payments-api",
				Namespace:  "payments",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(contractCRD, binding, stateCRD).
		WithStatusSubresource(binding, stateCRD).
		Build()

	reconciler := &ControlBindingReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		Log:            logr.Discard(),
		ClaimEvaluator: &ContractEvaluator{EvidenceRepo: repo, Verifier: verifier.NewDefaultEvidenceVerifier()},
		EvidenceRepo:   repo,
	}
	rcptMgr, err := receipts.NewReceiptManager(assurance.AuthorityRef{
		Scheme:  "spiffe",
		Subject: "prod/ns/ckodex-system/sa/oskal-controller",
	})
	if err != nil {
		t.Fatalf("failed to create receipt manager: %v", err)
	}
	reconciler.ReceiptSigner = rcptMgr

	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "payments", Name: "payments-api-binding"}}
	res, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}
	if res.RequeueAfter != 5*time.Minute {
		t.Fatalf("expected requeue after 5m, got: %v", res.RequeueAfter)
	}

	// Verify ControlBinding transitioned to ASSURED
	var updatedBinding assurancev1alpha1.ControlBinding
	if err := fakeClient.Get(ctx, req.NamespacedName, &updatedBinding); err != nil {
		t.Fatalf("failed to get updated binding: %v", err)
	}
	if len(updatedBinding.Status.Conditions) == 0 {
		t.Fatal("expected status conditions on binding")
	}
	if updatedBinding.Status.Conditions[0].Reason != "ASSURED" {
		t.Fatalf("expected ASSURED status condition reason, got: %s (msg: %s)",
			updatedBinding.Status.Conditions[0].Reason, updatedBinding.Status.Conditions[0].Message)
	}

	// Verify AssuranceState CRD was projected with ASSURED and valid evidenceRoot
	var updatedState assurancev1alpha1.AssuranceState
	stateKey := types.NamespacedName{Namespace: "payments", Name: "payments-api-state"}
	if err := fakeClient.Get(ctx, stateKey, &updatedState); err != nil {
		t.Fatalf("failed to get updated assurance state: %v", err)
	}
	if updatedState.Status.State != "ASSURED" {
		t.Fatalf("expected AssuranceState to be ASSURED, got: %s", updatedState.Status.State)
	}
	if updatedState.Status.EvidenceRoot == "" || updatedState.Status.EvidenceRoot[:7] != "sha256:" {
		t.Fatalf("expected valid sha256 EvidenceRoot, got: %s", updatedState.Status.EvidenceRoot)
	}
	if len(updatedState.Status.Controls) == 0 || updatedState.Status.Controls[0].State != "ASSURED" {
		t.Fatalf("expected control status to be ASSURED, got: %+v", updatedState.Status.Controls)
	}

	// Verify signed ControlReceipt was persisted in CAS
	persistedRcpt, err := repo.GetReceipt(ctx, "rcpt-AC-6")
	if err != nil {
		t.Fatalf("expected signed receipt rcpt-AC-6 in CAS, got err: %v", err)
	}
	ok, err := receipts.VerifyIndependentReceipt(persistedRcpt, rcptMgr.PublicKey())
	if err != nil || !ok {
		t.Fatalf("persisted receipt failed cryptographic verification: ok=%v, err=%v", ok, err)
	}
}

func TestAdditionalCRDReconcilersAndDerogation(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = assurancev1alpha1.AddToScheme(scheme)

	now := time.Now().UTC()
	exc := &assurancev1alpha1.ControlException{
		ObjectMeta: metav1.ObjectMeta{Name: "exc-ac6", Namespace: "payments", Generation: 1},
		Spec: assurancev1alpha1.ControlExceptionSpec{
			Subject:       assurancev1alpha1.ExceptionSubjectRef{Kind: "Deployment", Name: "payments-api"},
			Controls:      []string{"AC-6"},
			Justification: assurancev1alpha1.ExceptionJustification{Ticket: "SEC-101"},
			Authority:     assurancev1alpha1.ExceptionAuthority{RequiredApprovers: []string{"spiffe://prod/ciso"}},
			Validity: assurancev1alpha1.ExceptionValidity{
				NotBefore: metav1.NewTime(now.Add(-1 * time.Hour)),
				NotAfter:  metav1.NewTime(now.Add(24 * time.Hour)),
			},
		},
	}

	pol := &assurancev1alpha1.AssurancePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "strict-pol", Namespace: "payments", Generation: 1},
		Spec: assurancev1alpha1.AssurancePolicySpec{
			RequiredState: "Assured",
		},
	}

	lease := &assurancev1alpha1.CapabilityLease{
		ObjectMeta: metav1.ObjectMeta{Name: "agent-lease", Namespace: "payments", Generation: 1},
		Spec: assurancev1alpha1.CapabilityLeaseSpec{
			Principal:           "spiffe://prod/agent/worker-1",
			Scope:               "payments",
			AllowedCapabilities: []string{"cap:inspect"},
			MaxTurns:            5,
			TTL:                 metav1.Duration{Duration: 10 * time.Minute},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(exc, pol, lease).
		WithStatusSubresource(exc, pol, lease).
		Build()

	excRec := &ControlExceptionReconciler{Client: fakeClient, Scheme: scheme, Log: logr.Discard()}
	if _, err := excRec.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "payments", Name: "exc-ac6"}}); err != nil {
		t.Fatalf("ControlExceptionReconciler failed: %v", err)
	}
	var updatedExc assurancev1alpha1.ControlException
	_ = fakeClient.Get(ctx, types.NamespacedName{Namespace: "payments", Name: "exc-ac6"}, &updatedExc)
	if updatedExc.Status.Phase != "Active" {
		t.Fatalf("expected Active phase on ControlException, got %s", updatedExc.Status.Phase)
	}

	polRec := &AssurancePolicyReconciler{Client: fakeClient, Scheme: scheme, Log: logr.Discard()}
	if _, err := polRec.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "payments", Name: "strict-pol"}}); err != nil {
		t.Fatalf("AssurancePolicyReconciler failed: %v", err)
	}

	rcptMgr, _ := receipts.NewReceiptManager(assurance.AuthorityRef{Scheme: "spiffe", Subject: "prod/ns/ckodex/sa/controller"})
	leaseRec := &CapabilityLeaseReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Log:           logr.Discard(),
		ReceiptSigner: rcptMgr,
	}
	if _, err := leaseRec.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "payments", Name: "agent-lease"}}); err != nil {
		t.Fatalf("CapabilityLeaseReconciler failed: %v", err)
	}
	var updatedLease assurancev1alpha1.CapabilityLease
	_ = fakeClient.Get(ctx, types.NamespacedName{Namespace: "payments", Name: "agent-lease"}, &updatedLease)
	if updatedLease.Status.Phase != "SafeHold" {
		t.Fatalf("lease without a real UID or exact resource scope must remain SafeHold, got %s", updatedLease.Status.Phase)
	}
	if updatedLease.Status.LastReceiptHash != "" || updatedLease.Status.LastExecutionHash != "" || len(updatedLease.Status.ExecutionHistory) != 0 {
		t.Fatalf("reconciliation must not fabricate execution evidence")
	}
}

func TestControlBindingReconciler_MultiRequirementsAndPodEpochAlignment(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = assurancev1alpha1.AddToScheme(scheme)

	contract1 := &assurancev1alpha1.EvidenceContract{
		ObjectMeta: metav1.ObjectMeta{Name: "contract-adm", Namespace: "payments"},
		Spec: assurancev1alpha1.EvidenceContractSpec{
			Requirements: []assurancev1alpha1.ContractRequirement{
				{
					ID:                "req-adm",
					Type:              "kubernetes.admission",
					Required:          true,
					Freshness:         metav1.Duration{Duration: 15 * time.Minute},
					AcceptedProducers: []string{"k8s:admission-controller://"},
				},
			},
		},
	}
	contract2 := &assurancev1alpha1.EvidenceContract{
		ObjectMeta: metav1.ObjectMeta{Name: "contract-net", Namespace: "payments"},
		Spec: assurancev1alpha1.EvidenceContractSpec{
			Requirements: []assurancev1alpha1.ContractRequirement{
				{
					ID:                "req-net",
					Type:              "cilium.network",
					Required:          true,
					Freshness:         metav1.Duration{Duration: 15 * time.Minute},
					AcceptedProducers: []string{"spiffe://"},
				},
			},
		},
	}

	binding := &assurancev1alpha1.ControlBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "payments-multi-binding", Namespace: "payments", Generation: 1},
		Spec: assurancev1alpha1.ControlBindingSpec{
			Controls: []assurancev1alpha1.ControlBindingItem{
				{Canonical: assurancev1alpha1.CanonicalControlRef{Namespace: "nist-sp-800-53", ID: "SC-7"}},
			},
			Requirements: []assurancev1alpha1.RequirementBinding{
				{ID: "req-adm", EvidenceContract: "contract-adm"},
				{ID: "req-net", EvidenceContract: "contract-net"},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(contract1, contract2, binding).
		WithStatusSubresource(binding).
		Build()

	repo := storage.NewMemoryEvidenceRepository()
	now := time.Now().UTC()

	// Seed only first requirement from a child Pod with Pod-specific SubjectDigest
	podSub := assurance.SubjectRef{Scheme: "k8s", ID: "payments/Pod/payments-multi-7f8b9-xyz12"}
	envAdm := assurance.EvidenceEnvelope{
		ID:              "env-pod-adm-1",
		Subject:         podSub,
		ObservationType: "kubernetes.admission",
		CapturedAt:      now,
		Producer:        assurance.AuthorityRef{Scheme: "k8s:admission-controller", Subject: "oskal-validating-webhook"},
		Artifact:        assurance.EvidenceRef{URI: "k8s://adm/1", Digest: assurance.ComputeStringDigest("adm1"), MediaType: "application/json"},
		IntegrityDigest: assurance.ComputeStringDigest("adm1"),
		Epoch:           assurance.AssuranceEpoch{SubjectDigest: podSub.Digest()},
	}
	_, _ = repo.Put(ctx, envAdm, nil)

	reconciler := &ControlBindingReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		Log:            logr.Discard(),
		ClaimEvaluator: &ContractEvaluator{EvidenceRepo: repo, Verifier: verifier.NewDefaultEvidenceVerifier()},
		EvidenceRepo:   repo,
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "payments", Name: "payments-multi-binding"}}
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("first reconcile failed: %v", err)
	}

	var partialBinding assurancev1alpha1.ControlBinding
	_ = fakeClient.Get(ctx, req.NamespacedName, &partialBinding)
	if len(partialBinding.Status.Conditions) == 0 || partialBinding.Status.Conditions[0].Reason == "ASSURED" {
		t.Fatalf("expected non-ASSURED when second requirement is missing, got: %+v", partialBinding.Status.Conditions)
	}

	// Now satisfy second requirement with spiffe:// producer
	envNet := assurance.EvidenceEnvelope{
		ID:              "env-pod-net-1",
		Subject:         podSub,
		ObservationType: "cilium.network",
		CapturedAt:      now,
		Producer:        assurance.AuthorityRef{Scheme: "spiffe", TrustDomain: "prod", Subject: "ns/kube-system/sa/cilium"},
		Artifact:        assurance.EvidenceRef{URI: "k8s://net/1", Digest: assurance.ComputeStringDigest("net1"), MediaType: "application/json"},
		IntegrityDigest: assurance.ComputeStringDigest("net1"),
		Epoch:           assurance.AssuranceEpoch{SubjectDigest: podSub.Digest()},
	}
	_, _ = repo.Put(ctx, envNet, nil)

	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("second reconcile failed: %v", err)
	}

	var assuredBinding assurancev1alpha1.ControlBinding
	_ = fakeClient.Get(ctx, req.NamespacedName, &assuredBinding)
	if len(assuredBinding.Status.Conditions) == 0 || assuredBinding.Status.Conditions[0].Reason != "ASSURED" {
		t.Fatalf("expected ASSURED when both requirements are satisfied, got: %+v", assuredBinding.Status.Conditions)
	}
}
