package v1alpha1

import (
	"encoding/json"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestCRD_DeepCopyAndSerialization(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add to scheme: %v", err)
	}

	// 1. ControlBinding
	cb := &ControlBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "binding-1", Namespace: "default"},
		Spec: ControlBindingSpec{
			Controls: []ControlBindingItem{
				{
					Canonical: CanonicalControlRef{Namespace: "ckodex", ID: "least-privilege"},
					Mappings:  []FrameworkMapping{{Framework: "nist-sp-800-53", Control: "AC-6"}},
				},
			},
			Requirements: []RequirementBinding{
				{ID: "req-1", Implementations: []ImplementationBindingRef{{Provider: "cel"}}},
			},
		},
	}
	cbCopy := cb.DeepCopy()
	if cbCopy.Name != cb.Name || len(cbCopy.Spec.Controls) != 1 {
		t.Fatalf("unexpected DeepCopy result: %+v", cbCopy)
	}

	// 2. EvidenceContract
	ec := &EvidenceContract{
		ObjectMeta: metav1.ObjectMeta{Name: "contract-1", Namespace: "default"},
		Spec: EvidenceContractSpec{
			Requirements: []ContractRequirement{
				{
					ID:        "req-1",
					Type:      "admission",
					Required:  true,
					Freshness: metav1.Duration{Duration: 5 * time.Minute},
				},
			},
		},
	}
	ecCopy := ec.DeepCopy()
	if ecCopy.Name != ec.Name || len(ecCopy.Spec.Requirements) != 1 {
		t.Fatalf("unexpected EvidenceContract DeepCopy: %+v", ecCopy)
	}

	// 3. AssuranceState
	now := metav1.Now()
	as := &AssuranceState{
		ObjectMeta: metav1.ObjectMeta{Name: "state-1", Namespace: "default"},
		Spec: AssuranceStateSpec{
			SubjectRef: StateSubjectRef{APIVersion: "apps/v1", Kind: "Deployment", Name: "app"},
		},
		Status: AssuranceStateStatus{
			State:        "Assured",
			EvidenceRoot: "sha256:root",
			EvaluatedAt:  &now,
		},
	}
	asCopy := as.DeepCopy()
	if asCopy.Status.State != "Assured" {
		t.Fatalf("unexpected AssuranceState DeepCopy: %+v", asCopy)
	}

	// 4. AssurancePolicy
	ap := &AssurancePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy-1", Namespace: "default"},
		Spec: AssurancePolicySpec{
			RequiredState: "Assured",
			Evidence: PolicyEvidenceConfig{
				RequireFresh: true,
			},
			Freshness: PolicyFreshnessConfig{
				MaxEvaluationAge: metav1.Duration{Duration: 300 * time.Second},
			},
		},
	}
	apCopy := ap.DeepCopy()
	if apCopy.Spec.Freshness.MaxEvaluationAge.Duration != 300*time.Second {
		t.Fatalf("unexpected AssurancePolicy DeepCopy: %+v", apCopy)
	}

	// 5. ControlException
	expiry := metav1.NewTime(time.Now().Add(24 * time.Hour))
	ce := &ControlException{
		ObjectMeta: metav1.ObjectMeta{Name: "exc-1", Namespace: "default"},
		Spec: ControlExceptionSpec{
			Controls: []string{"AC-6"},
			Justification: ExceptionJustification{
				Ticket: "SEC-1234",
				Notes:  "Migration waiver",
			},
			Validity: ExceptionValidity{
				NotAfter: expiry,
			},
		},
	}
	ceCopy := ce.DeepCopy()
	if len(ceCopy.Spec.Controls) != 1 || ceCopy.Spec.Controls[0] != "AC-6" {
		t.Fatalf("unexpected ControlException DeepCopy: %+v", ceCopy)
	}

	// 6. CapabilityLease
	cl := &CapabilityLease{
		ObjectMeta: metav1.ObjectMeta{Name: "lease-1", Namespace: "default"},
		Spec: CapabilityLeaseSpec{
			Principal:           "workcell:auditor",
			Scope:               "namespace:default",
			AllowedCapabilities: []string{"tool:read-evidence"},
			MaxTurns:            10,
			TTL:                 metav1.Duration{Duration: time.Hour},
		},
	}
	clCopy := cl.DeepCopy()
	if clCopy.Spec.Principal != "workcell:auditor" {
		t.Fatalf("unexpected CapabilityLease DeepCopy: %+v", clCopy)
	}

	// JSON Round-trip
	data, err := json.Marshal(cl)
	if err != nil {
		t.Fatalf("failed to marshal CapabilityLease: %v", err)
	}
	var unmarshaled CapabilityLease
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal CapabilityLease: %v", err)
	}
	if unmarshaled.Spec.MaxTurns != 10 {
		t.Fatalf("unexpected unmarshaled spec: %+v", unmarshaled.Spec)
	}
}
