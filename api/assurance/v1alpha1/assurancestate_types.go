package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StateSubjectRef targets the specific workload subject.
type StateSubjectRef struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
}

// StateEpoch records the environment digests at the time of evaluation.
type StateEpoch struct {
	Subject        string `json:"subject"`
	Policy         string `json:"policy"`
	Implementation string `json:"implementation"`
	Authority      string `json:"authority"`
	Environment    string `json:"environment"`
	Composite      string `json:"composite"`
}

// ControlStatus records the summarized state of an individual evaluated control.
type ControlStatus struct {
	ID              string `json:"id"`
	State           string `json:"state"` // "Assured", "Verified", "Observed", "Stale", "Failed", "Unknown"
	EvidenceSummary string `json:"evidenceSummary,omitempty"`
}

// Condition types for AssuranceState
const (
	ConditionTypeEvidenceReady   = "EvidenceReady"
	ConditionTypeEvaluationReady = "EvaluationReady"
	ConditionTypeAssured         = "Assured"
	ConditionTypeStale           = "Stale"
	ConditionTypeDegraded        = "Degraded"
)

// AssuranceStateSpec defines the desired state target of AssuranceState.
type AssuranceStateSpec struct {
	SubjectRef StateSubjectRef `json:"subjectRef"`
}

// AssuranceStateStatus defines the observed summary projection (ADR-002, ADR-004).
type AssuranceStateStatus struct {
	State        string            `json:"state"` // "Assured", "Stale", "Failed", "Unknown"
	Epoch        StateEpoch        `json:"epoch,omitempty"`
	EvidenceRoot string            `json:"evidenceRoot,omitempty"`
	Controls     []ControlStatus   `json:"controls,omitempty"`
	EvaluatedAt  *metav1.Time      `json:"evaluatedAt,omitempty"`
	ValidUntil   *metav1.Time      `json:"validUntil,omitempty"`
	Conditions   []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=as
// AssuranceState is the Schema for the assurancestates API.
type AssuranceState struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AssuranceStateSpec   `json:"spec,omitempty"`
	Status AssuranceStateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// AssuranceStateList contains a list of AssuranceState.
type AssuranceStateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AssuranceState `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AssuranceState{}, &AssuranceStateList{})
}
