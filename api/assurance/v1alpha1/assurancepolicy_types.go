package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicyEvidenceConfig configures evidence constraints.
type PolicyEvidenceConfig struct {
	RequireFresh bool `json:"requireFresh"`
}

// PolicyBehaviorConfig configures violation behaviors.
type PolicyBehaviorConfig struct {
	FailOnConfirmedViolation bool `json:"failOnConfirmedViolation"`
	UnknownIsViolation       bool `json:"unknownIsViolation"`
}

// PolicyFreshnessConfig configures freshness thresholds.
type PolicyFreshnessConfig struct {
	MaxEvaluationAge metav1.Duration `json:"maxEvaluationAge"`
}

// AdmissionEnforcementConfig configures admission gating.
type AdmissionEnforcementConfig struct {
	Enabled bool `json:"enabled"`
}

// PolicyEnforcementConfig configures enforcement hooks.
type PolicyEnforcementConfig struct {
	Admission AdmissionEnforcementConfig `json:"admission,omitempty"`
}

// AssurancePolicySpec defines the desired state of AssurancePolicy.
type AssurancePolicySpec struct {
	RequiredState string                  `json:"requiredState"` // "Assured"
	Evidence      PolicyEvidenceConfig    `json:"evidence,omitempty"`
	Behavior      PolicyBehaviorConfig    `json:"behavior,omitempty"`
	Freshness     PolicyFreshnessConfig   `json:"freshness,omitempty"`
	Enforcement   PolicyEnforcementConfig `json:"enforcement,omitempty"`
}

// AssurancePolicyStatus defines the observed state of AssurancePolicy.
type AssurancePolicyStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ap
// AssurancePolicy is the Schema for the assurancepolicies API.
type AssurancePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AssurancePolicySpec   `json:"spec,omitempty"`
	Status AssurancePolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// AssurancePolicyList contains a list of AssurancePolicy.
type AssurancePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AssurancePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AssurancePolicy{}, &AssurancePolicyList{})
}
