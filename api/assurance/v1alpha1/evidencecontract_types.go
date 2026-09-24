package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ContractRequirement defines an individual required evidence type.
type ContractRequirement struct {
	ID                string          `json:"id"`
	Type              string          `json:"type"`
	Required          bool            `json:"required"`
	Freshness         metav1.Duration `json:"freshness,omitempty"`
	AcceptedProducers []string        `json:"acceptedProducers,omitempty"`
}

// MissingEvidencePolicy configures action when required evidence is missing.
type MissingEvidencePolicy struct {
	State string `json:"state"` // "Unknown", "Failed"
}

// EvidenceContractSpec defines the desired state of EvidenceContract.
type EvidenceContractSpec struct {
	Requirements              []ContractRequirement `json:"requirements"`
	OnMissingRequiredEvidence MissingEvidencePolicy `json:"onMissingRequiredEvidence,omitempty"`
}

// EvidenceContractStatus defines the observed state of EvidenceContract.
type EvidenceContractStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ec
// EvidenceContract is the Schema for the evidencecontracts API.
type EvidenceContract struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EvidenceContractSpec   `json:"spec,omitempty"`
	Status EvidenceContractStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// EvidenceContractList contains a list of EvidenceContract.
type EvidenceContractList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EvidenceContract `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EvidenceContract{}, &EvidenceContractList{})
}
