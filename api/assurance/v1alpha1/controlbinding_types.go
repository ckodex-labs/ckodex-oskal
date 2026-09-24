package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CanonicalControlRef identifies the canonical control requirement.
type CanonicalControlRef struct {
	Namespace string `json:"namespace"`
	ID        string `json:"id"`
	Version   string `json:"version,omitempty"`
}

// FrameworkMapping maps a canonical control to an external standard (NIST, ISO, CIS).
type FrameworkMapping struct {
	Framework string `json:"framework"`
	Control   string `json:"control"`
	Version   string `json:"version,omitempty"`
}

// ControlBindingItem represents a single control and its framework mappings.
type ControlBindingItem struct {
	Canonical CanonicalControlRef `json:"canonical"`
	Mappings []FrameworkMapping  `json:"mappings,omitempty"`
}

// SubjectSelector targets Kubernetes workload resources.
type SubjectSelector struct {
	APIGroups         []string               `json:"apiGroups,omitempty"`
	Kinds             []string               `json:"kinds"`
	NamespaceSelector *metav1.LabelSelector  `json:"namespaceSelector,omitempty"`
	LabelSelector     *metav1.LabelSelector  `json:"labelSelector,omitempty"`
}

// ImplementationBindingRef identifies an implementation provider.
type ImplementationBindingRef struct {
	Purpose  string             `json:"purpose"` // preventive, detective, corrective, compensating
	Provider string             `json:"provider"` // kubernetes-validating-admission, tetragon, cilium, sigstore
	Ref      ImplementationTargetRef `json:"ref"`
}

// ImplementationTargetRef references a concrete resource or configuration.
type ImplementationTargetRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// RequirementBinding associates a requirement with implementation mechanisms and evidence contracts.
type RequirementBinding struct {
	ID               string                     `json:"id"`
	Implementations  []ImplementationBindingRef `json:"implementations"`
	EvidenceContract string                     `json:"evidenceContract"`
}

// ControlBindingSpec defines the desired state of ControlBinding.
type ControlBindingSpec struct {
	Controls     []ControlBindingItem `json:"controls"`
	Subjects     SubjectSelector      `json:"subjects"`
	Requirements []RequirementBinding `json:"requirements"`
}

// ControlBindingStatus defines the observed state of ControlBinding.
type ControlBindingStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	ActiveSubjects     int                `json:"activeSubjects,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=cb
// ControlBinding is the Schema for the controlbindings API.
type ControlBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ControlBindingSpec   `json:"spec,omitempty"`
	Status ControlBindingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// ControlBindingList contains a list of ControlBinding.
type ControlBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ControlBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ControlBinding{}, &ControlBindingList{})
}
