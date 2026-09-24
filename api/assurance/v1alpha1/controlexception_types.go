package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ExceptionSubjectRef targets the specific subject granted an exception.
type ExceptionSubjectRef struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

// ExceptionJustification explains why the exception is necessary.
type ExceptionJustification struct {
	Ticket string `json:"ticket"`
	Notes  string `json:"notes,omitempty"`
}

// ExceptionAuthority lists authorized approvers for this exception.
type ExceptionAuthority struct {
	RequiredApprovers []string `json:"requiredApprovers"`
}

// ExceptionValidity bounds the exception temporally (Invariant I-05).
type ExceptionValidity struct {
	NotBefore metav1.Time `json:"notBefore"`
	NotAfter  metav1.Time `json:"notAfter"`
}

// ControlExceptionSpec defines the desired state of ControlException.
type ControlExceptionSpec struct {
	Subject              ExceptionSubjectRef    `json:"subject"`
	Controls             []string               `json:"controls"`
	Justification        ExceptionJustification `json:"justification"`
	Authority            ExceptionAuthority     `json:"authority"`
	Validity             ExceptionValidity      `json:"validity"`
	CompensatingControls []string               `json:"compensatingControls,omitempty"`
}

// ControlExceptionStatus defines the observed state of ControlException.
type ControlExceptionStatus struct {
	Phase              string             `json:"phase,omitempty"` // "Active", "Expired", "Revoked"
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ce
// ControlException is the Schema for the controlexceptions API.
type ControlException struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ControlExceptionSpec   `json:"spec,omitempty"`
	Status ControlExceptionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// ControlExceptionList contains a list of ControlException.
type ControlExceptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ControlException `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ControlException{}, &ControlExceptionList{})
}
