package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// CapabilityLeaseSpec defines the desired execution bounds and privileges for an AI workcell.
type CapabilityLeaseSpec struct {
	Principal           string          `json:"principal"`
	Scope               string          `json:"scope"`
	AllowedCapabilities []string        `json:"allowedCapabilities"`
	MaxTurns            int             `json:"maxTurns"`
	TTL                 metav1.Duration `json:"ttl"`
}

// CapabilityLeaseStatus defines the observed execution state and turn chaining of the lease.
type CapabilityLeaseStatus struct {
	Phase              string             `json:"phase,omitempty"` // "Active", "Exhausted", "Expired", "Revoked"
	CurrentTurn        int                `json:"currentTurn,omitempty"`
	LastReceiptHash    string             `json:"lastReceiptHash,omitempty"`
	IssuedAt           *metav1.Time       `json:"issuedAt,omitempty"`
	ExpiresAt          *metav1.Time       `json:"expiresAt,omitempty"`
	RevocationReason   string             `json:"revocationReason,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=cl
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Turn",type="integer",JSONPath=".status.currentTurn"
// +kubebuilder:printcolumn:name="MaxTurns",type="integer",JSONPath=".spec.maxTurns"
// CapabilityLease is the Schema for the capabilityleases API in an AI workcell environment.
type CapabilityLease struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CapabilityLeaseSpec   `json:"spec,omitempty"`
	Status CapabilityLeaseStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// CapabilityLeaseList contains a list of CapabilityLease.
type CapabilityLeaseList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CapabilityLease `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CapabilityLease{}, &CapabilityLeaseList{})
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out.
func (in *CapabilityLeaseSpec) DeepCopyInto(out *CapabilityLeaseSpec) {
	*out = *in
	if in.AllowedCapabilities != nil {
		in, out := &in.AllowedCapabilities, &out.AllowedCapabilities
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is a deepcopy function, creating a new CapabilityLeaseSpec.
func (in *CapabilityLeaseSpec) DeepCopy() *CapabilityLeaseSpec {
	if in == nil {
		return nil
	}
	out := new(CapabilityLeaseSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out.
func (in *CapabilityLeaseStatus) DeepCopyInto(out *CapabilityLeaseStatus) {
	*out = *in
	if in.IssuedAt != nil {
		in, out := &in.IssuedAt, &out.IssuedAt
		*out = (*in).DeepCopy()
	}
	if in.ExpiresAt != nil {
		in, out := &in.ExpiresAt, &out.ExpiresAt
		*out = (*in).DeepCopy()
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]metav1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is a deepcopy function, creating a new CapabilityLeaseStatus.
func (in *CapabilityLeaseStatus) DeepCopy() *CapabilityLeaseStatus {
	if in == nil {
		return nil
	}
	out := new(CapabilityLeaseStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out.
func (in *CapabilityLease) DeepCopyInto(out *CapabilityLease) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is a deepcopy function, creating a new CapabilityLease.
func (in *CapabilityLease) DeepCopy() *CapabilityLease {
	if in == nil {
		return nil
	}
	out := new(CapabilityLease)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is a deepcopy function, creating a new runtime.Object.
func (in *CapabilityLease) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out.
func (in *CapabilityLeaseList) DeepCopyInto(out *CapabilityLeaseList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CapabilityLease, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is a deepcopy function, creating a new CapabilityLeaseList.
func (in *CapabilityLeaseList) DeepCopy() *CapabilityLeaseList {
	if in == nil {
		return nil
	}
	out := new(CapabilityLeaseList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is a deepcopy function, creating a new runtime.Object.
func (in *CapabilityLeaseList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
