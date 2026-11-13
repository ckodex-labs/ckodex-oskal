// Package cel hashes supplied native ValidatingAdmissionPolicy definitions.
// A definition digest does not establish installation, evaluation or enforcement.
package cel

import (
	"encoding/json"
	"fmt"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/types"
)

// ComputePolicyDigest binds the supplied policy identity, generation and complete
// spec. Callers must separately establish the policy's authoritative provenance.
func ComputePolicyDigest(policy *admissionregistrationv1.ValidatingAdmissionPolicy) (string, error) {
	if policy == nil || policy.Name == "" {
		return "", fmt.Errorf("named policy definition is required")
	}
	raw, err := json.Marshal(struct {
		Name       string
		UID        types.UID
		Generation int64
		Spec       admissionregistrationv1.ValidatingAdmissionPolicySpec
	}{policy.Name, policy.UID, policy.Generation, policy.Spec})
	if err != nil {
		return "", err
	}
	return assurance.ComputeDigest(raw), nil
}
