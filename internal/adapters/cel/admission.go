package cel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// AdmissionObserver discovers and digests Kubernetes CEL ValidatingAdmissionPolicies (Section 20).
type AdmissionObserver struct {
	observerIdentity assurance.AuthorityRef
}

// NewAdmissionObserver creates an admission observer with a trusted authority identity.
func NewAdmissionObserver(observerIdentity assurance.AuthorityRef) *AdmissionObserver {
	if observerIdentity.Scheme == "" {
		observerIdentity = assurance.AuthorityRef{
			Scheme:      "spiffe",
			Subject:     "prod/ns/ckodex-assurance/sa/cel-admission-observer",
			TrustDomain: "prod",
		}
	}
	return &AdmissionObserver{observerIdentity: observerIdentity}
}

// ComputePolicyDigest computes a deterministic digest for a ValidatingAdmissionPolicy.
func ComputePolicyDigest(policy *admissionregistrationv1.ValidatingAdmissionPolicy) string {
	var sb strings.Builder
	sb.WriteString(policy.Name)
	sb.WriteString("|")
	sb.WriteString(fmt.Sprintf("%d", policy.Generation))
	sb.WriteString("|")

	for _, v := range policy.Spec.Validations {
		sb.WriteString(v.Expression)
		sb.WriteString(";")
		if v.Message != "" {
			sb.WriteString(v.Message)
			sb.WriteString(";")
		}
	}

	h := sha256.Sum256([]byte(sb.String()))
	return "sha256:" + hex.EncodeToString(h[:])
}

// GenerateAdmissionEvidence creates a verified EvidenceEnvelope for an admitted resource.
func (o *AdmissionObserver) GenerateAdmissionEvidence(
	subject assurance.SubjectRef,
	policy *admissionregistrationv1.ValidatingAdmissionPolicy,
	allowed bool,
	epoch assurance.AssuranceEpoch,
	now time.Time,
) (assurance.EvidenceEnvelope, error) {
	if !allowed {
		return assurance.EvidenceEnvelope{}, fmt.Errorf("resource admission was denied by policy %s", policy.Name)
	}

	policyDigest := ComputePolicyDigest(policy)
	epochWithPolicy := epoch
	epochWithPolicy.PolicyDigest = policyDigest

	rawPayload := fmt.Sprintf("admission|%s|%s|allowed=true|%d", subject.URI(), policy.Name, now.Unix())
	artifactDigest := assurance.ComputeStringDigest(rawPayload)

	evidenceRef := assurance.EvidenceRef{
		URI:       fmt.Sprintf("evidence://admission/%s/%s", subject.Attributes["namespace"], subject.Attributes["name"]),
		Digest:    artifactDigest,
		MediaType: "application/vnd.ckodex.evidence+json",
	}

	envelope := assurance.EvidenceEnvelope{
		Schema:          "assurance.ckodex.io/evidence/v1alpha1",
		ID:              fmt.Sprintf("ev-adm-%d", now.UnixNano()),
		Subject:         subject,
		ObservationType: "kubernetes.admission",
		CapturedAt:      now,
		Producer:        o.observerIdentity,
		Artifact:        evidenceRef,
		IntegrityDigest: artifactDigest,
		Epoch:           epochWithPolicy,
		ControlRefs: []assurance.ControlRef{
			{Namespace: "ckodex", ID: "container.least-privilege"},
		},
	}

	return envelope, nil
}

// SampleRestrictedContainerPolicy returns a canonical in-process CEL policy for workloads.
func SampleRestrictedContainerPolicy() *admissionregistrationv1.ValidatingAdmissionPolicy {
	return &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "workloads-least-privilege-cel",
			Generation: 1,
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: func() *admissionregistrationv1.FailurePolicyType {
				p := admissionregistrationv1.Fail
				return &p
			}(),
			Validations: []admissionregistrationv1.Validation{
				{
					Expression: "object.spec.template.spec.securityContext.runAsNonRoot == true",
					Message:    "Pod must configure runAsNonRoot to true",
				},
				{
					Expression: "!has(object.spec.template.spec.containers[0].securityContext.privileged) || object.spec.template.spec.containers[0].securityContext.privileged == false",
					Message:    "Privileged containers are strictly prohibited",
				},
			},
		},
	}
}
