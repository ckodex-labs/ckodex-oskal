package cilium

import (
	"fmt"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// NetworkFlowEvent models a Cilium eBPF network flow observation.
type NetworkFlowEvent struct {
	SourcePod        string `json:"sourcePod"`
	DestinationPod   string `json:"destinationPod"`
	DestinationPort  int    `json:"destinationPort"`
	TrafficAllowed   bool   `json:"trafficAllowed"`
	EgressIsolated   bool   `json:"egressIsolated"`
	AppliedPolicyRef string `json:"appliedPolicyRef"`
}

// CiliumObserver transforms Cilium network telemetry into canonical assurance evidence.
type CiliumObserver struct {
	observerIdentity assurance.AuthorityRef
}

// NewCiliumObserver creates a new Cilium network observer.
func NewCiliumObserver(identity assurance.AuthorityRef) *CiliumObserver {
	if identity.Scheme == "" {
		identity = assurance.AuthorityRef{
			Scheme:      "spiffe",
			Subject:     "prod/ns/ckodex-evidence/sa/cilium-collector",
			TrustDomain: "prod",
		}
	}
	return &CiliumObserver{observerIdentity: identity}
}

// GenerateNetworkEvidence evaluates network flow isolation.
func (o *CiliumObserver) GenerateNetworkEvidence(
	subject assurance.SubjectRef,
	event NetworkFlowEvent,
	epoch assurance.AssuranceEpoch,
	now time.Time,
) (assurance.EvidenceEnvelope, *assurance.Finding, error) {
	if !event.EgressIsolated {
		finding := &assurance.Finding{
			ID:           fmt.Sprintf("find-net-%d", now.UnixNano()),
			Subject:      subject,
			Control:      assurance.ControlRef{Namespace: "ckodex", ID: "network.isolated"},
			Severity:     "HIGH",
			Title:        "Unenforced egress isolation detected",
			Description:  fmt.Sprintf("Workload %s active without default-deny egress isolation policy", subject.URI()),
			DiscoveredAt: now,
		}
		return assurance.EvidenceEnvelope{}, finding, fmt.Errorf("network policy violation: unisolated egress")
	}

	payload := fmt.Sprintf("net|%s|policy=%s|isolated=true|%d", subject.URI(), event.AppliedPolicyRef, now.Unix())
	artifactDigest := assurance.ComputeStringDigest(payload)

	envelope := assurance.EvidenceEnvelope{
		Schema:          "assurance.ckodex.io/evidence/v1alpha1",
		ID:              fmt.Sprintf("ev-net-%d", now.UnixNano()),
		Subject:         subject,
		ObservationType: "network.flow.isolation",
		CapturedAt:      now,
		Producer:        o.observerIdentity,
		Artifact: assurance.EvidenceRef{
			URI:       fmt.Sprintf("cilium://flows/%s", subject.ID),
			Digest:    artifactDigest,
			MediaType: "application/vnd.cilium.flow+json",
		},
		IntegrityDigest: artifactDigest,
		Epoch:           epoch,
		ControlRefs: []assurance.ControlRef{
			{Namespace: "ckodex", ID: "network.isolated"},
		},
	}

	return envelope, nil, nil
}
