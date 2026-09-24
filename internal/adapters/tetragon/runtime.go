package tetragon

import (
	"fmt"
	"time"

	"github.com/ckodex-labs/oskal/core/assurance"
)

// ProcessEvent models an eBPF-captured process execution fact from Tetragon.
type ProcessEvent struct {
	Binary         string   `json:"binary"`
	UID            uint32   `json:"uid"`
	GID            uint32   `json:"gid"`
	Capabilities   []string `json:"capabilities"`
	PodNamespace   string   `json:"podNamespace"`
	PodName        string   `json:"podName"`
	ContainerName  string   `json:"containerName"`
	ViolationFound bool     `json:"violationFound"`
	ViolationType  string   `json:"violationType,omitempty"`
}

// TetragonObserver transforms Tetragon telemetry into canonical assurance evidence.
type TetragonObserver struct {
	observerIdentity assurance.AuthorityRef
}

// NewTetragonObserver creates a new runtime observer.
func NewTetragonObserver(identity assurance.AuthorityRef) *TetragonObserver {
	if identity.Scheme == "" {
		identity = assurance.AuthorityRef{
			Scheme:      "spiffe",
			Subject:     "prod/ns/ckodex-evidence/sa/tetragon-collector",
			TrustDomain: "prod",
		}
	}
	return &TetragonObserver{observerIdentity: identity}
}

// GenerateProcessEvidence evaluates a process event and produces evidence.
func (o *TetragonObserver) GenerateProcessEvidence(
	subject assurance.SubjectRef,
	event ProcessEvent,
	epoch assurance.AssuranceEpoch,
	now time.Time,
) (assurance.EvidenceEnvelope, *assurance.Finding, error) {
	// Rule: run-as-non-root runtime violation check
	if event.UID == 0 {
		finding := &assurance.Finding{
			ID:           fmt.Sprintf("find-root-%d", now.UnixNano()),
			Subject:      subject,
			Control:      assurance.ControlRef{Namespace: "ckodex", ID: "container.least-privilege"},
			Severity:     "CRITICAL",
			Title:        "Runtime root execution detected",
			Description:  fmt.Sprintf("Process %s executed with UID 0 in container %s", event.Binary, event.ContainerName),
			DiscoveredAt: now,
		}
		return assurance.EvidenceEnvelope{}, finding, fmt.Errorf("runtime violation: UID 0 execution detected")
	}

	// Rule: capability violation check (e.g. CAP_SYS_ADMIN, CAP_NET_ADMIN)
	for _, capName := range event.Capabilities {
		if capName == "CAP_SYS_ADMIN" || capName == "CAP_NET_ADMIN" {
			finding := &assurance.Finding{
				ID:           fmt.Sprintf("find-cap-%d", now.UnixNano()),
				Subject:      subject,
				Control:      assurance.ControlRef{Namespace: "ckodex", ID: "container.least-privilege"},
				Severity:     "HIGH",
				Title:        "Prohibited capability exercise detected",
				Description:  fmt.Sprintf("Process %s exercised prohibited capability %s", event.Binary, capName),
				DiscoveredAt: now,
			}
			return assurance.EvidenceEnvelope{}, finding, fmt.Errorf("runtime violation: %s exercised", capName)
		}
	}

	payload := fmt.Sprintf("proc|%s|%s|uid=%d|%d", subject.URI(), event.Binary, event.UID, now.Unix())
	artifactDigest := assurance.ComputeStringDigest(payload)

	envelope := assurance.EvidenceEnvelope{
		Schema:          "assurance.ckodex.io/evidence/v1alpha1",
		ID:              fmt.Sprintf("ev-proc-%d", now.UnixNano()),
		Subject:         subject,
		ObservationType: "workload.runtime.process",
		CapturedAt:      now,
		Producer:        o.observerIdentity,
		Artifact: assurance.EvidenceRef{
			URI:       fmt.Sprintf("tetragon://events/%s", subject.ID),
			Digest:    artifactDigest,
			MediaType: "application/vnd.tetragon.event+json",
		},
		IntegrityDigest: artifactDigest,
		Epoch:           epoch,
		ControlRefs: []assurance.ControlRef{
			{Namespace: "ckodex", ID: "container.least-privilege"},
		},
	}

	return envelope, nil, nil
}
