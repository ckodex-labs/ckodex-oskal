package evaluation

import (
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestOfflineMaterialDoesNotEstablishCoherenceOrTrust(t *testing.T) {
	subject := assurance.SubjectRef{Scheme: "k8s", ID: "example/Pod/material"}
	control := assurance.ControlRef{Namespace: "example", ID: "observed"}
	now := time.Now().UTC()
	for _, envelopes := range [][]assurance.EvidenceEnvelope{nil, {{Subject: subject, Producer: assurance.AuthorityRef{Scheme: "spiffe", Subject: "example.test/observer"}, CapturedAt: now, Epoch: assurance.AssuranceEpoch{PolicyDigest: assurance.ComputeStringDigest("supplied-policy")}, Artifact: assurance.EvidenceRef{URI: "cas://sha256/supplied", Digest: assurance.ComputeStringDigest("supplied-bytes")}}}} {
		result := UnverifiedEvaluation(subject, control, envelopes, now)
		if result.State != assurance.AssuranceStateUnknown || result.Vector.Coherence != assurance.CoherenceUnknown || result.Vector.Authority != assurance.ValenceUnresolved || result.Vector.Integrity != assurance.ValenceUnresolved || result.EvidenceRoot != "" || result.Epoch.PolicyDigest != "" {
			t.Fatalf("local material acquired verified semantics: %+v", result)
		}
	}
}
