package explain

import (
	"context"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"strings"
	"testing"
	"time"
)

func TestExplanationContainsOnlySuppliedFacts(t *testing.T) {
	subject := assurance.SubjectRef{Scheme: "k8s", ID: "ns/Pod/app"}
	control := assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "SC-28", Version: "v5"}
	eval := assurance.ClaimEvaluation{Subject: subject, Control: control, State: assurance.AssuranceStateAssured, EvaluatedAt: time.Now(), Evidence: []assurance.EvidenceRef{{URI: "opaque://sigstore/spiffe/cilium", Digest: assurance.ComputeStringDigest("metadata"), MediaType: "application/json"}}, Completeness: assurance.EvidenceCompleteness{Required: 1, Present: 1, Verified: 1}}
	graph := NewExplainer().BuildExplainGraph(context.Background(), subject, control, eval)
	if graph.CanonicalControl != control.Canonical() || len(graph.AtomicRequirements) != 0 || len(graph.Implementations) != 0 || len(graph.Projections) != 0 || graph.Epoch != (assurance.AssuranceEpoch{}) {
		t.Fatalf("fabricated contract/implementation: %+v", graph)
	}
	if len(graph.Evidence) != 1 || graph.Evidence[0].Producer != "" || !graph.Evidence[0].CapturedAt.IsZero() || graph.Evidence[0].Verified {
		t.Fatal("reference became a verified envelope")
	}
	if graph.Applicability != "unknown" || graph.Authority != "unverified" {
		t.Fatal("state invented applicability or authority")
	}
	rendered := RenderText(graph, eval.Evidence)
	if strings.Contains(rendered, "[PASS]") || !strings.Contains(rendered, "EPOCH\nUNKNOWN") || !strings.Contains(rendered, eval.Evidence[0].URI) {
		t.Fatal(rendered)
	}
	different := control
	different.ID = "AC-6"
	if got := NewExplainer().BuildExplainGraph(context.Background(), subject, different, eval); got.AssuranceState != assurance.AssuranceStateUnknown || len(got.Evidence) != 0 {
		t.Fatal("evaluation transferred across controls")
	}
}
