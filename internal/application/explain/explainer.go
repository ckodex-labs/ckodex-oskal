package explain

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// Explainer projects supplied evaluations. It is not an evidence verifier and
// cannot infer enforcement, applicability, producers or capture time from a URI.
type Explainer struct{}

func NewExplainer() *Explainer { return &Explainer{} }

func (e *Explainer) BuildExplainGraph(ctx context.Context, subject assurance.SubjectRef, control assurance.ControlRef, eval assurance.ClaimEvaluation) assurance.ExplainGraph {
	graph := assurance.ExplainGraph{Subject: subject, Control: control, CanonicalControl: control.Canonical(), Applicability: "unknown", Freshness: "unknown", Authority: "unverified", AssuranceState: assurance.AssuranceStateUnknown}
	if ctx.Err() != nil || eval.Subject.URI() != subject.URI() || !maps.Equal(eval.Subject.Attributes, subject.Attributes) || eval.Control != control {
		return graph
	}
	graph.AssuranceState = eval.State
	graph.Epoch = eval.Epoch
	graph.Completeness = eval.Completeness
	graph.EvidenceRoot = eval.EvidenceRoot
	if eval.Vector.Applicability == assurance.ValencePositive {
		graph.Applicability = "applicable"
	}
	if eval.Vector.Authority == assurance.ValencePositive {
		graph.Authority = "verified"
	}
	if eval.Vector.Freshness == assurance.ValencePositive {
		graph.Freshness = "current at evaluation"
	}
	if eval.State == assurance.AssuranceStateStale {
		graph.Freshness = "stale"
	}
	// References do not contain producer identity or capture timestamps. Leave
	// those fields absent, and never infer per-reference verification from state.
	for _, ref := range eval.Evidence {
		graph.Evidence = append(graph.Evidence, assurance.ExplainEvidenceItem{Type: ref.MediaType, Digest: ref.Digest})
	}
	return graph
}

// RenderText preserves unknowns rather than the legacy graph renderer's binary
// PASS/FAIL labels or hash of an empty epoch. References remain actual references.
func RenderText(graph assurance.ExplainGraph, refs []assurance.EvidenceRef) string {
	var text strings.Builder
	fmt.Fprintf(&text, "SUBJECT\n%s\n\nCONTROL\n%s\n\nAPPLICABILITY\n%s\n\nASSURANCE\n%s\n\n", graph.Subject.URI(), graph.CanonicalControl, graph.Applicability, graph.AssuranceState)
	fmt.Fprintf(&text, "COMPLETENESS\n%d verified / %d required\n\nAUTHORITY\n%s\n\nFRESHNESS\n%s\n\n", graph.Completeness.Verified, graph.Completeness.Required, graph.Authority, graph.Freshness)
	text.WriteString("EPOCH\n")
	if graph.Epoch == (assurance.AssuranceEpoch{}) {
		text.WriteString("UNKNOWN\n")
	} else {
		fmt.Fprintf(&text, "%s\n", graph.Epoch.CompositeDigest())
	}
	text.WriteString("\nEVIDENCE REFERENCES (producer and capture time unavailable)\n")
	for _, ref := range refs {
		fmt.Fprintf(&text, "%s %s %s\n", ref.URI, ref.Digest, ref.MediaType)
	}
	fmt.Fprintf(&text, "\nEVIDENCE ROOT\n%s\n", graph.EvidenceRoot)
	return text.String()
}
