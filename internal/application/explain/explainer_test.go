package explain

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestExplainer_BuildExplainGraph(t *testing.T) {
	ctx := context.Background()
	expl := NewExplainer()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "payments/payments-api"}
	ctrl := assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
	now := time.Now().UTC()
	epoch := assurance.AssuranceEpoch{
		SubjectDigest: assurance.ComputeStringDigest(sub.URI()),
	}

	// 1. Assured State
	evalAssured := assurance.ClaimEvaluation{
		ID:           "eval-01",
		Subject:      sub,
		Control:      ctrl,
		State:        assurance.AssuranceStateAssured,
		Epoch:        epoch,
		EvidenceRoot: assurance.ComputeStringDigest("merkle-root"),
		EvaluatedAt:  now,
		ValidUntil:   now.Add(5 * time.Minute),
	}
	graphAssured := expl.BuildExplainGraph(ctx, sub, ctrl, evalAssured)
	if graphAssured.AssuranceState != assurance.AssuranceStateAssured {
		t.Fatalf("expected ASSURED state, got %s", graphAssured.AssuranceState)
	}
	if graphAssured.Completeness.Verified != 6 {
		t.Fatalf("expected 6 verified evidence items in assured graph, got %d", graphAssured.Completeness.Verified)
	}
	if graphAssured.Freshness != "current" {
		t.Fatalf("expected current freshness, got %s", graphAssured.Freshness)
	}
	renderedAssured := graphAssured.RenderText()
	if !strings.Contains(renderedAssured, "[PASS] non-root execution") {
		t.Fatal("expected PASS on non-root execution in assured graph")
	}

	// 2. Unknown State (No evidence)
	evalUnknown := assurance.ClaimEvaluation{
		ID:          "eval-02",
		Subject:     sub,
		Control:     ctrl,
		State:       assurance.AssuranceStateUnknown,
		Epoch:       epoch,
		EvaluatedAt: now,
	}
	graphUnknown := expl.BuildExplainGraph(ctx, sub, ctrl, evalUnknown)
	if graphUnknown.AssuranceState != assurance.AssuranceStateUnknown {
		t.Fatalf("expected UNKNOWN state, got %s", graphUnknown.AssuranceState)
	}
	if graphUnknown.Completeness.Verified != 0 {
		t.Fatalf("expected 0 verified items in unknown graph, got %d", graphUnknown.Completeness.Verified)
	}
	if graphUnknown.Freshness != "unknown" {
		t.Fatalf("expected unknown freshness, got %s", graphUnknown.Freshness)
	}
	renderedUnknown := graphUnknown.RenderText()
	if !strings.Contains(renderedUnknown, "[FAIL] non-root execution") {
		t.Fatal("expected FAIL on non-root execution in unknown graph")
	}

	// 3. Stale State
	evalStale := assurance.ClaimEvaluation{
		ID:          "eval-03",
		Subject:     sub,
		Control:     ctrl,
		State:       assurance.AssuranceStateStale,
		Epoch:       epoch,
		EvaluatedAt: now,
	}
	graphStale := expl.BuildExplainGraph(ctx, sub, ctrl, evalStale)
	if graphStale.Freshness != "stale" {
		t.Fatalf("expected stale freshness, got %s", graphStale.Freshness)
	}

	// 4. Failed State
	evalFailed := assurance.ClaimEvaluation{
		ID:          "eval-04",
		Subject:     sub,
		Control:     ctrl,
		State:       assurance.AssuranceStateFailed,
		Epoch:       epoch,
		EvaluatedAt: now,
	}
	graphFailed := expl.BuildExplainGraph(ctx, sub, ctrl, evalFailed)
	if graphFailed.AssuranceState != assurance.AssuranceStateFailed {
		t.Fatalf("expected FAILED state, got %s", graphFailed.AssuranceState)
	}

	// 5. Evidence-proportional ExplainGraph when eval.Evidence is provided
	evalSingleEv := assurance.ClaimEvaluation{
		ID:          "eval-05",
		Subject:     sub,
		Control:     ctrl,
		State:       assurance.AssuranceStateAssured,
		Epoch:       epoch,
		EvaluatedAt: now,
		Evidence: []assurance.EvidenceRef{
			{
				URI:       "evidence://cel/admission",
				Digest:    assurance.ComputeStringDigest("adm-payload"),
				MediaType: "application/json",
			},
		},
	}
	graphProp := expl.BuildExplainGraph(ctx, sub, ctrl, evalSingleEv)
	if graphProp.Completeness.Verified != 1 {
		t.Fatalf("expected 1 verified evidence category when only admission evidence is supplied, got %d", graphProp.Completeness.Verified)
	}
	if !graphProp.Evidence[0].Verified || graphProp.Evidence[0].Digest == "" {
		t.Fatalf("expected admission decision slot to be verified with digest, got %+v", graphProp.Evidence[0])
	}
	if graphProp.Evidence[1].Verified {
		t.Fatalf("expected signed OCI artifact slot to remain unverified when only admission evidence was supplied")
	}
}
