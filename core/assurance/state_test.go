package assurance

import (
	"encoding/json"
	"testing"
)

func TestAssuranceStateStringAndParse(t *testing.T) {
	states := []AssuranceState{
		AssuranceStateUnknown,
		AssuranceStateObserved,
		AssuranceStateVerified,
		AssuranceStateAssured,
		AssuranceStateStale,
		AssuranceStateFailed,
	}

	for _, s := range states {
		str := s.String()
		parsed, err := ParseAssuranceState(str)
		if err != nil {
			t.Fatalf("failed to parse state %s: %v", str, err)
		}
		if parsed != s {
			t.Fatalf("expected %v, got %v", s, parsed)
		}

		data, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("failed to marshal state %s: %v", str, err)
		}
		var unmarshaled AssuranceState
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("failed to unmarshal state %s: %v", str, err)
		}
		if unmarshaled != s {
			t.Fatalf("expected unmarshaled %v, got %v", s, unmarshaled)
		}
	}
}

func TestCanonicalFSMTransitions(t *testing.T) {
	// UNKNOWN -> OBSERVED
	s, err := Transition(AssuranceStateUnknown, EventEvidenceIngested)
	if err != nil || s != AssuranceStateObserved {
		t.Fatalf("expected OBSERVED, got %v (err: %v)", s, err)
	}

	// OBSERVED -> VERIFIED
	s, err = Transition(s, EventEvidenceVerified)
	if err != nil || s != AssuranceStateVerified {
		t.Fatalf("expected VERIFIED, got %v (err: %v)", s, err)
	}

	// VERIFIED -> ASSURED
	s, err = Transition(s, EventPolicyAssured)
	if err != nil || s != AssuranceStateAssured {
		t.Fatalf("expected ASSURED, got %v (err: %v)", s, err)
	}

	// ASSURED -> STALE on epoch change
	s, err = Transition(s, EventEpochChanged)
	if err != nil || s != AssuranceStateStale {
		t.Fatalf("expected STALE, got %v (err: %v)", s, err)
	}

	// STALE -> OBSERVED on re-evaluation
	s, err = Transition(s, EventReevaluated)
	if err != nil || s != AssuranceStateObserved {
		t.Fatalf("expected OBSERVED, got %v (err: %v)", s, err)
	}

	// Any state -> FAILED on confirmed violation
	s, err = Transition(AssuranceStateAssured, EventViolationConfirmed)
	if err != nil || s != AssuranceStateFailed {
		t.Fatalf("expected FAILED, got %v (err: %v)", s, err)
	}

	// Any state -> UNKNOWN on evidence corruption
	s, err = Transition(AssuranceStateFailed, EventEvidenceInvalid)
	if err != nil || s != AssuranceStateUnknown {
		t.Fatalf("expected UNKNOWN, got %v (err: %v)", s, err)
	}
}

func TestInvalidTransitions(t *testing.T) {
	// Cannot jump directly from UNKNOWN to ASSURED without evidence verification
	_, err := Transition(AssuranceStateUnknown, EventPolicyAssured)
	if err == nil {
		t.Fatalf("expected error transitioning from UNKNOWN via POLICY_ASSURED")
	}

	// Cannot jump from OBSERVED directly to ASSURED without verification
	_, err = Transition(AssuranceStateObserved, EventPolicyAssured)
	if err == nil {
		t.Fatalf("expected error transitioning from OBSERVED via POLICY_ASSURED")
	}
}

func TestVectorStateResolution(t *testing.T) {
	policy := VectorResolutionPolicy{
		RequireFresh:       true,
		UnknownIsViolation: false,
	}

	// Default vector is unresolved -> UNKNOWN
	v := NewDefaultAssuranceVector()
	if s := v.Resolve(policy); s != AssuranceStateUnknown {
		t.Fatalf("expected default vector to resolve to UNKNOWN, got %s", s)
	}

	// All positive -> ASSURED
	vAllPositive := AssuranceVector{
		Applicability: ValencePositive,
		Conformance:   ValencePositive,
		Provenance:    ValencePositive,
		Integrity:     ValencePositive,
		Authority:     ValencePositive,
		Identity:      ValencePositive,
		Runtime:       ValencePositive,
		Freshness:     ValencePositive,
		Completeness:  ValencePositive,
		Coherence:     CoherenceCoherent,
	}
	if s := vAllPositive.Resolve(policy); s != AssuranceStateAssured {
		t.Fatalf("expected all positive vector to resolve to ASSURED, got %s", s)
	}

	// Hard Invariant: Anti/Negative conformance dominates -> FAILED
	vAnti := vAllPositive
	vAnti.Conformance = ValenceNegative
	if s := vAnti.Resolve(policy); s != AssuranceStateFailed {
		t.Fatalf("expected negative conformance to dominate and resolve to FAILED, got %s", s)
	}

	// Hard Invariant: Decoherence -> FAILED
	vDecoherent := vAllPositive
	vDecoherent.Coherence = CoherenceDecoherent
	if s := vDecoherent.Resolve(policy); s != AssuranceStateFailed {
		t.Fatalf("expected decoherence to resolve to FAILED, got %s", s)
	}

	// Stale freshness -> STALE
	vStale := vAllPositive
	vStale.Freshness = ValenceNegative
	if s := vStale.Resolve(policy); s != AssuranceStateStale {
		t.Fatalf("expected stale freshness to resolve to STALE, got %s", s)
	}

	// Incomplete evidence -> UNKNOWN
	vIncomplete := vAllPositive
	vIncomplete.Completeness = ValenceUnresolved
	if s := vIncomplete.Resolve(policy); s != AssuranceStateUnknown {
		t.Fatalf("expected incomplete evidence to resolve to UNKNOWN, got %s", s)
	}
}
