package assurance

import (
	"encoding/json"
	"errors"
	"fmt"
)

// AssuranceState represents the canonical assurance lifecycle states.
type AssuranceState int

const (
	AssuranceStateUnspecified AssuranceState = 0
	AssuranceStateUnknown     AssuranceState = 1
	AssuranceStateObserved    AssuranceState = 2
	AssuranceStateVerified    AssuranceState = 3
	AssuranceStateAssured     AssuranceState = 4
	AssuranceStateStale       AssuranceState = 5
	AssuranceStateFailed      AssuranceState = 6
)

var stateNames = map[AssuranceState]string{
	AssuranceStateUnspecified: "UNSPECIFIED",
	AssuranceStateUnknown:     "UNKNOWN",
	AssuranceStateObserved:    "OBSERVED",
	AssuranceStateVerified:    "VERIFIED",
	AssuranceStateAssured:     "ASSURED",
	AssuranceStateStale:       "STALE",
	AssuranceStateFailed:      "FAILED",
}

var stateValues = map[string]AssuranceState{
	"UNSPECIFIED": AssuranceStateUnspecified,
	"UNKNOWN":     AssuranceStateUnknown,
	"OBSERVED":    AssuranceStateObserved,
	"VERIFIED":    AssuranceStateVerified,
	"ASSURED":     AssuranceStateAssured,
	"STALE":       AssuranceStateStale,
	"FAILED":      AssuranceStateFailed,
}

func (s AssuranceState) String() string {
	if name, ok := stateNames[s]; ok {
		return name
	}
	return fmt.Sprintf("AssuranceState(%d)", s)
}

func ParseAssuranceState(str string) (AssuranceState, error) {
	if val, ok := stateValues[str]; ok {
		return val, nil
	}
	return AssuranceStateUnspecified, fmt.Errorf("invalid assurance state: %s", str)
}

func (s AssuranceState) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *AssuranceState) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	val, err := ParseAssuranceState(str)
	if err != nil {
		return err
	}
	*s = val
	return nil
}

// TransitionEvent represents stimuli causing state machine transitions.
type TransitionEvent string

const (
	EventEvidenceIngested   TransitionEvent = "EVIDENCE_INGESTED"
	EventEvidenceVerified   TransitionEvent = "EVIDENCE_VERIFIED"
	EventPolicyAssured      TransitionEvent = "POLICY_ASSURED"
	EventEpochChanged       TransitionEvent = "EPOCH_CHANGED"
	EventEvidenceExpired    TransitionEvent = "EVIDENCE_EXPIRED"
	EventReevaluated        TransitionEvent = "REEVALUATED"
	EventViolationConfirmed TransitionEvent = "VIOLATION_CONFIRMED"
	EventEvidenceInvalid    TransitionEvent = "EVIDENCE_INVALID"
	EventReset              TransitionEvent = "RESET"
)

var (
	ErrInvalidTransition = errors.New("invalid assurance state transition")
)

// Transition computes the next state given the current state and stimulus.
// Canonical FSM:
//
//	UNKNOWN  + EVIDENCE_INGESTED   -> OBSERVED
//	OBSERVED + EVIDENCE_VERIFIED   -> VERIFIED
//	VERIFIED + POLICY_ASSURED      -> ASSURED
//	ASSURED  + EPOCH_CHANGED       -> STALE
//	ASSURED  + EVIDENCE_EXPIRED    -> STALE
//	STALE    + REEVALUATED         -> OBSERVED
//	ANY      + VIOLATION_CONFIRMED -> FAILED
//	ANY      + EVIDENCE_INVALID    -> UNKNOWN
//	ANY      + RESET               -> UNKNOWN
func Transition(current AssuranceState, event TransitionEvent) (AssuranceState, error) {
	switch event {
	case EventViolationConfirmed:
		return AssuranceStateFailed, nil
	case EventEvidenceInvalid, EventReset:
		return AssuranceStateUnknown, nil
	}

	switch current {
	case AssuranceStateUnknown, AssuranceStateUnspecified:
		if event == EventEvidenceIngested {
			return AssuranceStateObserved, nil
		}
	case AssuranceStateObserved:
		if event == EventEvidenceVerified {
			return AssuranceStateVerified, nil
		}
	case AssuranceStateVerified:
		if event == EventPolicyAssured {
			return AssuranceStateAssured, nil
		}
		if event == EventEpochChanged || event == EventEvidenceExpired {
			return AssuranceStateStale, nil
		}
	case AssuranceStateAssured:
		if event == EventEpochChanged || event == EventEvidenceExpired {
			return AssuranceStateStale, nil
		}
	case AssuranceStateStale:
		if event == EventReevaluated || event == EventEvidenceIngested {
			return AssuranceStateObserved, nil
		}
	case AssuranceStateFailed:
		if event == EventReevaluated {
			return AssuranceStateObserved, nil
		}
	}

	return current, fmt.Errorf("%w: cannot transition from %s via %s", ErrInvalidTransition, current, event)
}

// Presence semantics (Rule 14: EMPTY is not negative).
type Presence string

const (
	PresenceEmpty    Presence = "EMPTY"
	PresencePresent  Presence = "PRESENT"
	PresenceUnknown  Presence = "UNKNOWN"
	PresenceRedacted Presence = "REDACTED"
)

// Valence describes the directional effect of evidence relative to a proposition.
type Valence string

const (
	ValencePositive   Valence = "POSITIVE"
	ValenceNegative   Valence = "NEGATIVE"
	ValenceNeutral    Valence = "NEUTRAL"
	ValenceMixed      Valence = "MIXED"
	ValenceUnresolved Valence = "UNRESOLVED"
)

// Coherence describes whether representations form one trustworthy state.
type Coherence string

const (
	CoherenceCoherent          Coherence = "COHERENT"
	CoherencePartiallyCoherent Coherence = "PARTIALLY_COHERENT"
	CoherenceDecoherent        Coherence = "DECOHERENT"
	CoherenceReconciling       Coherence = "RECONCILING"
)

// AssuranceVector models continuous multidimensional state (Rule 13).
type AssuranceVector struct {
	Applicability Valence   `json:"applicability"`
	Conformance   Valence   `json:"conformance"`
	Provenance    Valence   `json:"provenance"`
	Integrity     Valence   `json:"integrity"`
	Authority     Valence   `json:"authority"`
	Identity      Valence   `json:"identity"`
	Runtime       Valence   `json:"runtime"`
	Freshness     Valence   `json:"freshness"`
	Completeness  Valence   `json:"completeness"`
	Coherence     Coherence `json:"coherence"`
}

// NewDefaultAssuranceVector initializes a vector in the UNRESOLVED/UNKNOWN state.
func NewDefaultAssuranceVector() AssuranceVector {
	return AssuranceVector{
		Applicability: ValenceUnresolved,
		Conformance:   ValenceUnresolved,
		Provenance:    ValenceUnresolved,
		Integrity:     ValenceUnresolved,
		Authority:     ValenceUnresolved,
		Identity:      ValenceUnresolved,
		Runtime:       ValenceUnresolved,
		Freshness:     ValenceUnresolved,
		Completeness:  ValenceUnresolved,
		Coherence:     CoherenceCoherent,
	}
}

// VectorResolutionPolicy guides derivation of AssuranceState from an AssuranceVector.
type VectorResolutionPolicy struct {
	RequireFresh       bool `json:"requireFresh"`
	UnknownIsViolation bool `json:"unknownIsViolation"`
}

// Resolve derives top-level AssuranceState from the vector (Rule 22: Hard invariants dominate scores).
func (v AssuranceVector) Resolve(policy VectorResolutionPolicy) AssuranceState {
	// Rule 16: Anti / Negative invariant violation dominates
	if v.Conformance == ValenceNegative || v.Integrity == ValenceNegative || v.Authority == ValenceNegative {
		return AssuranceStateFailed
	}

	// Decoherence indicates divergent state that cannot be assured
	if v.Coherence == CoherenceDecoherent {
		return AssuranceStateFailed
	}

	// Check if mandatory freshness is stale
	if policy.RequireFresh && v.Freshness == ValenceNegative {
		return AssuranceStateStale
	}

	// Check if any mandatory element is unresolved or missing
	hasUnknown := v.Applicability == ValenceUnresolved ||
		v.Conformance == ValenceUnresolved ||
		v.Provenance == ValenceUnresolved ||
		v.Integrity == ValenceUnresolved ||
		v.Authority == ValenceUnresolved ||
		v.Identity == ValenceUnresolved ||
		v.Freshness == ValenceUnresolved ||
		v.Completeness == ValenceUnresolved

	if hasUnknown {
		if policy.UnknownIsViolation {
			return AssuranceStateFailed
		}
		return AssuranceStateUnknown
	}

	// Completeness missing required evidence cannot be ASSURED
	if v.Completeness != ValencePositive {
		if policy.UnknownIsViolation {
			return AssuranceStateFailed
		}
		return AssuranceStateUnknown
	}

	// If all dimensions are positively verified
	if v.Applicability == ValencePositive &&
		v.Conformance == ValencePositive &&
		v.Provenance == ValencePositive &&
		v.Integrity == ValencePositive &&
		v.Authority == ValencePositive &&
		v.Identity == ValencePositive &&
		v.Freshness == ValencePositive &&
		v.Completeness == ValencePositive {
		return AssuranceStateAssured
	}

	return AssuranceStateObserved
}
