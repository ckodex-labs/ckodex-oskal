package assurance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Claim represents a statement that a subject satisfies a control.
type Claim struct {
	ID          string         `json:"id"`
	Subject     SubjectRef     `json:"subject"`
	Control     ControlRef     `json:"control"`
	TargetState AssuranceState `json:"targetState"`
}

// ClaimEvaluation is the deterministic evaluation of a Claim against verified evidence.
type ClaimEvaluation struct {
	ID           string               `json:"id"`
	Control      ControlRef           `json:"control"`
	Subject      SubjectRef           `json:"subject"`
	State        AssuranceState       `json:"state"`
	Vector       AssuranceVector      `json:"vector"`
	Epoch        AssuranceEpoch       `json:"epoch"`
	Evidence     []EvidenceRef        `json:"evidence"`
	Completeness EvidenceCompleteness `json:"completeness"`
	EvidenceRoot string               `json:"evidenceRoot"`
	EvaluatedAt  time.Time            `json:"evaluatedAt"`
	ValidUntil   time.Time            `json:"validUntil"`
	Trace        []string             `json:"trace,omitempty"`
}

// Finding represents a confirmed, material non-conformance or vulnerability.
type Finding struct {
	ID           string        `json:"id"`
	Subject      SubjectRef    `json:"subject"`
	Control      ControlRef    `json:"control"`
	Severity     string        `json:"severity"` // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"
	Title        string        `json:"title"`
	Description  string        `json:"description"`
	DiscoveredAt time.Time     `json:"discoveredAt"`
	EvidenceRefs []EvidenceRef `json:"evidenceRefs"`
}

// ControlException models an authorized, bounded derogation (Invariant I-05).
type ControlException struct {
	ID                   string         `json:"id"`
	Subject              SubjectRef     `json:"subject"`
	Controls             []ControlRef   `json:"controls"`
	Justification        string         `json:"justification"`
	RequiredApprovers    []AuthorityRef `json:"requiredApprovers"`
	NotBefore            time.Time      `json:"notBefore"`
	NotAfter             time.Time      `json:"notAfter"`
	CompensatingControls []ControlRef   `json:"compensatingControls"`
}

// IsValidAt checks whether this exception is temporally valid (never permanent).
func (e ControlException) IsValidAt(t time.Time) bool {
	if e.NotAfter.IsZero() || e.NotBefore.IsZero() {
		return false // Mandatory time boundaries
	}
	return !t.Before(e.NotBefore) && !t.After(e.NotAfter)
}

// AppliesTo checks if the exception covers a specific subject and control.
func (e ControlException) AppliesTo(sub SubjectRef, ctrl ControlRef) bool {
	if e.Subject.URI() != sub.URI() {
		return false
	}
	for _, c := range e.Controls {
		if c.Canonical() == ctrl.Canonical() || (c.Namespace == ctrl.Namespace && c.ID == ctrl.ID) {
			return true
		}
	}
	return false
}

// AssurancePolicy specifies higher-level evaluation rules.
type AssurancePolicy struct {
	Name                     string         `json:"name"`
	RequiredState            AssuranceState `json:"requiredState"`
	RequireFresh             bool           `json:"requireFresh"`
	FailOnConfirmedViolation bool           `json:"failOnConfirmedViolation"`
	UnknownIsViolation       bool           `json:"unknownIsViolation"`
	MaxEvaluationAge         time.Duration  `json:"maxEvaluationAge"`
}

// ControlReceipt is a cryptographically verifiable record of an evaluation (Section 41).
type ControlReceipt struct {
	Subject      SubjectRef     `json:"subject"`
	Control      ControlRef     `json:"control"`
	State        AssuranceState `json:"state"`
	Epoch        AssuranceEpoch `json:"epoch"`
	EvidenceRoot string         `json:"evidenceRoot"`
	Evaluator    AuthorityRef   `json:"evaluator"`
	EvaluatedAt  time.Time      `json:"evaluatedAt"`
	Signature    string         `json:"signature,omitempty"`
}

// CanonicalBytes returns deterministic bytes for signing or verification.
func (r ControlReceipt) CanonicalBytes() []byte {
	raw := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%d",
		r.Subject.URI(),
		r.Control.Canonical(),
		r.State.String(),
		r.Epoch.CompositeDigest(),
		r.EvidenceRoot,
		r.Evaluator.Canonical(),
		r.EvaluatedAt.UnixNano(),
	)
	return []byte(raw)
}

// Digest computes the receipt payload hash.
func (r ControlReceipt) Digest() string {
	h := sha256.Sum256(r.CanonicalBytes())
	return "sha256:" + hex.EncodeToString(h[:])
}

// ExplainAtomicRequirement models individual decomposed atoms of a canonical control.
type ExplainAtomicRequirement struct {
	ID        string `json:"id"`
	Satisfied bool   `json:"satisfied"`
	Details   string `json:"details"`
}

// ExplainImplementation models concrete implementation realizing the control.
type ExplainImplementation struct {
	Requirement string `json:"requirement"`
	Provider    string `json:"provider"`
	Digest      string `json:"digest"`
	Purpose     string `json:"purpose"`
}

// ExplainEvidenceItem models a verified piece of evidence in the graph.
type ExplainEvidenceItem struct {
	Type       string    `json:"type"`
	CapturedAt time.Time `json:"capturedAt"`
	Producer   string    `json:"producer"`
	Digest     string    `json:"digest"`
	Verified   bool      `json:"verified"`
}

// ExplainGraph models the full reverse-traceable graph for Explain(subject, control) (Section 49 & 51).
type ExplainGraph struct {
	Subject            SubjectRef                 `json:"subject"`
	Control            ControlRef                 `json:"control"`
	CanonicalControl   string                     `json:"canonicalControl"`
	Applicability      string                     `json:"applicability"` // "applicable", "inapplicable"
	AtomicRequirements []ExplainAtomicRequirement `json:"atomicRequirements"`
	Implementations    []ExplainImplementation    `json:"implementations"`
	Evidence           []ExplainEvidenceItem      `json:"evidence"`
	Completeness       EvidenceCompleteness       `json:"completeness"`
	Freshness          string                     `json:"freshness"` // "current", "stale", "expired"
	Authority          string                     `json:"authority"` // "verified", "unverified"
	Epoch              AssuranceEpoch             `json:"epoch"`
	AssuranceState     AssuranceState             `json:"assuranceState"`
	EvidenceRoot       string                     `json:"evidenceRoot"`
	Projections        map[string]string          `json:"projections,omitempty"`
}

// RenderText formats the explanation to match the canonical terminal output in Section 51.
func (g ExplainGraph) RenderText() string {
	var sb strings.Builder

	sb.WriteString("SUBJECT\n")
	sb.WriteString(g.Subject.URI() + "\n\n")

	sb.WriteString("CONTROL\n")
	sb.WriteString(g.Control.Canonical() + "\n\n")

	sb.WriteString("CANONICAL CONTROL\n")
	sb.WriteString(g.CanonicalControl + "\n\n")

	sb.WriteString("APPLICABILITY\n")
	if g.Applicability == "applicable" {
		sb.WriteString("[PASS] applicable\n\n")
	} else {
		sb.WriteString("[FAIL] " + g.Applicability + "\n\n")
	}

	sb.WriteString("ATOMIC REQUIREMENTS\n\n")
	for _, atom := range g.AtomicRequirements {
		icon := "[PASS]"
		if !atom.Satisfied {
			icon = "[FAIL]"
		}
		fmt.Fprintf(&sb, "%s %s\n", icon, atom.ID)
	}
	sb.WriteString("\n")

	sb.WriteString("IMPLEMENTATIONS\n\n")
	for _, imp := range g.Implementations {
		fmt.Fprintf(&sb, "%s\n  %s\n  digest %s\n\n", imp.Requirement, imp.Provider, imp.Digest)
	}

	sb.WriteString("EVIDENCE\n\n")
	for _, ev := range g.Evidence {
		icon := "[PASS]"
		if !ev.Verified {
			icon = "[FAIL]"
		}
		fmt.Fprintf(&sb, "%s %s\n", icon, ev.Type)
	}
	sb.WriteString("\n")

	sb.WriteString("COMPLETENESS\n")
	fmt.Fprintf(&sb, "%d / %d required\n\n", g.Completeness.Verified, g.Completeness.Required)

	sb.WriteString("FRESHNESS\n")
	sb.WriteString(g.Freshness + "\n\n")

	sb.WriteString("AUTHORITY\n")
	sb.WriteString(g.Authority + "\n\n")

	sb.WriteString("EPOCH\n")
	sb.WriteString(g.Epoch.CompositeDigest() + "\n\n")

	sb.WriteString("ASSURANCE\n")
	sb.WriteString(g.AssuranceState.String() + "\n\n")

	if len(g.Projections) > 0 {
		sb.WriteString("OSCAL PROJECTIONS\n\n")
		for k, v := range g.Projections {
			fmt.Fprintf(&sb, "%s\n  %s\n\n", k, v)
		}
	}

	sb.WriteString("EVIDENCE ROOT\n")
	sb.WriteString(g.EvidenceRoot + "\n")

	return sb.String()
}
