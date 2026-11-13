package evaluation

import (
	"fmt"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// UnverifiedEvaluation exposes supplied material without inferring admission,
// trust, contract completeness, current epoch, or a verified evidence root.
func UnverifiedEvaluation(subject assurance.SubjectRef, control assurance.ControlRef, envelopes []assurance.EvidenceEnvelope, now time.Time) assurance.ClaimEvaluation {
	result := assurance.ClaimEvaluation{ID: "unverified-" + subject.URI() + "-" + control.Canonical(), Subject: subject, Control: control, State: assurance.AssuranceStateUnknown, Vector: assurance.NewDefaultAssuranceVector(), EvaluatedAt: now, Trace: []string{"unverified material only: no authored effective contract, trusted producer verification, or authoritative epoch was supplied"}}
	result.Vector.Coherence = assurance.CoherenceUnknown
	for _, envelope := range envelopes {
		if envelope.Subject.URI() != subject.URI() {
			continue
		}
		result.Completeness.Present++
		if envelope.Artifact.URI != "" && envelope.Artifact.Digest != "" {
			result.Evidence = append(result.Evidence, envelope.Artifact)
		}
	}
	return result
}

// ParseControlReference requires explicit canonical namespace:id[@version].
// A bare control ID never establishes a framework or version.
func ParseControlReference(raw string) (assurance.ControlRef, error) {
	namespace, rest, ok := strings.Cut(raw, ":")
	if !ok || strings.Contains(rest, ":") {
		return assurance.ControlRef{}, fmt.Errorf("control must be an explicit namespace:id[@version] reference")
	}
	id, version, versioned := strings.Cut(rest, "@")
	if strings.Contains(version, "@") || (versioned && version == "") {
		return assurance.ControlRef{}, fmt.Errorf("invalid control version in %q", raw)
	}
	control := assurance.ControlRef{Namespace: namespace, ID: id, Version: version}
	if err := control.Validate(); err != nil {
		return assurance.ControlRef{}, err
	}
	return control, nil
}

// UnverifiedExplanation describes only supplied facts, without inferring a control
// decomposition, implementation binding, applicability, producer, or trust state.
func UnverifiedExplanation(result assurance.ClaimEvaluation) string {
	var text strings.Builder
	fmt.Fprintf(&text, "SUBJECT\n%s\n\nCONTROL\n%s\n\nASSURANCE\nUNKNOWN\n\nSUPPLIED MATERIAL\n%d envelopes; %d references; 0 verified\n\nAUTHORITY\nUNKNOWN\n\nEPOCH\nUNKNOWN\n\nCONTRACT\nUNKNOWN\n", result.Subject.URI(), result.Control.Canonical(), result.Completeness.Present, len(result.Evidence))
	for _, reference := range result.Evidence {
		fmt.Fprintf(&text, "\nUNVERIFIED REFERENCE\n%s\n%s\n", reference.Digest, reference.URI)
	}
	text.WriteString("\nVerification requires an authored effective contract, authoritative binding context, actual artifact bytes, and explicitly trusted producer keys.\n")
	return text.String()
}
