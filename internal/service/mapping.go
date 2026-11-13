package service

import (
	"maps"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	assessmentv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/assessment/v1"
	commonv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/control/v1"
	evidencev1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/evidence/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func coreSubject(s *commonv1.SubjectRef) assurance.SubjectRef {
	if s == nil {
		return assurance.SubjectRef{}
	}
	return assurance.SubjectRef{Scheme: s.Scheme, ID: s.Id, Attributes: maps.Clone(s.Attributes)}
}
func protoSubject(s assurance.SubjectRef) *commonv1.SubjectRef {
	return &commonv1.SubjectRef{Scheme: s.Scheme, Id: s.ID, Attributes: maps.Clone(s.Attributes)}
}
func coreControl(c *controlv1.ControlRef) assurance.ControlRef {
	if c == nil {
		return assurance.ControlRef{}
	}
	return assurance.ControlRef{Namespace: c.Namespace, ID: c.Id, Version: c.Version}
}
func protoControl(c assurance.ControlRef) *controlv1.ControlRef {
	return &controlv1.ControlRef{Namespace: c.Namespace, Id: c.ID, Version: c.Version}
}
func coreEpoch(e *commonv1.AssuranceEpoch) assurance.AssuranceEpoch {
	if e == nil {
		return assurance.AssuranceEpoch{}
	}
	return assurance.AssuranceEpoch{SubjectDigest: e.SubjectDigest, ImplementationDigest: e.ImplementationDigest, PolicyDigest: e.PolicyDigest, AuthorityDigest: e.AuthorityDigest, EnvironmentDigest: e.EnvironmentDigest}
}
func protoEpoch(e assurance.AssuranceEpoch) *commonv1.AssuranceEpoch {
	if e == (assurance.AssuranceEpoch{}) {
		return nil
	}
	return &commonv1.AssuranceEpoch{SubjectDigest: e.SubjectDigest, ImplementationDigest: e.ImplementationDigest, PolicyDigest: e.PolicyDigest, AuthorityDigest: e.AuthorityDigest, EnvironmentDigest: e.EnvironmentDigest}
}
func protoEvidence(refs []assurance.EvidenceRef) []*evidencev1.EvidenceRef {
	var out []*evidencev1.EvidenceRef
	for _, ref := range refs {
		out = append(out, &evidencev1.EvidenceRef{Uri: ref.URI, Digest: ref.Digest, MediaType: ref.MediaType})
	}
	return out
}
func protoCompleteness(c assurance.EvidenceCompleteness) *evidencev1.EvidenceCompleteness {
	return &evidencev1.EvidenceCompleteness{Required: int32(c.Required), Present: int32(c.Present), Verified: int32(c.Verified), Stale: int32(c.Stale), Missing: int32(c.Missing)}
}
func protoTime(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}
func protoValence(v assurance.Valence) commonv1.Valence {
	switch v {
	case assurance.ValencePositive:
		return commonv1.Valence_VALENCE_POSITIVE
	case assurance.ValenceNegative:
		return commonv1.Valence_VALENCE_NEGATIVE
	case assurance.ValenceMixed:
		return commonv1.Valence_VALENCE_MIXED
	case assurance.ValenceNeutral:
		return commonv1.Valence_VALENCE_NEUTRAL
	case assurance.ValenceUnresolved:
		return commonv1.Valence_VALENCE_UNRESOLVED
	}
	return commonv1.Valence_VALENCE_UNSPECIFIED
}
func protoCoherence(c assurance.Coherence) commonv1.Coherence {
	switch c {
	case assurance.CoherenceCoherent:
		return commonv1.Coherence_COHERENCE_COHERENT
	case assurance.CoherencePartiallyCoherent:
		return commonv1.Coherence_COHERENCE_PARTIALLY_COHERENT
	case assurance.CoherenceDecoherent:
		return commonv1.Coherence_COHERENCE_DECOHERENT
	case assurance.CoherenceReconciling:
		return commonv1.Coherence_COHERENCE_RECONCILING
	}
	return commonv1.Coherence_COHERENCE_UNSPECIFIED
}
func protoEvaluation(e assurance.ClaimEvaluation) *assessmentv1.ClaimEvaluation {
	v := e.Vector
	return &assessmentv1.ClaimEvaluation{Id: e.ID, Subject: protoSubject(e.Subject), Control: protoControl(e.Control), State: commonv1.AssuranceState(e.State), Epoch: protoEpoch(e.Epoch), Evidence: protoEvidence(e.Evidence), Completeness: protoCompleteness(e.Completeness), EvidenceRoot: e.EvidenceRoot, EvaluatedAt: protoTime(e.EvaluatedAt), ValidUntil: protoTime(e.ValidUntil), Trace: append([]string(nil), e.Trace...), Vector: &commonv1.AssuranceVector{Applicability: protoValence(v.Applicability), Conformance: protoValence(v.Conformance), Provenance: protoValence(v.Provenance), Integrity: protoValence(v.Integrity), Authority: protoValence(v.Authority), Identity: protoValence(v.Identity), Runtime: protoValence(v.Runtime), Freshness: protoValence(v.Freshness), Completeness: protoValence(v.Completeness), Coherence: protoCoherence(v.Coherence)}}
}
