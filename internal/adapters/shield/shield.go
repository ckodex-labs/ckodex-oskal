package shield

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// ModelForensics captures weight integrity and tamper checks (Section 59).
type ModelForensics struct {
	ModelURI      string  `json:"modelUri"`
	WeightsDigest string  `json:"weightsDigest"`
	Format        string  `json:"format"` // e.g. "safetensors", "gguf"
	TamperProof   bool    `json:"tamperProof"`
	AIBOMDigest   string  `json:"aibomDigest"`
	SafetyScore   float64 `json:"safetyScore"` // 0.0 - 1.0
}

// ShieldObserver represents the AI model security admission observer (Section 59).
type ShieldObserver struct {
	observerIdentity assurance.AuthorityRef
}

func NewShieldObserver(identity assurance.AuthorityRef) *ShieldObserver {
	if identity.Scheme == "" {
		identity = assurance.AuthorityRef{
			Scheme:      "spiffe",
			Subject:     "prod/ns/shield-system/sa/shield-admission-inspector",
			TrustDomain: "prod",
		}
	}
	return &ShieldObserver{observerIdentity: identity}
}

// BuildModelSubjectRef constructs a canonical subject reference for an AI Model.
func BuildModelSubjectRef(modelURI, digest string) assurance.SubjectRef {
	return assurance.SubjectRef{
		Scheme: "model",
		ID:     fmt.Sprintf("%s@%s", modelURI, digest),
		Attributes: map[string]string{
			"modelURI": modelURI,
			"digest":   digest,
			"type":     "foundation-model",
		},
	}
}

// BuildAgentSubjectRef constructs a canonical subject reference for an AI Agent.
func BuildAgentSubjectRef(agentID, version, promptDigest string) assurance.SubjectRef {
	return assurance.SubjectRef{
		Scheme: "agent",
		ID:     fmt.Sprintf("%s:%s", agentID, version),
		Attributes: map[string]string{
			"agentID":      agentID,
			"version":      version,
			"promptDigest": promptDigest,
			"type":         "autonomous-agent",
		},
	}
}

// GenerateModelEvidence creates evidence envelopes for model weights, AIBOM, and safety guardrails.
func (s *ShieldObserver) GenerateModelEvidence(
	subject assurance.SubjectRef,
	forensics ModelForensics,
	epoch assurance.AssuranceEpoch,
	now time.Time,
) ([]assurance.EvidenceEnvelope, *assurance.Finding, error) {
	if !forensics.TamperProof {
		finding := &assurance.Finding{
			ID:           fmt.Sprintf("find-shield-tamper-%d", now.UnixNano()),
			Subject:      subject,
			Control:      assurance.ControlRef{Namespace: "ckodex", ID: "ai.weight.integrity"},
			Severity:     "CRITICAL",
			Title:        "Model weight tampering detected",
			Description:  fmt.Sprintf("Weights for %s failed cryptographic integrity check", subject.URI()),
			DiscoveredAt: now,
		}
		return nil, finding, fmt.Errorf("shield security violation: weight tampering detected")
	}

	if forensics.SafetyScore < 0.80 {
		finding := &assurance.Finding{
			ID:           fmt.Sprintf("find-shield-safety-%d", now.UnixNano()),
			Subject:      subject,
			Control:      assurance.ControlRef{Namespace: "ckodex", ID: "ai.safety.guardrails"},
			Severity:     "HIGH",
			Title:        "Safety alignment score below threshold",
			Description:  fmt.Sprintf("Safety alignment score %.2f is below acceptable minimum 0.80", forensics.SafetyScore),
			DiscoveredAt: now,
		}
		return nil, finding, fmt.Errorf("shield security violation: safety alignment score insufficient")
	}

	// 1. Weight Forensics Evidence
	weightsPayload := fmt.Sprintf("weights|%s|%s|tamperProof=true|%d", subject.URI(), forensics.WeightsDigest, now.Unix())
	hW := sha256.Sum256([]byte(weightsPayload))
	weightsDig := "sha256:" + hex.EncodeToString(hW[:])

	weightsEnv := assurance.EvidenceEnvelope{
		Schema:          "assurance.ckodex.io/evidence/v1alpha1",
		ID:              fmt.Sprintf("ev-weights-%d", now.UnixNano()),
		Subject:         subject,
		ObservationType: "model.weights.forensics",
		CapturedAt:      now,
		Producer:        s.observerIdentity,
		Artifact: assurance.EvidenceRef{
			URI:       fmt.Sprintf("shield://weights/%s", forensics.WeightsDigest),
			Digest:    weightsDig,
			MediaType: "application/vnd.shield.weights+json",
		},
		IntegrityDigest: weightsDig,
		Epoch:           epoch,
		ControlRefs: []assurance.ControlRef{
			{Namespace: "ckodex", ID: "ai.weight.integrity"},
		},
	}

	// 2. AI-BOM Evidence
	aibomPayload := fmt.Sprintf("aibom|%s|%s|%d", subject.URI(), forensics.AIBOMDigest, now.Unix())
	hA := sha256.Sum256([]byte(aibomPayload))
	aibomDig := "sha256:" + hex.EncodeToString(hA[:])

	aibomEnv := assurance.EvidenceEnvelope{
		Schema:          "assurance.ckodex.io/evidence/v1alpha1",
		ID:              fmt.Sprintf("ev-aibom-%d", now.UnixNano()),
		Subject:         subject,
		ObservationType: "model.aibom",
		CapturedAt:      now,
		Producer:        s.observerIdentity,
		Artifact: assurance.EvidenceRef{
			URI:       fmt.Sprintf("shield://aibom/%s", forensics.AIBOMDigest),
			Digest:    aibomDig,
			MediaType: "application/vnd.cyclonedx.aibom+json",
		},
		IntegrityDigest: aibomDig,
		Epoch:           epoch,
		ControlRefs: []assurance.ControlRef{
			{Namespace: "ckodex", ID: "ai.provenance.aibom"},
		},
	}

	return []assurance.EvidenceEnvelope{weightsEnv, aibomEnv}, nil, nil
}
