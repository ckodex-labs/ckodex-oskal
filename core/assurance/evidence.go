package assurance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// SubjectRef uniquely and stably identifies any evaluated entity.
type SubjectRef struct {
	Scheme     string            `json:"scheme"`
	ID         string            `json:"id"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// URI returns the canonical URI for this subject.
func (s SubjectRef) URI() string {
	if s.Scheme == "" {
		return s.ID
	}
	return fmt.Sprintf("%s://%s", s.Scheme, s.ID)
}

// Digest computes a content-addressed digest of the subject reference.
func (s SubjectRef) Digest() string {
	raw := fmt.Sprintf("%s|%s|%s", s.Scheme, s.ID, ComputeMapDigest(s.Attributes))
	h := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(h[:])
}

// ControlRef identifies a standard or canonical security control.
type ControlRef struct {
	Namespace string `json:"namespace"`
	ID        string `json:"id"`
	Version   string `json:"version,omitempty"`
}

// Canonical returns the standard string representation (e.g. "ckodex:container.least-privilege").
func (c ControlRef) Canonical() string {
	if c.Version != "" {
		return fmt.Sprintf("%s:%s@%s", c.Namespace, c.ID, c.Version)
	}
	return fmt.Sprintf("%s:%s", c.Namespace, c.ID)
}

// ImplementationPurpose defines control realization purpose.
type ImplementationPurpose string

const (
	PurposePreventive    ImplementationPurpose = "preventive"
	PurposeDetective     ImplementationPurpose = "detective"
	PurposeCorrective    ImplementationPurpose = "corrective"
	PurposeCompensating  ImplementationPurpose = "compensating"
	PurposeInformational ImplementationPurpose = "informational"
)

// ImplementationRef identifies a realization mechanism.
type ImplementationRef struct {
	Provider string                `json:"provider"`
	ID       string                `json:"id"`
	Digest   string                `json:"digest"`
	Purpose  ImplementationPurpose `json:"purpose"`
}

// AuthorityRef identifies the authority backing an assertion or signature.
type AuthorityRef struct {
	Scheme      string `json:"scheme"`
	Subject     string `json:"subject"`
	TrustDomain string `json:"trustDomain,omitempty"`
}

// Canonical returns the identity string.
func (a AuthorityRef) Canonical() string {
	if a.Scheme == "" {
		return a.Subject
	}
	return fmt.Sprintf("%s://%s", a.Scheme, a.Subject)
}

// EvidenceRef points to an immutable stored evidence artifact.
type EvidenceRef struct {
	URI       string `json:"uri"`
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
}

// Observation represents an atomic fact captured about a subject.
type Observation struct {
	ID         string            `json:"id"`
	Subject    SubjectRef        `json:"subject"`
	Type       string            `json:"type"`
	ObservedAt time.Time         `json:"observedAt"`
	Observer   AuthorityRef      `json:"observer"`
	Evidence   []EvidenceRef     `json:"evidence,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Digest computes a canonical hash of the observation.
func (o Observation) Digest() string {
	evidenceDigests := make([]string, len(o.Evidence))
	for i, e := range o.Evidence {
		evidenceDigests[i] = e.Digest
	}
	raw := fmt.Sprintf("%s|%s|%s|%d|%s|%s|%s",
		o.ID,
		o.Subject.URI(),
		o.Type,
		o.ObservedAt.UnixNano(),
		o.Observer.Canonical(),
		CanonicalDigestList(evidenceDigests),
		ComputeMapDigest(o.Attributes),
	)
	h := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(h[:])
}

// EvidenceRequirement specifies an individual required piece of evidence.
type EvidenceRequirement struct {
	ID                string        `json:"id"`
	EvidenceType      string        `json:"evidenceType"`
	Required          bool          `json:"required"`
	MaxAge            time.Duration `json:"maxAge"`
	AcceptedProducers []string      `json:"acceptedProducers,omitempty"`
}

// IsFresh checks whether evidence captured at capturedAt satisfies maxAge.
func (r EvidenceRequirement) IsFresh(capturedAt time.Time, now time.Time) bool {
	if r.MaxAge <= 0 {
		return true
	}
	if capturedAt.After(now) {
		// Future timestamp is invalid / clock skew
		return false
	}
	return now.Sub(capturedAt) <= r.MaxAge
}

// IsProducerAccepted verifies producer authorization against accepted list.
func (r EvidenceRequirement) IsProducerAccepted(producerID string) bool {
	if len(r.AcceptedProducers) == 0 {
		return true // No whitelist restriction
	}
	for _, accepted := range r.AcceptedProducers {
		if accepted == "*" || accepted == producerID {
			return true
		}
		// Prefix match for SPIFFE trust domain patterns
		if strings.HasSuffix(accepted, "*") && strings.HasPrefix(producerID, strings.TrimSuffix(accepted, "*")) {
			return true
		}
	}
	return false
}

// EvidenceEnvelope packages evidence metadata and cryptographic bindings.
type EvidenceEnvelope struct {
	Schema          string         `json:"schema"`
	ID              string         `json:"id"`
	Subject         SubjectRef     `json:"subject"`
	ObservationType string         `json:"observationType"`
	CapturedAt      time.Time      `json:"capturedAt"`
	Producer        AuthorityRef   `json:"producer"`
	Artifact        EvidenceRef    `json:"artifact"`
	IntegrityDigest string         `json:"integrityDigest"`
	SignatureRef    string         `json:"signatureRef,omitempty"`
	Epoch           AssuranceEpoch `json:"epoch"`
	ControlRefs     []ControlRef   `json:"controlRefs,omitempty"`
}

// Digest computes the deterministic envelope digest.
func (e EvidenceEnvelope) Digest() string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%d|%s|%s|%s|%s",
		e.Schema,
		e.ID,
		e.Subject.URI(),
		e.ObservationType,
		e.CapturedAt.UnixNano(),
		e.Producer.Canonical(),
		e.Artifact.Digest,
		e.IntegrityDigest,
		e.Epoch.CompositeDigest(),
	)
	h := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(h[:])
}

// EvidenceCompleteness tracks coverage of required evidence.
type EvidenceCompleteness struct {
	Required int `json:"required"`
	Present  int `json:"present"`
	Verified int `json:"verified"`
	Stale    int `json:"stale"`
	Missing  int `json:"missing"`
}

// Summary returns a human-readable completeness string (Section 34).
func (c EvidenceCompleteness) Summary() string {
	return fmt.Sprintf("%d/%d verified, %d stale, %d missing", c.Verified, c.Required, c.Stale, c.Missing)
}

// IsComplete returns true if all required evidence items are verified and none are missing or stale.
func (c EvidenceCompleteness) IsComplete() bool {
	return c.Required > 0 && c.Verified >= c.Required && c.Missing == 0 && c.Stale == 0
}

// ContractEvaluationResult records the result of evaluating an EvidenceContract.
type ContractEvaluationResult struct {
	ContractID          string                `json:"contractId"`
	Completeness        EvidenceCompleteness  `json:"completeness"`
	VerifiedEvidences   []EvidenceEnvelope    `json:"verifiedEvidences"`
	StaleEvidences      []EvidenceEnvelope    `json:"staleEvidences"`
	MissingRequirements []EvidenceRequirement `json:"missingRequirements"`
	State               AssuranceState        `json:"state"`
}

// EvidenceContract defines the mandatory proof requirements for a control binding.
type EvidenceContract struct {
	ID                     string                `json:"id"`
	Name                   string                `json:"name"`
	Requirements           []EvidenceRequirement `json:"requirements"`
	OnMissingRequiredState AssuranceState        `json:"onMissingRequiredState"`
}

// Evaluate checks candidate evidence envelopes against this contract at time `now`.
func (c EvidenceContract) Evaluate(envelopes []EvidenceEnvelope, currentEpoch AssuranceEpoch, now time.Time) ContractEvaluationResult {
	result := ContractEvaluationResult{
		ContractID: c.ID,
		Completeness: EvidenceCompleteness{
			Required: len(c.Requirements),
		},
	}

	// Map envelopes by observation/evidence type for fast lookup
	envByType := make(map[string][]EvidenceEnvelope)
	for _, env := range envelopes {
		envByType[env.ObservationType] = append(envByType[env.ObservationType], env)
	}

	for _, req := range c.Requirements {
		candidates := envByType[req.EvidenceType]
		var matched *EvidenceEnvelope
		var isStale bool

		// Find best matching candidate
		for _, cand := range candidates {
			// Check producer authorization
			if !req.IsProducerAccepted(cand.Producer.Canonical()) {
				continue
			}

			// Check epoch match
			if !cand.Epoch.Matches(currentEpoch) {
				isStale = true
				result.StaleEvidences = append(result.StaleEvidences, cand)
				continue
			}

			// Check freshness
			if !req.IsFresh(cand.CapturedAt, now) {
				isStale = true
				result.StaleEvidences = append(result.StaleEvidences, cand)
				continue
			}

			// Verified candidate found
			cCopy := cand
			matched = &cCopy
			break
		}

		if matched != nil {
			result.VerifiedEvidences = append(result.VerifiedEvidences, *matched)
			result.Completeness.Present++
			result.Completeness.Verified++
		} else {
			if isStale {
				result.Completeness.Stale++
			} else {
				result.Completeness.Missing++
			}
			if req.Required {
				result.MissingRequirements = append(result.MissingRequirements, req)
			}
		}
	}

	// Determine resulting state per contract
	if result.Completeness.IsComplete() {
		result.State = AssuranceStateVerified
	} else if result.Completeness.Stale > 0 && result.Completeness.Missing == 0 {
		result.State = AssuranceStateStale
	} else {
		if c.OnMissingRequiredState != AssuranceStateUnspecified {
			result.State = c.OnMissingRequiredState
		} else {
			result.State = AssuranceStateUnknown
		}
	}

	return result
}
