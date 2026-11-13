package assurance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
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

// Validate checks that SubjectRef contains non-empty scheme and ID.
func (s SubjectRef) Validate() error {
	if strings.TrimSpace(s.Scheme) == "" {
		return fmt.Errorf("subject scheme cannot be empty")
	}
	if strings.TrimSpace(s.ID) == "" {
		return fmt.Errorf("subject id cannot be empty")
	}
	return nil
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

// Validate checks that ControlRef contains non-empty namespace and ID.
func (c ControlRef) Validate() error {
	if strings.TrimSpace(c.Namespace) == "" {
		return fmt.Errorf("control namespace cannot be empty")
	}
	if strings.TrimSpace(c.ID) == "" {
		return fmt.Errorf("control id cannot be empty")
	}
	return nil
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

// Validate checks authority label structure and trust-domain consistency. It
// does not authenticate the identity or establish ownership of a signing key.
func (a AuthorityRef) Validate() error {
	if strings.TrimSpace(a.Scheme) == "" {
		return fmt.Errorf("authority scheme cannot be empty")
	}
	if strings.TrimSpace(a.Subject) == "" {
		return fmt.Errorf("authority subject cannot be empty")
	}
	for _, value := range []string{a.Scheme, a.Subject, a.TrustDomain} {
		if strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("authority labels must not contain surrounding whitespace or control delimiters")
		}
	}
	if strings.EqualFold(a.Scheme, "spiffe") && a.Scheme != "spiffe" {
		return fmt.Errorf("SPIFFE authority scheme must use its canonical lowercase spelling")
	}
	if a.Scheme != "spiffe" {
		if a.TrustDomain != "" {
			return fmt.Errorf("trustDomain is only defined for SPIFFE authority references")
		}
		return nil
	}
	uri, err := url.Parse(a.Canonical())
	if err != nil || uri.Scheme != "spiffe" || uri.Host == "" || uri.Hostname() != uri.Host || uri.User != nil || uri.Opaque != "" || uri.ForceQuery || uri.RawQuery != "" || uri.Fragment != "" || uri.RawPath != "" || uri.String() != a.Canonical() {
		return fmt.Errorf("SPIFFE authority requires an unambiguous identity URI without user info, port, query or fragment")
	}
	for _, character := range uri.Host {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '.' || character == '-' || character == '_' {
			continue
		}
		return fmt.Errorf("SPIFFE trust domain must be a canonical lowercase authority name")
	}
	if a.TrustDomain != "" && a.TrustDomain != uri.Host {
		return fmt.Errorf("authority trustDomain contradicts its SPIFFE URI host")
	}
	return nil
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
	if capturedAt.IsZero() || capturedAt.After(now) {
		// Zero or future timestamp is invalid
		return false
	}
	if r.MaxAge <= 0 {
		return true
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
		if strings.HasSuffix(accepted, "://") && strings.HasPrefix(producerID, accepted) {
			return true
		}
		if strings.HasPrefix(producerID, accepted+"://") {
			return true
		}
		if strings.EqualFold(producerID, accepted) {
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
	controlRefStrs := make([]string, len(e.ControlRefs))
	for i, c := range e.ControlRefs {
		controlRefStrs[i] = c.Canonical()
	}
	sort.Strings(controlRefStrs)
	raw := fmt.Sprintf("%s|%s|%s|%s|%d|%s|%s|%s|%s|%s|%s",
		e.Schema,
		e.ID,
		e.Subject.URI(),
		e.ObservationType,
		e.CapturedAt.UnixNano(),
		e.Producer.Canonical(),
		e.Artifact.Digest,
		e.IntegrityDigest,
		e.SignatureRef,
		e.Epoch.CompositeDigest(),
		strings.Join(controlRefStrs, ","),
	)
	h := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(h[:])
}

// SigningDigest computes the canonical digest to be signed (excluding SignatureRef).
func (e EvidenceEnvelope) SigningDigest() string {
	unsigned := e
	unsigned.SignatureRef = ""
	return unsigned.Digest()
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

// IsAdverseObservationType returns true when an observation type represents a violation, denial, or structural ANTI signal.
func IsAdverseObservationType(obsType string) bool {
	lower := strings.ToLower(strings.TrimSpace(obsType))
	return strings.Contains(lower, "violation") ||
		strings.Contains(lower, "denied") ||
		strings.Contains(lower, "fail") ||
		strings.Contains(lower, "adverse") ||
		strings.Contains(lower, "quarantine")
}

// Evaluate checks candidate evidence envelopes against this contract at time `now`.
func (c EvidenceContract) Evaluate(envelopes []EvidenceEnvelope, currentEpoch AssuranceEpoch, now time.Time) ContractEvaluationResult {
	requiredCount := 0
	for _, req := range c.Requirements {
		if req.Required {
			requiredCount++
		}
	}

	result := ContractEvaluationResult{
		ContractID: c.ID,
		Completeness: EvidenceCompleteness{
			Required: requiredCount,
		},
	}

	hasAdverse := false
	for _, env := range envelopes {
		if !IsAdverseObservationType(env.ObservationType) {
			continue
		}
		if env.CapturedAt.IsZero() || env.CapturedAt.After(now) {
			continue
		}
		if !env.Epoch.Matches(currentEpoch) {
			continue
		}
		producerURI := strings.TrimSpace(env.Producer.Canonical())
		if producerURI == "" || strings.TrimSpace(env.Artifact.Digest) == "" {
			continue
		}
		accepted := len(c.Requirements) == 0
		for _, req := range c.Requirements {
			if req.IsProducerAccepted(producerURI) {
				accepted = true
				break
			}
		}
		if !accepted {
			continue
		}
		hasAdverse = true
	}

	for _, req := range c.Requirements {
		var candidates []EvidenceEnvelope
		for _, env := range envelopes {
			if IsAdverseObservationType(env.ObservationType) && !IsAdverseObservationType(req.EvidenceType) {
				continue
			}
			if matchesEvidenceType(env.ObservationType, req.EvidenceType) {
				candidates = append(candidates, env)
			}
		}
		var matched *EvidenceEnvelope
		var isStale bool

		// Find best matching candidate
		for _, cand := range candidates {
			// Check producer authorization
			if !req.IsProducerAccepted(cand.Producer.Canonical()) {
				continue
			}

			// Reject zero or future-dated evidence outright
			if cand.CapturedAt.IsZero() || cand.CapturedAt.After(now) {
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
			if req.Required {
				result.Completeness.Verified++
			}
		} else {
			if isStale {
				if req.Required {
					result.Completeness.Stale++
				}
			} else {
				if req.Required {
					result.Completeness.Missing++
				}
			}
			if req.Required {
				result.MissingRequirements = append(result.MissingRequirements, req)
			}
		}
	}

	// Determine resulting state per contract (Section 23: Mandatory anti/violation invariants dominate scores)
	if hasAdverse {
		result.State = AssuranceStateFailed
	} else if result.Completeness.IsComplete() {
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

func normalizeEvidenceType(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, ":", ".")
	s = strings.ReplaceAll(s, "-", ".")
	s = strings.TrimSuffix(s, ".review")
	if strings.HasPrefix(s, "k8s.") {
		s = "kubernetes." + strings.TrimPrefix(s, "k8s.")
	}
	return s
}

// matchesEvidenceType checks if an observed evidence type satisfies a required evidence type.
// It supports exact matches (e.g. "kubernetes.admission" == "kubernetes.admission"),
// hierarchical suffix matches (e.g. "admission" matches "kubernetes.admission"),
// and normalized case-insensitive comparisons (including "k8s:admission:review").
func matchesEvidenceType(obsType, reqType string) bool {
	if obsType == reqType {
		return true
	}
	if strings.EqualFold(obsType, reqType) {
		return true
	}
	if strings.HasSuffix(obsType, "."+reqType) || strings.HasSuffix(reqType, "."+obsType) {
		return true
	}
	cleanObs := normalizeEvidenceType(obsType)
	cleanReq := normalizeEvidenceType(reqType)
	if cleanObs == cleanReq {
		return true
	}
	if strings.HasSuffix(cleanObs, "."+cleanReq) || strings.HasSuffix(cleanReq, "."+cleanObs) {
		return true
	}
	return false
}
