package assurance

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// EpochDriftReason identifies the semantic dimension that diverged.
type EpochDriftReason string

const (
	DriftSubject        EpochDriftReason = "SUBJECT_DRIFT"
	DriftImplementation EpochDriftReason = "IMPLEMENTATION_DRIFT"
	DriftPolicy         EpochDriftReason = "POLICY_DRIFT"
	DriftAuthority      EpochDriftReason = "AUTHORITY_DRIFT"
	DriftEnvironment    EpochDriftReason = "ENVIRONMENT_DRIFT"
)

// AssuranceEpoch encapsulates the cryptographic state vector of the environment
// in which an assurance evaluation was performed (ADR-003).
type AssuranceEpoch struct {
	SubjectDigest        string `json:"subjectDigest"`
	ImplementationDigest string `json:"implementationDigest"`
	PolicyDigest         string `json:"policyDigest"`
	AuthorityDigest      string `json:"authorityDigest"`
	EnvironmentDigest    string `json:"environmentDigest"`
}

// CompositeDigest returns the canonical SHA-256 hash across all five dimensions.
func (e AssuranceEpoch) CompositeDigest() string {
	parts := []string{
		e.SubjectDigest,
		e.ImplementationDigest,
		e.PolicyDigest,
		e.AuthorityDigest,
		e.EnvironmentDigest,
	}
	raw := strings.Join(parts, ":")
	h := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(h[:])
}

// Matches checks whether this epoch is byte-for-byte identical to another epoch.
func (e AssuranceEpoch) Matches(other AssuranceEpoch) bool {
	return e.SubjectDigest == other.SubjectDigest &&
		e.ImplementationDigest == other.ImplementationDigest &&
		e.PolicyDigest == other.PolicyDigest &&
		e.AuthorityDigest == other.AuthorityDigest &&
		e.EnvironmentDigest == other.EnvironmentDigest
}

// Diff returns all dimensions where this epoch diverges from the target epoch.
func (e AssuranceEpoch) Diff(other AssuranceEpoch) []EpochDriftReason {
	var reasons []EpochDriftReason
	if e.SubjectDigest != other.SubjectDigest {
		reasons = append(reasons, DriftSubject)
	}
	if e.ImplementationDigest != other.ImplementationDigest {
		reasons = append(reasons, DriftImplementation)
	}
	if e.PolicyDigest != other.PolicyDigest {
		reasons = append(reasons, DriftPolicy)
	}
	if e.AuthorityDigest != other.AuthorityDigest {
		reasons = append(reasons, DriftAuthority)
	}
	if e.EnvironmentDigest != other.EnvironmentDigest {
		reasons = append(reasons, DriftEnvironment)
	}
	return reasons
}

// ComputeDigest computes a canonical sha256 hex string prefixed with "sha256:".
func ComputeDigest(payload []byte) string {
	h := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(h[:])
}

// ComputeStringDigest computes sha256 over a string.
func ComputeStringDigest(s string) string {
	return ComputeDigest([]byte(s))
}

// ComputeMapDigest computes a deterministic sha256 over sorted key-value pairs.
func ComputeMapDigest(m map[string]string) string {
	if len(m) == 0 {
		return ComputeDigest([]byte("{}"))
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(m[k])
		sb.WriteString(";")
	}
	return ComputeDigest([]byte(sb.String()))
}

// CanonicalDigestList sorts a list of digests and computes a Merkle-like root digest.
func CanonicalDigestList(digests []string) string {
	if len(digests) == 0 {
		return ComputeDigest([]byte(""))
	}
	sorted := make([]string, len(digests))
	copy(sorted, digests)
	sort.Strings(sorted)

	combined := strings.Join(sorted, "\n")
	return ComputeDigest([]byte(combined))
}
