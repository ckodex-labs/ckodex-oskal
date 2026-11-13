package spire

import (
	"context"
	"fmt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// AuthorityPolicy maps SPIFFE identities to permitted evidence types (Section 25).
type AuthorityPolicy struct {
	AllowedTrustDomains []string
	// ProducerPermissions maps SPIFFE ID or wildcard patterns to allowed evidence types
	ProducerPermissions map[string][]string
}

// NewDefaultAuthorityPolicy creates a standard production authority policy for OSKAL.
func NewDefaultAuthorityPolicy() *AuthorityPolicy {
	return &AuthorityPolicy{
		AllowedTrustDomains: []string{"prod", "ckodex.local"},
		ProducerPermissions: map[string][]string{
			"spiffe://prod/ns/ckodex-assurance/sa/cel-admission-observer": {
				"kubernetes.admission",
			},
			"spiffe://prod/ns/ckodex-evidence/sa/tetragon-collector": {
				"workload.runtime.process",
				"workload.runtime.capabilities",
			},
			"spiffe://prod/ns/ckodex-evidence/sa/cilium-collector": {
				"network.flow.isolation",
			},
			"spiffe://prod/ns/ckodex-evidence/sa/sigstore-verifier": {
				"supply-chain.signature",
				"supply-chain.provenance",
			},
		},
	}
}

// SpireAuthorityResolver implements ports.AuthorityResolver.
type SpireAuthorityResolver struct {
	policy *AuthorityPolicy
}

// NewSpireAuthorityResolver creates an authority resolver backed by SPIFFE/SPIRE rules.
func NewSpireAuthorityResolver(policy *AuthorityPolicy) *SpireAuthorityResolver {
	if policy == nil {
		policy = NewDefaultAuthorityPolicy()
	}
	return &SpireAuthorityResolver{policy: policy}
}

// ValidateIdentity checks if the authority reference is a valid SPIFFE ID within an allowed trust domain.
func (r *SpireAuthorityResolver) ValidateIdentity(auth assurance.AuthorityRef) error {
	if auth.Scheme != "spiffe" {
		return fmt.Errorf("unsupported identity scheme: %s; expected spiffe", auth.Scheme)
	}

	id, err := spiffeid.FromString(auth.Canonical())
	if err != nil || id.Path() == "" {
		return fmt.Errorf("invalid workload SPIFFE ID: %s", auth.Canonical())
	}
	trustDomain := id.TrustDomain().String()
	if auth.TrustDomain != "" && auth.TrustDomain != trustDomain {
		return fmt.Errorf("authority trust domain contradicts SPIFFE ID")
	}
	trusted := false
	for _, td := range r.policy.AllowedTrustDomains {
		if td == trustDomain {
			trusted = true
			break
		}
	}
	if !trusted {
		return fmt.Errorf("untrusted SPIFFE trust domain: %s", trustDomain)
	}

	return nil
}

// IsAuthorizedProducer verifies that the authenticated identity is authorized to assert the specific evidence type.
// Implements ports.AuthorityResolver.
func (r *SpireAuthorityResolver) IsAuthorizedProducer(ctx context.Context, producer assurance.AuthorityRef, evidenceType string) (bool, error) {
	if err := r.ValidateIdentity(producer); err != nil {
		return false, err
	}

	canonical := producer.Canonical()
	allowedTypes, exists := r.policy.ProducerPermissions[canonical]
	if !exists {
		return false, fmt.Errorf("producer identity %s has no registered evidence authorities", canonical)
	}

	for _, t := range allowedTypes {
		if t == evidenceType || t == "*" {
			return true, nil
		}
	}

	return false, fmt.Errorf("producer %s is unauthorized to assert evidence type %s", canonical, evidenceType)
}
