package spire

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// AuthorityPolicy maps exact SPIFFE identity labels to permitted evidence types.
// The caller must authenticate the peer independently before using these rules.
// A literal "*" evidence type is an explicit all-types grant, never a default.
type AuthorityPolicy struct {
	AllowedTrustDomains []string
	ProducerPermissions map[string][]string
}

// NewDefaultAuthorityPolicy grants no trust domains or producer permissions.
func NewDefaultAuthorityPolicy() *AuthorityPolicy { return &AuthorityPolicy{} }

// SpireAuthorityResolver evaluates configured authorization labels. It does not
// validate an SVID, prove possession, or authenticate a network peer.
type SpireAuthorityResolver struct {
	policy             AuthorityPolicy
	configurationError error
}

// NewSpireAuthorityResolver snapshots an explicit policy. Nil means deny all.
// Invalid configuration also denies all; validation returns the concrete error.
func NewSpireAuthorityResolver(policy *AuthorityPolicy) *SpireAuthorityResolver {
	r := &SpireAuthorityResolver{}
	if policy == nil {
		return r
	}
	if err := validateAuthorityPolicy(policy); err != nil {
		r.configurationError = err
		return r
	}
	r.policy.AllowedTrustDomains = slices.Clone(policy.AllowedTrustDomains)
	r.policy.ProducerPermissions = make(map[string][]string, len(policy.ProducerPermissions))
	for producer, types := range policy.ProducerPermissions {
		r.policy.ProducerPermissions[producer] = slices.Clone(types)
	}
	return r
}

func validateAuthorityPolicy(policy *AuthorityPolicy) error {
	if len(policy.AllowedTrustDomains) > 64 || len(policy.ProducerPermissions) > 256 {
		return fmt.Errorf("authority policy exceeds 64 trust domains or 256 producer grants")
	}
	trusted := make(map[string]bool, len(policy.AllowedTrustDomains))
	for _, name := range policy.AllowedTrustDomains {
		if len(name) > 255 {
			return fmt.Errorf("authority trust domain exceeds its name bound")
		}
		domain, err := spiffeid.TrustDomainFromString(name)
		if err != nil || domain.String() != name || trusted[name] {
			return fmt.Errorf("authority policy requires unique bare SPIFFE trust domain names")
		}
		trusted[name] = true
	}
	for producer, types := range policy.ProducerPermissions {
		if len(producer) > 2048 || strings.ContainsAny(producer, "*?\r\n") || len(types) == 0 || len(types) > 64 {
			return fmt.Errorf("authority producer identity or evidence-type grant exceeds bounds")
		}
		id, err := spiffeid.FromString(producer)
		if err != nil || id.Path() == "" || !trusted[id.TrustDomain().String()] {
			return fmt.Errorf("producer grant requires an exact workload SPIFFE ID in a configured trust domain")
		}
		for _, evidenceType := range types {
			if strings.TrimSpace(evidenceType) == "" || len(evidenceType) > 256 || strings.ContainsAny(evidenceType, "\r\n") {
				return fmt.Errorf("authority grant requires a bounded nonempty evidence type")
			}
		}
	}
	return nil
}

// ValidateIdentity checks SPIFFE label syntax and configured trust-domain scope.
// It does not authenticate the supplied authority label or validate its SVID.
func (r *SpireAuthorityResolver) ValidateIdentity(auth assurance.AuthorityRef) error {
	if r == nil {
		return fmt.Errorf("explicit authority policy is required")
	}
	if r.configurationError != nil {
		return fmt.Errorf("invalid configured authority policy: %w", r.configurationError)
	}
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
	if !slices.Contains(r.policy.AllowedTrustDomains, trustDomain) {
		return fmt.Errorf("untrusted SPIFFE trust domain: %s", trustDomain)
	}
	return nil
}

// IsAuthorizedProducer applies policy to a label that the caller has already
// authenticated through an independent peer/SVID verification boundary.
func (r *SpireAuthorityResolver) IsAuthorizedProducer(ctx context.Context, producer assurance.AuthorityRef, evidenceType string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if strings.TrimSpace(evidenceType) == "" {
		return false, fmt.Errorf("an explicit evidence type is required")
	}
	if err := r.ValidateIdentity(producer); err != nil {
		return false, err
	}
	for _, permitted := range r.policy.ProducerPermissions[producer.Canonical()] {
		if permitted == evidenceType || permitted == "*" {
			return true, nil
		}
	}
	return false, fmt.Errorf("producer %s has no configured authority for evidence type %s", producer.Canonical(), evidenceType)
}
