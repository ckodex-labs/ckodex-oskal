package spire

import (
	"context"
	"errors"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestAuthorityPolicyRequiresExplicitGrants(t *testing.T) {
	producer := assurance.AuthorityRef{Scheme: "spiffe", Subject: "example.test/ns/observed/sa/collector", TrustDomain: "example.test"}
	for _, policy := range []*AuthorityPolicy{nil, NewDefaultAuthorityPolicy(), {}} {
		resolver := NewSpireAuthorityResolver(policy)
		if allowed, err := resolver.IsAuthorizedProducer(t.Context(), producer, "workload.runtime.process"); allowed || err == nil {
			t.Fatal("an empty policy granted a producer authority")
		}
		formerDefault := assurance.AuthorityRef{Scheme: "spiffe", Subject: "prod/ns/ckodex-evidence/sa/tetragon-collector", TrustDomain: "prod"}
		if allowed, err := resolver.IsAuthorizedProducer(t.Context(), formerDefault, "workload.runtime.process"); allowed || err == nil {
			t.Fatal("a former production example retained implicit authority")
		}
		if err := resolver.ValidateIdentity(assurance.AuthorityRef{Scheme: "spiffe", Subject: "ckodex.local/workload"}); err == nil {
			t.Fatal("a former example trust domain retained implicit trust")
		}
	}
	policy := &AuthorityPolicy{AllowedTrustDomains: []string{"example.test"}, ProducerPermissions: map[string][]string{producer.Canonical(): {"workload.runtime.process"}}}
	resolver := NewSpireAuthorityResolver(policy)
	// These are authorization labels, not authenticated peer/SVID evidence.
	if allowed, err := resolver.IsAuthorizedProducer(t.Context(), producer, "workload.runtime.process"); !allowed || err != nil {
		t.Fatalf("explicit grant was refused: %v", err)
	}
	for _, test := range []struct {
		producer assurance.AuthorityRef
		evidence string
	}{
		{producer, "supply-chain.signature"},
		{producer, ""},
		{assurance.AuthorityRef{Scheme: "spiffe", Subject: "example.test/ns/other/sa/collector"}, "workload.runtime.process"},
		{assurance.AuthorityRef{Scheme: "spiffe", Subject: "foreign.test/ns/observed/sa/collector"}, "workload.runtime.process"},
	} {
		if allowed, err := resolver.IsAuthorizedProducer(t.Context(), test.producer, test.evidence); allowed || err == nil {
			t.Fatalf("unconfigured authority was admitted: %+v", test)
		}
	}
	policy.AllowedTrustDomains[0] = "foreign.test"
	policy.ProducerPermissions[producer.Canonical()][0] = "supply-chain.signature"
	policy.ProducerPermissions["spiffe://example.test/ns/other/sa/collector"] = []string{"*"}
	if allowed, err := resolver.IsAuthorizedProducer(t.Context(), producer, "workload.runtime.process"); !allowed || err != nil {
		t.Fatal("caller mutation changed the configured policy snapshot")
	}
	if allowed, _ := resolver.IsAuthorizedProducer(t.Context(), producer, "supply-chain.signature"); allowed {
		t.Fatal("caller mutation expanded the configured grant")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if allowed, err := resolver.IsAuthorizedProducer(ctx, producer, "workload.runtime.process"); allowed || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled authorization continued: %v", err)
	}
}

func TestMalformedAuthorityPolicyDeniesAll(t *testing.T) {
	producer := assurance.AuthorityRef{Scheme: "spiffe", Subject: "example.test/workload"}
	for _, policy := range []*AuthorityPolicy{
		{AllowedTrustDomains: []string{"spiffe://example.test/workload"}, ProducerPermissions: map[string][]string{producer.Canonical(): {"*"}}},
		{AllowedTrustDomains: []string{"example.test", "example.test"}, ProducerPermissions: map[string][]string{producer.Canonical(): {"*"}}},
		{AllowedTrustDomains: []string{"example.test"}, ProducerPermissions: map[string][]string{producer.Canonical(): {"*"}, "spiffe://foreign.test/workload": {"*"}}},
		{AllowedTrustDomains: []string{"example.test"}, ProducerPermissions: map[string][]string{producer.Canonical(): {"*"}, "spiffe://example.test/ns/*": {"*"}}},
		{AllowedTrustDomains: []string{"example.test"}, ProducerPermissions: map[string][]string{producer.Canonical(): {""}}},
	} {
		resolver := NewSpireAuthorityResolver(policy)
		if allowed, err := resolver.IsAuthorizedProducer(t.Context(), producer, "workload.runtime.process"); allowed || err == nil {
			t.Fatalf("malformed policy partially granted authority: %+v", policy)
		}
	}
}
