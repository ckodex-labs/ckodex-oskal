package assurance

import "testing"

func TestAuthorityTrustDomainHasOneMeaning(t *testing.T) {
	for _, authority := range []AuthorityRef{{Scheme: "local", Subject: "explicit-observer"}, {Scheme: "k8s:admission-controller", Subject: "legacy-observer-label"}, {Scheme: "spiffe", Subject: "example.test/ns/observer"}, {Scheme: "spiffe", Subject: "example.test/ns/observer", TrustDomain: "example.test"}} {
		if err := authority.Validate(); err != nil {
			t.Errorf("valid label rejected: %+v: %v", authority, err)
		}
	}
	for _, authority := range []AuthorityRef{
		{Scheme: "spiffe", Subject: "example.test/ns/observer", TrustDomain: "different.test"},
		{Scheme: "local", Subject: "explicit-observer", TrustDomain: "example.test"},
		{Scheme: "spiffe", Subject: "user@example.test/ns/observer"},
		{Scheme: "spiffe", Subject: "example.test:443/ns/observer"},
		{Scheme: "spiffe", Subject: "example.test/ns/observer?domain=different.test"},
		{Scheme: "spiffe", Subject: "example.test/ns/observer#different"},
		{Scheme: "SPIFFE", Subject: "user@example.test/ns/observer"},
		{Scheme: "spiffe", Subject: "/missing-domain"},
		{Scheme: "spiffe", Subject: "EXAMPLE.test/ns/observer", TrustDomain: "EXAMPLE.test"},
		{Scheme: "local", Subject: "observer\nforged-field"},
	} {
		if err := authority.Validate(); err == nil {
			t.Errorf("contradictory or malformed authority accepted: %+v", authority)
		}
	}
}
