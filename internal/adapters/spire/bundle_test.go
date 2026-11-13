package spire

import (
	"crypto/x509"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func TestPublicBundleDigestCanonicalizesTrustAndDetectsRootChange(t *testing.T) {
	first, _, _ := generateTestCA(t, "First public root")
	second, _, _ := generateTestCA(t, "Second public root")
	primary := spiffeid.RequireTrustDomainFromString("primary.test")
	federated := spiffeid.RequireTrustDomainFromString("federated.test")
	snapshot := func(reverse bool, root *x509.Certificate) *workloadapi.X509Context {
		roots := []*x509.Certificate{first, root}
		if reverse {
			roots[0], roots[1] = roots[1], roots[0]
		}
		return &workloadapi.X509Context{Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(primary, roots), x509bundle.FromX509Authorities(federated, []*x509.Certificate{first}))}
	}
	a, err := publicBundleDigest(snapshot(false, second))
	if err != nil {
		t.Fatal(err)
	}
	b, err := publicBundleDigest(snapshot(true, second))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("certificate order changed authority identity")
	}
	changed, err := publicBundleDigest(snapshot(false, first))
	if err != nil {
		t.Fatal(err)
	}
	if changed == a {
		t.Fatal("changed public root retained old authority identity")
	}
	if _, err := publicBundleDigest(nil); err == nil {
		t.Fatal("missing bundle acquired identity")
	}
	if _, err := (*WorkloadClient)(nil).TrustBundleDigest(t.Context()); err == nil {
		t.Fatal("missing live source acquired bundle identity")
	}
}
