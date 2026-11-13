package spire

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// TrustBundleDigest validates the exact own SVID against the same freshly
// fetched bundle snapshot and hashes sorted public trust-domain/certificate DER
// bytes. It never returns SVID private keys or silently reuses a cached bundle.
func (c *WorkloadClient) TrustBundleDigest(ctx context.Context) (string, error) {
	if c == nil || c.client == nil {
		return "", fmt.Errorf("workload API client is required")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	current, err := c.client.FetchX509Context(ctx)
	if err != nil {
		return "", fmt.Errorf("fetch public Workload API bundle: %w", err)
	}
	verified := false
	for _, svid := range current.SVIDs {
		if svid.ID != c.expected {
			continue
		}
		id, _, err := x509svid.Verify(svid.Certificates, current.Bundles)
		if err != nil || id != c.expected {
			return "", fmt.Errorf("own identity does not verify against fresh public bundle")
		}
		verified = true
	}
	if !verified {
		return "", fmt.Errorf("fresh public bundle snapshot lacks exact own identity")
	}
	return publicBundleDigest(current)
}
func publicBundleDigest(current *workloadapi.X509Context) (string, error) {
	if current == nil || current.Bundles == nil || current.Bundles.Len() < 1 || current.Bundles.Len() > 64 {
		return "", fmt.Errorf("public bundle set exceeds bounds or is empty")
	}
	type publicBundle struct {
		TrustDomain string
		Authorities [][]byte
	}
	var public []publicBundle
	size := 0
	count := 0
	for _, bundle := range current.Bundles.Bundles() {
		item := publicBundle{TrustDomain: bundle.TrustDomain().String()}
		for _, cert := range bundle.X509Authorities() {
			size += len(cert.Raw)
			count++
			if size > 1<<20 || count > 256 {
				return "", fmt.Errorf("public bundle certificates exceed bounds")
			}
			item.Authorities = append(item.Authorities, append([]byte(nil), cert.Raw...))
		}
		if len(item.Authorities) == 0 {
			return "", fmt.Errorf("public trust domain has no root certificates")
		}
		sort.Slice(item.Authorities, func(i, j int) bool { return bytes.Compare(item.Authorities[i], item.Authorities[j]) < 0 })
		public = append(public, item)
	}
	raw, err := json.Marshal(public)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
