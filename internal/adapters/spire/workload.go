package spire

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// WorkloadClient obtains identity and trust roots from a local SPIRE agent.
// Each call opens a bounded Workload API stream and closes it after one update.
// No last-good identity or root cache can mask an unavailable agent.
type WorkloadClient struct {
	client   *workloadapi.Client
	expected spiffeid.ID
	timeout  time.Duration
}

// NewWorkloadClient requires an explicit local socket, exact workload identity,
// and operation timeout. The caller owns socket permissions and agent trust.
func NewWorkloadClient(ctx context.Context, address, expectedSPIFFEID string, timeout time.Duration) (*WorkloadClient, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "unix" || u.Host != "" || !strings.HasPrefix(u.Path, "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("workload API address must be an absolute unix socket URI")
	}
	expected, err := spiffeid.FromString(expectedSPIFFEID)
	if err != nil || expected.Path() == "" {
		return nil, fmt.Errorf("expected workload SPIFFE ID must contain a valid trust domain and path")
	}
	if timeout <= 0 || timeout > time.Minute {
		return nil, fmt.Errorf("workload API timeout must be between zero and one minute")
	}
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(address))
	if err != nil {
		return nil, fmt.Errorf("create Workload API client: %w", err)
	}
	return &WorkloadClient{client: client, expected: expected, timeout: timeout}, nil
}

// Identity returns only facts from a chain validated against the fresh bundle.
// It establishes this process's identity, not the identity of another workload.
func (c *WorkloadClient) Identity(ctx context.Context) (*SVIDInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	current, err := c.client.FetchX509Context(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch Workload API identity: %w", err)
	}
	for _, svid := range current.SVIDs {
		if svid.ID != c.expected {
			continue
		}
		id, _, err := x509svid.Verify(svid.Certificates, current.Bundles)
		if err != nil {
			return nil, fmt.Errorf("validate Workload API identity: %w", err)
		}
		if id != c.expected {
			return nil, fmt.Errorf("verified identity differs from requested identity")
		}
		leaf := svid.Certificates[0]
		fp := sha256.Sum256(leaf.Raw)
		return &SVIDInfo{SPIFFEID: id.String(), TrustDomain: id.TrustDomain().String(), Fingerprint: "sha256:" + hex.EncodeToString(fp[:]), Serial: leaf.SerialNumber.String(), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
	}
	return nil, fmt.Errorf("workload API did not issue expected identity %s", c.expected)
}

// Close releases the gRPC connection. Identity fails after the client is closed.
func (c *WorkloadClient) Close() error { return c.client.Close() }

// TLSClientConfig authenticates both peers, requiring an exact server SPIFFE ID.
// ctx governs the lifetime of subsequent Workload API fetches during handshakes.
func (c *WorkloadClient) TLSClientConfig(ctx context.Context, serverID string) (*tls.Config, error) {
	peer, err := spiffeid.FromString(serverID)
	if err != nil || peer.Path() == "" {
		return nil, fmt.Errorf("exact server SPIFFE ID is required")
	}
	source := workloadSource{client: c, ctx: ctx}
	config := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(peer))
	config.MinVersion = tls.VersionTLS13
	return config, nil
}

// TLSServerConfig authenticates both peers against an explicit allowlist.
func (c *WorkloadClient) TLSServerConfig(ctx context.Context, clientIDs []string) (*tls.Config, error) {
	if len(clientIDs) == 0 {
		return nil, fmt.Errorf("at least one exact client SPIFFE ID is required")
	}
	peers := make([]spiffeid.ID, 0, len(clientIDs))
	for _, raw := range clientIDs {
		peer, err := spiffeid.FromString(raw)
		if err != nil || peer.Path() == "" {
			return nil, fmt.Errorf("invalid client SPIFFE ID %q", raw)
		}
		peers = append(peers, peer)
	}
	source := workloadSource{client: c, ctx: ctx}
	config := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeOneOf(peers...))
	config.MinVersion = tls.VersionTLS13
	return config, nil
}

type workloadSource struct {
	client *WorkloadClient
	ctx    context.Context
}

func (s workloadSource) GetX509SVID() (*x509svid.SVID, error) {
	current, err := s.fetch()
	if err != nil {
		return nil, err
	}
	for _, identity := range current.SVIDs {
		if identity.ID != s.client.expected {
			continue
		}
		id, _, err := x509svid.Verify(identity.Certificates, current.Bundles)
		if err != nil {
			return nil, fmt.Errorf("verify TLS workload SVID: %w", err)
		}
		if id != s.client.expected {
			return nil, fmt.Errorf("verified TLS identity differs from requested identity")
		}
		return identity, nil
	}
	return nil, fmt.Errorf("workload API did not issue expected TLS identity %s", s.client.expected)
}

func (s workloadSource) GetX509BundleForTrustDomain(domain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	current, err := s.fetch()
	if err != nil {
		return nil, err
	}
	return current.Bundles.GetX509BundleForTrustDomain(domain)
}

func (s workloadSource) fetch() (*workloadapi.X509Context, error) {
	ctx, cancel := context.WithTimeout(s.ctx, s.client.timeout)
	defer cancel()
	current, err := s.client.client.FetchX509Context(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch TLS Workload API context: %w", err)
	}
	return current, nil
}
