package spire

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// TLSStateExtractor must return transport-owned state, never request claims.
type TLSStateExtractor func(context.Context) (tls.ConnectionState, bool)

// PeerPrincipal resolves a fresh authenticated peer for every consequential call.
type PeerPrincipal struct {
	client  *WorkloadClient
	allowed []string
	state   TLSStateExtractor
}

var _ ports.PrincipalResolver = (*PeerPrincipal)(nil)

func NewPeerPrincipal(client *WorkloadClient, allowed []string, state TLSStateExtractor) (*PeerPrincipal, error) {
	if client == nil || state == nil {
		return nil, fmt.Errorf("workload API client and transport TLS-state extractor are required")
	}
	if err := validatePeerIDs(allowed); err != nil {
		return nil, err
	}
	return &PeerPrincipal{client: client, allowed: append([]string(nil), allowed...), state: state}, nil
}

func (p *PeerPrincipal) AuthenticatedPrincipal(ctx context.Context) (string, error) {
	if p == nil || p.client == nil || p.state == nil {
		return "", fmt.Errorf("peer principal is not configured")
	}
	state, ok := p.state(ctx)
	if !ok {
		return "", fmt.Errorf("authenticated transport TLS state is missing")
	}
	return p.client.AuthenticatedPeer(ctx, state, p.allowed)
}

func validatePeerIDs(ids []string) error {
	if len(ids) == 0 || len(ids) > 64 {
		return fmt.Errorf("supply 1 to 64 exact allowed peer SPIFFE IDs")
	}
	for _, raw := range ids {
		id, err := spiffeid.FromString(raw)
		if err != nil || id.Path() == "" {
			return fmt.Errorf("invalid exact peer SPIFFE ID %q", raw)
		}
	}
	return nil
}

// AuthenticatedPeer revalidates the real TLS peer chain against a fresh Workload
// API bundle and exact allowlist. It also requires a fresh valid own SVID.
// It never derives the caller from a header, request argument, or server account.
func (c *WorkloadClient) AuthenticatedPeer(ctx context.Context, state tls.ConnectionState, allowed []string) (string, error) {
	principal, _, err := c.authenticatedPeerSnapshot(ctx, state, allowed)
	return principal, err
}

// AuthenticatedPeerWithTrustBundleDigest returns the peer and canonical public
// bundle digest from the SAME fresh snapshot that verified the own SVID and peer
// chain. Callers compare this digest with their admitted authority pin; a later
// fetch cannot prove which trust roots admitted an earlier peer.
func (c *WorkloadClient) AuthenticatedPeerWithTrustBundleDigest(ctx context.Context, state tls.ConnectionState, allowed []string) (string, string, error) {
	principal, current, err := c.authenticatedPeerSnapshot(ctx, state, allowed)
	if err != nil {
		return "", "", err
	}
	digest, err := publicBundleDigest(current)
	if err != nil {
		return "", "", err
	}
	return principal, digest, nil
}

func (c *WorkloadClient) authenticatedPeerSnapshot(ctx context.Context, state tls.ConnectionState, allowed []string) (string, *workloadapi.X509Context, error) {
	if c == nil || c.client == nil {
		return "", nil, fmt.Errorf("workload API client is required")
	}
	if err := validatePeerIDs(allowed); err != nil {
		return "", nil, err
	}
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || len(state.PeerCertificates) == 0 {
		return "", nil, fmt.Errorf("completed TLS 1.3 mutual authentication is required")
	}
	if err := validateTLSExporter(state); err != nil {
		return "", nil, err
	}
	current, err := (workloadSource{client: c, ctx: ctx}).fetch()
	if err != nil {
		return "", nil, err
	}
	ownPresent := false
	for _, svid := range current.SVIDs {
		if svid.ID != c.expected {
			continue
		}
		id, _, err := x509svid.Verify(svid.Certificates, current.Bundles)
		if err != nil || id != c.expected {
			return "", nil, fmt.Errorf("fresh own workload identity could not be verified")
		}
		ownPresent = true
	}
	if !ownPresent {
		return "", nil, fmt.Errorf("fresh own workload identity is unavailable")
	}
	peer, _, err := x509svid.Verify(state.PeerCertificates, current.Bundles)
	if err != nil {
		return "", nil, fmt.Errorf("verify peer against fresh SPIRE bundle: %w", err)
	}
	for _, id := range allowed {
		if peer.String() == id {
			return peer.String(), current, nil
		}
	}
	return "", nil, fmt.Errorf("authenticated peer %s is outside the exact allowlist", peer.String())
}

// Go's exporter calls an unexported callback and panics for a manually assembled
// ConnectionState. Recover only around this call to reject such fabricated state.
// Exported keying material is discarded and must never be logged or returned.
func validateTLSExporter(state tls.ConnectionState) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("TLS state lacks an authenticated connection exporter")
		}
	}()
	if _, err := state.ExportKeyingMaterial("EXPORTER-OSKAL-Peer-Principal", nil, 32); err != nil {
		return fmt.Errorf("TLS connection exporter unavailable: %w", err)
	}
	return nil
}
