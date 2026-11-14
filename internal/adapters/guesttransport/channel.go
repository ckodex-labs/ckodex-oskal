// Package guesttransport binds attestation to the actual TLS connection carrying
// a gRPC stream. An echoed producer binding is never an authority anchor.
package guesttransport

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// ChannelBinding derives RFC 9266 tls-exporter from a completed TLS 1.3
// handshake. It authenticates a channel, not physical guest co-residence.
func ChannelBinding(info credentials.AuthInfo) ([32]byte, error) {
	var result [32]byte
	tlsInfo, ok := info.(credentials.TLSInfo)
	if !ok || tlsInfo.State.Version != tls.VersionTLS13 || !tlsInfo.State.HandshakeComplete {
		return result, fmt.Errorf("attested telemetry requires a completed TLS 1.3 connection; configure authenticated TLS before retrying")
	}
	material, err := tlsInfo.State.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, len(result))
	if err != nil {
		return result, fmt.Errorf("derive actual TLS exporter: %w", err)
	}
	copy(result[:], material)
	return result, nil
}

// ServerChannelBinding reads gRPC's authenticated peer state. No header or
// producer-provided byte string can replace the connection's exporter.
func ServerChannelBinding(ctx context.Context) ([32]byte, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return [32]byte{}, fmt.Errorf("gRPC peer is unavailable; establish the TLS stream before requesting attestation")
	}
	return ChannelBinding(p.AuthInfo)
}

// ClientBinding is a per-RPC credential observer. gRPC supplies the connection's
// AuthInfo before opening the stream, so the producer derives the same exporter
// without trusting an echoed server value or waiting for a stream to finish.
// Use a new instance per stream and disable transparent RPC retries.
type ClientBinding struct {
	mu       sync.Mutex
	binding  [32]byte
	observed bool
}

var _ credentials.PerRPCCredentials = (*ClientBinding)(nil)

func (c *ClientBinding) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	if c == nil || ctx == nil {
		return nil, fmt.Errorf("a per-stream binding observer and context are required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	request, ok := credentials.RequestInfoFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("gRPC did not supply connection authentication; do not send unattested telemetry")
	}
	binding, err := ChannelBinding(request.AuthInfo)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.observed && c.binding != binding {
		return nil, fmt.Errorf("RPC changed TLS connections; discard the prior challenge and establish a fresh attested session")
	}
	c.binding, c.observed = binding, true
	return nil, nil
}

func (*ClientBinding) RequireTransportSecurity() bool { return true }

func (c *ClientBinding) Exporter() ([32]byte, error) {
	if c == nil {
		return [32]byte{}, fmt.Errorf("a per-stream binding observer is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.observed {
		return [32]byte{}, fmt.Errorf("TLS exporter is not available before gRPC opens the stream")
	}
	return c.binding, nil
}
