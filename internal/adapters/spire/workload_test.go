package spire

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"testing"
	"time"
)

func TestWorkloadClientRejectsConfiguration(t *testing.T) {
	for _, tc := range []struct {
		address, id string
		timeout     time.Duration
	}{
		{"", "spiffe://prod/client", time.Second}, {"tcp://localhost:8081", "spiffe://prod/client", time.Second}, {"unix:///tmp/agent.sock", "", time.Second}, {"unix:///tmp/agent.sock", "spiffe://prod", time.Second}, {"unix:///tmp/agent.sock", "spiffe://prod/client", 0},
	} {
		if c, err := NewWorkloadClient(t.Context(), tc.address, tc.id, tc.timeout); err == nil {
			_ = c.Close()
			t.Fatal("invalid configuration accepted")
		}
	}
}

func TestWorkloadClientUnavailable(t *testing.T) {
	c, err := NewWorkloadClient(t.Context(), "unix://"+t.TempDir()+"/missing.sock", "spiffe://prod/client", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Identity(t.Context()); err == nil {
		t.Fatal("unavailable agent accepted")
	}
}

// TestRealWorkloadAPI uses a real SPIRE agent and registration entries. Set
// OSKAL_SPIRE_TEST_SOCKET and OSKAL_SPIRE_TEST_ID to opt into live integration.
func TestRealWorkloadAPI(t *testing.T) {
	socket := os.Getenv("OSKAL_SPIRE_TEST_SOCKET")
	if socket == "" {
		t.Skip("real SPIRE agent not configured")
	}
	id := os.Getenv("OSKAL_SPIRE_TEST_ID")
	c, err := NewWorkloadClient(t.Context(), socket, id, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	info, err := c.Identity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if info.SPIFFEID != id || info.Fingerprint == "" {
		t.Fatalf("invalid identity: %+v", info)
	}
	t.Logf("SPIRE identity %s serial=%s expires=%s fingerprint=%s", info.SPIFFEID, info.Serial, info.NotAfter, info.Fingerprint)
	wrong, err := NewWorkloadClient(t.Context(), socket, id+"-wrong", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wrong.Close() }()
	if _, err := wrong.Identity(t.Context()); err == nil {
		t.Fatal("wrong own SPIFFE ID accepted")
	}
	for _, tc := range []struct {
		server, client string
		allowed        bool
	}{{id, id, true}, {id + "-wrong", id, false}, {id, id + "-wrong", false}} {
		peer := tc.server
		serverConfig, err := c.TLSServerConfig(t.Context(), []string{tc.client})
		if err != nil {
			t.Fatal(err)
		}
		clientConfig, err := c.TLSClientConfig(t.Context(), peer)
		if err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			raw, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			conn := tls.Server(raw, serverConfig)
			defer func() { _ = conn.Close() }()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			done <- conn.HandshakeContext(ctx)
		}()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		dialer := tls.Dialer{Config: clientConfig}
		conn, dialErr := dialer.DialContext(ctx, "tcp", listener.Addr().String())
		if conn != nil {
			_ = conn.Close()
		}
		cancel()
		_ = listener.Close()
		serverErr := <-done
		if tc.allowed && (dialErr != nil || serverErr != nil) {
			t.Fatalf("real mTLS failed: client=%v server=%v", dialErr, serverErr)
		}
		if !tc.allowed && dialErr == nil && serverErr == nil {
			t.Fatal("wrong server SPIFFE ID accepted")
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Identity(t.Context()); err == nil {
		t.Fatal("closed client returned identity")
	}
}

// TestRealWorkloadAPIUnavailable exercises a stopped real agent using its socket.
func TestRealWorkloadAPIUnavailable(t *testing.T) {
	socket := os.Getenv("OSKAL_SPIRE_UNAVAILABLE_SOCKET")
	if socket == "" {
		t.Skip("stopped real SPIRE agent not configured")
	}
	c, err := NewWorkloadClient(t.Context(), socket, "spiffe://phase1.oskal.test/workload", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Identity(t.Context()); err == nil {
		t.Fatal("stopped real agent returned identity")
	}
}
