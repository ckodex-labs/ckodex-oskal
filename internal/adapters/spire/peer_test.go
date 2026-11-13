package spire

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPeerRejectsUnprovenTransportState(t *testing.T) {
	if err := validateTLSExporter(tls.ConnectionState{}); err == nil {
		t.Fatal("fabricated TLS state acquired exporter proof")
	}
	if _, err := NewPeerPrincipal(nil, []string{"spiffe://example.test/peer"}, nil); err == nil {
		t.Fatal("missing principal dependencies accepted")
	}
	for _, ids := range [][]string{nil, {"*"}, {"spiffe://example.test"}} {
		if err := validatePeerIDs(ids); err == nil {
			t.Fatal("non-exact peer allowlist accepted")
		}
	}
}

func TestRealPeerPrincipal(t *testing.T) {
	socket, id := os.Getenv("OSKAL_SPIRE_TEST_SOCKET"), os.Getenv("OSKAL_SPIRE_TEST_ID")
	if socket == "" {
		t.Skip("real SPIRE Workload API not configured")
	}
	client, err := NewWorkloadClient(t.Context(), socket, id, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Identity(t.Context()); err != nil {
		t.Fatal(err)
	}
	serverTLS, err := client.TLSServerConfig(t.Context(), []string{id})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := client.TLSClientConfig(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	stateC := make(chan tls.ConnectionState, 1)
	done := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		connection := tls.Server(raw, serverTLS)
		defer func() { _ = connection.Close() }()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		if err := connection.HandshakeContext(ctx); err != nil {
			done <- err
			return
		}
		state := connection.ConnectionState()
		peer, err := client.AuthenticatedPeer(ctx, state, []string{id})
		if err != nil {
			done <- err
			return
		}
		if peer != id {
			done <- context.Canceled
			return
		}
		principal, err := NewPeerPrincipal(client, []string{id}, func(context.Context) (tls.ConnectionState, bool) { return state, true })
		if err != nil {
			done <- err
			return
		}
		if _, err := principal.AuthenticatedPrincipal(ctx); err != nil {
			done <- err
			return
		}
		if _, err := client.AuthenticatedPeer(ctx, state, []string{id + "-wrong"}); err == nil {
			done <- context.Canceled
			return
		}
		forged := tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: state.PeerCertificates}
		if _, err := client.AuthenticatedPeer(ctx, forged, []string{id}); err == nil {
			done <- context.Canceled
			return
		}
		stateC <- state
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	connection, err := (&tls.Dialer{Config: clientTLS}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	if err := <-done; err != nil {
		t.Fatalf("real peer proof failed: %v", err)
	}
	state := <-stateC
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AuthenticatedPeer(ctx, state, []string{id}); err == nil || !strings.Contains(err.Error(), "Workload API") {
		t.Fatalf("closed fresh-identity source accepted existing TLS peer: %v", err)
	}
	t.Logf("VERIFIED real TLS1.3 peer %s; exact allowlist, fabricated state, and unavailable fresh identity denied", id)
}
