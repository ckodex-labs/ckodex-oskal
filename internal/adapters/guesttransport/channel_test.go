package guesttransport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func channelTLS(t *testing.T, version uint16) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OSKAL channel test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	issue := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, root, pub, private)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, rootDER}, PrivateKey: priv}
	}
	return &tls.Config{MinVersion: version, MaxVersion: version, Certificates: []tls.Certificate{issue(2, x509.ExtKeyUsageServerAuth)}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool},
		&tls.Config{MinVersion: version, MaxVersion: version, ServerName: "localhost", RootCAs: pool, Certificates: []tls.Certificate{issue(3, x509.ExtKeyUsageClientAuth)}}
}

func channelServer(t *testing.T, config *tls.Config) (string, <-chan [32]byte) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bindings := make(chan [32]byte, 2)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(config)), grpc.UnaryInterceptor(func(ctx context.Context, request any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		binding, err := ServerChannelBinding(ctx)
		if err != nil {
			return nil, err
		}
		select {
		case bindings <- binding:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return handler(ctx, request)
	}))
	// The real gRPC health service maintains and serves its own status; no
	// attestation verifier, channel authentication, or transport is substituted.
	healthpb.RegisterHealthServer(server, health.NewServer())
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("gRPC serve: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("gRPC server did not stop")
		}
	})
	return listener.Addr().String(), bindings
}

func TestActualGRPCChannelBinding(t *testing.T) {
	serverTLS, clientTLS := channelTLS(t, tls.VersionTLS13)
	address, serverBindings := channelServer(t, serverTLS)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	call := func(observer *ClientBinding) ([32]byte, error) {
		connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS.Clone())), grpc.WithDisableRetry())
		if err != nil {
			return [32]byte{}, err
		}
		defer func() {
			if err := connection.Close(); err != nil {
				t.Errorf("close client: %v", err)
			}
		}()
		_, err = healthpb.NewHealthClient(connection).Check(ctx, &healthpb.HealthCheckRequest{}, grpc.PerRPCCredentials(observer))
		if err != nil {
			return [32]byte{}, err
		}
		return observer.Exporter()
	}
	firstObserver := &ClientBinding{}
	if _, err := firstObserver.Exporter(); err == nil {
		t.Fatal("exporter available before real handshake")
	}
	first, err := call(firstObserver)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case actual := <-serverBindings:
		if first != actual || first == [32]byte{} {
			t.Fatal("independently derived client and server exporters differ")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	second, err := call(&ClientBinding{})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case actual := <-serverBindings:
		if second != actual || second == first {
			t.Fatal("different TLS connections reused channel binding")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := call(firstObserver); err == nil || !strings.Contains(err.Error(), "changed TLS connections") {
		t.Fatalf("reusing a previous session binding was not rejected: %v", err)
	}
	t.Log("real TLS 1.3 gRPC: both endpoints agree; separate connections differ; prior binding reuse rejected")
}

func TestChannelBindingRejectsRealTLS12(t *testing.T) {
	serverTLS, clientTLS := channelTLS(t, tls.VersionTLS12)
	address, _ := channelServer(t, serverTLS)
	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)), grpc.WithDisableRetry())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := connection.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = healthpb.NewHealthClient(connection).Check(ctx, &healthpb.HealthCheckRequest{}, grpc.PerRPCCredentials(&ClientBinding{}))
	if err == nil || !strings.Contains(err.Error(), "TLS 1.3") {
		t.Fatalf("real TLS 1.2 connection was not refused: %v", err)
	}
}

func TestChannelBindingRequiresActualAuthentication(t *testing.T) {
	if _, err := ChannelBinding(nil); err == nil {
		t.Fatal("nil authentication accepted")
	}
	if _, err := ServerChannelBinding(context.Background()); err == nil {
		t.Fatal("missing gRPC peer accepted")
	}
	if _, err := (&ClientBinding{}).GetRequestMetadata(context.Background()); err == nil {
		t.Fatal("missing transport request authentication accepted")
	}
}
