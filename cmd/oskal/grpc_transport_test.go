package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
)

type grpcTestPKI struct{ ca, serverCert, serverKey, clientCert, clientKey string }

func createGRPCTestPKI(t *testing.T) grpcTestPKI {
	t.Helper()
	directory := t.TempDir()
	rootPublic, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	config := grpcTestPKI{ca: write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))}
	for i, role := range []string{"server", "client"} {
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		usage := x509.ExtKeyUsageServerAuth
		if role == "client" {
			usage = x509.ExtKeyUsageClientAuth
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: []string{"server.oskal.test"}}
		der, err := x509.CreateCertificate(rand.Reader, template, root, public, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certificate := write(role+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		privatePath := write(role+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
		if role == "server" {
			config.serverCert = certificate
			config.serverKey = privatePath
		} else {
			config.clientCert = certificate
			config.clientKey = privatePath
		}
	}
	return config
}

func startCLIService(t *testing.T, binary string, config grpcTestPKI, mtls bool) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	log, err := os.Create(filepath.Join(t.TempDir(), "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"serve", "--port", "0", "--tls-cert-file", config.serverCert, "--tls-key-file", config.serverKey}
	if mtls {
		args = append(args, "--tls-client-ca-file", config.ca)
	}
	process := exec.CommandContext(ctx, binary, args...)
	process.Stdout = log
	process.Stderr = log
	if err := process.Start(); err != nil {
		cancel()
		_ = log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	t.Cleanup(func() {
		_ = process.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				data, _ := os.ReadFile(log.Name())
				t.Errorf("TLS server exit: %v: %s", err, data)
			}
		case <-time.After(7 * time.Second):
			cancel()
			if err := <-done; err != nil {
				t.Logf("forced TLS server exit: %v", err)
			}
			t.Error("TLS server did not stop within shutdown budget")
		}
		cancel()
		_ = log.Close()
	})
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
		raw, err := os.ReadFile(log.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if rest, ok := strings.CutPrefix(line, "OSKAL TLS gRPC listening on "); ok {
				address, _, _ := strings.Cut(rest, ";")
				_, port, err := net.SplitHostPort(address)
				if err != nil {
					t.Fatal(err)
				}
				return net.JoinHostPort("127.0.0.1", port)
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	raw, _ := os.ReadFile(log.Name())
	t.Fatalf("TLS server startup did not complete: %s", raw)
	return ""
}

func runGRPCCLI(t *testing.T, binary string, wantSuccess bool, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	if (err == nil) != wantSuccess {
		t.Fatalf("CLI %v success=%t: %v: %s", args, wantSuccess, err, output)
	}
	return string(output)
}

func TestActualCLIRequiresVerifiedTLS(t *testing.T) {
	binary := buildCLI(t)
	pki := createGRPCTestPKI(t)
	if out := runGRPCCLI(t, binary, false, "serve", "--port", "0"); !strings.Contains(out, "--tls-cert-file") {
		t.Fatal(out)
	}
	if out := runGRPCCLI(t, binary, false, "serve", "--port", "0", "--tls-cert-file", pki.serverCert); !strings.Contains(out, "--tls-key-file") {
		t.Fatal(out)
	}
	if out := runGRPCCLI(t, binary, false, "serve", "--port", "0", "--tls-cert-file", pki.serverCert, "--tls-key-file", pki.clientKey); strings.Contains(out, "listening on") {
		t.Fatal("invalid TLS configuration bound listener")
	}
	address := startCLIService(t, binary, pki, false)
	args := []string{"assurance", "state", "k8s://fixture/Pod/unconfigured", "--server", address}
	if out := runGRPCCLI(t, binary, false, args...); !strings.Contains(out, "--tls-ca-file") {
		t.Fatal(out)
	}
	if out := runGRPCCLI(t, binary, false, append(args, "--tls-ca-file", pki.ca)...); !strings.Contains(out, "--tls-server-name") {
		t.Fatal(out)
	}
	secured := append(append([]string{}, args...), "--tls-ca-file", pki.ca, "--tls-server-name", "server.oskal.test")
	if out := runGRPCCLI(t, binary, true, secured...); !strings.Contains(out, "UNKNOWN") || strings.Contains(out, "ASSURED") {
		t.Fatal(out)
	}
	mismatch := append(append([]string{}, args...), "--tls-ca-file", pki.ca, "--tls-server-name", "wrong.oskal.test")
	runGRPCCLI(t, binary, false, mismatch...)
	untrusted := createGRPCTestPKI(t)
	runGRPCCLI(t, binary, false, append(args, "--tls-ca-file", untrusted.ca, "--tls-server-name", "server.oskal.test")...)
	// An explicitly plaintext test client cannot invoke even the health RPC.
	plain, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 400*time.Millisecond)
	_, err = grpc_health_v1.NewHealthClient(plain).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	cancel()
	_ = plain.Close()
	if err == nil {
		t.Fatal("plaintext reached TLS listener")
	}
}

func TestActualCLIMutualTLSAndPairValidation(t *testing.T) {
	binary := buildCLI(t)
	pki := createGRPCTestPKI(t)
	address := startCLIService(t, binary, pki, true)
	args := []string{"assurance", "state", "k8s://fixture/Pod/unconfigured", "--server", address, "--tls-ca-file", pki.ca, "--tls-server-name", "server.oskal.test"}
	runGRPCCLI(t, binary, false, args...)
	if out := runGRPCCLI(t, binary, false, append(args, "--tls-client-cert-file", pki.clientCert)...); !strings.Contains(out, "supplied together") {
		t.Fatal(out)
	}
	if out := runGRPCCLI(t, binary, true, append(args, "--tls-client-cert-file", pki.clientCert, "--tls-client-key-file", pki.clientKey)...); !strings.Contains(out, "UNKNOWN") {
		t.Fatal(out)
	}
	other := createGRPCTestPKI(t)
	runGRPCCLI(t, binary, false, append(args, "--tls-client-cert-file", other.clientCert, "--tls-client-key-file", other.clientKey)...)
	oversized := filepath.Join(t.TempDir(), "oversized.pem")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("x", maxTLSFileBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if out := runGRPCCLI(t, binary, false, "serve", "--port", "0", "--tls-cert-file", oversized, "--tls-key-file", pki.serverKey); !strings.Contains(out, fmt.Sprint(maxTLSFileBytes)) {
		t.Fatal(out)
	}
}
