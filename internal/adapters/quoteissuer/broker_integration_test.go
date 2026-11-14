//go:build integration

package quoteissuer_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/quoteissuer"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tpm"
	"github.com/ckodex-labs/ckodex-oskal/internal/demos/softwareroot"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
	pb "github.com/ckodex-labs/ckodex-oskal/proto/assurance/attestation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func TestRealSoftwareTPMBroker(t *testing.T) {
	address := os.Getenv("OSKAL_BROKER_SWTPM_ADDRESS")
	if address == "" {
		t.Fatal("OSKAL_BROKER_SWTPM_ADDRESS must identify a dedicated fresh owned software TPM")
	}
	source, err := os.ReadFile(os.Getenv("OSKAL_BROKER_ELF"))
	if err != nil {
		t.Fatal(err)
	}
	measured := filepath.Join(t.TempDir(), "sensor.elf")
	if err := os.WriteFile(measured, source, 0500); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	config := softwareroot.Config{Network: "tcp", Address: address, FreshStateDirectory: state, ExecutablePath: measured, ConfirmFreshSoftwareTPM: true}
	root, err := softwareroot.Initialize(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	if _, err := softwareroot.Initialize(t.Context(), config); err == nil {
		t.Fatal("reused consumed state marker")
	}
	changed := config
	changed.FreshStateDirectory = t.TempDir()
	_ = os.Chmod(changed.FreshStateDirectory, 0700)
	if _, err := softwareroot.Initialize(t.Context(), changed); err == nil {
		t.Fatal("initialized nonzero PCR16 as fresh root")
	}
	provider, err := tpm.NewProvider(root.ProviderConfig)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := tpm.NewVerifier(root.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	inspector, err := quoteissuer.NewPinnedFileInspector(measured, root.Measurement)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inspector.Close() }()
	serverTLS, clientTLS, wrongTLS, pin := certificates(t)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := quoteissuer.NewServer(quoteissuer.Config{Provider: provider, Inspector: inspector, AllowedClientCertificateDigest: pin, ExportPublicKey: public, TLS: serverTLS, ProofTTL: 250 * time.Millisecond, Capacity: 2})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("broker shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("broker shutdown exceeded bound")
		}
	}()
	client, err := quoteissuer.NewClient(quoteissuer.ClientConfig{Address: listener.Addr().String(), TLS: clientTLS, ExportPrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	rpc := pb.NewQuoteIssuerClient(connection)
	var qualification [64]byte
	if _, err := rand.Read(qualification[:]); err != nil {
		t.Fatal(err)
	}
	report, err := client.Attest(t.Context(), qualification)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := verifier.VerifyAttestation(t.Context(), report, qualification)
	if err != nil || facts.RootLabel != "software TPM root — not hardware-backed" {
		t.Fatalf("real broker quote: %+v %v", facts, err)
	}
	t.Log("VERIFIED real mTLS -> registered Ed25519 DSSE proof -> pre/post outside ELF inspection -> swtpm quote -> enrolled TPM verifier; software TPM root — not hardware-backed")
	t.Run("qualification_binding", func(t *testing.T) {
		other := qualification
		other[0] ^= 1
		if _, err := verifier.VerifyAttestation(t.Context(), report, other); err == nil {
			t.Fatal("accepted changed qualification")
		}
	})
	t.Run("one_use_proof", func(t *testing.T) {
		challenge := getChallenge(t, rpc)
		signed := signProof(t, key, qualification, challenge)
		if _, err := rpc.Issue(t.Context(), &pb.IssueRequest{SignedProof: signed}); err != nil {
			t.Fatal(err)
		}
		_, err := rpc.Issue(t.Context(), &pb.IssueRequest{SignedProof: signed})
		requireCode(t, err, codes.PermissionDenied)
	})
	t.Run("wrong_export_key", func(t *testing.T) {
		_, wrong, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		challenge := getChallenge(t, rpc)
		_, err = rpc.Issue(t.Context(), &pb.IssueRequest{SignedProof: signProof(t, wrong, qualification, challenge)})
		requireCode(t, err, codes.PermissionDenied)
		_, err = rpc.Issue(t.Context(), &pb.IssueRequest{SignedProof: signProof(t, key, qualification, challenge)})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unknown_proof_nonce", func(t *testing.T) {
		challenge := &pb.ChallengeResponse{Nonce: bytes.Repeat([]byte{1}, 32), IssuedUnixNano: time.Now().UnixNano()}
		_, err := rpc.Issue(t.Context(), &pb.IssueRequest{SignedProof: signProof(t, key, qualification, challenge)})
		requireCode(t, err, codes.PermissionDenied)
	})
	t.Run("proof_expiry", func(t *testing.T) {
		challenge := getChallenge(t, rpc)
		time.Sleep(300 * time.Millisecond)
		_, err := rpc.Issue(t.Context(), &pb.IssueRequest{SignedProof: signProof(t, key, qualification, challenge)})
		requireCode(t, err, codes.PermissionDenied)
	})
	t.Run("bounded_challenge_capacity", func(t *testing.T) {
		a := getChallenge(t, rpc)
		b := getChallenge(t, rpc)
		_, err := rpc.Challenge(t.Context(), &pb.ChallengeRequest{})
		requireCode(t, err, codes.ResourceExhausted)
		for _, challenge := range []*pb.ChallengeResponse{a, b} {
			if _, err := rpc.Issue(t.Context(), &pb.IssueRequest{SignedProof: signProof(t, key, qualification, challenge)}); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("wrong_mTLS_caller", func(t *testing.T) {
		wrong, err := quoteissuer.NewClient(quoteissuer.ClientConfig{Address: listener.Addr().String(), TLS: wrongTLS, ExportPrivateKey: key})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = wrong.Close() }()
		_, err = wrong.Attest(t.Context(), qualification)
		requireCode(t, err, codes.PermissionDenied)
	})
	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := client.Attest(ctx, qualification)
		requireCode(t, err, codes.Canceled)
	})
	t.Run("oversized_proof", func(t *testing.T) {
		_, err := rpc.Issue(t.Context(), &pb.IssueRequest{SignedProof: make([]byte, 8193)})
		requireCode(t, err, codes.ResourceExhausted)
	})
	t.Run("concurrent_real_quotes", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() {
				report, err := client.Attest(t.Context(), qualification)
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := verifier.VerifyAttestation(t.Context(), report, qualification); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
	})
	t.Run("mutation_while_real_TPM_paused", func(t *testing.T) {
		container := os.Getenv("OSKAL_BROKER_SWTPM_CONTAINER")
		if !strings.HasPrefix(container, "oskal-p2-broker-") {
			t.Fatal("dedicated broker TPM container required")
		}
		docker := func(operation string) {
			t.Helper()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if output, err := exec.CommandContext(ctx, "docker", operation, container).CombinedOutput(); err != nil {
				t.Fatalf("%s: %v: %s", operation, err, output)
			}
		}
		docker("pause")
		paused := true
		defer func() {
			if paused {
				docker("unpause")
			}
		}()
		challenge := getChallenge(t, rpc)
		request := &pb.IssueRequest{SignedProof: signProof(t, key, qualification, challenge)}
		finished := make(chan error, 1)
		go func() { _, err := rpc.Issue(t.Context(), request); finished <- err }()
		time.Sleep(50 * time.Millisecond)
		changed := bytes.Clone(source)
		changed[len(changed)-1] ^= 1
		if err := os.Chmod(measured, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(measured, changed, 0500); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.WriteFile(measured, source, 0500); err != nil {
				t.Error(err)
			}
			if err := os.Chmod(measured, 0500); err != nil {
				t.Error(err)
			}
		}()
		docker("unpause")
		paused = false
		select {
		case err := <-finished:
			requireCode(t, err, codes.FailedPrecondition)
			if status.Convert(err).Message() != "outside measurement changed during quote" {
				t.Fatalf("post-quote check not demonstrated: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("paused quote recovery exceeded bound")
		}
	})
	t.Run("recovery_after_measurement_restoration", func(t *testing.T) {
		report, err := client.Attest(t.Context(), qualification)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifier.VerifyAttestation(t.Context(), report, qualification); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("file_changed_after_success", func(t *testing.T) {
		changed := bytes.Clone(source)
		changed[len(changed)-1] ^= 1
		if err := os.Chmod(measured, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(measured, changed, 0500); err != nil {
			t.Fatal(err)
		}
		_, err := client.Attest(t.Context(), qualification)
		requireCode(t, err, codes.FailedPrecondition)
		if err := os.WriteFile(measured, source, 0500); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(measured, 0500); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("file_identity_replaced_same_bytes", func(t *testing.T) {
		replacement := measured + ".new"
		if err := os.WriteFile(replacement, source, 0500); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, measured); err != nil {
			t.Fatal(err)
		}
		_, err := client.Attest(t.Context(), qualification)
		requireCode(t, err, codes.FailedPrecondition)
	})
}
func getChallenge(t *testing.T, rpc pb.QuoteIssuerClient) *pb.ChallengeResponse {
	t.Helper()
	challenge, err := rpc.Challenge(t.Context(), &pb.ChallengeRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return challenge
}
func signProof(t *testing.T, key ed25519.PrivateKey, q [64]byte, c *pb.ChallengeResponse) []byte {
	t.Helper()
	hash := sha256.Sum256(key.Public().(ed25519.PublicKey))
	raw, err := json.Marshal(struct {
		Qualification  []byte `json:"qualification"`
		Nonce          []byte `json:"nonce"`
		IssuedUnixNano int64  `json:"issuedUnixNano"`
		ExportKeyHash  []byte `json:"exportKeyHash"`
	}{q[:], c.Nonce, c.IssuedUnixNano, hash[:]})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signedrecords.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(t.Context(), "application/vnd.oskal.quote-authorization.v1+json", raw)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
func requireCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("wanted %s, got %v", want, err)
	}
}
func certificates(t *testing.T) (*tls.Config, *tls.Config, *tls.Config, [32]byte) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "broker test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		pub, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
	}
	server := leaf(2, x509.ExtKeyUsageServerAuth)
	client := leaf(3, x509.ExtKeyUsageClientAuth)
	wrong := leaf(4, x509.ExtKeyUsageClientAuth)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server}, ClientCAs: roots}, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{client}, RootCAs: roots, ServerName: "localhost"}, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{wrong}, RootCAs: roots, ServerName: "localhost"}, sha256.Sum256(client.Certificate[0])
}
