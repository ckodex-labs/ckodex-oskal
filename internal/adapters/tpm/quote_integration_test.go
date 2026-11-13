//go:build integration

package tpm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
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

	"github.com/google/go-tpm/tpm2"
)

func TestSoftwareTPMQuote(t *testing.T) {
	address := os.Getenv("OSKAL_SWTPM_ADDRESS")
	if address == "" {
		t.Fatal("real swtpm endpoint required: OSKAL_SWTPM_ADDRESS; no simulator or fallback")
	}
	if err := validateEndpoint("tcp", address); err != nil {
		t.Fatal(err)
	}
	t.Log(SoftwareRootLabel)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	tr := &socketTransport{ctx: ctx, network: "tcp", address: address}
	enrollment, config := provision(t, tr, address)
	provider, err := NewProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	channel := realTLSBinding(t)
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	qualification := qualify(nonce, key, channel)
	quote, err := provider.Quote(ctx, qualification)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.Verify(quote, qualification)
	if err != nil {
		t.Fatal(err)
	}
	if verified.RootLabel != SoftwareRootLabel || verified.RootCode != SoftwareRootCode || verified.PCRValue != enrollment.ExpectedPCR {
		t.Fatal("verified quote lost its root classification or measurement")
	}
	writeEvidence(t, enrollment, quote, qualification, verified)

	t.Run("wrong_nonce", func(t *testing.T) {
		changed := nonce
		changed[0] ^= 1
		reject(t, verifier, quote, qualify(changed, key, channel))
	})
	t.Run("wrong_export_key", func(t *testing.T) {
		other, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		reject(t, verifier, quote, qualify(nonce, other, channel))
	})
	t.Run("different_real_TLS_connection", func(t *testing.T) {
		other := realTLSBinding(t)
		if channel == other {
			t.Fatal("independent TLS connections shared an exporter")
		}
		reject(t, verifier, quote, qualify(nonce, key, other))
	})
	t.Run("replayed_quote_new_challenge", func(t *testing.T) {
		var next [32]byte
		if _, err := rand.Read(next[:]); err != nil {
			t.Fatal(err)
		}
		reject(t, verifier, quote, qualify(next, key, channel))
	})
	for _, field := range []string{"attestation", "signature"} {
		t.Run("trailing_"+field, func(t *testing.T) {
			changed := cloneQuote(quote)
			if field == "attestation" {
				changed.Attestation = append(changed.Attestation, 0)
			} else {
				changed.Signature = append(changed.Signature, 0)
			}
			reject(t, verifier, changed, qualification)
		})
	}
	t.Run("signature_corruption", func(t *testing.T) {
		changed := cloneQuote(quote)
		changed.Signature[len(changed.Signature)-1] ^= 1
		reject(t, verifier, changed, qualification)
	})
	t.Run("AK_handle_identity_change", func(t *testing.T) {
		other := config
		other.AKName = bytes.Clone(config.AKName)
		other.AKName[2] ^= 1
		p, err := NewProvider(other)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Quote(ctx, qualification); err == nil {
			t.Fatal("accepted substituted AK handle identity")
		}
	})
	t.Run("wrong_AK_authorization", func(t *testing.T) {
		other := config
		other.AKAuth = []byte("wrong authorization")
		p, err := NewProvider(other)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Quote(ctx, qualification); err == nil {
			t.Fatal("quoted without enrolled AK authorization")
		}
	})
	t.Run("malformed_and_oversized_wire_data", func(t *testing.T) {
		for _, attestation := range [][]byte{nil, {1}, quote.Attestation[:len(quote.Attestation)-1], make([]byte, maxAttestationSize+1)} {
			changed := cloneQuote(quote)
			changed.Attestation = attestation
			reject(t, verifier, changed, qualification)
		}
		for _, signature := range [][]byte{nil, {1}, quote.Signature[:len(quote.Signature)-1], make([]byte, maxSignatureSize+1)} {
			changed := cloneQuote(quote)
			changed.Signature = signature
			reject(t, verifier, changed, qualification)
		}
	})
	t.Run("PCR_value_substitution", func(t *testing.T) {
		changed := cloneQuote(quote)
		changed.PCRValue[0] ^= 1
		reject(t, verifier, changed, qualification)
	})
	t.Run("missing_root_label", func(t *testing.T) {
		changed := cloneQuote(quote)
		changed.RootLabel = ""
		reject(t, verifier, changed, qualification)
	})
	t.Run("different_PCR_signed_by_real_TPM", func(t *testing.T) {
		other := config
		other.PCRIndex = 15
		p, err := NewProvider(other)
		if err != nil {
			t.Fatal(err)
		}
		q, err := p.Quote(ctx, qualification)
		if err != nil {
			t.Fatal(err)
		}
		reject(t, verifier, q, qualification)
	})
	t.Run("wrong_enrolled_qualified_name", func(t *testing.T) {
		other := enrollment
		other.AKQualifiedName = bytes.Clone(enrollment.AKQualifiedName)
		other.AKQualifiedName[2] ^= 1
		v, err := NewVerifier(other)
		if err != nil {
			t.Fatal(err)
		}
		reject(t, v, quote, qualification)
	})
	t.Run("enrollment_public_trailing_bytes", func(t *testing.T) {
		other := enrollment
		other.AKPublic = append(bytes.Clone(enrollment.AKPublic), 0)
		if _, err := NewVerifier(other); err == nil {
			t.Fatal("accepted trailing public key bytes")
		}
	})
	t.Run("concurrent_real_quotes", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				q, err := provider.Quote(ctx, qualification)
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := verifier.Verify(q, qualification); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
	})
	t.Run("canceled_context", func(t *testing.T) {
		canceled, stop := context.WithCancel(ctx)
		stop()
		if _, err := provider.Quote(canceled, qualification); !errors.Is(err, context.Canceled) {
			t.Fatalf("wanted canceled, got %v", err)
		}
	})
	t.Run("real_TPM_pause_cancel_timeout_recovery", func(t *testing.T) {
		container := os.Getenv("OSKAL_SWTPM_CONTAINER")
		if !strings.HasPrefix(container, "oskal-p2-tpm-") {
			t.Fatal("OSKAL_SWTPM_CONTAINER must identify the dedicated oskal-p2-tpm-* container")
		}
		docker(t, "pause", container)
		defer docker(t, "unpause", container)
		pending, cancel := context.WithCancel(ctx)
		timer := time.AfterFunc(50*time.Millisecond, cancel)
		defer timer.Stop()
		started := time.Now()
		_, err := provider.Quote(pending, qualification)
		if !errors.Is(err, context.Canceled) || time.Since(started) > time.Second {
			t.Fatalf("in-flight cancellation was not bounded: %v after %s", err, time.Since(started))
		}
		short := config
		short.CommandTimeout = 100 * time.Millisecond
		p, err := NewProvider(short)
		if err != nil {
			t.Fatal(err)
		}
		started = time.Now()
		_, err = p.Quote(ctx, qualification)
		var networkError net.Error
		timedOut := errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout())
		if !timedOut || time.Since(started) > time.Second {
			t.Fatalf("paused TPM timeout was not bounded: %v after %s", err, time.Since(started))
		}
	})
	t.Run("real_TPM_recovers_after_pause", func(t *testing.T) {
		q, err := provider.Quote(ctx, qualification)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifier.Verify(q, qualification); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("PCR_mutation_real_quote", func(t *testing.T) {
		digest := sha256.Sum256([]byte("changed software measurement"))
		extend(t, tr, digest)
		q, err := provider.Quote(ctx, qualification)
		if err != nil {
			t.Fatal(err)
		}
		reject(t, verifier, q, qualification)
	})
}

func provision(t *testing.T, tr *socketTransport, address string) (Enrollment, ProviderConfig) {
	t.Helper()
	// These mutations are restricted to an explicitly supplied disposable demo
	// TPM. Production provider code never creates keys or resets measurements.
	if _, err := (tpm2.PCRReset{PCRHandle: tpm2.TPMHandle(16)}).Execute(tr); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	measurement := sha256.Sum256(data)
	extend(t, tr, measurement)
	var auth [32]byte
	if _, err := rand.Read(auth[:]); err != nil {
		t.Fatal(err)
	}
	public := tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, UserWithAuth: true, Restricted: true, SignEncrypt: true},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA, Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256})},
			CurveID:   tpm2.TPMECCNistP256, KDF: tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
	}
	rsp, err := (tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{UserAuth: tpm2.TPM2BAuth{Buffer: auth[:]}}},
		InPublic:    tpm2.New2B(public),
	}).Execute(tr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cleanup := &socketTransport{ctx: ctx, network: "tcp", address: address}
		if _, err := (tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}).Execute(cleanup); err != nil {
			t.Error(err)
		}
	})
	read, err := (tpm2.ReadPublic{ObjectHandle: rsp.ObjectHandle}).Execute(tr)
	if err != nil {
		t.Fatal(err)
	}
	var preimage [64]byte
	copy(preimage[32:], measurement[:])
	enrollment := Enrollment{AKPublic: bytes.Clone(read.OutPublic.Bytes()), AKName: bytes.Clone(read.Name.Buffer), AKQualifiedName: bytes.Clone(read.QualifiedName.Buffer), PCRIndex: 16, ExpectedPCR: sha256.Sum256(preimage[:])}
	config := ProviderConfig{Network: "tcp", Address: address, AKHandle: uint32(rsp.ObjectHandle), AKName: enrollment.AKName, AKAuth: auth[:], PCRIndex: 16, CommandTimeout: 5 * time.Second}
	return enrollment, config
}

func extend(t *testing.T, tr *socketTransport, digest [32]byte) {
	t.Helper()
	if _, err := (tpm2.PCRExtend{PCRHandle: tpm2.TPMHandle(16), Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: digest[:]}}}}).Execute(tr); err != nil {
		t.Fatal(err)
	}
}

func qualify(nonce [32]byte, key ed25519.PublicKey, channel [32]byte) [64]byte {
	keyDigest := sha256.Sum256(key)
	preimage := append([]byte("oskal/tpm-integration/v1\x00"), keyDigest[:]...)
	preimage = append(preimage, channel[:]...)
	digest := sha256.Sum256(preimage)
	var result [64]byte
	copy(result[:32], nonce[:])
	copy(result[32:], digest[:])
	return result
}

func reject(t *testing.T, v *Verifier, q Quote, expected [64]byte) {
	t.Helper()
	if _, err := v.Verify(q, expected); err == nil {
		t.Fatal("accepted invalid quote")
	} else {
		t.Log(err)
	}
}

func cloneQuote(q Quote) Quote {
	q.Attestation = bytes.Clone(q.Attestation)
	q.Signature = bytes.Clone(q.Signature)
	return q
}

func writeEvidence(t *testing.T, e Enrollment, q Quote, qualification [64]byte, verified VerifiedQuote) {
	t.Helper()
	dir := os.Getenv("OSKAL_TPM_EVIDENCE_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(struct {
		Enrollment    Enrollment
		Quote         Quote
		Qualification [64]byte
		Verified      VerifiedQuote
	}{e, q, qualification, verified}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "quote.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	public, err := tpm2.Unmarshal[tpm2.TPMTPublic](e.AKPublic)
	if err != nil {
		t.Fatal(err)
	}
	key, err := tpm2.Pub(*public)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](q.Signature)
	if err != nil {
		t.Fatal(err)
	}
	ecc, err := sig.Signature.ECDSA()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(ecc.SignatureR.Buffer), new(big.Int).SetBytes(ecc.SignatureS.Buffer)})
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string][]byte{"ak.pem": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), "quote.sig": encoded, "quote.attest": q.Attestation} {
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func realTLSBinding(t *testing.T) [32]byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "oskal-tpm-test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	type result struct {
		binding []byte
		err     error
	}
	server := make(chan result, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			server <- result{err: err}
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			server <- result{err: err}
			return
		}
		secured := conn.(*tls.Conn)
		if err := secured.Handshake(); err != nil {
			server <- result{err: err}
			return
		}
		state := secured.ConnectionState()
		binding, err := state.ExportKeyingMaterial("EXPORTER-Channel-Binding", []byte{}, 32)
		server <- result{binding: binding, err: err}
	}()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	state := conn.ConnectionState()
	binding, err := state.ExportKeyingMaterial("EXPORTER-Channel-Binding", []byte{}, 32)
	if err != nil {
		t.Fatal(err)
	}
	remote := <-server
	if remote.err != nil || !bytes.Equal(binding, remote.binding) {
		t.Fatalf("TLS endpoint exporter mismatch: %v", remote.err)
	}
	return [32]byte(binding)
}

func docker(t *testing.T, operation, container string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "docker", operation, container).CombinedOutput(); err != nil {
		t.Fatalf("docker %s %s: %v: %s", operation, container, err, output)
	}
}
