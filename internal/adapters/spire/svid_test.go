package spire

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// generateTestCA creates a test self-signed CA certificate and private key.
func generateTestCA(t *testing.T, commonName string) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"CKODEX Test CA"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse generated CA cert: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return cert, priv, pemBytes
}

// generateTestSVID creates an X.509 SVID signed by the test CA.
func generateTestSVID(
	t *testing.T,
	caCert *x509.Certificate,
	caKey *rsa.PrivateKey,
	spiffeID string,
	notBefore time.Time,
	notAfter time.Time,
) *x509.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate SVID key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "Workload SVID",
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	if spiffeID != "" {
		u, err := url.Parse(spiffeID)
		if err != nil {
			t.Fatalf("failed to parse SPIFFE ID: %v", err)
		}
		template.URIs = []*url.URL{u}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create SVID certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse SVID certificate: %v", err)
	}

	return cert
}

func TestSVIDValidator_ValidChain(t *testing.T) {
	caCert, caKey, caPEM := generateTestCA(t, "SPIFFE Root CA")
	bundle := NewTrustBundle()
	if err := bundle.AddRootCA("prod", caPEM); err != nil {
		t.Fatalf("failed to add root CA to bundle: %v", err)
	}

	validator := NewSVIDValidator(bundle, assurance.AuthorityRef{
		Scheme:  "spiffe",
		Subject: "prod/ns/security/sa/oskal-validator",
	})

	now := time.Now()
	svid := generateTestSVID(t, caCert, caKey, "spiffe://prod/ns/payments/sa/payment-service", now.Add(-10*time.Minute), now.Add(1*time.Hour))

	info, err := validator.ValidateSVID(svid)
	if err != nil {
		t.Fatalf("expected valid SVID, got error: %v", err)
	}

	if info.SPIFFEID != "spiffe://prod/ns/payments/sa/payment-service" {
		t.Errorf("unexpected SPIFFE ID: %s", info.SPIFFEID)
	}
	if info.TrustDomain != "prod" {
		t.Errorf("unexpected trust domain: %s", info.TrustDomain)
	}
	if info.Namespace != "payments" {
		t.Errorf("unexpected namespace: %s", info.Namespace)
	}
	if info.ServiceAcct != "payment-service" {
		t.Errorf("unexpected service account: %s", info.ServiceAcct)
	}
	if info.Fingerprint == "" || info.Serial == "" {
		t.Errorf("missing fingerprint or serial in SVID info")
	}
}

func TestSVIDValidator_ExpiredAndNotYetValid(t *testing.T) {
	caCert, caKey, caPEM := generateTestCA(t, "SPIFFE Root CA")
	bundle := NewTrustBundle()
	_ = bundle.AddRootCA("prod", caPEM)
	validator := NewSVIDValidator(bundle, assurance.AuthorityRef{})

	now := time.Now()

	// 1. Expired
	expiredSVID := generateTestSVID(t, caCert, caKey, "spiffe://prod/ns/test/sa/test-sa", now.Add(-2*time.Hour), now.Add(-1*time.Hour))
	if _, err := validator.ValidateSVID(expiredSVID); err == nil {
		t.Errorf("expected error for expired SVID, got nil")
	}

	// 2. Not yet valid
	futureSVID := generateTestSVID(t, caCert, caKey, "spiffe://prod/ns/test/sa/test-sa", now.Add(1*time.Hour), now.Add(2*time.Hour))
	if _, err := validator.ValidateSVID(futureSVID); err == nil {
		t.Errorf("expected error for not-yet-valid SVID, got nil")
	}
}

func TestSVIDValidator_UntrustedRootCA(t *testing.T) {
	caCert1, caKey1, _ := generateTestCA(t, "CA 1")
	_, _, caPEM2 := generateTestCA(t, "CA 2")

	bundle := NewTrustBundle()
	// Register CA 2 under "prod", but SVID is signed by CA 1
	_ = bundle.AddRootCA("prod", caPEM2)
	validator := NewSVIDValidator(bundle, assurance.AuthorityRef{})

	now := time.Now()
	svid := generateTestSVID(t, caCert1, caKey1, "spiffe://prod/ns/test/sa/test-sa", now.Add(-10*time.Minute), now.Add(1*time.Hour))

	if _, err := validator.ValidateSVID(svid); err == nil {
		t.Errorf("expected verification failure for SVID signed by untrusted CA, got nil")
	}
}

func TestSVIDValidator_MissingSPIFFESAN(t *testing.T) {
	caCert, caKey, caPEM := generateTestCA(t, "SPIFFE Root CA")
	bundle := NewTrustBundle()
	_ = bundle.AddRootCA("prod", caPEM)
	validator := NewSVIDValidator(bundle, assurance.AuthorityRef{})

	now := time.Now()
	svid := generateTestSVID(t, caCert, caKey, "", now.Add(-10*time.Minute), now.Add(1*time.Hour))

	if _, err := validator.ValidateSVID(svid); err == nil {
		t.Errorf("expected error for missing SPIFFE SAN URI, got nil")
	}
}

func TestSVIDValidator_WorkloadIdentityAttestation(t *testing.T) {
	caCert, caKey, caPEM := generateTestCA(t, "SPIFFE Root CA")
	bundle := NewTrustBundle()
	_ = bundle.AddRootCA("prod", caPEM)
	validator := NewSVIDValidator(bundle, assurance.AuthorityRef{
		Scheme:  "spiffe",
		Subject: "prod/ns/ckodex/sa/attestor",
	})

	now := time.Now()
	svid := generateTestSVID(t, caCert, caKey, "spiffe://prod/ns/checkout/sa/cart-worker", now.Add(-5*time.Minute), now.Add(2*time.Hour))
	subject := assurance.SubjectRef{Scheme: "k8s", ID: "checkout/Pod/cart-worker-9x8f7"}

	// 1. Success matching
	envelope, info, err := validator.WorkloadIdentityAttestation(
		context.Background(),
		subject,
		svid,
		"checkout",
		"cart-worker",
	)
	if err != nil {
		t.Fatalf("unexpected attestation error: %v", err)
	}

	if envelope == nil || info == nil {
		t.Fatalf("expected non-nil envelope and info")
	}
	if envelope.ObservationType != "workload.identity" {
		t.Errorf("expected observation type workload.identity, got: %s", envelope.ObservationType)
	}
	if envelope.IntegrityDigest == "" {
		t.Errorf("expected non-empty integrity digest")
	}
	if envelope.Artifact.MediaType != "application/vnd.spiffe.svid+json" {
		t.Errorf("unexpected artifact media type: %s", envelope.Artifact.MediaType)
	}

	// 2. Namespace mismatch
	_, _, errNS := validator.WorkloadIdentityAttestation(
		context.Background(),
		subject,
		svid,
		"other-ns",
		"cart-worker",
	)
	if errNS == nil {
		t.Errorf("expected error on namespace mismatch, got nil")
	}

	// 3. Service account mismatch
	_, _, errSA := validator.WorkloadIdentityAttestation(
		context.Background(),
		subject,
		svid,
		"checkout",
		"rogue-sa",
	)
	if errSA == nil {
		t.Errorf("expected error on service account mismatch, got nil")
	}
}
