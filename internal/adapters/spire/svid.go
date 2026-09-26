package spire

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// TrustBundle stores trusted X.509 root CA pools keyed by SPIFFE trust domain.
type TrustBundle struct {
	pools map[string]*x509.CertPool
}

// NewTrustBundle creates an empty SPIFFE trust bundle.
func NewTrustBundle() *TrustBundle {
	return &TrustBundle{
		pools: make(map[string]*x509.CertPool),
	}
}

// AddRootCA adds a PEM-encoded X.509 root certificate for a given trust domain.
func (b *TrustBundle) AddRootCA(trustDomain string, certPEM []byte) error {
	pool, exists := b.pools[trustDomain]
	if !exists {
		pool = x509.NewCertPool()
		b.pools[trustDomain] = pool
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		// Try raw DER if not PEM
		cert, err := x509.ParseCertificate(certPEM)
		if err != nil {
			return fmt.Errorf("failed to parse root CA for trust domain %s: %w", trustDomain, err)
		}
		pool.AddCert(cert)
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse PEM root certificate: %w", err)
	}
	pool.AddCert(cert)
	return nil
}

// GetCertPool returns the X.509 cert pool for a trust domain.
func (b *TrustBundle) GetCertPool(trustDomain string) (*x509.CertPool, bool) {
	pool, ok := b.pools[trustDomain]
	return pool, ok
}

// SVIDInfo contains extracted identity and cryptographic metadata from an X.509 SVID.
type SVIDInfo struct {
	SPIFFEID    string            `json:"spiffeId"`
	TrustDomain string            `json:"trustDomain"`
	Namespace   string            `json:"namespace,omitempty"`
	ServiceAcct string            `json:"serviceAccount,omitempty"`
	Fingerprint string            `json:"sha256Fingerprint"`
	Serial      string            `json:"serialNumber"`
	NotBefore   time.Time         `json:"notBefore"`
	NotAfter    time.Time         `json:"notAfter"`
	Selectors   map[string]string `json:"selectors,omitempty"`
}

// SVIDValidator validates X.509 SVID certificates and produces continuous assurance evidence.
type SVIDValidator struct {
	bundle        *TrustBundle
	verifierAuth  assurance.AuthorityRef
	clockOverride func() time.Time
}

// NewSVIDValidator creates a new SVID validator backed by a TrustBundle.
func NewSVIDValidator(bundle *TrustBundle, verifierAuth assurance.AuthorityRef) *SVIDValidator {
	if bundle == nil {
		bundle = NewTrustBundle()
	}
	if verifierAuth.Scheme == "" {
		verifierAuth = assurance.AuthorityRef{
			Scheme:  "spiffe",
			Subject: "ckodex-assurance/spire-validator",
		}
	}
	return &SVIDValidator{
		bundle:       bundle,
		verifierAuth: verifierAuth,
	}
}

// SetClockOverride allows deterministic unit testing of expiry.
func (v *SVIDValidator) SetClockOverride(f func() time.Time) {
	v.clockOverride = f
}

func (v *SVIDValidator) now() time.Time {
	if v.clockOverride != nil {
		return v.clockOverride()
	}
	return time.Now()
}

// ParseCertificate parses a PEM-encoded or DER certificate.
func (v *SVIDValidator) ParseCertificate(rawCert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(rawCert)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	return x509.ParseCertificate(rawCert)
}

// ValidateSVID validates an X.509 SVID certificate against its trust domain bundle.
func (v *SVIDValidator) ValidateSVID(cert *x509.Certificate) (*SVIDInfo, error) {
	if cert == nil {
		return nil, errors.New("certificate is nil")
	}

	currentTime := v.now()
	if currentTime.Before(cert.NotBefore) {
		return nil, fmt.Errorf("SVID is not yet valid (notBefore: %s)", cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if currentTime.After(cert.NotAfter) {
		return nil, fmt.Errorf("SVID is expired (notAfter: %s)", cert.NotAfter.UTC().Format(time.RFC3339))
	}

	// Extract SPIFFE ID from URI SANs
	var spiffeURI *url.URL
	for _, u := range cert.URIs {
		if u.Scheme == "spiffe" {
			spiffeURI = u
			break
		}
	}

	if spiffeURI == nil {
		return nil, errors.New("certificate does not contain a SPIFFE ID in URI SAN")
	}

	spiffeID := spiffeURI.String()
	trustDomain := spiffeURI.Host
	if trustDomain == "" {
		return nil, fmt.Errorf("invalid SPIFFE URI (missing trust domain): %s", spiffeID)
	}

	// Verify certificate chain against the trust domain's root CA pool
	pool, ok := v.bundle.GetCertPool(trustDomain)
	if !ok || pool == nil {
		return nil, fmt.Errorf("untrusted SPIFFE trust domain (no root CA registered): %s", trustDomain)
	}

	verifyOpts := x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: currentTime,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	if _, err := cert.Verify(verifyOpts); err != nil {
		// Also allow ExtKeyUsageAny if specified
		verifyOpts.KeyUsages = nil
		if _, errRetry := cert.Verify(verifyOpts); errRetry != nil {
			return nil, fmt.Errorf("X.509 SVID chain verification failed: %w", errRetry)
		}
	}

	// Extract fingerprint and serial
	fp := sha256.Sum256(cert.Raw)
	fpHex := "sha256:" + hex.EncodeToString(fp[:])
	serialStr := cert.SerialNumber.String()

	info := &SVIDInfo{
		SPIFFEID:    spiffeID,
		TrustDomain: trustDomain,
		Fingerprint: fpHex,
		Serial:      serialStr,
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		Selectors:   make(map[string]string),
	}

	// Parse Kubernetes path segments if formatted as /ns/<namespace>/sa/<serviceaccount>
	pathSegments := strings.Split(strings.Trim(spiffeURI.Path, "/"), "/")
	for i := 0; i < len(pathSegments)-1; i += 2 {
		key := pathSegments[i]
		val := pathSegments[i+1]
		switch key {
		case "ns":
			info.Namespace = val
			info.Selectors["k8s:ns"] = val
		case "sa":
			info.ServiceAcct = val
			info.Selectors["k8s:sa"] = val
		default:
			info.Selectors[key] = val
		}
	}

	return info, nil
}

// WorkloadIdentityAttestation verifies that a running workload matches the authenticated SVID
// and synthesizes an immutable EvidenceEnvelope.
func (v *SVIDValidator) WorkloadIdentityAttestation(
	ctx context.Context,
	subject assurance.SubjectRef,
	svidCert *x509.Certificate,
	expectedNamespace string,
	expectedServiceAccount string,
) (*assurance.EvidenceEnvelope, *SVIDInfo, error) {
	svidInfo, err := v.ValidateSVID(svidCert)
	if err != nil {
		return nil, nil, fmt.Errorf("workload SVID validation failed: %w", err)
	}

	// Validate expected namespace and service account against SVID selectors
	if expectedNamespace != "" && svidInfo.Namespace != "" && svidInfo.Namespace != expectedNamespace {
		return nil, svidInfo, fmt.Errorf("workload namespace mismatch: expected %s, SVID asserts %s", expectedNamespace, svidInfo.Namespace)
	}
	if expectedServiceAccount != "" && svidInfo.ServiceAcct != "" && svidInfo.ServiceAcct != expectedServiceAccount {
		return nil, svidInfo, fmt.Errorf("workload service account mismatch: expected %s, SVID asserts %s", expectedServiceAccount, svidInfo.ServiceAcct)
	}

	payloadData, err := json.Marshal(svidInfo)
	if err != nil {
		return nil, svidInfo, fmt.Errorf("failed to marshal SVID attestation payload: %w", err)
	}

	payloadHash := sha256.Sum256(payloadData)
	payloadDigest := "sha256:" + hex.EncodeToString(payloadHash[:])

	now := v.now()
	envelopeID := fmt.Sprintf("ev-svid-%d", now.UnixNano())

	producerAuth := assurance.AuthorityRef{
		Scheme:      "spiffe",
		Subject:     svidInfo.SPIFFEID,
		TrustDomain: svidInfo.TrustDomain,
	}

	envelope := &assurance.EvidenceEnvelope{
		Schema:          "assurance.ckodex.io/evidence/v1alpha1",
		ID:              envelopeID,
		Subject:         subject,
		ObservationType: "workload.identity",
		CapturedAt:      now,
		Producer:        producerAuth,
		Artifact: assurance.EvidenceRef{
			URI:       fmt.Sprintf("spiffe://%s/svid/%s", svidInfo.TrustDomain, svidInfo.Serial),
			Digest:    payloadDigest,
			MediaType: "application/vnd.spiffe.svid+json",
		},
		IntegrityDigest: payloadDigest,
		Epoch: assurance.AssuranceEpoch{
			SubjectDigest:        subject.Digest(),
			ImplementationDigest: payloadDigest,
			AuthorityDigest:      producerAuth.Canonical(),
		},
		ControlRefs: []assurance.ControlRef{
			{Namespace: "ckodex", ID: "workload.identity"},
			{Namespace: "nist-sp-800-53", ID: "IA-2"},
		},
	}

	return envelope, svidInfo, nil
}
