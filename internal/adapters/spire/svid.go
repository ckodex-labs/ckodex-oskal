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
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"strings"
	"sync"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// TrustBundle stores trusted X.509 root CA pools keyed by SPIFFE trust domain.
type TrustBundle struct {
	mu    sync.RWMutex
	roots map[spiffeid.TrustDomain]*x509bundle.Bundle
}

// NewTrustBundle creates an empty SPIFFE trust bundle.
func NewTrustBundle() *TrustBundle {
	return &TrustBundle{
		roots: make(map[spiffeid.TrustDomain]*x509bundle.Bundle),
	}
}

// AddRootCA adds a PEM-encoded X.509 root certificate for a given trust domain.
func (b *TrustBundle) AddRootCA(trustDomain string, certPEM []byte) error {
	domain, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return fmt.Errorf("invalid trust domain: %w", err)
	}
	var roots []*x509.Certificate
	if block, _ := pem.Decode(certPEM); block == nil {
		roots, err = x509.ParseCertificates(certPEM)
	} else {
		for len(certPEM) > 0 {
			block, rest := pem.Decode(certPEM)
			if block == nil || block.Type != "CERTIFICATE" {
				return fmt.Errorf("invalid root certificate PEM")
			}
			cert, parseErr := x509.ParseCertificate(block.Bytes)
			if parseErr != nil {
				return fmt.Errorf("parse root certificate: %w", parseErr)
			}
			roots = append(roots, cert)
			certPEM = rest
		}
	}
	if err != nil {
		return fmt.Errorf("parse root certificates: %w", err)
	}
	if len(roots) == 0 {
		return fmt.Errorf("root certificates are required")
	}
	for _, cert := range roots {
		if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("trust anchor must be a certificate authority")
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	existing := b.roots[domain]
	if existing == nil {
		existing = x509bundle.New(domain)
		b.roots[domain] = existing
	}
	for _, cert := range roots {
		existing.AddX509Authority(cert)
	}
	return nil
}

// GetCertPool returns a snapshot of the configured domain roots.
func (b *TrustBundle) GetCertPool(trustDomain string) (*x509.CertPool, bool) {
	domain, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, false
	}
	bundle, err := b.GetX509BundleForTrustDomain(domain)
	if err != nil {
		return nil, false
	}
	pool := x509.NewCertPool()
	for _, cert := range bundle.X509Authorities() {
		pool.AddCert(cert)
	}
	return pool, true
}

func (b *TrustBundle) GetX509BundleForTrustDomain(domain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	bundle := b.roots[domain]
	if bundle == nil {
		return nil, fmt.Errorf("no trusted roots for %s", domain)
	}
	return x509bundle.FromX509Authorities(domain, bundle.X509Authorities()), nil
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
	bundle             *TrustBundle
	verifierAuth       assurance.AuthorityRef
	clockOverride      func() time.Time
	clockSkewTolerance time.Duration
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
		bundle:             bundle,
		verifierAuth:       verifierAuth,
		clockSkewTolerance: 0,
	}
}

// SetClockSkewTolerance configures clock skew tolerance for distributed/air-gapped nodes.
func (v *SVIDValidator) SetClockSkewTolerance(d time.Duration) {
	v.clockSkewTolerance = d
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
	// Allow clock skew tolerance for distributed and air-gapped nodes
	if currentTime.Add(v.clockSkewTolerance).Before(cert.NotBefore) {
		return nil, fmt.Errorf("SVID is not yet valid (notBefore: %s)", cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if currentTime.Add(-v.clockSkewTolerance).After(cert.NotAfter) {
		return nil, fmt.Errorf("SVID is expired (notAfter: %s)", cert.NotAfter.UTC().Format(time.RFC3339))
	}

	id, err := x509svid.IDFromCert(cert)
	if err != nil {
		return nil, fmt.Errorf("invalid X509-SVID identity: %w", err)
	}
	if id.Path() == "" {
		return nil, fmt.Errorf("workload SPIFFE ID must have a path")
	}
	verifyTime := currentTime
	if verifyTime.Before(cert.NotBefore) {
		verifyTime = cert.NotBefore
	}
	if verifyTime.After(cert.NotAfter) {
		verifyTime = cert.NotAfter
	}
	if _, _, err := x509svid.Verify([]*x509.Certificate{cert}, v.bundle, x509svid.WithTime(verifyTime)); err != nil {
		return nil, fmt.Errorf("X509-SVID chain verification: %w", err)
	}
	spiffeID := id.String()
	trustDomain := id.TrustDomain().String()

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
	pathSegments := strings.Split(strings.Trim(id.Path(), "/"), "/")
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
	if expectedNamespace != "" && svidInfo.Namespace != expectedNamespace {
		return nil, svidInfo, fmt.Errorf("workload namespace mismatch: expected %s, SVID asserts %s", expectedNamespace, svidInfo.Namespace)
	}
	if expectedServiceAccount != "" && svidInfo.ServiceAcct != expectedServiceAccount {
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
		Subject:     strings.TrimPrefix(svidInfo.SPIFFEID, "spiffe://"),
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
