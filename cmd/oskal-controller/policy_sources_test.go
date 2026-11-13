package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/opa"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/policycollection"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func policyTestCertificates(t *testing.T) (opaSourceSpec, *x509.CertPool, tls.Certificate, tls.Certificate) {
	t.Helper()
	directory := t.TempDir()
	rootPublic, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Policy Test Root"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, rootPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pool := x509.NewCertPool()
	pool.AddCert(root)
	save := func(name string, data []byte) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	issue := func(serial int64, identity string, server bool) (tls.Certificate, string, string) {
		t.Helper()
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: identity}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			uri, err := url.Parse(identity)
			if err != nil {
				t.Fatal(err)
			}
			leaf.URIs = []*url.URL{uri}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, root, pub, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		cert := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca...)
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pair, err := tls.X509KeyPair(cert, private)
		if err != nil {
			t.Fatal(err)
		}
		return pair, save(identityFile(serial)+".crt", cert), save(identityFile(serial)+".key", private)
	}
	_, serverCert, serverKey := issue(2, "server", true)
	client, _, _ := issue(3, "spiffe://policy.test/opa", false)
	wrong, _, _ := issue(4, "spiffe://policy.test/other", false)
	return opaSourceSpec{Listen: "127.0.0.1:9443", TLSMode: "pki", ExpectedPublisher: "spiffe://policy.test/opa", DecisionPath: "custom/allow", BundleName: "authored", AllowResult: json.RawMessage("true"), DenyResult: json.RawMessage("false"), RequestTimeout: "2s", ServerCertFile: serverCert, ServerKeyFile: serverKey, ClientCAFile: save("ca.crt", ca)}, pool, client, wrong
}
func identityFile(n int64) string { return big.NewInt(n).String() }

func TestPolicySourceConfigurationRejectsAmbiguousAuthority(t *testing.T) {
	opaSpec, _, _, _ := policyTestCertificates(t)
	report := sourceSpec{ID: "reports", Kind: "policy-report", PolicyMode: "CAPTURE", Namespace: "observed", Report: &reportSourceSpec{Group: "openreports.io", Version: "v1alpha1", Resource: "reports", Kind: "Report", PollInterval: "2s", RequestTimeout: "2s", MaxObjects: 16, MaxBatchBytes: 1 << 20}}
	if err := validateSourceSpec(report); err != nil {
		t.Fatal(err)
	}
	policy := sourceSpec{ID: "opa", Kind: "opa", PolicyMode: "CAPTURE", OPA: &opaSpec}
	if err := validateSourceSpec(policy); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"mode", "implicit-tls", "publisher-wildcard", "allow-default", "pki-missing-key", "policy-runtime-config", "report-namespace", "secret-resource", "implicit-interval", "noncanonical-spiffe"} {
		t.Run(mutation, func(t *testing.T) {
			candidate := policy
			config := opaSpec
			candidate.OPA = &config
			switch mutation {
			case "noncanonical-spiffe":
				config.TLSMode = "spiffe"
				config.ServerCertFile = ""
				config.ServerKeyFile = ""
				config.ClientCAFile = ""
				config.ExpectedPublisher = "spiffe://policy.test/a//b"
			case "mode":
				candidate.PolicyMode = ""
			case "implicit-tls":
				config.TLSMode = ""
			case "publisher-wildcard":
				config.ExpectedPublisher = "spiffe://policy.test/*"
			case "allow-default":
				config.AllowResult = nil
			case "pki-missing-key":
				config.ServerKeyFile = ""
			case "policy-runtime-config":
				candidate.Endpoint = "127.0.0.1:1"
			case "report-namespace":
				candidate = report
				candidate.Namespace = ""
			case "secret-resource":
				candidate = report
				r := *report.Report
				candidate.Report = &r
				r.Group = ""
				r.Version = "v1"
				r.Resource = "secrets"
				r.Kind = "Secret"
			case "implicit-interval":
				candidate = report
				r := *report.Report
				candidate.Report = &r
				r.PollInterval = ""
			}
			if err := validateSourceSpec(candidate); err == nil {
				t.Fatal("ambiguous policy authority was accepted")
			}
		})
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "sources.json")
	for _, sources := range [][]sourceSpec{{policy, policy}, {report, policy, sourceSpec{ID: "another-listener", Kind: "opa", PolicyMode: "CAPTURE", OPA: &opaSpec}}} {
		raw, err := json.Marshal(sourceConfiguration{Sources: sources})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readSourceConfiguration(path); err == nil {
			t.Fatal("duplicate source authority or listener accepted")
		}
	}
	if allowedPolicySubject(schema.GroupVersionKind{Version: "v1", Kind: "Secret"}) {
		t.Fatal("Secret metadata lookup admitted")
	}
}

func TestPolicyPublisherUsesActualTLSAndPropagatesSessionFailure(t *testing.T) {
	config, pool, clientCertificate, wrongCertificate := policyTestCertificates(t)
	transportTLS, roots, _, err := policyServerTLS(config)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := storage.NewFilesystemEvidenceRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := collection.NewCandidates(archive, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := opa.NewDecoder(opa.Config{DecisionPath: config.DecisionPath, BundleName: config.BundleName, AllowResult: config.AllowResult, DenyResult: config.DenyResult, Producer: assurance.AuthorityRef{Scheme: "local", Subject: "real-transport-test"}})
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := policycollection.NewOPAReceiver(policycollection.OPAConfig{Decoder: decoder, Principals: policyPKIPrincipal{roots: roots, expected: config.ExpectedPublisher}, ExpectedPrincipal: config.ExpectedPublisher, RequestTimeout: 2 * time.Second, BeginBatch: func(context.Context) (ports.CapturedEventWriter, func(error), error) {
		_, err := candidates.BeginSession("unconfigured-source")
		return nil, nil, err
	}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: receiver, TLSConfig: transportTLS, ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, ErrorLog: policyHTTPLogger()}
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	defer func() {
		_ = server.Close()
		err := <-done
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("actual TLS server: %v", err)
		}
	}()
	for _, test := range []struct {
		name        string
		certificate tls.Certificate
		want        int
	}{{"actual-publisher-session-failure", clientCertificate, 503}, {"header-cannot-override-wrong-publisher", wrongCertificate, 401}} {
		t.Run(test.name, func(t *testing.T) {
			transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{test.certificate}}}
			defer transport.CloseIdleConnections()
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+listener.Addr().String(), strings.NewReader("not read before authentication"))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Publisher", config.ExpectedPublisher)
			response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != test.want {
				t.Fatalf("HTTP%d want%d", response.StatusCode, test.want)
			}
			t.Logf("real TLS1.3 HTTP%d; no fabricated source success", response.StatusCode)
		})
	}
	if err := policyTLSExporter(tls.ConnectionState{}); err == nil {
		t.Fatal("fabricated transport acquired exporter proof")
	}
}

func TestPolicyBatchSafeHoldCannotBeResetByAnotherDelivery(t *testing.T) {
	archive, err := storage.NewFilesystemEvidenceRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	producer := assurance.AuthorityRef{Scheme: "local", Subject: "safe-hold-test"}
	signer, err := receipts.NewReceiptManager(producer)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := collection.NewCandidates(archive, []collection.SourceConfig{{ID: "source", Producer: producer, Signer: signer}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	batches := &policyBatches{group: &sourceGroup{captureCandidates: candidates, window: time.Second}, source: preparedSource{spec: sourceSpec{ID: "source"}, policy: &preparedPolicySource{}}}
	writer, end, err := batches.begin(t.Context())
	if err != nil || writer == nil || end == nil {
		t.Fatalf("batch setup: %v", err)
	}
	end(policycollection.ErrSafeHold)
	if _, _, err := batches.begin(t.Context()); !errors.Is(err, policycollection.ErrSafeHold) {
		t.Fatalf("new delivery bypassed SAFE_HOLD: %v", err)
	}
	before := candidates.Snapshot()[0]
	if before.Lifecycle != collection.SourceSafeHold || before.Reason == "" {
		t.Fatalf("SAFE_HOLD hidden from operational state: %+v", before)
	}
	batches.end("source stopped")
	batches.mu.Lock()
	batches.expires = time.Now().Add(-time.Second)
	batches.mu.Unlock()
	batches.expire()
	after := candidates.Snapshot()[0]
	if after.Lifecycle != collection.SourceSafeHold || after.Reason != before.Reason {
		t.Fatalf("source shutdown/expiry erased hold: %+v", after)
	}

}
