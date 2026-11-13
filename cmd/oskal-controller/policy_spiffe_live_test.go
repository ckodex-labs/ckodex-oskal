package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/opa"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/spire"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/policycollection"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

// The caller must make an actual isolated SPIRE bundle change after PIN_READY.
// No fake Workload API, TLS state, trust root, or cryptographic success is used.
func TestRealPolicySPIFFEBundleChange(t *testing.T) {
	socket, id := os.Getenv("OSKAL_SPIRE_TEST_SOCKET"), os.Getenv("OSKAL_SPIRE_TEST_ID")
	if socket == "" || id == "" || os.Getenv("OSKAL_SPIRE_PIN_CHANGE") != "1" {
		t.Skip("explicit real SPIRE source and operator-owned live bundle-change run required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	workload, err := spire.NewWorkloadClient(ctx, socket, id, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = workload.Close() }()
	pin, err := workload.TrustBundleDigest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	info, err := workload.Identity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	producer := assurance.AuthorityRef{Scheme: "spiffe", Subject: strings.TrimPrefix(id, "spiffe://"), TrustDomain: info.TrustDomain}
	manager, err := receipts.NewReceiptManager(producer)
	if err != nil {
		t.Fatal(err)
	}
	signer := &identitySigner{ReceiptManager: manager, workload: workload, bundleDigest: pin}
	payload, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	digest := assurance.ComputeDigest(payload)
	envelope := assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/evidence/v1alpha1", ID: "actual-own-spiffe-read", Subject: assurance.SubjectRef{Scheme: "spiffe", ID: strings.TrimPrefix(id, "spiffe://")}, Producer: producer, CapturedAt: time.Now().UTC(), ObservationType: "identity.spiffe.read", Epoch: assurance.AssuranceEpoch{SubjectDigest: digest}, Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(digest, "sha256:"), Digest: digest, MediaType: "application/json"}, IntegrityDigest: digest}
	signed, err := signer.SignEvidence(ctx, envelope)
	if err != nil || signed.SignatureRef == "" {
		t.Fatalf("actual pinned own SVID did not permit signing: %v", err)
	}
	archive, err := storage.NewFilesystemEvidenceRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := collection.NewCandidates(archive, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := opa.NewDecoder(opa.Config{DecisionPath: "pin/test", BundleName: "pin", AllowResult: json.RawMessage("true"), DenyResult: json.RawMessage("false"), Producer: producer})
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := policycollection.NewOPAReceiver(policycollection.OPAConfig{Decoder: decoder, Principals: policyPinnedPrincipal{workload: workload, publisher: id, bundleDigest: pin}, ExpectedPrincipal: id, RequestTimeout: 5 * time.Second, BeginBatch: func(context.Context) (ports.CapturedEventWriter, func(error), error) {
		_, err := candidates.BeginSession("unconfigured")
		return nil, nil, err
	}})
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := workload.TLSServerConfig(ctx, []string{id})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := workload.TLSClientConfig(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	states := make(chan tls.ConnectionState, 4)
	server := &http.Server{TLSConfig: serverTLS, ReadHeaderTimeout: time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			states <- *r.TLS
		}
		receiver.ServeHTTP(w, r)
	})}
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	defer func() {
		_ = server.Close()
		if err := <-done; err != nil && err != http.ErrServerClosed {
			t.Error(err)
		}
	}()
	transport := &http.Transport{TLSClientConfig: clientTLS}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	request := func(want int) tls.ConnectionState {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+listener.Addr().String()+"/logs", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("actual pinned peer HTTP%d want%d", response.StatusCode, want)
		}
		return <-states
	}
	baselineState := request(http.StatusMethodNotAllowed)
	principal, peerDigest, err := workload.AuthenticatedPeerWithTrustBundleDigest(ctx, baselineState, []string{id})
	if err != nil || principal != id || peerDigest != pin {
		t.Fatalf("same-snapshot baseline peer/digest: %s %s %v", principal, peerDigest, err)
	}
	t.Logf("PIN_READY actual SPIRE peer=%s fingerprint=%s bundle=%s; own signing succeeded, pinned receiver HTTP405", id, info.Fingerprint, pin)
	changed := ""
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); {
		current, err := workload.TrustBundleDigest(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if current != pin {
			changed = current
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if changed == "" {
		t.Fatal("caller did not perform an actual public bundle change")
	}
	changedState := request(http.StatusUnauthorized)
	principal, peerDigest, err = workload.AuthenticatedPeerWithTrustBundleDigest(ctx, changedState, []string{id})
	if err != nil || principal != id || peerDigest != changed {
		t.Fatalf("changed snapshot did not still verify real peer: principal=%s digest=%s err=%v", principal, peerDigest, err)
	}
	denied, err := signer.SignEvidence(ctx, envelope)
	if err == nil || denied.SignatureRef != "" || !strings.Contains(err.Error(), "bundle differs") {
		t.Fatalf("changed roots retained pinned signing authority: %v", err)
	}
	t.Logf("VERIFIED actual SPIRE bundle changed %s -> %s; same-snapshot peer still cryptographically valid but old pin rejected HTTP401 and signing; no trust fallback", pin, changed)
}
