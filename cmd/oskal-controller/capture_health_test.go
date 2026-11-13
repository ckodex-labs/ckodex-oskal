package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/opa"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

func TestCaptureListenerReadyBeforeFirstDeliveryWithoutControlStanding(t *testing.T) {
	config, roots, clientCertificate, _ := policyTestCertificates(t)
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config.Listen = reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	transport, clientRoots, _, err := policyServerTLS(config)
	if err != nil {
		t.Fatal(err)
	}
	producer := assurance.AuthorityRef{Scheme: "local", Subject: "readiness-test"}
	decoder, err := opa.NewDecoder(opa.Config{DecisionPath: config.DecisionPath, BundleName: config.BundleName, AllowResult: config.AllowResult, DenyResult: config.DenyResult, Producer: producer})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := storage.NewFilesystemEvidenceRepository(filepath.Join(t.TempDir(), "archive"))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := receipts.NewReceiptManager(producer)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := collection.NewCandidates(archive, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	captures, err := collection.NewCandidates(archive, []collection.SourceConfig{{ID: "opa", Producer: producer, Signer: signer}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	group := &sourceGroup{candidates: runtime, captureCandidates: captures, producer: producer, window: time.Second}
	source := preparedSource{spec: sourceSpec{ID: "opa", Kind: "opa", PolicyMode: "CAPTURE", OPA: &config}, policy: &preparedPolicySource{decoder: decoder, tls: transport, principals: policyPKIPrincipal{roots: clientRoots, expected: config.ExpectedPublisher}}}
	batches := &policyBatches{group: group, source: source}
	if err := group.Ready(nil); err == nil {
		t.Fatal("capture became ready before its listener started")
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- group.runPolicy(ctx, source, batches) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("listener stop: %v", err)
			}
		case <-time.After(6 * time.Second):
			t.Error("policy listener did not stop within its shutdown bound")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for group.Ready(nil) != nil {
		select {
		case err := <-done:
			t.Fatalf("listener failed before readiness: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("bound TLS listener never became ready: %v", group.Ready(nil))
		}
		time.Sleep(10 * time.Millisecond)
	}
	status := group.Snapshot()
	if len(status) != 1 || status[0].Transport != "LISTENING" || status[0].Eligible != 0 || status[0].Lifecycle == collection.SourceRunning || runtime.Revision() != 0 {
		t.Fatalf("listener readiness invented native or runtime evidence: %+v", status)
	}
	clientTransport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientCertificate}}}
	defer clientTransport.CloseIdleConnections()
	client := &http.Client{Transport: clientTransport, Timeout: 3 * time.Second}
	response, err := client.Get("https://" + config.Listen + "/logs")
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("actual mTLS listener was not accepting authenticated traffic: status=%d read=%v close=%v", response.StatusCode, readErr, closeErr)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+config.Listen+"/logs", bytes.NewReader(make([]byte, opa.MaxCompressedBytes+1)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Encoding", "gzip")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr = io.Copy(io.Discard, response.Body)
	closeErr = response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("actual oversized request was not rejected: status=%d read=%v close=%v", response.StatusCode, readErr, closeErr)
	}
	if group.Ready(nil) == nil || group.Snapshot()[0].Lifecycle != collection.SourceSafeHold {
		t.Fatal("serving listener hid SAFE_HOLD behind transport readiness")
	}
	cancel()
	deadline = time.Now().Add(5 * time.Second)
	for group.captureTransport("opa") != "UNAVAILABLE" {
		if time.Now().After(deadline) {
			t.Fatal("stopped listener retained service readiness")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
