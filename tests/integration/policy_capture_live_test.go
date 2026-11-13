package integration

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/gatekeeper"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/opa"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/policyreports"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/ingestion"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/policycollection"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
)

// These tests require real caller-managed engines and API resources. No fake
// Kubernetes clients, policy engines, report servers, or persistence are used.
func policyLive(t *testing.T) (dynamic.Interface, *ingestion.Writer, *storage.ContentAddressedEvidenceRepository) {
	t.Helper()
	path := os.Getenv("OSKAL_POLICY_KUBECONFIG")
	if path == "" {
		t.Skip("real policy integration kubeconfig was not configured")
	}
	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		t.Fatal(err)
	}
	config.Timeout = 5 * time.Second
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	discover, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(discover))
	dir := os.Getenv("OSKAL_POLICY_EVIDENCE_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	repo, err := storage.NewFilesystemEvidenceRepository(filepath.Join(dir, t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	resolver := ports.CaptureResolverFunc(func(ctx context.Context, event ports.CapturedEvent) (assurance.SubjectRef, assurance.AssuranceEpoch, error) {
		ref := event.Subject.Attributes
		gv, err := schema.ParseGroupVersion(ref["apiVersion"])
		if err != nil {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, err
		}
		mapping, err := mapper.RESTMapping(schema.GroupKind{Group: gv.Group, Kind: ref["kind"]}, gv.Version)
		if err != nil {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, err
		}
		object, err := client.Resource(mapping.Resource).Namespace(ref["namespace"]).Get(ctx, ref["name"], metav1.GetOptions{})
		if err != nil {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, err
		}
		if ref["uid"] == "" || ref["uid"] != string(object.GetUID()) || event.CapturedAt.Before(object.GetCreationTimestamp().Time) {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("policy subject UID or creation time differs from live object")
		}
		raw, err := json.Marshal(object.Object)
		if err != nil {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, err
		}
		return event.Subject, assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeDigest(raw)}, nil
	})
	return client, &ingestion.Writer{Repository: repo, Resolver: resolver, MaxClockAhead: time.Second}, repo
}

func verifyPolicyCapture(t *testing.T, writer *ingestion.Writer, repo *storage.ContentAddressedEvidenceRepository, capture policyreports.Capture) {
	t.Helper()
	if err := writer.WriteCapturedEvent(t.Context(), capture.Event); err != nil {
		t.Fatal(err)
	}
	envelopes, err := repo.ListBySubject(t.Context(), capture.Event.Subject)
	if err != nil || len(envelopes) == 0 {
		t.Fatalf("real capture was not stored: %v", err)
	}
	for _, envelope := range envelopes {
		if ok, err := repo.Verify(t.Context(), envelope.Artifact); !ok || err != nil {
			t.Fatalf("real policy payload failed CAS verification: %v", err)
		}
		if envelope.Artifact.Digest == assurance.ComputeDigest(capture.Event.Payload) {
			contract := assurance.EvidenceContract{Requirements: []assurance.EvidenceRequirement{{ID: "independent-coverage", EvidenceType: "policy.coverage.verified", Required: true}}}
			if result := contract.Evaluate(envelopes, envelope.Epoch, time.Now()); result.State != assurance.AssuranceStateUnknown {
				t.Fatal("observed engine facts were promoted into coverage proof")
			}
			t.Logf("real %s subject=%s artifact=%s revision=%s", envelope.ObservationType, envelope.Subject.URI(), envelope.Artifact.Digest, capture.Record.Metadata["policyRevisionStatus"])
			return
		}
	}
	t.Fatal("stored payload digest differs from exact capture record")
}

func TestLivePolicyReportCapture(t *testing.T) {
	client, writer, repo := policyLive(t)
	group, version, resource := "wgpolicyk8s.io", "v1alpha2", "policyreports"
	if os.Getenv("OSKAL_POLICY_OPENREPORTS") == "1" {
		group, version, resource = "openreports.io", "v1alpha1", "reports"
	}
	list, err := client.Resource(schema.GroupVersionResource{Group: group, Version: version, Resource: resource}).Namespace("oskal-policy-test").List(t.Context(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, object := range list.Items {
		// Kubernetes list items may omit TypeMeta; the queried GVR supplies the
		// exact transport type rather than inferring an engine or result.
		if object.GetAPIVersion() == "" {
			object.SetAPIVersion(group + "/" + version)
		}
		if object.GetKind() == "" {
			if resource == "reports" {
				object.SetKind("Report")
			} else {
				object.SetKind("PolicyReport")
			}
		}
		raw, err := json.Marshal(object.Object)
		if err != nil {
			t.Fatal(err)
		}
		captures, err := policyreports.Decode(raw, assurance.AuthorityRef{Scheme: "local-test", Subject: "kyverno-api-reader"})
		if err != nil {
			t.Fatal(err)
		}
		for _, capture := range captures {
			for _, fact := range capture.Record.Results {
				seen[fact.Result] = true
				if fact.RevisionStatus != "UNKNOWN" {
					t.Fatal("report invented a policy revision")
				}
			}
			verifyPolicyCapture(t, writer, repo, capture)
			if capture.Event.Subject.Attributes["name"] == "has-team" {
				verifyReportRejections(t, raw, capture, writer)
			}
		}
	}
	if !seen["pass"] || !seen["fail"] {
		t.Fatal("real reports did not contain both evaluated pass and fail facts")
	}
}

func TestLiveGatekeeperAuditCapture(t *testing.T) {
	client, writer, repo := policyLive(t)
	object, err := client.Resource(schema.GroupVersionResource{Group: "constraints.gatekeeper.sh", Version: "v1beta1", Resource: "oskalrequiredlabels"}).Get(t.Context(), "oskal-require-team", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	capture, err := gatekeeper.DecodeConstraint(raw, assurance.AuthorityRef{Scheme: "local-test", Subject: "gatekeeper-api-reader"})
	if err != nil {
		t.Fatal(err)
	}
	if capture.Record.Metadata["totalViolations"] == "0" || capture.Record.Metadata["workloadIdentityStatus"] != "UNKNOWN" {
		t.Fatal("expected actual violations without invented workload UID")
	}
	if capture.Record.Metadata["truncated"] != "true" {
		t.Fatal("the configured one-violation limit did not retain explicit truncation evidence")
	}
	verifyPolicyCapture(t, writer, repo, capture)
}

func TestLivePolicyCollectionRunners(t *testing.T) {
	client, writer, repo := policyLive(t)
	started, finished := 0, 0
	var completionError error
	begin := func(context.Context) (ports.CapturedEventWriter, func(error), error) {
		started++
		return writer, func(err error) { finished++; completionError = err }, nil
	}
	config := policycollection.ReportsConfig{Client: client, GVR: schema.GroupVersionResource{Group: "openreports.io", Version: "v1alpha1", Resource: "reports"}, Namespace: "oskal-policy-test", Producer: assurance.AuthorityRef{Scheme: "local-test", Subject: "policy-snapshot-poller"}, PollInterval: time.Second, RequestTimeout: 5 * time.Second, MaxObjects: 16, MaxBatchBytes: 2 << 20, BeginBatch: begin}
	for _, source := range []string{"reports", "gatekeeper"} {
		current := config
		if source == "gatekeeper" {
			current.GVR = schema.GroupVersionResource{Group: "constraints.gatekeeper.sh", Version: "v1beta1", Resource: "oskalrequiredlabels"}
			current.Kind = "OskalRequiredLabels"
			current.Namespace = ""
		}
		runner, err := policycollection.NewReportsRunner(current)
		if err != nil {
			t.Fatal(err)
		}
		if err := runner.Poll(t.Context()); err != nil {
			t.Fatal(err)
		}
		if started != finished || completionError != nil {
			t.Fatal("actual successful source batch did not finish")
		}
	}
	subject := assurance.SubjectRef{Scheme: "k8s", ID: "oskal-policy-test/ConfigMap/has-team"}
	envelopes, err := repo.ListBySubject(t.Context(), subject)
	if err != nil || len(envelopes) == 0 {
		t.Fatalf("real report poll did not persist: %v", err)
	}
	for _, envelope := range envelopes {
		if ok, err := repo.Verify(t.Context(), envelope.Artifact); !ok || err != nil {
			t.Fatalf("actual poll payload verification failed: %v", err)
		}
	}
	config.MaxObjects = 1
	capped, err := policycollection.NewReportsRunner(config)
	if err != nil {
		t.Fatal(err)
	}
	beforeCap := started
	if err := capped.Run(t.Context()); !errors.Is(err, policycollection.ErrSafeHold) || !errors.Is(completionError, policycollection.ErrSafeHold) || started != beforeCap+1 {
		t.Fatalf("actual API cap did not invalidate its batch: %v", err)
	}
	config.MaxObjects = 16
	config.GVR = schema.GroupVersionResource{Group: "constraints.gatekeeper.sh", Version: "v1beta1", Resource: "oskalunconfiguredconstraints"}
	config.Kind = "OskalUnconfiguredConstraint"
	config.Namespace = ""
	missing, err := policycollection.NewReportsRunner(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := missing.Poll(t.Context()); err == nil || completionError == nil {
		t.Fatal("missing actual CRD was accepted as empty success")
	}
	config.GVR = schema.GroupVersionResource{Group: "openreports.io", Version: "v1alpha1", Resource: "reports"}
	config.Namespace = "oskal-p1-policy-gatekeeper"
	config.Kind = ""
	empty, err := policycollection.NewReportsRunner(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := empty.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if started != finished || completionError != nil {
		t.Fatal("empty snapshot did not establish a distinct completed batch")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cycles := 0
	config.Namespace = "oskal-policy-test"
	config.BeginBatch = func(context.Context) (ports.CapturedEventWriter, func(error), error) {
		return writer, func(err error) {
			if err == nil {
				cycles++
				if cycles == 2 {
					cancel()
				}
			}
		}, nil
	}
	continuous, err := policycollection.NewReportsRunner(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := continuous.Run(ctx); !errors.Is(err, context.Canceled) || cycles != 2 {
		t.Fatalf("continuous actual source polling did not stop after two completed snapshots: cycles=%d err=%v", cycles, err)
	}
	t.Logf("actual Lists and CAS writes; batches=%d completed=%d; capped/missing sources invalidated; empty source emitted no evidence", started, finished)
}

// TestLiveOPADecisionCapture starts the actual configured OPA binary, loads a real
// revisioned bundle, invokes it, and receives its own gzip log plugin over mTLS.
func TestLiveOPADecisionCapture(t *testing.T) {
	client, writer, repo := policyLive(t)
	binary := os.Getenv("OSKAL_POLICY_OPA_BINARY")
	if binary == "" {
		t.Fatal("actual OPA binary is required")
	}
	caPath, serverCert, serverKey := os.Getenv("OSKAL_POLICY_TLS_CA"), os.Getenv("OSKAL_POLICY_TLS_SERVER_CERT"), os.Getenv("OSKAL_POLICY_TLS_SERVER_KEY")
	clientCert, clientKey := os.Getenv("OSKAL_POLICY_TLS_CLIENT_CERT"), os.Getenv("OSKAL_POLICY_TLS_CLIENT_KEY")
	if caPath == "" || serverCert == "" || serverKey == "" || clientCert == "" || clientKey == "" {
		t.Fatal("explicit mTLS certificate paths are required")
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("invalid policy test CA")
	}
	dir := os.Getenv("OSKAL_POLICY_EVIDENCE_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	opaDir := filepath.Join(dir, "opa-runtime")
	if err := os.MkdirAll(opaDir, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(opaDir, "source")
	if err := os.MkdirAll(source, 0700); err != nil {
		t.Fatal(err)
	}
	rego := `package oskal.authz
default allow := false
allow if input.subject.name == "has-team"
`
	mask := `package system.log
mask contains "/input/secret"
drop if input.path != "oskal/authz/allow"
`
	for name, text := range map[string]string{"policy.rego": rego, "mask.rego": mask} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	bundlePath := filepath.Join(opaDir, "policy.tar.gz")
	if output, err := exec.CommandContext(t.Context(), binary, "build", "--bundle", source, "--revision", "oskal-policy-v1", "--output", bundlePath).CombinedOutput(); err != nil {
		t.Fatalf("real OPA bundle build: %v %s", err, output)
	}
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := opa.NewDecoder(opa.Config{DecisionPath: "oskal/authz/allow", BundleName: "oskal", AllowResult: json.RawMessage("true"), DenyResult: json.RawMessage("false"), Producer: assurance.AuthorityRef{Scheme: "local-test", Subject: "opa-policy-collector"}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var receiveError error
	completed := 0
	activeWriter := writer
	begin := func(context.Context) (ports.CapturedEventWriter, func(error), error) {
		mu.Lock()
		current := activeWriter
		mu.Unlock()
		return current, func(err error) { mu.Lock(); defer mu.Unlock(); receiveError = err; completed++ }, nil
	}
	receiver, err := policycollection.NewOPAReceiver(policycollection.OPAConfig{Decoder: decoder, Principals: policyPKIPrincipal{roots: pool}, ExpectedPrincipal: "spiffe://oskal-policy-test/opa", BeginBatch: begin, RequestTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	deniedReceiver, err := policycollection.NewOPAReceiver(policycollection.OPAConfig{Decoder: decoder, Principals: policyPKIPrincipal{roots: pool}, ExpectedPrincipal: "spiffe://oskal-policy-test/different-publisher", BeginBatch: begin, RequestTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	server := &http.Server{ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0][0].URIs) != 1 || r.TLS.VerifiedChains[0][0].URIs[0].String() != "spiffe://oskal-policy-test/opa" {
				http.Error(w, "unexpected authenticated OPA client identity", http.StatusForbidden)
				return
			}
			if r.URL.Path == "/bundle.tar.gz" {
				w.Header().Set("Content-Type", "application/gzip")
				_, _ = w.Write(bundle)
				return
			}
			if r.URL.Path == "/denied" {
				deniedReceiver.ServeHTTP(w, r)
				return
			}
			if r.URL.Path != "/logs" || r.Method != http.MethodPost || r.Header.Get("Content-Encoding") != "gzip" {
				http.Error(w, "invalid decision log request", http.StatusBadRequest)
				return
			}
			receiver.ServeHTTP(w, r)
		})}
	go func() { _ = server.ServeTLS(listener, serverCert, serverKey) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	config := map[string]any{
		"services":      map[string]any{"capture": map[string]any{"url": "https://" + listener.Addr().String(), "tls": map[string]any{"ca_cert": caPath}, "credentials": map[string]any{"client_tls": map[string]any{"cert": clientCert, "private_key": clientKey}}}},
		"bundles":       map[string]any{"oskal": map[string]any{"service": "capture", "resource": "/bundle.tar.gz", "polling": map[string]any{"min_delay_seconds": 1, "max_delay_seconds": 2}}},
		"decision_logs": map[string]any{"service": "capture", "resource": "/logs", "reporting": map[string]any{"min_delay_seconds": 1, "max_delay_seconds": 1}},
	}
	configBytes, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(opaDir, "config.json")
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	port, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := port.Addr().String()
	if err := port.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "run", "--server", "--addr", address, "--config-file", configPath, "--skip-version-check")
	log, err := os.OpenFile(filepath.Join(opaDir, "opa.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = command.Wait() })
	httpClient := &http.Client{Timeout: time.Second}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("real OPA did not activate the revisioned bundle")
		case <-ticker.C:
			response, err := httpClient.Get("http://" + address + "/health?bundles=true")
			if err == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					goto ready
				}
			}
		}
	}
ready:
	for _, name := range []string{"has-team", "missing-team"} {
		object, err := client.Resource(schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}).Namespace("oskal-policy-test").Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		query, err := json.Marshal(map[string]any{"input": map[string]any{"subject": map[string]string{"apiVersion": "v1", "kind": "ConfigMap", "namespace": "oskal-policy-test", "name": name, "uid": string(object.GetUID())}, "secret": "OPA_INPUT_MUST_NOT_PERSIST"}})
		if err != nil {
			t.Fatal(err)
		}
		response, err := httpClient.Post("http://"+address+"/v1/data/oskal/authz/allow", "application/json", bytes.NewReader(query))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("decision_id")) {
			t.Fatalf("real OPA did not return logged decision: %v", err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			mu.Lock()
			err := receiveError
			mu.Unlock()
			t.Fatalf("real OPA decision logs did not arrive: %v", err)
		case <-ticker.C:
			mu.Lock()
			err := receiveError
			done := completed
			mu.Unlock()
			if err != nil {
				t.Fatalf("actual OPA logs were rejected: %v", err)
			}
			seen := map[string]bool{}
			var lastSource []byte
			for _, name := range []string{"has-team", "missing-team"} {
				envelopes, err := repo.ListBySubject(ctx, assurance.SubjectRef{Scheme: "k8s", ID: "oskal-policy-test/ConfigMap/" + name})
				if err != nil {
					t.Fatal(err)
				}
				for _, envelope := range envelopes {
					if envelope.CapturedAt.Before(started) || envelope.Producer.Canonical() != "local-test://opa-policy-collector" {
						continue
					}
					body, err := repo.Get(ctx, envelope.Artifact)
					if err != nil {
						t.Fatal(err)
					}
					payload, err := io.ReadAll(body)
					_ = body.Close()
					if err != nil {
						t.Fatal(err)
					}
					var record policyreports.Record
					if err := json.Unmarshal(payload, &record); err != nil {
						t.Fatal(err)
					}
					if record.Metadata["authenticatedPublisher"] != "spiffe://oskal-policy-test/opa" || record.Metadata["observer"] != "local-test://opa-policy-collector" {
						t.Fatal("receiver conflated authenticated publisher and observing collector")
					}
					capture := policyreports.Capture{Record: record, Event: ports.CapturedEvent{Subject: envelope.Subject, Type: envelope.ObservationType, CapturedAt: envelope.CapturedAt, Producer: envelope.Producer, Payload: payload, MediaType: envelope.Artifact.MediaType, ControlRefs: envelope.ControlRefs}}
					if strings.Contains(string(capture.Record.SourceBytes), "OPA_INPUT_MUST_NOT_PERSIST") {
						t.Fatal("OPA masking failed before persistence")
					}
					seen[capture.Record.Metadata["resultMapping"]] = true
					lastSource = capture.Record.SourceBytes
					verifyPolicyCapture(t, writer, repo, capture)
					verifyOPARejections(t, decoder, capture.Record.SourceBytes)
				}
			}
			if seen["allow"] && seen["deny"] && done > 0 {
				cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
				if err != nil {
					t.Fatal(err)
				}
				transport := http.DefaultTransport.(*http.Transport).Clone()
				transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}}
				defer transport.CloseIdleConnections()
				secureClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
				mu.Lock()
				before := completed
				mu.Unlock()
				response, err := secureClient.Post("https://"+listener.Addr().String()+"/denied", "application/json", strings.NewReader("not-gzip-and-must-not-be-decoded"))
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if response.StatusCode != http.StatusForbidden {
					t.Fatalf("wrong exact publisher received status %d", response.StatusCode)
				}
				mu.Lock()
				after := completed
				mu.Unlock()
				if before != after {
					t.Fatal("unauthorized publisher began a source batch")
				}
				request, err := http.NewRequest(http.MethodPost, "https://"+listener.Addr().String()+"/logs", strings.NewReader("not-a-gzip-batch"))
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Content-Encoding", "gzip")
				response, err = secureClient.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if response.StatusCode != http.StatusBadRequest {
					t.Fatalf("authenticated invalid batch received status %d", response.StatusCode)
				}
				mu.Lock()
				after, err = completed, receiveError
				mu.Unlock()
				if after != before+1 || err == nil {
					t.Fatal("failed authenticated batch did not invalidate through completion callback")
				}
				failedWriter := brokenPolicyWriter(t, writer)
				mu.Lock()
				activeWriter = failedWriter
				before = completed
				mu.Unlock()
				request, err = http.NewRequest(http.MethodPost, "https://"+listener.Addr().String()+"/logs", gzipJSON(t, append(append([]byte("["), lastSource...), ']')))
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Content-Encoding", "gzip")
				response, err = secureClient.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				mu.Lock()
				after, err = completed, receiveError
				mu.Unlock()
				if response.StatusCode != http.StatusServiceUnavailable || after != before+1 || !errors.Is(err, syscall.ENOTDIR) {
					t.Fatalf("real CAS failure was acknowledged or not invalidated: status=%d error=%v", response.StatusCode, err)
				}
				t.Log("production receiver authenticated publisher before batch; malformed authenticated batch returned 400 after End(error)")
				t.Log("actual filesystem persistence failure returned 503 and End(error); retained CAS history was not deleted")
				return
			}
		}
	}
}

func brokenPolicyWriter(t *testing.T, template *ingestion.Writer) *ingestion.Writer {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cas")
	repo, err := storage.NewFilesystemEvidenceRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	// Preserve even this empty test repository, then obstruct only its original
	// path with a file. Production Put must return the actual filesystem error.
	if err := os.Rename(path, path+"-retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("bounded write-failure test"), 0600); err != nil {
		t.Fatal(err)
	}
	copy := *template
	copy.Repository = repo
	return &copy
}

// This resolver performs real current PKI verification, then derives identity
// from the verified leaf URI. It does not trust headers or asserted log labels.
type policyPKIPrincipal struct{ roots *x509.CertPool }

func (p policyPKIPrincipal) AuthenticatedPrincipal(ctx context.Context) (string, error) {
	state, ok := policycollection.PeerTLSState(ctx)
	if !ok || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return "", fmt.Errorf("verified TLS peer is missing")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: p.roots, Intermediates: intermediates, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return "", err
	}
	if len(state.PeerCertificates[0].URIs) != 1 {
		return "", fmt.Errorf("exact peer URI is required")
	}
	return state.PeerCertificates[0].URIs[0].String(), nil
}

func verifyReportRejections(t *testing.T, raw []byte, capture policyreports.Capture, writer *ingestion.Writer) {
	t.Helper()
	for _, mutation := range []string{"missing-resource-uid", "missing-timestamp", "unsupported-api", "empty-results"} {
		var object map[string]any
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		switch mutation {
		case "missing-resource-uid":
			delete(object["scope"].(map[string]any), "uid")
		case "missing-timestamp":
			delete(object["results"].([]any)[0].(map[string]any), "timestamp")
		case "unsupported-api":
			object["apiVersion"] = "invented.example/v1"
		case "empty-results":
			object["results"] = []any{}
		}
		modified, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := policyreports.Decode(modified, capture.Event.Producer); err == nil {
			t.Fatalf("real report boundary mutation was admitted: %s", mutation)
		}
	}
	stale := capture.Event
	stale.Subject.Attributes = map[string]string{}
	for key, value := range capture.Event.Subject.Attributes {
		stale.Subject.Attributes[key] = value
	}
	stale.Subject.Attributes["uid"] = "stale-resource-incarnation"
	if err := writer.WriteCapturedEvent(t.Context(), stale); err == nil {
		t.Fatal("stale report UID was bound to the current resource epoch")
	}
}

func verifyOPARejections(t *testing.T, decoder *opa.Decoder, raw []byte) {
	t.Helper()
	for _, mutation := range []string{"unmasked-input", "missing-revision", "result-type", "wrong-path"} {
		var object map[string]any
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		switch mutation {
		case "unmasked-input":
			object["input"].(map[string]any)["secret"] = "must-not-persist"
		case "missing-revision":
			object["bundles"] = map[string]any{}
		case "result-type":
			object["result"] = "true"
		case "wrong-path":
			object["path"] = "another/policy"
		}
		modified, err := json.Marshal([]any{object})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decoder.DecodeBatch(gzipJSON(t, modified)); err == nil {
			t.Fatalf("actual decision boundary mutation was admitted: %s", mutation)
		}
	}
}

func gzipJSON(t *testing.T, raw []byte) *bytes.Reader {
	t.Helper()
	var buffer bytes.Buffer
	zip := gzip.NewWriter(&buffer)
	if _, err := zip.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zip.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buffer.Bytes())
}
