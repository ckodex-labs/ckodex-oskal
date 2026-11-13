package webhook

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/ckodex-labs/ckodex-oskal/internal/verifier"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func ptrBool(b bool) *bool    { return &b }
func ptrInt64(i int64) *int64 { return &i }
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func compliantPod() *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "declared-pod", Namespace: "declared-namespace"}, Spec: corev1.PodSpec{SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptrBool(true), RunAsUser: ptrInt64(10001)}, Containers: []corev1.Container{{Name: "app", Image: "example:test", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: ptrBool(true), RunAsUser: ptrInt64(10001), Privileged: ptrBool(false), AllowPrivilegeEscalation: ptrBool(false), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}}}}
}
func reviewBytes(t *testing.T, pod *corev1.Pod) []byte {
	t.Helper()
	object, err := json.Marshal(pod)
	must(t, err)
	request := &admissionv1.AdmissionRequest{UID: "request-correlation-123", Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}, Resource: metav1.GroupVersionResource{Version: "v1", Resource: "pods"}, Operation: admissionv1.Create, Namespace: pod.Namespace, Name: pod.Name, Object: runtime.RawExtension{Raw: object}}
	raw, err := json.MarshalIndent(admissionv1.AdmissionReview{TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"}, Request: request}, "", "  ")
	must(t, err)
	return raw
}

// This is an actual TCP/TLS 1.3 server with an explicitly trusted test certificate.
// It authenticates the server only; no Kubernetes API client identity is claimed.
func serveWebhook(t *testing.T, cfg ServerConfig) (*http.Client, string) {
	t.Helper()
	cert, key, err := GenerateSelfSignedCert("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	must(t, err)
	pair, err := tls.X509KeyPair(cert, key)
	must(t, err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		t.Fatal("invalid actual certificate")
	}
	server := NewAdmissionWebhookServer(cfg)
	server.server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	done := make(chan error, 1)
	go func() { done <- server.server.ServeTLS(listener, "", "") }()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		_ = server.server.Close()
		if err := <-done; err != nil && err != http.ErrServerClosed {
			t.Error(err)
		}
	})
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}, "https://" + listener.Addr().String()
}
func postReview(t *testing.T, client *http.Client, address string, raw []byte) (int, *admissionv1.AdmissionResponse) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, address+"/validate", bytes.NewReader(raw))
	must(t, err)
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	must(t, err)
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	must(t, err)
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, nil
	}
	var review admissionv1.AdmissionReview
	must(t, json.Unmarshal(data, &review))
	if review.Response == nil {
		t.Fatal("missing AdmissionResponse")
	}
	return response.StatusCode, review.Response
}

func realCaptureSink(t *testing.T, limits storage.ArchiveLimits) (*storage.ContentAddressedEvidenceRepository, *receipts.ReceiptManager, assurance.AuthorityRef, EvidenceSink, string) {
	t.Helper()
	directory := t.TempDir()
	repo, err := storage.NewFilesystemEvidenceRepositoryWithLimits(directory, limits)
	must(t, err)
	observer := assurance.AuthorityRef{Scheme: "local", Subject: "webhook-capture-test"}
	signer, err := receipts.NewReceiptManager(observer)
	must(t, err)
	sink := func(ctx context.Context, env assurance.EvidenceEnvelope, payload []byte) error {
		signed, err := signer.SignEvidence(ctx, env)
		if err != nil {
			return err
		}
		_, err = repo.Put(ctx, signed, bytes.NewReader(payload))
		return err
	}
	return repo, signer, observer, sink, directory
}

func TestActualTLSAdmissionCapturePreservesFactsAndSignature(t *testing.T) {
	repo, signer, observer, sink, _ := realCaptureSink(t, storage.DefaultArchiveLimits())
	client, address := serveWebhook(t, ServerConfig{ObserverAuth: observer, EvidenceSink: sink})
	pod := compliantPod()
	pod.UID = "declared-object-uid"
	raw := reviewBytes(t, pod)
	code, response := postReview(t, client, address, raw)
	if code != 200 || !response.Allowed || response.UID != "request-correlation-123" || response.AuditAnnotations["assurance.ckodex.io/capture-status"] != "RECORDED" {
		t.Fatalf("actual response: %d %+v", code, response)
	}
	envelopes, err := repo.ListAll(t.Context())
	must(t, err)
	if len(envelopes) != 1 {
		t.Fatal("missing actual capture")
	}
	envelope := envelopes[0]
	if envelope.Subject.Scheme != "admission-request" || envelope.Subject.ID != string(response.UID) || envelope.Subject.Attributes["uid"] != "" || envelope.Producer != observer || len(envelope.ControlRefs) != 0 {
		t.Fatalf("invented subject/authority/control: %+v", envelope)
	}
	if envelope.Epoch != (assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeDigest(raw)}) {
		t.Fatalf("invented governing epoch: %+v", envelope.Epoch)
	}
	reader, err := repo.Get(t.Context(), envelope.Artifact)
	must(t, err)
	payload, err := io.ReadAll(reader)
	must(t, err)
	must(t, reader.Close())
	if assurance.ComputeDigest(payload) != envelope.Artifact.Digest || envelope.Artifact.URI != "cas://sha256/"+strings.TrimPrefix(envelope.Artifact.Digest, "sha256:") {
		t.Fatal("artifact is not actual capture bytes")
	}
	var capture AdmissionCapture
	must(t, json.Unmarshal(payload, &capture))
	if !bytes.Equal(capture.SourceBytes, raw) || capture.DeclaredSubject.ObjectUID != "declared-object-uid" || !capture.PolicyAllowed || len(capture.Checks) != 2 || capture.Limitations["controlStanding"] != "UNKNOWN_CAPTURE_ONLY" || capture.Limitations["apiClientIdentity"] != "NOT_AUTHENTICATED_BY_THIS_CAPTURE" {
		t.Fatalf("capture facts changed: %+v", capture)
	}
	key, err := hex.DecodeString(signer.PublicKey())
	must(t, err)
	verification := verifier.NewDefaultEvidenceVerifier()
	verification.RegisterPublicKey(observer.Canonical(), ed25519.PublicKey(key))
	valid, err := verification.VerifySignature(t.Context(), envelope)
	must(t, err)
	if !valid {
		t.Fatal("actual signature invalid")
	}
	if response.AuditAnnotations["assurance.ckodex.io/capture-digest"] != envelope.Artifact.Digest || response.AuditAnnotations["assurance.ckodex.io/capture-uri"] != envelope.Artifact.URI {
		t.Fatal("response reference differs from stored capture")
	}
	t.Log("real TLS, original request bytes, actual CAS payload and Ed25519 signature verified; no workload or CEL enforcement standing inferred")
}

func TestActualTLSBuiltInChecksRetainEnforcement(t *testing.T) {
	client, address := serveWebhook(t, ServerConfig{})
	cases := []struct {
		name   string
		change func(*corev1.Pod)
		text   string
	}{
		{"root", func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.RunAsUser = ptrInt64(0) }, "runAsUser=0"},
		{"nonroot-override", func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.RunAsNonRoot = ptrBool(false) }, "runAsNonRoot=false"},
		{"missing-nonroot", func(p *corev1.Pod) {
			p.Spec.SecurityContext = nil
			p.Spec.Containers[0].SecurityContext.RunAsNonRoot = nil
		}, "does not specify runAsNonRoot"},
		{"privileged", func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.Privileged = ptrBool(true) }, "privileged mode"},
		{"escalation", func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = ptrBool(true) }, "allows privilege escalation"},
		{"init", func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: "init", SecurityContext: &corev1.SecurityContext{Privileged: ptrBool(true)}}}
		}, "init requests privileged"},
		{"ephemeral", func(p *corev1.Pod) {
			p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", SecurityContext: &corev1.SecurityContext{Privileged: ptrBool(true)}}}}
		}, "debug requests privileged"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			pod := compliantPod()
			test.change(pod)
			code, response := postReview(t, client, address, reviewBytes(t, pod))
			if code != 200 || response.Allowed || !strings.Contains(response.Result.Message, test.text) {
				t.Fatalf("expected %s denial: %d %+v", test.text, code, response)
			}
		})
	}
	for _, capability := range []corev1.Capability{"CAP_SYS_ADMIN", "NET_ADMIN", "CAP_SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE", "NET_RAW"} {
		pod := compliantPod()
		pod.Spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{capability}
		_, response := postReview(t, client, address, reviewBytes(t, pod))
		if response.Allowed || !strings.Contains(response.Result.Message, string(capability)) {
			t.Fatalf("prohibited capability allowed: %s", capability)
		}
	}
	_, response := postReview(t, client, address, reviewBytes(t, compliantPod()))
	if !response.Allowed || response.AuditAnnotations["assurance.ckodex.io/capture-status"] != "NOT_RECORDED" || response.AuditAnnotations["assurance.ckodex.io/capture-uri"] != "" || response.AuditAnnotations["assurance.ckodex.io/admission-envelope-id"] != "" {
		t.Fatal("policy-only response invented durable capture")
	}
}

func TestActualTLSAdverseCaptureAndGeneratedName(t *testing.T) {
	for _, mode := range []WebhookMode{ModeEnforcing, ModeAudit, ModeWarn} {
		t.Run(string(mode), func(t *testing.T) {
			repo, _, observer, sink, _ := realCaptureSink(t, storage.DefaultArchiveLimits())
			client, address := serveWebhook(t, ServerConfig{ObserverAuth: observer, EvidenceSink: sink, Mode: mode})
			pod := compliantPod()
			pod.Name = ""
			pod.GenerateName = "pending-"
			pod.Spec.Containers[0].SecurityContext.Privileged = ptrBool(true)
			_, response := postReview(t, client, address, reviewBytes(t, pod))
			if response.Allowed != (mode != ModeEnforcing) {
				t.Fatal("mode policy decision changed")
			}
			if (len(response.Warnings) > 0) != (mode == ModeWarn) {
				t.Fatal("warning behavior changed")
			}
			envelopes, err := repo.ListAll(t.Context())
			must(t, err)
			if len(envelopes) != 1 || envelopes[0].ObservationType != "kubernetes.admission.violation" {
				t.Fatal("adverse fact not retained")
			}
			reader, err := repo.Get(t.Context(), envelopes[0].Artifact)
			must(t, err)
			payload, err := io.ReadAll(reader)
			must(t, err)
			must(t, reader.Close())
			var capture AdmissionCapture
			must(t, json.Unmarshal(payload, &capture))
			if capture.DeclaredSubject.NameResolution != "UNRESOLVED" || capture.DeclaredSubject.ObjectName != "" || capture.DeclaredSubject.RequestName != "" || capture.DeclaredSubject.GenerateName != "pending-" || capture.Checks[1].Result != "FAIL" || len(capture.Checks[1].Violations) == 0 {
				t.Fatal("generated name or adverse result fabricated")
			}
		})
	}
}

func TestActualTLSQuotaAndFilesystemFailureDenyEveryMode(t *testing.T) {
	for _, mode := range []WebhookMode{ModeEnforcing, ModeAudit, ModeWarn} {
		t.Run(string(mode), func(t *testing.T) {
			repo, _, observer, sink, _ := realCaptureSink(t, storage.ArchiveLimits{MaxBytes: 1, MaxEntries: 8})
			client, address := serveWebhook(t, ServerConfig{ObserverAuth: observer, EvidenceSink: sink, Mode: mode})
			for _, adverse := range []bool{false, true} {
				pod := compliantPod()
				pod.Spec.Containers[0].SecurityContext.Privileged = ptrBool(adverse)
				_, response := postReview(t, client, address, reviewBytes(t, pod))
				if response.Allowed || response.AuditAnnotations["assurance.ckodex.io/capture-status"] != "FAILED" || response.AuditAnnotations["assurance.ckodex.io/capture-error"] != "CAPACITY_EXHAUSTED" || response.AuditAnnotations["assurance.ckodex.io/admitted-in-degraded-mode"] != "" || response.AuditAnnotations["assurance.ckodex.io/capture-uri"] != "" {
					t.Fatalf("quota failure permitted admission: %+v", response)
				}
			}
			envelopes, err := repo.ListAll(t.Context())
			must(t, err)
			if len(envelopes) != 0 {
				t.Fatal("quota failure claimed stored material")
			}
		})
	}
	_, _, observer, sink, directory := realCaptureSink(t, storage.DefaultArchiveLimits())
	blobDirectory := filepath.Join(directory, "blobs", "sha256")
	must(t, os.Rename(blobDirectory, blobDirectory+"-preserved"))
	must(t, os.WriteFile(blobDirectory, []byte("intentional filesystem obstruction"), 0600))
	client, address := serveWebhook(t, ServerConfig{ObserverAuth: observer, EvidenceSink: sink, Mode: ModeAudit})
	_, response := postReview(t, client, address, reviewBytes(t, compliantPod()))
	if response.Allowed || response.AuditAnnotations["assurance.ckodex.io/capture-error"] != "PERSISTENCE_ERROR" {
		t.Fatal("actual filesystem failure was ignored")
	}
}

func TestActualTLSCaptureDeadlineAndNoDefaultObserver(t *testing.T) {
	repo, _, observer, sink, _ := realCaptureSink(t, storage.DefaultArchiveLimits())
	boundedSink := func(ctx context.Context, env assurance.EvidenceEnvelope, payload []byte) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("sink lacks request deadline")
		}
		<-ctx.Done()
		return sink(ctx, env, payload)
	}
	client, address := serveWebhook(t, ServerConfig{ObserverAuth: observer, EvidenceSink: boundedSink, Mode: ModeWarn, RequestTimeout: 30 * time.Millisecond})
	_, response := postReview(t, client, address, reviewBytes(t, compliantPod()))
	if response.Allowed || response.AuditAnnotations["assurance.ckodex.io/capture-error"] != "REQUEST_EXPIRED" {
		t.Fatal("expired persistence allowed")
	}
	envelopes, err := repo.ListAll(t.Context())
	must(t, err)
	if len(envelopes) != 0 {
		t.Fatal("expired capture persisted")
	}
	client, address = serveWebhook(t, ServerConfig{EvidenceSink: sink})
	_, response = postReview(t, client, address, reviewBytes(t, compliantPod()))
	if response.Allowed || response.AuditAnnotations["assurance.ckodex.io/capture-status"] != "FAILED" {
		t.Fatal("missing observer acquired a default identity")
	}
}

func TestActualTLSAdmissionInputBoundsAndOutOfScope(t *testing.T) {
	client, address := serveWebhook(t, ServerConfig{})
	if code, _ := postReview(t, client, address, bytes.Repeat([]byte("x"), MaxWebhookBodyBytes+1)); code != 413 {
		t.Fatalf("oversized body: HTTP%d", code)
	}
	raw := []byte(`{"request":{"uid":"a","uid":"b"}}`)
	if code, _ := postReview(t, client, address, raw); code != 400 {
		t.Fatal("ambiguous duplicate keys admitted")
	}
	raw = []byte(`{"request":{"uid":"not-a-pod","kind":{"version":"v1","kind":"Secret"},"operation":"CREATE"}}`)
	_, response := postReview(t, client, address, raw)
	if !response.Allowed || response.AuditAnnotations["assurance.ckodex.io/check-scope"] != "NOT_APPLICABLE" || response.AuditAnnotations["assurance.ckodex.io/capture-status"] != "NOT_RECORDED" {
		t.Fatal("out-of-scope request claimed checks or recording")
	}
	pod := compliantPod()
	for i := 0; i < MaxJSONArrayItems; i++ {
		pod.Spec.Containers = append(pod.Spec.Containers, pod.Spec.Containers[0])
	}
	if code, _ := postReview(t, client, address, reviewBytes(t, pod)); code != 400 {
		t.Fatal("container array amplified past structural bound")
	}
}
