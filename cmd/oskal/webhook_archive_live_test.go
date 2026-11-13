package main

import (
	"bytes"
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
	"syscall"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func startBudgetWebhook(t *testing.T, binary, store, mode string, budget int64, global bool) (string, *http.Client) {
	t.Helper()
	pki := createGRPCTestPKI(t)
	ca, err := os.ReadFile(pki.ca)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("actual test root missing")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	args := []string{"webhook", "--listen", address, "--tls-cert-file", pki.serverCert, "--tls-key-file", pki.serverKey, "--self-signed=false", "--mode", mode, fmt.Sprintf("--archive-max-bytes=%d", budget)}
	if global {
		args = append(args, "--evidence-dir", store)
	} else {
		args = append(args, "--evidence-dir", "", "--webhook-evidence-dir", store)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, binary, args...)
	logfile, err := os.Create(filepath.Join(t.TempDir(), "webhook.log"))
	if err != nil {
		t.Fatal(err)
	}
	command.Stdout = logfile
	command.Stderr = logfile
	if err := command.Start(); err != nil {
		_ = logfile.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { err := command.Wait(); _ = logfile.Close(); done <- err }()
	t.Cleanup(func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				data, _ := os.ReadFile(logfile.Name())
				t.Errorf("actual CLI webhook exit: %v %s", err, data)
			}
		case <-time.After(6 * time.Second):
			_ = command.Process.Kill()
			err := <-done
			t.Errorf("webhook did not drain: %v", err)
		}
	})
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "server.oskal.test"}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		response, err := client.Get("https://" + address + "/healthz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !ready {
		data, _ := os.ReadFile(logfile.Name())
		t.Fatalf("actual CLI webhook unavailable: %s", data)
	}
	return "https://" + address + "/validate", client
}
func actualAdmissionRequest(t *testing.T) []byte {
	t.Helper()
	yes, no, user := true, false, int64(10001)
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "declared-settings", Namespace: "example"}, Spec: corev1.PodSpec{SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &yes, RunAsUser: &user}, Containers: []corev1.Container{{Name: "declared", Image: "registry.k8s.io/pause:3.10", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &yes, RunAsUser: &user, AllowPrivilegeEscalation: &no, Privileged: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}}}}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	request := admissionv1.AdmissionReview{TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"}, Request: &admissionv1.AdmissionRequest{UID: types.UID(fmt.Sprintf("request-%d", time.Now().UnixNano())), Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}, Resource: metav1.GroupVersionResource{Version: "v1", Resource: "pods"}, Namespace: "example", Name: pod.Name, Operation: admissionv1.Create, Object: runtime.RawExtension{Raw: raw}}}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
func TestActualCLIWebhookArchiveQuotaAndCapture(t *testing.T) {
	binary := buildCLI(t)
	for _, mode := range []string{"enforcing", "warn", "audit"} {
		t.Run("quota-"+mode, func(t *testing.T) {
			store := filepath.Join(t.TempDir(), "archive")
			endpoint, client := startBudgetWebhook(t, binary, store, mode, 1, false)
			response, err := client.Post(endpoint, "application/json", bytes.NewReader(actualAdmissionRequest(t)))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			var review admissionv1.AdmissionReview
			if err := json.Unmarshal(raw, &review); err != nil {
				t.Fatal(err)
			}
			if review.Response == nil || review.Response.Allowed || review.Response.AuditAnnotations["assurance.ckodex.io/capture-error"] != "CAPACITY_EXHAUSTED" || review.Response.AuditAnnotations["assurance.ckodex.io/capture-status"] != "FAILED" {
				t.Fatalf("actual configured sink quota failure was not reported for %s request: %s", mode, raw)
			}
			repository, err := storage.OpenFilesystemEvidenceRepository(store)
			if err != nil {
				t.Fatal(err)
			}
			envelopes, err := repository.ListAll(t.Context())
			if err != nil || len(envelopes) != 0 {
				t.Fatalf("quota refusal manufactured capture: %d %v", len(envelopes), err)
			}
			t.Logf("actual CLI TLS admission %s denied configured quota failure", mode)
		})
	}
	t.Run("global-archive-capture", func(t *testing.T) {
		store := filepath.Join(t.TempDir(), "archive")
		endpoint, client := startBudgetWebhook(t, binary, store, "enforcing", 1<<20, true)
		request := actualAdmissionRequest(t)
		var original admissionv1.AdmissionReview
		if err := json.Unmarshal(request, &original); err != nil {
			t.Fatal(err)
		}
		response, err := client.Post(endpoint, "application/json", bytes.NewReader(request))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		var review admissionv1.AdmissionReview
		if err := json.Unmarshal(raw, &review); err != nil {
			t.Fatal(err)
		}
		if review.Response == nil || !review.Response.Allowed {
			t.Fatalf("actual declared-setting check failed: %s", raw)
		}
		repository, err := storage.OpenFilesystemEvidenceRepository(store)
		if err != nil {
			t.Fatal(err)
		}
		envelopes, err := repository.ListAll(t.Context())
		if err != nil || len(envelopes) != 1 {
			t.Fatalf("actual global archive capture missing: %d %v", len(envelopes), err)
		}
		envelope := envelopes[0]
		if envelope.Subject.Scheme != "admission-request" || envelope.Subject.ID != string(original.Request.UID) || envelope.Subject.Attributes["uid"] != "" || envelope.SignatureRef != "" || envelope.Epoch.SubjectDigest != assurance.ComputeDigest(request) || envelope.Producer.Canonical() != "local://oskal-cli-webhook" || len(envelope.ControlRefs) != 0 || envelope.Epoch.AuthorityDigest != "" || envelope.Epoch.ImplementationDigest != "" || envelope.Epoch.EnvironmentDigest != "" {
			t.Fatalf("CLI capture invented workload identity/control standing: %+v", envelope)
		}
		reader, err := repository.Get(t.Context(), envelope.Artifact)
		if err != nil {
			t.Fatal(err)
		}
		payload, readErr := io.ReadAll(reader)
		if err := errors.Join(readErr, reader.Close()); err != nil {
			t.Fatal(err)
		}
		if assurance.ComputeDigest(payload) != envelope.Artifact.Digest || envelope.IntegrityDigest != envelope.Artifact.Digest || review.Response.AuditAnnotations["assurance.ckodex.io/capture-digest"] != envelope.Artifact.Digest || review.Response.AuditAnnotations["assurance.ckodex.io/capture-uri"] != envelope.Artifact.URI || !bytes.Contains(payload, []byte("declared-settings")) {
			t.Fatal("actual capture payload was not digest-bound to the request")
		}
		t.Log("actual CLI global archive stored truthful request/check capture with exact payload hash and no workload creation claim")
	})
	first, second := filepath.Join(t.TempDir(), "one"), filepath.Join(t.TempDir(), "two")
	command := exec.CommandContext(t.Context(), binary, "webhook", "--evidence-dir", first, "--webhook-evidence-dir", second)
	output, err := command.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), "conflicting") {
		t.Fatalf("conflicting actual webhook paths did not fail: %v %s", err, output)
	}
	for _, path := range []string{first, second} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("conflicting roots caused archive side effects")
		}
	}
}
