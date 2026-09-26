package webhook

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func ptrBool(b bool) *bool    { return &b }
func ptrInt64(i int64) *int64 { return &i }

func TestGenerateSelfSignedCert(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCert(
		"oskal-webhook.ckodex.svc",
		[]string{"oskal-webhook", "oskal-webhook.ckodex.svc"},
		[]net.IP{net.ParseIP("127.0.0.1")},
	)
	if err != nil {
		t.Fatalf("unexpected error generating cert: %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("expected non-empty cert and key PEM")
	}
	if !strings.Contains(string(certPEM), "BEGIN CERTIFICATE") {
		t.Fatal("expected CERTIFICATE block in cert PEM")
	}
	if !strings.Contains(string(keyPEM), "BEGIN PRIVATE KEY") {
		t.Fatal("expected PRIVATE KEY block in key PEM")
	}
}

func TestAdmissionWebhook_CompliantPod(t *testing.T) {
	var capturedEnvelopes []assurance.EvidenceEnvelope
	server := NewAdmissionWebhookServer(ServerConfig{
		ObserverAuth: assurance.AuthorityRef{Scheme: "spiffe", Subject: "prod/sa/webhook"},
		EvidenceSink: func(env assurance.EvidenceEnvelope) {
			capturedEnvelopes = append(capturedEnvelopes, env)
		},
	})

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "payments-api",
			Namespace: "payments",
		},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: ptrBool(true),
				RunAsUser:    ptrInt64(10001),
			},
			Containers: []corev1.Container{
				{
					Name:  "payments",
					Image: "payments:v1.0.0",
					SecurityContext: &corev1.SecurityContext{
						RunAsNonRoot:             ptrBool(true),
						RunAsUser:                ptrInt64(10001),
						AllowPrivilegeEscalation: ptrBool(false),
						Privileged:               ptrBool(false),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
					},
				},
			},
		},
	}

	podRaw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("failed to marshal test pod: %v", err)
	}

	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID: "req-1234",
			Kind: metav1.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "Pod",
			},
			Namespace: "payments",
			Name:      "payments-api",
			Object:    runtime.RawExtension{Raw: podRaw},
		},
	}
	body, _ := json.Marshal(review)

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", w.Code, w.Body.String())
	}

	var responseReview admissionv1.AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &responseReview); err != nil {
		t.Fatalf("failed to unmarshal response review: %v", err)
	}

	if responseReview.Response == nil {
		t.Fatal("expected non-nil AdmissionResponse")
	}
	if !responseReview.Response.Allowed {
		t.Fatalf("expected compliant pod to be allowed, got denied: %s", responseReview.Response.Result.Message)
	}
	if responseReview.Response.UID != "req-1234" {
		t.Fatalf("expected UID req-1234, got %s", responseReview.Response.UID)
	}

	// Verify Audit Annotations
	annotations := responseReview.Response.AuditAnnotations
	if annotations == nil {
		t.Fatal("expected audit annotations on allowed pod")
	}
	if annotations["assurance.ckodex.io/admission-envelope-id"] == "" {
		t.Fatal("expected admission envelope ID in audit annotations")
	}
	if annotations["assurance.ckodex.io/admission-envelope-digest"] == "" {
		t.Fatal("expected admission envelope digest in audit annotations")
	}

	// Verify EvidenceSink captured envelope
	if len(capturedEnvelopes) != 1 {
		t.Fatalf("expected 1 captured envelope in sink, got %d", len(capturedEnvelopes))
	}
	if capturedEnvelopes[0].ObservationType != "kubernetes.admission" {
		t.Fatalf("unexpected observation type: %s", capturedEnvelopes[0].ObservationType)
	}
}

func TestAdmissionWebhook_RootUserViolation(t *testing.T) {
	server := NewAdmissionWebhookServer(ServerConfig{})

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "root-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "root-app",
					Image: "evil:latest",
					SecurityContext: &corev1.SecurityContext{
						RunAsUser: ptrInt64(0),
					},
				},
			},
		},
	}
	podRaw, _ := json.Marshal(pod)

	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:       "req-root",
			Kind:      metav1.GroupVersionKind{Kind: "Pod"},
			Namespace: "default",
			Name:      "root-pod",
			Object:    runtime.RawExtension{Raw: podRaw},
		},
	}
	body, _ := json.Marshal(review)

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	var responseReview admissionv1.AdmissionReview
	_ = json.Unmarshal(w.Body.Bytes(), &responseReview)

	if responseReview.Response == nil || responseReview.Response.Allowed {
		t.Fatal("expected root pod to be denied")
	}
	if !strings.Contains(responseReview.Response.Result.Message, "runAsUser=0 (root)") {
		t.Fatalf("unexpected rejection message: %s", responseReview.Response.Result.Message)
	}
}

func TestAdmissionWebhook_PrivilegedAndCapViolation(t *testing.T) {
	server := NewAdmissionWebhookServer(ServerConfig{})

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "priv-app",
					Image: "app:latest",
					SecurityContext: &corev1.SecurityContext{
						RunAsNonRoot: ptrBool(true),
						RunAsUser:    ptrInt64(1001),
						Privileged:   ptrBool(true),
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{"CAP_SYS_ADMIN"},
						},
					},
				},
			},
		},
	}
	podRaw, _ := json.Marshal(pod)

	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:       "req-priv",
			Kind:      metav1.GroupVersionKind{Kind: "Pod"},
			Namespace: "default",
			Name:      "priv-pod",
			Object:    runtime.RawExtension{Raw: podRaw},
		},
	}
	body, _ := json.Marshal(review)

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	var responseReview admissionv1.AdmissionReview
	_ = json.Unmarshal(w.Body.Bytes(), &responseReview)

	if responseReview.Response == nil || responseReview.Response.Allowed {
		t.Fatal("expected privileged pod with CAP_SYS_ADMIN to be denied")
	}
	if !strings.Contains(responseReview.Response.Result.Message, "privileged mode") {
		t.Fatalf("expected privileged mode rejection: %s", responseReview.Response.Result.Message)
	}
}

func TestAdmissionWebhook_NonPodPassthrough(t *testing.T) {
	server := NewAdmissionWebhookServer(ServerConfig{})

	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:  "req-svc",
			Kind: metav1.GroupVersionKind{Kind: "Service"},
		},
	}
	body, _ := json.Marshal(review)

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	var responseReview admissionv1.AdmissionReview
	_ = json.Unmarshal(w.Body.Bytes(), &responseReview)

	if responseReview.Response == nil || !responseReview.Response.Allowed {
		t.Fatal("expected non-Pod resource to be allowed automatically")
	}
}

func TestAdmissionWebhook_HealthEndpoints(t *testing.T) {
	server := NewAdmissionWebhookServer(ServerConfig{})

	reqHealth := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	wHealth := httptest.NewRecorder()
	server.Handler().ServeHTTP(wHealth, reqHealth)
	if wHealth.Code != http.StatusOK || wHealth.Body.String() != "ok" {
		t.Fatalf("unexpected healthz response: %d, %s", wHealth.Code, wHealth.Body.String())
	}

	reqReady := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	wReady := httptest.NewRecorder()
	server.Handler().ServeHTTP(wReady, reqReady)
	if wReady.Code != http.StatusOK || wReady.Body.String() != "ready" {
		t.Fatalf("unexpected readyz response: %d, %s", wReady.Code, wReady.Body.String())
	}
}
