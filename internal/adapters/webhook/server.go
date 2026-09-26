package webhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/cel"
)

var (
	universalDeserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
)

// EvidenceSink is a callback to consume in-flight evidence envelopes produced during admission.
type EvidenceSink func(env assurance.EvidenceEnvelope)

// ServerConfig configures the admission webhook server.
type ServerConfig struct {
	ListenAddr   string
	TLSCertPath  string
	TLSKeyPath   string
	TLSCertBytes []byte
	TLSKeyBytes  []byte
	ObserverAuth assurance.AuthorityRef
	EvidenceSink EvidenceSink
}

// AdmissionWebhookServer handles Kubernetes ValidatingAdmissionWebhook requests.
type AdmissionWebhookServer struct {
	config   ServerConfig
	observer *cel.AdmissionObserver
	server   *http.Server
}

// NewAdmissionWebhookServer creates a new AdmissionWebhookServer.
func NewAdmissionWebhookServer(cfg ServerConfig) *AdmissionWebhookServer {
	observer := cel.NewAdmissionObserver(cfg.ObserverAuth)
	s := &AdmissionWebhookServer{
		config:   cfg,
		observer: observer,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", s.handleValidate)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)

	s.server = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	return s
}

// Handler returns the underlying http.Handler for testing or custom hosting.
func (s *AdmissionWebhookServer) Handler() http.Handler {
	return s.server.Handler
}

// Start launches the HTTPS webhook server. It satisfies manager.Runnable.
func (s *AdmissionWebhookServer) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
	}()

	var err error
	if len(s.config.TLSCertBytes) > 0 && len(s.config.TLSKeyBytes) > 0 {
		cert, keyErr := tls.X509KeyPair(s.config.TLSCertBytes, s.config.TLSKeyBytes)
		if keyErr != nil {
			return fmt.Errorf("failed to parse in-memory TLS key pair: %w", keyErr)
		}
		s.server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		err = s.server.ListenAndServeTLS("", "")
	} else {
		err = s.server.ListenAndServeTLS(s.config.TLSCertPath, s.config.TLSKeyPath)
	}

	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully stops the webhook server.
func (s *AdmissionWebhookServer) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func (s *AdmissionWebhookServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *AdmissionWebhookServer) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

func (s *AdmissionWebhookServer) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not read request body: %v", err), http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var review admissionv1.AdmissionReview
	if _, _, err := universalDeserializer.Decode(body, nil, &review); err != nil {
		// Fallback to standard JSON unmarshaling
		if jsonErr := json.Unmarshal(body, &review); jsonErr != nil {
			http.Error(w, fmt.Sprintf("could not decode admission review: %v", jsonErr), http.StatusBadRequest)
			return
		}
	}

	if review.Request == nil {
		http.Error(w, "admission review request is nil", http.StatusBadRequest)
		return
	}

	resp := s.validateRequest(review.Request)
	resp.UID = review.Request.UID

	responseReview := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: resp,
	}

	respBytes, err := json.Marshal(responseReview)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(respBytes)
}

// validateRequest executes in-flight validation and generates evidence envelopes.
func (s *AdmissionWebhookServer) validateRequest(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	// Only evaluate Pod resource creations / updates
	if req.Kind.Kind != "Pod" {
		return &admissionv1.AdmissionResponse{Allowed: true}
	}

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  "Failure",
				Message: fmt.Sprintf("failed to unmarshal Pod object: %v", err),
			},
		}
	}

	now := time.Now().UTC()
	sub := assurance.SubjectRef{
		Scheme: "k8s",
		ID:     fmt.Sprintf("%s/Pod/%s", req.Namespace, req.Name),
		Attributes: map[string]string{
			"namespace": req.Namespace,
			"name":      req.Name,
			"uid":       string(req.UID),
		},
	}
	if sub.Attributes["name"] == "" && pod.Name != "" {
		sub.Attributes["name"] = pod.Name
		sub.ID = fmt.Sprintf("%s/Pod/%s", req.Namespace, pod.Name)
	}

	epoch := assurance.AssuranceEpoch{
		SubjectDigest:        sub.Digest(),
		ImplementationDigest: assurance.ComputeStringDigest("kubernetes:validating-webhook"),
		AuthorityDigest:      assurance.ComputeStringDigest(s.config.ObserverAuth.Canonical()),
		EnvironmentDigest:    assurance.ComputeStringDigest("cluster:kubernetes"),
	}

	// 1. Invariant Evaluation: Run as non-root
	nonRootViolations := checkNonRootCompliance(&pod)
	if len(nonRootViolations) > 0 {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  "Failure",
				Message: fmt.Sprintf("Admission denied by policy: %s", strings.Join(nonRootViolations, "; ")),
			},
		}
	}

	// 2. Invariant Evaluation: Dropped capabilities and privilege escalation
	capViolations := checkCapabilityCompliance(&pod)
	if len(capViolations) > 0 {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  "Failure",
				Message: fmt.Sprintf("Admission denied by policy: %s", strings.Join(capViolations, "; ")),
			},
		}
	}

	// 3. Generate In-Flight Evidence Envelope (Proof before side effect)
	policy := cel.SampleRestrictedContainerPolicy()
	env, err := s.observer.GenerateAdmissionEvidence(sub, policy, true, epoch, now)
	if err != nil {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  "Failure",
				Message: fmt.Sprintf("Failed to generate in-flight admission evidence: %v", err),
			},
		}
	}

	// Deliver evidence to sink if configured
	if s.config.EvidenceSink != nil {
		s.config.EvidenceSink(env)
	}

	return &admissionv1.AdmissionResponse{
		Allowed: true,
		AuditAnnotations: map[string]string{
			"assurance.ckodex.io/admission-envelope-id":     env.ID,
			"assurance.ckodex.io/admission-envelope-digest": env.IntegrityDigest,
			"assurance.ckodex.io/assurance-epoch":           env.Epoch.CompositeDigest(),
		},
	}
}

// checkNonRootCompliance validates that container executes as non-root.
func checkNonRootCompliance(pod *corev1.Pod) []string {
	var violations []string

	podNonRoot := pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil && *pod.Spec.SecurityContext.RunAsNonRoot
	podUserZero := pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsUser != nil && *pod.Spec.SecurityContext.RunAsUser == 0

	if podUserZero {
		violations = append(violations, "pod SecurityContext defines runAsUser=0 (root)")
	}

	for _, c := range pod.Spec.Containers {
		if c.SecurityContext != nil {
			if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
				violations = append(violations, fmt.Sprintf("container %s defines runAsUser=0 (root)", c.Name))
			}
			if c.SecurityContext.RunAsNonRoot != nil && !*c.SecurityContext.RunAsNonRoot {
				violations = append(violations, fmt.Sprintf("container %s explicitly sets runAsNonRoot=false", c.Name))
			}
		} else if !podNonRoot {
			violations = append(violations, fmt.Sprintf("container %s does not specify runAsNonRoot and pod default is not enforced", c.Name))
		}
	}

	return violations
}

// checkCapabilityCompliance validates dropped capabilities and privilege escalation prohibitions.
func checkCapabilityCompliance(pod *corev1.Pod) []string {
	var violations []string

	for _, c := range pod.Spec.Containers {
		if c.SecurityContext != nil {
			if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				violations = append(violations, fmt.Sprintf("container %s requests privileged mode", c.Name))
			}
			if c.SecurityContext.AllowPrivilegeEscalation != nil && *c.SecurityContext.AllowPrivilegeEscalation {
				violations = append(violations, fmt.Sprintf("container %s allows privilege escalation", c.Name))
			}
			if c.SecurityContext.Capabilities != nil {
				for _, addCap := range c.SecurityContext.Capabilities.Add {
					if addCap == "CAP_SYS_ADMIN" || addCap == "SYS_ADMIN" || addCap == "CAP_NET_ADMIN" || addCap == "NET_ADMIN" {
						violations = append(violations, fmt.Sprintf("container %s adds prohibited capability %s", c.Name, addCap))
					}
				}
			}
		}
	}

	return violations
}
