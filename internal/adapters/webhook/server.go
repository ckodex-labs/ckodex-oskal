package webhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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

// WebhookMode defines the enforcement behavior of the admission webhook.
type WebhookMode string

const (
	// ModeEnforcing blocks admission on invariant violations (default).
	ModeEnforcing WebhookMode = "enforcing"
	// ModeAudit permits admission on invariant violations with audit annotations and logs.
	ModeAudit WebhookMode = "audit"
	// ModeWarn permits admission on invariant violations with admission warnings and audit annotations.
	ModeWarn WebhookMode = "warn"
	// MaxWebhookBodyBytes bounds AdmissionReview request payload size (4 MiB) per Constitution Section 30.
	MaxWebhookBodyBytes = 4 << 20
	// MaxWebhookInFlight bounds simultaneous in-flight admission validations before backpressure.
	MaxWebhookInFlight = 256
)

// ServerConfig configures the admission webhook server.
type ServerConfig struct {
	ListenAddr   string
	TLSCertPath  string
	TLSKeyPath   string
	TLSCertBytes []byte
	TLSKeyBytes  []byte
	ObserverAuth assurance.AuthorityRef
	EvidenceSink EvidenceSink
	Mode         WebhookMode
}

// AdmissionWebhookServer handles Kubernetes ValidatingAdmissionWebhook requests.
type AdmissionWebhookServer struct {
	config   ServerConfig
	observer *cel.AdmissionObserver
	server   *http.Server
	sem      chan struct{}
}

// NewAdmissionWebhookServer creates a new AdmissionWebhookServer.
func NewAdmissionWebhookServer(cfg ServerConfig) *AdmissionWebhookServer {
	observer := cel.NewAdmissionObserver(cfg.ObserverAuth)
	s := &AdmissionWebhookServer{
		config:   cfg,
		observer: observer,
		sem:      make(chan struct{}, MaxWebhookInFlight),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", s.handleValidate)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)

	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				http.Error(w, fmt.Sprintf("admission webhook panic recovered: %v", rec), http.StatusInternalServerError)
			}
		}()
		mux.ServeHTTP(w, r)
	})

	s.server = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           wrapped,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
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

	if s.sem != nil {
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "admission webhook concurrency limit reached", http.StatusTooManyRequests)
			return
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxWebhookBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "admission review payload exceeds maximum size (4 MiB)", http.StatusRequestEntityTooLarge)
			return
		}
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
	podName := req.Name
	if podName == "" && pod.Name != "" {
		podName = pod.Name
	}
	if podName == "" && pod.GenerateName != "" {
		podName = fmt.Sprintf("%s%s", pod.GenerateName, string(req.UID))
	}
	if podName == "" {
		podName = string(req.UID)
	}

	sub := assurance.SubjectRef{
		Scheme: "k8s",
		ID:     fmt.Sprintf("%s/Pod/%s", req.Namespace, podName),
		Attributes: map[string]string{
			"namespace": req.Namespace,
			"name":      podName,
			"uid":       string(req.UID),
		},
	}

	epoch := assurance.AssuranceEpoch{
		SubjectDigest:        sub.Digest(),
		ImplementationDigest: assurance.ComputeStringDigest("kubernetes:validating-webhook"),
		AuthorityDigest:      assurance.ComputeStringDigest(s.config.ObserverAuth.Canonical()),
		EnvironmentDigest:    assurance.ComputeStringDigest("cluster:kubernetes"),
	}

	// 1. Invariant Evaluation: Run as non-root
	nonRootViolations := checkNonRootCompliance(&pod)

	// 2. Invariant Evaluation: Dropped capabilities and privilege escalation
	capViolations := checkCapabilityCompliance(&pod)

	var allViolations []string
	allViolations = append(allViolations, nonRootViolations...)
	allViolations = append(allViolations, capViolations...)

	mode := WebhookMode(strings.ToLower(strings.TrimSpace(string(s.config.Mode))))
	if mode != ModeAudit && mode != ModeWarn {
		mode = ModeEnforcing
	}

	if len(allViolations) > 0 {
		if mode != ModeAudit && mode != ModeWarn {
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  "Failure",
					Message: fmt.Sprintf("Admission denied by policy: %s", strings.Join(allViolations, "; ")),
				},
			}
		}

		// Degraded mode: ModeAudit or ModeWarn permits admission with full diagnostic audit trail
		// AND emits adverse violation evidence to EvidenceSink so CAS truthfully transitions to FAILED/DECOHERENT (Section 29).
		policy := cel.SampleRestrictedContainerPolicy()
		policyDigest := cel.ComputePolicyDigest(policy)
		epochWithPolicy := epoch
		epochWithPolicy.PolicyDigest = policyDigest
		rawViolationPayload := fmt.Sprintf("admission-violation|%s|%s|mode=%s|violations=%s|%d",
			sub.URI(), policy.Name, string(mode), strings.Join(allViolations, ";"), now.Unix())
		violationDigest := assurance.ComputeStringDigest(rawViolationPayload)
		adverseEnv := assurance.EvidenceEnvelope{
			Schema:          "assurance.ckodex.io/evidence/v1alpha1",
			ID:              fmt.Sprintf("ev-adm-viol-%d", now.UnixNano()),
			Subject:         sub,
			ObservationType: "kubernetes.admission.violation",
			CapturedAt:      now,
			Producer:        s.config.ObserverAuth,
			Artifact: assurance.EvidenceRef{
				URI:       fmt.Sprintf("evidence://admission-violation/%s/%s", req.Namespace, podName),
				Digest:    violationDigest,
				MediaType: "application/vnd.ckodex.evidence+json",
			},
			IntegrityDigest: violationDigest,
			Epoch:           epochWithPolicy,
			ControlRefs: []assurance.ControlRef{
				{Namespace: "ckodex", ID: "container.least-privilege"},
			},
		}
		if adverseEnv.Producer.Scheme == "" {
			adverseEnv.Producer = assurance.AuthorityRef{
				Scheme:      "spiffe",
				Subject:     "prod/ns/ckodex-assurance/sa/cel-admission-observer",
				TrustDomain: "prod",
			}
		}
		if s.config.EvidenceSink != nil {
			s.config.EvidenceSink(adverseEnv)
		}

		auditAnnotations := map[string]string{
			"assurance.ckodex.io/admitted-in-degraded-mode": "true",
			"assurance.ckodex.io/webhook-mode":              string(mode),
			"assurance.ckodex.io/violations":                strings.Join(allViolations, "; "),
			"assurance.ckodex.io/admission-envelope-id":     adverseEnv.ID,
			"assurance.ckodex.io/admission-envelope-digest": adverseEnv.IntegrityDigest,
		}

		resp := &admissionv1.AdmissionResponse{
			Allowed:          true,
			AuditAnnotations: auditAnnotations,
		}
		if mode == ModeWarn {
			resp.Warnings = allViolations
		}
		return resp
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
func allContainers(pod *corev1.Pod) []corev1.Container {
	total := len(pod.Spec.Containers) + len(pod.Spec.InitContainers) + len(pod.Spec.EphemeralContainers)
	all := make([]corev1.Container, 0, total)
	all = append(all, pod.Spec.Containers...)
	all = append(all, pod.Spec.InitContainers...)
	for _, ec := range pod.Spec.EphemeralContainers {
		all = append(all, corev1.Container(ec.EphemeralContainerCommon))
	}
	return all
}

func checkNonRootCompliance(pod *corev1.Pod) []string {
	var violations []string

	podNonRoot := pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil && *pod.Spec.SecurityContext.RunAsNonRoot
	podUserZero := pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsUser != nil && *pod.Spec.SecurityContext.RunAsUser == 0

	if podUserZero {
		violations = append(violations, "pod SecurityContext defines runAsUser=0 (root)")
	}

	for _, c := range allContainers(pod) {
		if c.SecurityContext != nil {
			if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
				violations = append(violations, fmt.Sprintf("container %s defines runAsUser=0 (root)", c.Name))
			}
			if c.SecurityContext.RunAsNonRoot != nil && !*c.SecurityContext.RunAsNonRoot {
				violations = append(violations, fmt.Sprintf("container %s explicitly sets runAsNonRoot=false", c.Name))
			}
			if c.SecurityContext.RunAsNonRoot == nil && !podNonRoot {
				violations = append(violations, fmt.Sprintf("container %s does not specify runAsNonRoot and pod default is not enforced", c.Name))
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
	forbiddenCaps := map[string]bool{
		"SYS_ADMIN":    true,
		"NET_ADMIN":    true,
		"SYS_PTRACE":   true,
		"SYS_MODULE":   true,
		"DAC_OVERRIDE": true,
		"NET_RAW":      true,
	}

	for _, c := range allContainers(pod) {
		if c.SecurityContext != nil {
			if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				violations = append(violations, fmt.Sprintf("container %s requests privileged mode", c.Name))
			}
			if c.SecurityContext.AllowPrivilegeEscalation != nil && *c.SecurityContext.AllowPrivilegeEscalation {
				violations = append(violations, fmt.Sprintf("container %s allows privilege escalation", c.Name))
			}
			if c.SecurityContext.Capabilities != nil {
				for _, addCap := range c.SecurityContext.Capabilities.Add {
					norm := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(string(addCap))), "CAP_")
					if forbiddenCaps[norm] {
						violations = append(violations, fmt.Sprintf("container %s adds prohibited capability %s", c.Name, addCap))
					}
				}
			}
		}
	}

	return violations
}
