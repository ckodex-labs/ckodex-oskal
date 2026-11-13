package webhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// EvidenceSink must durably persist the unchanged envelope/payload or return an
// error. A nil sink selects policy-only operation; no durable reference is issued.
type EvidenceSink func(context.Context, assurance.EvidenceEnvelope, []byte) error

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
	MaxWebhookInFlight = 16
)

// ServerConfig configures the admission webhook server.
type ServerConfig struct {
	ListenAddr     string
	TLSCertPath    string
	TLSKeyPath     string
	TLSCertBytes   []byte
	TLSKeyBytes    []byte
	ObserverAuth   assurance.AuthorityRef
	EvidenceSink   EvidenceSink
	Mode           WebhookMode
	RequestTimeout time.Duration
}

// AdmissionWebhookServer handles Kubernetes ValidatingAdmissionWebhook requests.
type AdmissionWebhookServer struct {
	config      ServerConfig
	configError error
	server      *http.Server
	sem         chan struct{}
}

// NewAdmissionWebhookServer creates a new AdmissionWebhookServer.
func NewAdmissionWebhookServer(cfg ServerConfig) *AdmissionWebhookServer {
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = DefaultRequestTimeout
	}
	var configError error
	if cfg.RequestTimeout <= 0 || cfg.RequestTimeout > 10*time.Second {
		configError = fmt.Errorf("admission request timeout must be in (0,10s]")
	}
	if cfg.EvidenceSink != nil {
		if err := captureIdentityValid(cfg.ObserverAuth); err != nil {
			configError = fmt.Errorf("explicit capture observer identity required: %w", err)
		}
	}
	s := &AdmissionWebhookServer{
		config:      cfg,
		configError: configError,
		sem:         make(chan struct{}, MaxWebhookInFlight),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", s.handleValidate)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)

	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				http.Error(w, "admission request processing failed", http.StatusInternalServerError)
			}
		}()
		mux.ServeHTTP(w, r)
	})

	s.server = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           wrapped,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      cfg.RequestTimeout + 5*time.Second,
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
	if s.configError != nil {
		return s.configError
	}
	var certificate tls.Certificate
	var err error
	if len(s.config.TLSCertBytes) > 0 || len(s.config.TLSKeyBytes) > 0 {
		if len(s.config.TLSCertBytes) == 0 || len(s.config.TLSKeyBytes) == 0 {
			return fmt.Errorf("inline TLS certificate and key must be supplied together")
		}
		certificate, err = tls.X509KeyPair(s.config.TLSCertBytes, s.config.TLSKeyBytes)
	} else {
		if s.config.TLSCertPath == "" || s.config.TLSKeyPath == "" {
			return fmt.Errorf("TLS certificate and key must be explicitly supplied")
		}
		certificate, err = tls.LoadX509KeyPair(s.config.TLSCertPath, s.config.TLSKeyPath)
	}
	if err != nil {
		return fmt.Errorf("load webhook TLS identity: %w", err)
	}
	s.server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen for admission requests: %w", err)
	}
	limited := newConnectionListener(listener, MaxWebhookConnections)
	defer func() { _ = limited.Close() }()
	finished := make(chan struct{})
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-finished:
			return
		case <-ctx.Done():
		}
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.server.Shutdown(shutdown); err != nil {
			_ = s.server.Close()
		}
	}()
	err = s.server.ServeTLS(limited, "", "")
	close(finished)
	// A context-triggered shutdown owns its bounded drain/forced close. Do not
	// let the manager return while that work is still running in a goroutine.
	<-shutdownDone

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	if s.configError != nil {
		http.Error(w, "admission capture configuration invalid", http.StatusServiceUnavailable)
		return
	}
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

	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := http.NewResponseController(w).SetReadDeadline(deadline); err != nil {
		http.Error(w, "host cannot enforce admission read deadline", http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = http.NewResponseController(w).SetReadDeadline(time.Time{}) }()
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

	if err := boundAdmissionJSON(body); err != nil {
		http.Error(w, "admission JSON is malformed, ambiguous or exceeds structural bounds", http.StatusBadRequest)
		return
	}
	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "could not decode admission review", http.StatusBadRequest)
		return
	}

	if review.APIVersion != "" && review.APIVersion != "admission.k8s.io/v1" || review.Kind != "" && review.Kind != "AdmissionReview" {
		http.Error(w, "unsupported admission review type", http.StatusBadRequest)
		return
	}
	if review.Request == nil {
		http.Error(w, "admission review request is nil", http.StatusBadRequest)
		return
	}

	resp := s.validateRequest(ctx, review.Request, body, time.Now().UTC())
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

// allContainers includes regular, init and ephemeral container declarations.
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

// checkCapabilityCompliance rejects explicit prohibited privilege requests.
// It does not require capability drops or treat omitted escalation flags as false.
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
				seen := make(map[string]bool)
				for _, addCap := range c.SecurityContext.Capabilities.Add {
					norm := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(string(addCap))), "CAP_")
					if forbiddenCaps[norm] && !seen[norm] {
						seen[norm] = true
						violations = append(violations, fmt.Sprintf("container %s adds prohibited capability %s", c.Name, addCap))
					}
				}
			}
		}
	}

	return violations
}
