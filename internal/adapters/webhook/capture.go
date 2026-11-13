package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	MaxCaptureBytes       = 8 << 20
	MaxJSONItems          = 65536
	MaxJSONArrayItems     = 256
	MaxJSONDepth          = 32
	DefaultRequestTimeout = 5 * time.Second
)

// AdmissionCapture records the local policy decision before persistence and
// response delivery. It is not proof that an API server admitted/created a Pod.
type AdmissionCapture struct {
	Schema          string            `json:"schema"`
	RequestUID      string            `json:"requestUID"`
	ReceivedAt      time.Time         `json:"receivedAt"`
	SourceBytes     []byte            `json:"sourceBytes"`
	Mode            WebhookMode       `json:"mode"`
	Checks          []AdmissionCheck  `json:"checks"`
	PolicyAllowed   bool              `json:"policyAllowed"`
	DeclaredSubject DeclaredSubject   `json:"declaredSubject"`
	Limitations     map[string]string `json:"limitations"`
}

type AdmissionCheck struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Result      string   `json:"result"`
	Violations  []string `json:"violations,omitempty"`
}

type DeclaredSubject struct {
	RequestName      string `json:"requestName,omitempty"`
	RequestNamespace string `json:"requestNamespace,omitempty"`
	ObjectName       string `json:"objectName,omitempty"`
	ObjectNamespace  string `json:"objectNamespace,omitempty"`
	GenerateName     string `json:"generateName,omitempty"`
	ObjectUID        string `json:"objectUID,omitempty"`
	NameResolution   string `json:"nameResolution"`
}

// boundAdmissionJSON limits structural amplification before decoding typed Pod
// slices/maps. It also rejects duplicate keys, which would make raw request bytes
// and the effective checked fields ambiguous.
func boundAdmissionJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	tokens := 0
	var value func(int) error
	value = func(depth int) error {
		tokens++
		if tokens > MaxJSONItems || depth > MaxJSONDepth {
			return fmt.Errorf("admission JSON structure exceeds capacity")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				tokens++
				if tokens > MaxJSONItems {
					return fmt.Errorf("admission JSON structure exceeds capacity")
				}
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return fmt.Errorf("duplicate or invalid JSON object key")
				}
				seen[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return fmt.Errorf("invalid JSON object")
			}
		case '[':
			count := 0
			for decoder.More() {
				count++
				if count > MaxJSONArrayItems {
					return fmt.Errorf("admission JSON array exceeds %d items", MaxJSONArrayItems)
				}
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return fmt.Errorf("invalid JSON array")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw[decoder.InputOffset():])) != 0 {
		return fmt.Errorf("admission review must contain one JSON object")
	}
	return nil
}

func effectiveMode(mode WebhookMode) WebhookMode {
	mode = WebhookMode(strings.ToLower(strings.TrimSpace(string(mode))))
	if mode == ModeAudit || mode == ModeWarn {
		return mode
	}
	return ModeEnforcing
}
func checked(id, description string, violations []string) AdmissionCheck {
	result := "PASS"
	if len(violations) > 0 {
		result = "FAIL"
	}
	return AdmissionCheck{ID: id, Description: description, Result: result, Violations: violations}
}

func captureIdentityValid(auth assurance.AuthorityRef) error {
	if err := auth.Validate(); err != nil {
		return err
	}
	for _, value := range []string{auth.Scheme, auth.Subject, auth.TrustDomain} {
		if len(value) > 2048 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "*|\r\n\x00") {
			return fmt.Errorf("observer identity must be exact and bounded")
		}
	}
	return nil
}

func denied(message string, annotations map[string]string) *admissionv1.AdmissionResponse {
	delete(annotations, "assurance.ckodex.io/admitted-in-degraded-mode")
	return &admissionv1.AdmissionResponse{Allowed: false, Result: &metav1.Status{Status: "Failure", Message: message}, AuditAnnotations: annotations}
}

func (s *AdmissionWebhookServer) validateRequest(ctx context.Context, req *admissionv1.AdmissionRequest, raw []byte, received time.Time) *admissionv1.AdmissionResponse {
	annotations := map[string]string{"assurance.ckodex.io/capture-status": "NOT_RECORDED", "assurance.ckodex.io/webhook-mode": string(effectiveMode(s.config.Mode)), "assurance.ckodex.io/standing": "UNKNOWN"}
	if req.UID == "" || len(req.UID) > 256 || strings.TrimSpace(string(req.UID)) != string(req.UID) || strings.ContainsAny(string(req.UID), "|\r\n\x00") {
		return denied("admission request UID is required and must be bounded", annotations)
	}
	if req.Kind.Kind == "" || req.Kind.Version == "" {
		return denied("admission kind and version are required", annotations)
	}
	switch req.Operation {
	case admissionv1.Create, admissionv1.Update, admissionv1.Delete, admissionv1.Connect:
	default:
		return denied("admission operation is missing or unsupported", annotations)
	}
	if s.configError != nil {
		annotations["assurance.ckodex.io/capture-status"] = "FAILED"
		return denied("admission capture configuration is invalid: "+s.configError.Error(), annotations)
	}
	if req.Kind.Kind != "Pod" || req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		annotations["assurance.ckodex.io/check-scope"] = "NOT_APPLICABLE"
		return &admissionv1.AdmissionResponse{Allowed: true, AuditAnnotations: annotations}
	}
	if req.Kind.Group != "" || req.Kind.Version != "v1" {
		return denied("built-in Pod checks require core/v1 Pod input", annotations)
	}
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return denied("failed to decode Pod object", annotations)
	}
	if len(pod.Spec.Containers) == 0 || pod.Kind != "" && pod.Kind != "Pod" || pod.APIVersion != "" && pod.APIVersion != "v1" {
		return denied("request does not contain a core/v1 Pod with containers", annotations)
	}
	if len(pod.Spec.Containers)+len(pod.Spec.InitContainers)+len(pod.Spec.EphemeralContainers) > MaxJSONArrayItems {
		return denied("Pod container count exceeds bounded validation capacity", annotations)
	}
	if err := podFieldBounds(req, &pod); err != nil {
		return denied(err.Error(), annotations)
	}
	checks := []AdmissionCheck{
		checked("pod.non-root-configuration", "Check declared runAsNonRoot defaults/overrides and reject explicit runAsUser=0; does not observe runtime UID", checkNonRootCompliance(&pod)),
		checked("pod.prohibited-privilege-requests", "Reject explicit privileged=true, allowPrivilegeEscalation=true and prohibited capability additions; omitted fields and capability drop lists are not validated", checkCapabilityCompliance(&pod)),
	}
	var violations []string
	for _, check := range checks {
		violations = append(violations, check.Violations...)
	}
	mode := effectiveMode(s.config.Mode)
	allowed := len(violations) == 0 || mode == ModeAudit || mode == ModeWarn
	response := &admissionv1.AdmissionResponse{Allowed: allowed, AuditAnnotations: annotations}
	annotations["assurance.ckodex.io/check-scope"] = "DECLARED_POD_CONFIGURATION"
	if len(violations) > 0 {
		if !allowed {
			response.Result = &metav1.Status{Status: "Failure", Message: "Admission denied by built-in checks: " + strings.Join(violations, "; ")}
		}
		if allowed {
			annotations["assurance.ckodex.io/admitted-in-degraded-mode"] = "true"
		}
		if mode == ModeWarn {
			response.Warnings = violations
		}
	}
	if err := ctx.Err(); err != nil {
		return denied("admission request context ended before capture", annotations)
	}
	if s.config.EvidenceSink == nil {
		return response
	}
	nameResolution := "DECLARED_UNVERIFIED"
	if req.Name == "" && pod.Name == "" {
		nameResolution = "UNRESOLVED"
	}
	record := AdmissionCapture{Schema: "assurance.ckodex.io/admission-capture/v1", RequestUID: string(req.UID), ReceivedAt: received, SourceBytes: raw, Mode: mode, Checks: checks, PolicyAllowed: allowed, DeclaredSubject: DeclaredSubject{RequestName: req.Name, RequestNamespace: req.Namespace, ObjectName: pod.Name, ObjectNamespace: pod.Namespace, GenerateName: pod.GenerateName, ObjectUID: string(pod.UID), NameResolution: nameResolution}, Limitations: map[string]string{
		"requestUID":            "REQUEST_CORRELATION_ONLY_NOT_WORKLOAD_UID",
		"subjectIdentity":       "DECLARED_NOT_RESOLVED_AGAINST_API",
		"apiClientIdentity":     "NOT_AUTHENTICATED_BY_THIS_CAPTURE",
		"workloadCreation":      "NOT_ESTABLISHED",
		"runtimePrivileges":     "NOT_OBSERVED",
		"celPolicyInstallation": "NOT_ESTABLISHED",
		"responseDelivery":      "NOT_ESTABLISHED_POLICY_DECISION_PRECEDES_PERSISTENCE_AND_RESPONSE",
		"controlStanding":       "UNKNOWN_CAPTURE_ONLY",
	}}
	payload, err := json.Marshal(record)
	if err != nil || len(payload) > MaxCaptureBytes {
		annotations["assurance.ckodex.io/capture-status"] = "FAILED"
		return denied("admission capture exceeds serialization bounds", annotations)
	}
	digest := assurance.ComputeDigest(payload)
	observation := "kubernetes.admission.request.checked"
	if len(violations) > 0 {
		observation = "kubernetes.admission.violation"
	}
	envelope := assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/evidence/v1alpha1", ID: "admission-" + strings.TrimPrefix(digest, "sha256:"), Subject: assurance.SubjectRef{Scheme: "admission-request", ID: string(req.UID), Attributes: map[string]string{"requestUID": string(req.UID), "identityScope": "request-correlation-only"}}, ObservationType: observation, CapturedAt: received, Producer: s.config.ObserverAuth, Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(digest, "sha256:"), Digest: digest, MediaType: "application/vnd.ckodex.admission-capture+json"}, IntegrityDigest: digest, Epoch: assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeDigest(raw)}}
	err = deliverCapture(ctx, s.config.EvidenceSink, envelope, payload)
	if err != nil || ctx.Err() != nil || assurance.ComputeDigest(payload) != digest {
		annotations["assurance.ckodex.io/capture-status"] = "FAILED"
		cause := "PERSISTENCE_ERROR"
		if errors.Is(err, ports.ErrEvidenceCapacity) {
			cause = "CAPACITY_EXHAUSTED"
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			cause = "REQUEST_EXPIRED"
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			cause = "REQUEST_CANCELED"
		}
		annotations["assurance.ckodex.io/capture-error"] = cause
		return denied("admission capture persistence failed; admission denied", annotations)
	}
	annotations["assurance.ckodex.io/capture-status"] = "RECORDED"
	annotations["assurance.ckodex.io/admission-envelope-id"] = envelope.ID
	annotations["assurance.ckodex.io/capture-digest"] = digest
	annotations["assurance.ckodex.io/capture-uri"] = envelope.Artifact.URI
	return response
}

func deliverCapture(ctx context.Context, sink EvidenceSink, envelope assurance.EvidenceEnvelope, payload []byte) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("admission capture sink panicked")
		}
	}()
	return sink(ctx, envelope, payload)
}

func podFieldBounds(req *admissionv1.AdmissionRequest, pod *corev1.Pod) error {
	for _, value := range []string{req.Name, req.Namespace, pod.Name, pod.Namespace, pod.GenerateName, string(pod.UID)} {
		if len(value) > 256 {
			return fmt.Errorf("declared Pod identity exceeds bounded validation capacity")
		}
	}
	for _, container := range allContainers(pod) {
		if len(container.Name) > 256 {
			return fmt.Errorf("container name exceeds bounded validation capacity")
		}
		if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
			for _, capability := range container.SecurityContext.Capabilities.Add {
				if len(capability) > 128 {
					return fmt.Errorf("capability name exceeds bounded validation capacity")
				}
			}
		}
	}
	return nil
}
