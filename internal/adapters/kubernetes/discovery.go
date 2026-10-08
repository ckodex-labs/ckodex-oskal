package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

var _ ports.SubjectResolver = (*SubjectResolver)(nil)

// SubjectResolver discovers and computes cryptographic digests for Kubernetes subjects.
type SubjectResolver struct {
	client client.Reader
}

// NewSubjectResolver creates a new Kubernetes subject resolver.
func NewSubjectResolver(client client.Reader) *SubjectResolver {
	return &SubjectResolver{client: client}
}

func parseK8sURI(uri string) (cluster, ns, kind, name string) {
	trimmed := strings.TrimPrefix(uri, "k8s://")
	parts := strings.Split(trimmed, "/")
	switch len(parts) {
	case 1:
		return "local", "default", "Deployment", parts[0]
	case 2:
		return "local", parts[0], "Deployment", parts[1]
	case 3:
		return "local", parts[0], parts[1], parts[2]
	default:
		return parts[0], parts[1], parts[2], parts[3]
	}
}

// ResolveSubject resolves a Kubernetes workload subject from a URI (implements ports.SubjectResolver).
func (r *SubjectResolver) ResolveSubject(ctx context.Context, uri string) (assurance.SubjectRef, error) {
	cluster, ns, kind, name := parseK8sURI(uri)
	if r.client != nil {
		switch kind {
		case "Deployment", "deploy":
			var deploy appsv1.Deployment
			if err := r.client.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &deploy); err == nil {
				return BuildDeploymentSubjectRef(&deploy), nil
			}
		case "Pod", "pod":
			var pod corev1.Pod
			if err := r.client.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &pod); err == nil {
				return BuildPodSubjectRef(&pod), nil
			}
		}
	}

	return assurance.SubjectRef{
		Scheme: "k8s",
		ID:     fmt.Sprintf("%s/%s/%s/%s", cluster, ns, kind, name),
		Attributes: map[string]string{
			"cluster":   cluster,
			"namespace": ns,
			"kind":      kind,
			"name":      name,
		},
	}, nil
}

// ComputeSubjectDigest computes a deterministic cryptographic digest for a subject (implements ports.SubjectResolver).
func (r *SubjectResolver) ComputeSubjectDigest(ctx context.Context, subject assurance.SubjectRef) (string, error) {
	ns := subject.Attributes["namespace"]
	kind := subject.Attributes["kind"]
	name := subject.Attributes["name"]

	if ns == "" || name == "" {
		_, parsedNs, parsedKind, parsedName := parseK8sURI(subject.URI())
		if ns == "" {
			ns = parsedNs
		}
		if kind == "" {
			kind = parsedKind
		}
		if name == "" {
			name = parsedName
		}
	}

	if r.client != nil && ns != "" && name != "" {
		switch kind {
		case "Deployment", "deploy":
			var deploy appsv1.Deployment
			if err := r.client.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &deploy); err == nil {
				return ComputeDeploymentDigest(&deploy), nil
			}
		case "Pod", "pod":
			var pod corev1.Pod
			if err := r.client.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &pod); err == nil {
				return ComputePodDigest(&pod), nil
			}
		}
	}

	keys := make([]string, 0, len(subject.Attributes))
	for k := range subject.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString(subject.Scheme)
	sb.WriteString(":")
	sb.WriteString(subject.ID)
	for _, k := range keys {
		sb.WriteString("|")
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(subject.Attributes[k])
	}
	h := sha256.Sum256([]byte(sb.String()))
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// BuildPodSubjectRef creates a canonical SubjectRef for a Kubernetes Pod.
func BuildPodSubjectRef(pod *corev1.Pod) assurance.SubjectRef {
	images := make([]string, 0, len(pod.Spec.Containers))
	for _, c := range pod.Spec.Containers {
		images = append(images, c.Image)
	}
	sort.Strings(images)

	return assurance.SubjectRef{
		Scheme: "k8s",
		ID:     fmt.Sprintf("%s/%s/Pod/%s", pod.Namespace, pod.Name, pod.Name),
		Attributes: map[string]string{
			"cluster":         "local",
			"namespace":       pod.Namespace,
			"kind":            "Pod",
			"name":            pod.Name,
			"uid":             string(pod.UID),
			"resourceVersion": pod.ResourceVersion,
			"images":          strings.Join(images, ","),
			"serviceAccount":  pod.Spec.ServiceAccountName,
		},
	}
}

// ComputePodDigest computes the cryptographic digest for a Pod across namespace, name, UID, and container images.
func ComputePodDigest(pod *corev1.Pod) string {
	images := make([]string, 0, len(pod.Spec.Containers))
	for _, c := range pod.Spec.Containers {
		images = append(images, c.Image)
	}
	sort.Strings(images)

	raw := fmt.Sprintf("pod|%s|%s|%s|%s",
		pod.Namespace,
		pod.Name,
		pod.UID,
		strings.Join(images, ";"),
	)
	h := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(h[:])
}

// BuildSubjectRef creates a canonical SubjectRef for a Kubernetes Deployment.
func BuildDeploymentSubjectRef(deploy *appsv1.Deployment) assurance.SubjectRef {
	images := make([]string, 0, len(deploy.Spec.Template.Spec.Containers))
	for _, c := range deploy.Spec.Template.Spec.Containers {
		images = append(images, c.Image)
	}
	sort.Strings(images)

	return assurance.SubjectRef{
		Scheme: "k8s",
		ID:     fmt.Sprintf("%s/%s/Deployment/%s", deploy.Namespace, deploy.Name, deploy.Name),
		Attributes: map[string]string{
			"cluster":         "local",
			"namespace":       deploy.Namespace,
			"kind":            "Deployment",
			"name":            deploy.Name,
			"uid":             string(deploy.UID),
			"generation":      fmt.Sprintf("%d", deploy.Generation),
			"resourceVersion": deploy.ResourceVersion,
			"images":          strings.Join(images, ","),
		},
	}
}

// ComputeSubjectDigest computes the cryptographic digest across spec, generation, UID, and container images.
func ComputeDeploymentDigest(deploy *appsv1.Deployment) string {
	images := make([]string, 0, len(deploy.Spec.Template.Spec.Containers))
	for _, c := range deploy.Spec.Template.Spec.Containers {
		images = append(images, c.Image)
	}
	sort.Strings(images)

	raw := fmt.Sprintf("deploy|%s|%s|%s|%d|%s",
		deploy.Namespace,
		deploy.Name,
		deploy.UID,
		deploy.Generation,
		strings.Join(images, ";"),
	)
	h := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(h[:])
}

// MatchesSelector checks if a deployment matches the SubjectSelector.
func MatchesSelector(deploy *appsv1.Deployment, sel assurancev1alpha1.SubjectSelector) bool {
	matchedKind := false
	for _, k := range sel.Kinds {
		if k == "Deployment" || k == "*" {
			matchedKind = true
			break
		}
	}
	if !matchedKind {
		return false
	}

	if sel.LabelSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(sel.LabelSelector)
		if err != nil || !selector.Matches(labels.Set(deploy.Labels)) {
			return false
		}
	}

	return true
}

// CalculateEpoch computes the composite AssuranceEpoch for a subject and its effective rules.
func CalculateEpoch(
	subjectDigest string,
	implementationDigest string,
	policyDigest string,
	authorityDigest string,
	environmentDigest string,
) assurance.AssuranceEpoch {
	if implementationDigest == "" {
		implementationDigest = assurance.ComputeStringDigest("provider:cel:v1")
	}
	if policyDigest == "" {
		policyDigest = assurance.ComputeStringDigest("policy:default:v1")
	}
	if authorityDigest == "" {
		authorityDigest = assurance.ComputeStringDigest("spiffe://local/ns/ckodex-assurance")
	}
	if environmentDigest == "" {
		environmentDigest = assurance.ComputeStringDigest("k8s:v1.31:oskal:v0.1.0")
	}

	return assurance.AssuranceEpoch{
		SubjectDigest:        subjectDigest,
		ImplementationDigest: implementationDigest,
		PolicyDigest:         policyDigest,
		AuthorityDigest:      authorityDigest,
		EnvironmentDigest:    environmentDigest,
	}
}

// EvaluateDrift compares an existing state against the newly computed epoch.
// If the subject digest changed, the state transitions from ASSURED to STALE.
func EvaluateDrift(currentState assurance.AssuranceState, recordedEpoch, currentEpoch assurance.AssuranceEpoch) (assurance.AssuranceState, []assurance.EpochDriftReason) {
	if recordedEpoch.Matches(currentEpoch) {
		return currentState, nil
	}

	diffs := recordedEpoch.Diff(currentEpoch)
	if currentState == assurance.AssuranceStateAssured {
		nextState, _ := assurance.Transition(currentState, assurance.EventEpochChanged)
		return nextState, diffs
	}

	return currentState, diffs
}
