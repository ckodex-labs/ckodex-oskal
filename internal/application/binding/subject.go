// Package binding resolves assurance inputs from an authoritative Kubernetes API.
// It never substitutes URI-derived identities or default evidence requirements.
package binding

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// Workload is a live supported Kubernetes object and its stable semantic identity.
type Workload struct {
	Subject assurance.SubjectRef
	Digest  string
	Object  client.Object
	Group   string
	Kind    string
}

// ParseSubjectURI accepts the canonical namespace/kind/name form only. A caller
// selects the cluster through its authenticated API reader, never through a label.
func ParseSubjectURI(uri string) (namespace, kind, name string, err error) {
	u, e := url.Parse(uri)
	if e != nil || u.Scheme != "k8s" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", "", "", fmt.Errorf("subject must be k8s://namespace/Pod/name or k8s://namespace/Deployment/name")
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 2 || len(validation.IsDNS1123Label(u.Host)) != 0 || len(validation.IsDNS1123Subdomain(parts[1])) != 0 {
		return "", "", "", fmt.Errorf("unsupported or ambiguous Kubernetes subject URI %q; use namespace/kind/name without a guessed cluster prefix", uri)
	}
	if parts[0] != "Pod" && parts[0] != "Deployment" {
		return "", "", "", fmt.Errorf("unsupported Kubernetes subject kind %q; supported: Pod, Deployment", parts[0])
	}
	return u.Host, parts[0], parts[1], nil
}

func checkAttributes(subject assurance.SubjectRef, namespace, kind, name string) error {
	for key, want := range map[string]string{"namespace": namespace, "kind": kind, "name": name} {
		if got := subject.Attributes[key]; got != "" && got != want {
			return fmt.Errorf("subject %s attribute %s=%q conflicts with URI", subject.URI(), key, got)
		}
	}
	return nil
}

// ResolveWorkload reads a real resource. An expected UID prevents name reuse from
// silently rebinding observations or callers to a different Kubernetes object.
func ResolveWorkload(ctx context.Context, reader client.Reader, subject assurance.SubjectRef) (Workload, error) {
	if reader == nil {
		return Workload{}, fmt.Errorf("authoritative Kubernetes reader is required")
	}
	ns, kind, name, err := ParseSubjectURI(subject.URI())
	if err != nil {
		return Workload{}, err
	}
	if err := checkAttributes(subject, ns, kind, name); err != nil {
		return Workload{}, err
	}
	var object client.Object
	switch kind {
	case "Pod":
		object = &corev1.Pod{}
	case "Deployment":
		object = &appsv1.Deployment{}
	}
	if err := reader.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, object); err != nil {
		return Workload{}, fmt.Errorf("read %s: %w", subject.URI(), err)
	}
	if object.GetUID() == "" || !object.GetDeletionTimestamp().IsZero() {
		return Workload{}, fmt.Errorf("subject %s has no live UID or is terminating", subject.URI())
	}
	if expected := subject.Attributes["uid"]; expected != "" && expected != string(object.GetUID()) {
		return Workload{}, fmt.Errorf("subject %s UID mismatch: captured/expected %s, current %s", subject.URI(), expected, object.GetUID())
	}
	return workload(object), nil
}

func workload(object client.Object) Workload {
	switch o := object.(type) {
	case *corev1.Pod:
		return Workload{Subject: PodSubject(o), Digest: PodDigest(o), Object: o, Kind: "Pod"}
	case *appsv1.Deployment:
		return Workload{Subject: DeploymentSubject(o), Digest: DeploymentDigest(o), Object: o, Group: "apps", Kind: "Deployment"}
	}
	panic("unsupported internal workload type")
}

func images(spec corev1.PodSpec) string {
	var all []string
	for _, c := range spec.Containers {
		all = append(all, c.Image)
	}
	for _, c := range spec.InitContainers {
		all = append(all, c.Image)
	}
	for _, c := range spec.EphemeralContainers {
		all = append(all, c.Image)
	}
	sort.Strings(all)
	return strings.Join(all, ",")
}

func subject(object client.Object, kind string, spec corev1.PodSpec) assurance.SubjectRef {
	return assurance.SubjectRef{Scheme: "k8s", ID: fmt.Sprintf("%s/%s/%s", object.GetNamespace(), kind, object.GetName()), Attributes: map[string]string{"namespace": object.GetNamespace(), "kind": kind, "name": object.GetName(), "uid": string(object.GetUID()), "generation": fmt.Sprint(object.GetGeneration()), "images": images(spec), "serviceAccount": spec.ServiceAccountName}}
}

func PodSubject(p *corev1.Pod) assurance.SubjectRef { return subject(p, "Pod", p.Spec) }
func DeploymentSubject(d *appsv1.Deployment) assurance.SubjectRef {
	return subject(d, "Deployment", d.Spec.Template.Spec)
}

// API specs contain JSON-serializable data only. Including full spec, UID, labels,
// and ownership detects meaningful drift without invalidating on status updates.
func digest(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("Kubernetes typed snapshot is not JSON serializable: %v", err))
	}
	return assurance.ComputeDigest(data)
}

func PodDigest(p *corev1.Pod) string {
	return digest(struct {
		Namespace, Name string
		UID             types.UID
		Generation      int64
		Labels          map[string]string
		Owners          []metav1.OwnerReference
		Spec            corev1.PodSpec
	}{p.Namespace, p.Name, p.UID, p.Generation, p.Labels, p.OwnerReferences, p.Spec})
}
func DeploymentDigest(d *appsv1.Deployment) string {
	return digest(struct {
		Namespace, Name string
		UID             types.UID
		Generation      int64
		Labels          map[string]string
		Spec            appsv1.DeploymentSpec
	}{d.Namespace, d.Name, d.UID, d.Generation, d.Labels, d.Spec})
}

func selectorMatches(w Workload, ns *corev1.Namespace, sel assurancev1alpha1.SubjectSelector) (bool, error) {
	kindMatch := false
	for _, kind := range sel.Kinds {
		if kind == w.Kind || kind == "*" {
			kindMatch = true
		}
	}
	if !kindMatch {
		return false, nil
	}
	if len(sel.APIGroups) > 0 {
		groupMatch := false
		for _, group := range sel.APIGroups {
			if group == w.Group || group == "*" {
				groupMatch = true
			}
		}
		if !groupMatch {
			return false, nil
		}
	}
	for _, entry := range []struct {
		selector *metav1.LabelSelector
		values   map[string]string
	}{{sel.LabelSelector, w.Object.GetLabels()}, {sel.NamespaceSelector, ns.Labels}} {
		if entry.selector == nil {
			continue
		}
		parsed, err := metav1.LabelSelectorAsSelector(entry.selector)
		if err != nil {
			return false, fmt.Errorf("invalid binding selector: %w", err)
		}
		if !parsed.Matches(labels.Set(entry.values)) {
			return false, nil
		}
	}
	return true, nil
}

func hasLabelSelection(sel *metav1.LabelSelector) bool {
	return sel != nil && (len(sel.MatchLabels) > 0 || len(sel.MatchExpressions) > 0)
}

func bindingMatches(b *assurancev1alpha1.ControlBinding, w Workload, ns *corev1.Namespace) (bool, error) {
	if b.Namespace != w.Object.GetNamespace() {
		return false, nil
	}
	matches, err := selectorMatches(w, ns, b.Spec.Subjects)
	if err != nil || !matches {
		return matches, err
	}
	if !hasLabelSelection(b.Spec.Subjects.LabelSelector) && b.Name != w.Object.GetName()+"-binding" {
		return false, nil
	}
	return true, nil
}
