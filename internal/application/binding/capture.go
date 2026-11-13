package binding

import (
	"context"
	"errors"
	"fmt"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"reflect"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

var _ ports.CaptureResolver = (*Resolver)(nil)

// ResolveCapture binds a live Pod fact to the same context used for evaluation.
// Its epoch describes configuration observed at ingestion, not a retrospective
// attestation that the captured event executed under that configuration.
func (r *Resolver) ResolveCapture(ctx context.Context, event ports.CapturedEvent) (assurance.SubjectRef, assurance.AssuranceEpoch, error) {
	ctx, cancel := context.WithTimeout(ctx, ResolutionTimeout)
	defer cancel()
	podWorkload, err := ResolveWorkload(ctx, r.reader, event.Subject)
	if err != nil {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, err
	}
	pod, ok := podWorkload.Object.(*corev1.Pod)
	if !ok {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("runtime capture must identify an actual Pod; generic resources require separate report resolution")
	}
	if event.Subject.Attributes["uid"] == "" && event.MediaType != "application/vnd.cilium.flow+json" {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("capture lacks Pod UID; only Hubble flows may use creation-time guarded name resolution")
	}
	if pod.CreationTimestamp.IsZero() || event.CapturedAt.IsZero() || event.CapturedAt.Before(pod.CreationTimestamp.Time) || event.CapturedAt.After(time.Now().UTC()) {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("capture timestamp must be at or after live Pod creation and no later than the resolver clock")
	}
	// metav1.Time JSON preserves only seconds. Without a UID, captures in the
	// first timestamp bucket cannot distinguish same-name Pods recreated within
	// that second. Reject that uncertainty instead of attaching historical facts.
	if event.Subject.Attributes["uid"] == "" && event.CapturedAt.Before(pod.CreationTimestamp.Add(time.Second)) {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("UID-less capture falls inside the Pod creation timestamp precision window")
	}

	// A direct Pod binding is authoritative even when its owner is a kind
	// whose rollout attribution is unsupported.
	direct, directErr := r.ContextForSubject(ctx, podWorkload.Subject)
	if directErr == nil {
		if direct.Epoch.SubjectDigest != podWorkload.Digest {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("directly bound Pod changed during capture resolution")
		}
		return direct.Subject, direct.Epoch, nil
	}
	if !errors.Is(directErr, ports.ErrNotApplicable) {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, directErr
	}
	target := podWorkload
	lineage := []client.Object{pod}
	owner, err := controllerOwner(pod)
	if err != nil {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, err
	}
	if owner != nil {
		if owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, r.unsupportedOwner(ctx, pod.Namespace, owner)
		}
		var rs appsv1.ReplicaSet
		if err := r.reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: owner.Name}, &rs); err != nil {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("read Pod owner ReplicaSet: %w", err)
		}
		if rs.UID != owner.UID || !rs.DeletionTimestamp.IsZero() {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("pod owner ReplicaSet UID mismatch or terminating")
		}
		deploymentOwner, err := controllerOwner(&rs)
		if err != nil {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, err
		}
		if deploymentOwner == nil {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, r.unsupportedOwner(ctx, pod.Namespace, owner)
		}
		if deploymentOwner.Kind != "Deployment" || deploymentOwner.APIVersion != "apps/v1" {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, r.unsupportedOwner(ctx, pod.Namespace, deploymentOwner)
		}
		ref := assurance.SubjectRef{Scheme: "k8s", ID: fmt.Sprintf("%s/Deployment/%s", pod.Namespace, deploymentOwner.Name), Attributes: map[string]string{"uid": string(deploymentOwner.UID)}}
		target, err = ResolveWorkload(ctx, r.reader, ref)
		if err != nil {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, err
		}
		deployment := target.Object.(*appsv1.Deployment)
		if !reflect.DeepEqual(rs.Spec.Template.Spec, deployment.Spec.Template.Spec) {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("captured Pod belongs to a previous ReplicaSet template, not the current Deployment epoch")
		}
		for _, selector := range []*metav1.LabelSelector{rs.Spec.Selector, deployment.Spec.Selector} {
			parsed, err := metav1.LabelSelectorAsSelector(selector)
			if err != nil || !parsed.Matches(labels.Set(pod.Labels)) {
				return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("captured Pod labels do not match its live controller selectors")
			}
		}
		lineage = append(lineage, &rs)
	}
	resolved, err := r.ContextForSubject(ctx, target.Subject)
	if err != nil {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, err
	}
	// Repeat ownership reads after context resolution; deletion/recreation or owner
	// changes during the query invalidate this attempt instead of moving the fact.
	for _, object := range lineage {
		fresh := object.DeepCopyObject().(client.Object)
		if err := r.reader.Get(ctx, client.ObjectKeyFromObject(object), fresh); err != nil {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, err
		}
		if fresh.GetUID() != object.GetUID() || !fresh.GetDeletionTimestamp().IsZero() || captureIdentityDigest(fresh) != captureIdentityDigest(object) {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("capture workload ownership changed during resolution")
		}
	}
	return resolved.Subject, resolved.Epoch, nil
}

func controllerOwner(object client.Object) (*metav1.OwnerReference, error) {
	var selected *metav1.OwnerReference
	for _, owner := range object.GetOwnerReferences() {
		if owner.Controller == nil || !*owner.Controller {
			continue
		}
		if selected != nil || owner.UID == "" || owner.Name == "" {
			return nil, fmt.Errorf("workload has ambiguous or incomplete controller ownership")
		}
		copy := owner
		selected = &copy
	}
	return selected, nil
}

func captureIdentityDigest(object client.Object) string {
	switch o := object.(type) {
	case *corev1.Pod:
		return PodDigest(o)
	case *appsv1.ReplicaSet:
		return digest(struct {
			UID    string
			Owners []metav1.OwnerReference
			Spec   appsv1.ReplicaSetSpec
		}{string(o.UID), o.OwnerReferences, o.Spec})
	}
	return ""
}

// unsupportedOwner distinguishes an unbound controller from unsupported configured
// scope using its real metadata. Read/UID/selector errors remain stream failures.
func (r *Resolver) unsupportedOwner(ctx context.Context, namespace string, owner *metav1.OwnerReference) error {
	groupVersion, err := schema.ParseGroupVersion(owner.APIVersion)
	if err != nil {
		return err
	}
	object := &unstructured.Unstructured{}
	object.SetGroupVersionKind(groupVersion.WithKind(owner.Kind))
	if err := r.reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: owner.Name}, object); err != nil {
		return err
	}
	if object.GetUID() != owner.UID || !object.GetDeletionTimestamp().IsZero() {
		return fmt.Errorf("unsupported controller UID mismatch or terminating")
	}
	ns, err := r.namespace(ctx, namespace)
	if err != nil {
		return err
	}
	w := Workload{Object: object, Kind: owner.Kind, Group: groupVersion.Group, Subject: assurance.SubjectRef{Scheme: "k8s", ID: namespace + "/" + owner.Kind + "/" + owner.Name}}
	_, err = r.matching(ctx, w, ns)
	if err != nil {
		return err
	}
	return fmt.Errorf("configured controller %s %s is unsupported for capture attribution", owner.APIVersion, owner.Kind)
}
