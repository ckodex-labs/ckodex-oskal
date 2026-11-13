package binding

import (
	"context"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

const MaxObjects = 256
const ResolutionTimeout = 10 * time.Second

// Context is one coherently read configuration for a real binding and workload.
// Epoch digests bind observed configuration; they do not attest enforcement or
// establish producer authority. AuthorityDigest stays empty without such a source.
type Context struct {
	Namespace   string
	BindingName string
	BindingUID  types.UID
	Subject     assurance.SubjectRef
	Controls    []assurance.ControlRef
	Contract    assurance.EvidenceContract
	Policies    []assurance.AssurancePolicy
	Epoch       assurance.AssuranceEpoch
}

// Resolver must receive an uncached API reader (manager.GetAPIReader or a direct
// client.New client). Controller caches are not authority for captured identity.
type Resolver struct {
	reader          client.Reader
	authorityDigest string
}

func NewResolver(reader client.Reader) *Resolver { return &Resolver{reader: reader} }

// WithAuthorityDigest returns an immutable resolver configuration bound to the
// caller's actual pinned authority/policy snapshot. The caller owns that proof.
func (r *Resolver) WithAuthorityDigest(value string) (*Resolver, error) {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return nil, fmt.Errorf("authority digest must be a canonical sha256 digest of the actual trusted authority snapshot")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:")); err != nil {
		return nil, fmt.Errorf("invalid authority digest: %w", err)
	}
	return &Resolver{reader: r.reader, authorityDigest: value}, nil
}

func (r *Resolver) namespace(ctx context.Context, name string) (*corev1.Namespace, error) {
	if r.reader == nil {
		return nil, fmt.Errorf("authoritative Kubernetes reader is required")
	}
	ns := &corev1.Namespace{}
	if err := r.reader.Get(ctx, client.ObjectKey{Name: name}, ns); err != nil {
		return nil, fmt.Errorf("read namespace %s: %w", name, err)
	}
	if ns.UID == "" || !ns.DeletionTimestamp.IsZero() {
		return nil, fmt.Errorf("namespace %s has no live UID or is terminating", name)
	}
	return ns, nil
}

func (r *Resolver) bindings(ctx context.Context, namespace string) ([]assurancev1alpha1.ControlBinding, error) {
	var list assurancev1alpha1.ControlBindingList
	if err := r.reader.List(ctx, &list, client.InNamespace(namespace), client.Limit(MaxObjects+1)); err != nil {
		return nil, fmt.Errorf("list namespace ControlBindings: %w", err)
	}
	if len(list.Items) > MaxObjects || list.Continue != "" {
		return nil, fmt.Errorf("binding resolution exceeds %d objects; narrow the namespace", MaxObjects)
	}
	sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Name < list.Items[j].Name })
	return list.Items, nil
}

func (r *Resolver) matching(ctx context.Context, w Workload, ns *corev1.Namespace) ([]assurancev1alpha1.ControlBinding, error) {
	list, err := r.bindings(ctx, ns.Name)
	if err != nil {
		return nil, err
	}
	var matches []assurancev1alpha1.ControlBinding
	for _, b := range list {
		match, err := bindingMatches(&b, w, ns)
		if err != nil {
			return nil, err
		}
		if match {
			if !b.DeletionTimestamp.IsZero() {
				return nil, fmt.Errorf("matching binding %s is terminating", b.Name)
			}
			matches = append(matches, b)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w: subject %s has no matching ControlBinding", ports.ErrNotApplicable, w.Subject.URI())
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("subject %s has %d matching ControlBindings; exactly one is required", w.Subject.URI(), len(matches))
	}
	return matches, nil
}

// ContextForSubject selects exactly one applicable binding for a live subject.
func (r *Resolver) ContextForSubject(ctx context.Context, subject assurance.SubjectRef) (Context, error) {
	ctx, cancel := context.WithTimeout(ctx, ResolutionTimeout)
	defer cancel()
	w, err := ResolveWorkload(ctx, r.reader, subject)
	if err != nil {
		return Context{}, err
	}
	ns, err := r.namespace(ctx, w.Object.GetNamespace())
	if err != nil {
		return Context{}, err
	}
	matches, err := r.matching(ctx, w, ns)
	if err != nil {
		return Context{}, err
	}
	selected, err := r.selectWorkload(ctx, &matches[0], ns)
	if err != nil {
		return Context{}, err
	}
	if selected.Object.GetUID() != w.Object.GetUID() {
		return Context{}, fmt.Errorf("binding selects a different workload than the requested subject")
	}
	return r.resolve(ctx, &matches[0], w, ns)
}

// ContextForBinding resolves selectors against actual objects. A selector-free
// binding uses the established <workload>-binding convention, never a generic URI.
func (r *Resolver) ContextForBinding(ctx context.Context, namespace, bindingName string) (Context, error) {
	ctx, cancel := context.WithTimeout(ctx, ResolutionTimeout)
	defer cancel()
	ns, err := r.namespace(ctx, namespace)
	if err != nil {
		return Context{}, err
	}
	var b assurancev1alpha1.ControlBinding
	if err := r.reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: bindingName}, &b); err != nil {
		return Context{}, fmt.Errorf("read binding %s/%s: %w", namespace, bindingName, err)
	}
	if b.UID == "" || !b.DeletionTimestamp.IsZero() {
		return Context{}, fmt.Errorf("binding has no live UID or is terminating")
	}
	selected, err := r.selectWorkload(ctx, &b, ns)
	if err != nil {
		return Context{}, err
	}
	matches, err := r.matching(ctx, selected, ns)
	if err != nil {
		return Context{}, err
	}
	if matches[0].UID != b.UID || !reflect.DeepEqual(matches[0].Spec, b.Spec) {
		return Context{}, fmt.Errorf("binding changed during resolution")
	}
	return r.resolve(ctx, &b, selected, ns)
}

func (r *Resolver) selectWorkload(ctx context.Context, b *assurancev1alpha1.ControlBinding, ns *corev1.Namespace) (Workload, error) {
	if len(b.Spec.Subjects.Kinds) == 0 {
		return Workload{}, fmt.Errorf("binding %s has no subject kinds", b.Name)
	}
	kinds := map[string]bool{}
	for _, kind := range b.Spec.Subjects.Kinds {
		switch kind {
		case "Pod", "Deployment":
			kinds[kind] = true
		case "*":
			return Workload{}, fmt.Errorf("wildcard subject kinds are unsupported; explicitly select Pod or Deployment")
		default:
			return Workload{}, fmt.Errorf("unsupported binding subject kind %q", kind)
		}
	}
	var candidates []Workload
	if !hasLabelSelection(b.Spec.Subjects.LabelSelector) {
		name := strings.TrimSuffix(b.Name, "-binding")
		if name == b.Name || name == "" {
			return Workload{}, fmt.Errorf("binding without an object label selector must be named <workload>-binding")
		}
		for _, kind := range []string{"Deployment", "Pod"} {
			if !kinds[kind] {
				continue
			}
			ref := assurance.SubjectRef{Scheme: "k8s", ID: fmt.Sprintf("%s/%s/%s", ns.Name, kind, name)}
			w, err := ResolveWorkload(ctx, r.reader, ref)
			if apierrors.IsNotFound(err) {
				continue
			}
			if err != nil {
				return Workload{}, err
			}
			match, err := bindingMatches(b, w, ns)
			if err != nil {
				return Workload{}, err
			}
			if match {
				candidates = append(candidates, w)
			}
		}
	} else {
		selector, err := metav1.LabelSelectorAsSelector(b.Spec.Subjects.LabelSelector)
		if err != nil {
			return Workload{}, fmt.Errorf("invalid subject label selector: %w", err)
		}
		opts := []client.ListOption{client.InNamespace(ns.Name), client.MatchingLabelsSelector{Selector: selector}, client.Limit(MaxObjects + 1)}
		if kinds["Deployment"] {
			var list appsv1.DeploymentList
			if err := r.reader.List(ctx, &list, opts...); err != nil {
				return Workload{}, err
			}
			if len(list.Items) > MaxObjects || list.Continue != "" {
				return Workload{}, fmt.Errorf("subject selection exceeds %d objects", MaxObjects)
			}
			for i := range list.Items {
				candidates = append(candidates, workload(&list.Items[i]))
			}
		}
		if kinds["Pod"] {
			var list corev1.PodList
			if err := r.reader.List(ctx, &list, opts...); err != nil {
				return Workload{}, err
			}
			if len(list.Items) > MaxObjects || list.Continue != "" {
				return Workload{}, fmt.Errorf("subject selection exceeds %d objects", MaxObjects)
			}
			for i := range list.Items {
				candidates = append(candidates, workload(&list.Items[i]))
			}
		}
	}
	var applicable []Workload
	for _, w := range candidates {
		match, err := bindingMatches(b, w, ns)
		if err != nil {
			return Workload{}, err
		}
		if match && w.Object.GetUID() != "" && w.Object.GetDeletionTimestamp().IsZero() {
			applicable = append(applicable, w)
		}
	}
	if len(applicable) != 1 {
		return Workload{}, fmt.Errorf("binding %s selects %d live subjects; exactly one is required", b.Name, len(applicable))
	}
	return applicable[0], nil
}

func (r *Resolver) policies(ctx context.Context, namespace string) ([]assurancev1alpha1.AssurancePolicy, error) {
	var list assurancev1alpha1.AssurancePolicyList
	if err := r.reader.List(ctx, &list, client.InNamespace(namespace), client.Limit(MaxObjects+1)); err != nil {
		return nil, fmt.Errorf("list AssurancePolicies: %w", err)
	}
	if len(list.Items) > MaxObjects || list.Continue != "" {
		return nil, fmt.Errorf("policy resolution exceeds %d objects", MaxObjects)
	}
	sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Name < list.Items[j].Name })
	return list.Items, nil
}

func (r *Resolver) resolve(ctx context.Context, b *assurancev1alpha1.ControlBinding, w Workload, ns *corev1.Namespace) (Context, error) {
	if len(b.Spec.Controls) == 0 || len(b.Spec.Controls) > MaxObjects || len(b.Spec.Requirements) == 0 || len(b.Spec.Requirements) > MaxObjects {
		return Context{}, fmt.Errorf("binding controls and contract references must each contain 1 to %d entries", MaxObjects)
	}
	out := Context{Namespace: b.Namespace, BindingName: b.Name, BindingUID: b.UID, Subject: w.Subject, Contract: assurance.EvidenceContract{ID: b.Namespace + "/" + b.Name, OnMissingRequiredState: assurance.AssuranceStateUnknown}}
	controls := map[string]assurance.ControlRef{}
	for _, entry := range b.Spec.Controls {
		c := assurance.ControlRef{Namespace: entry.Canonical.Namespace, ID: entry.Canonical.ID, Version: entry.Canonical.Version}
		if err := c.Validate(); err != nil {
			return Context{}, err
		}
		controls[c.Canonical()] = c
	}
	for _, c := range controls {
		out.Controls = append(out.Controls, c)
	}
	sort.Slice(out.Controls, func(i, j int) bool { return out.Controls[i].Canonical() < out.Controls[j].Canonical() })
	contractNames := map[string]bool{}
	for _, req := range b.Spec.Requirements {
		if req.ID == "" || req.EvidenceContract == "" {
			return Context{}, fmt.Errorf("binding requirement needs an ID and actual EvidenceContract reference; inline evidence defaults are unsupported")
		}
		contractNames[req.EvidenceContract] = true
	}
	names := make([]string, 0, len(contractNames))
	for name := range contractNames {
		names = append(names, name)
	}
	sort.Strings(names)
	var snapshots []objectSnapshot
	requirements := map[string]assurance.EvidenceRequirement{}
	for _, name := range names {
		var ec assurancev1alpha1.EvidenceContract
		if err := r.reader.Get(ctx, client.ObjectKey{Namespace: b.Namespace, Name: name}, &ec); err != nil {
			return Context{}, fmt.Errorf("read required EvidenceContract %s/%s: %w", b.Namespace, name, err)
		}
		if ec.UID == "" || !ec.DeletionTimestamp.IsZero() || len(ec.Spec.Requirements) == 0 || len(ec.Spec.Requirements) > MaxObjects {
			return Context{}, fmt.Errorf("contract %s must be live and contain 1 to %d actual requirements", name, MaxObjects)
		}
		switch ec.Spec.OnMissingRequiredEvidence.State {
		case "", "Unknown":
		case "Failed":
			out.Contract.OnMissingRequiredState = assurance.AssuranceStateFailed
		default:
			return Context{}, fmt.Errorf("contract %s has unsupported missing-evidence state %q", name, ec.Spec.OnMissingRequiredEvidence.State)
		}
		snapshots = append(snapshots, snapshot(&ec, ec.Spec))
		for _, req := range ec.Spec.Requirements {
			if req.ID == "" || req.Type == "" || req.Freshness.Duration < 0 {
				return Context{}, fmt.Errorf("contract %s has a missing requirement identity/type or negative freshness", name)
			}
			candidate := assurance.EvidenceRequirement{ID: req.ID, EvidenceType: req.Type, Required: req.Required, MaxAge: req.Freshness.Duration, AcceptedProducers: append([]string(nil), req.AcceptedProducers...)}
			if prev, ok := requirements[req.ID]; ok && !reflect.DeepEqual(prev, candidate) {
				return Context{}, fmt.Errorf("conflicting requirement ID %q across referenced contracts", req.ID)
			}
			requirements[req.ID] = candidate
			if len(requirements) > MaxObjects {
				return Context{}, fmt.Errorf("effective contract exceeds %d requirements", MaxObjects)
			}
		}
	}
	ids := make([]string, 0, len(requirements))
	for id := range requirements {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		out.Contract.Requirements = append(out.Contract.Requirements, requirements[id])
	}
	policies, err := r.policies(ctx, b.Namespace)
	if err != nil {
		return Context{}, err
	}
	for _, policy := range policies {
		if policy.UID == "" || !policy.DeletionTimestamp.IsZero() || policy.Spec.Freshness.MaxEvaluationAge.Duration < 0 {
			return Context{}, fmt.Errorf("policy %s is not live or has negative freshness", policy.Name)
		}
		state, err := assurance.ParseAssuranceState(strings.ToUpper(policy.Spec.RequiredState))
		if err != nil {
			return Context{}, fmt.Errorf("policy %s required state: %w", policy.Name, err)
		}
		out.Policies = append(out.Policies, assurance.AssurancePolicy{Name: policy.Namespace + "/" + policy.Name, RequiredState: state, RequireFresh: policy.Spec.Evidence.RequireFresh, FailOnConfirmedViolation: policy.Spec.Behavior.FailOnConfirmedViolation, UnknownIsViolation: policy.Spec.Behavior.UnknownIsViolation, MaxEvaluationAge: policy.Spec.Freshness.MaxEvaluationAge.Duration})
		snapshots = append(snapshots, snapshot(&policy, policy.Spec))
		if policy.Spec.Behavior.UnknownIsViolation {
			out.Contract.OnMissingRequiredState = assurance.AssuranceStateFailed
		}
		for i := range out.Contract.Requirements {
			req := &out.Contract.Requirements[i]
			if age := policy.Spec.Freshness.MaxEvaluationAge.Duration; age > 0 && (req.MaxAge == 0 || age < req.MaxAge) {
				req.MaxAge = age
			}
			if policy.Spec.Evidence.RequireFresh && req.Required && req.MaxAge == 0 {
				return Context{}, fmt.Errorf("policy %s requires fresh evidence but requirement %s has no freshness bound", policy.Name, req.ID)
			}
		}
	}
	out.Epoch = assurance.AssuranceEpoch{SubjectDigest: w.Digest, AuthorityDigest: r.authorityDigest, ImplementationDigest: digest(snapshot(b, b.Spec)), PolicyDigest: digest(snapshots), EnvironmentDigest: digest(namespaceSnapshot(ns))}
	// Read the governing objects again before publishing a context. Any detected
	// change fails this bounded attempt; the caller may reconcile from a new query.
	freshW, err := ResolveWorkload(ctx, r.reader, w.Subject)
	if err != nil {
		return Context{}, err
	}
	freshNS, err := r.namespace(ctx, ns.Name)
	if err != nil {
		return Context{}, err
	}
	if freshW.Digest != w.Digest || digest(namespaceSnapshot(freshNS)) != out.Epoch.EnvironmentDigest {
		return Context{}, fmt.Errorf("subject or namespace changed during context resolution")
	}
	matching, err := r.matching(ctx, freshW, freshNS)
	if err != nil {
		return Context{}, err
	}
	if matching[0].UID != b.UID || !reflect.DeepEqual(matching[0].Spec, b.Spec) {
		return Context{}, fmt.Errorf("binding changed during context resolution")
	}
	for _, s := range snapshots {
		fresh := s.Object.DeepCopyObject().(client.Object)
		if err := r.reader.Get(ctx, client.ObjectKeyFromObject(s.Object), fresh); err != nil {
			return Context{}, err
		}
		if fresh.GetUID() != s.UID || !fresh.GetDeletionTimestamp().IsZero() || objectSpecDigest(fresh) != s.SpecDigest {
			return Context{}, fmt.Errorf("governing object %s changed during resolution", s.Name)
		}
	}
	freshPolicies, err := r.policies(ctx, b.Namespace)
	if err != nil {
		return Context{}, err
	}
	if policyDigest(policies) != policyDigest(freshPolicies) {
		return Context{}, fmt.Errorf("policy membership changed during context resolution")
	}
	return out, nil
}

type objectSnapshot struct {
	Namespace  string
	Name       string
	UID        types.UID
	SpecDigest string
	Object     client.Object `json:"-"`
}

func snapshot(object client.Object, spec any) objectSnapshot {
	return objectSnapshot{Namespace: object.GetNamespace(), Name: object.GetName(), UID: object.GetUID(), SpecDigest: digest(spec), Object: object}
}
func namespaceSnapshot(ns *corev1.Namespace) any {
	return struct {
		UID    types.UID
		Labels map[string]string
	}{ns.UID, ns.Labels}
}
func objectSpecDigest(object client.Object) string {
	switch o := object.(type) {
	case *assurancev1alpha1.EvidenceContract:
		return digest(o.Spec)
	case *assurancev1alpha1.AssurancePolicy:
		return digest(o.Spec)
	}
	return ""
}
func policyDigest(policies []assurancev1alpha1.AssurancePolicy) string {
	var snapshots []objectSnapshot
	for i := range policies {
		snapshots = append(snapshots, snapshot(&policies[i], policies[i].Spec))
	}
	return digest(snapshots)
}
