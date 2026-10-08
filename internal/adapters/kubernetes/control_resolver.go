package kubernetes

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

var _ ports.ControlResolver = (*ControlResolver)(nil)

// ControlResolver determines which controls apply to a subject by inspecting ControlBindings.
type ControlResolver struct {
	client client.Reader
}

// NewControlResolver creates a new Kubernetes control resolver.
func NewControlResolver(client client.Reader) *ControlResolver {
	return &ControlResolver{client: client}
}

// ResolveControls discovers controls bound to the given subject (implements ports.ControlResolver).
func (r *ControlResolver) ResolveControls(ctx context.Context, subject assurance.SubjectRef) ([]assurance.ControlRef, error) {
	if r.client == nil {
		return []assurance.ControlRef{
			{Namespace: "ckodex", ID: "container.least-privilege"},
		}, nil
	}

	ns := subject.Attributes["namespace"]
	var bindings assurancev1alpha1.ControlBindingList
	var listOpts []client.ListOption
	if ns != "" {
		listOpts = append(listOpts, client.InNamespace(ns))
	}

	if err := r.client.List(ctx, &bindings, listOpts...); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var controls []assurance.ControlRef

	subName := subject.Attributes["name"]
	subKind := subject.Attributes["kind"]

	for _, b := range bindings.Items {
		matched := false
		if len(b.Spec.Subjects.Kinds) > 0 {
			for _, k := range b.Spec.Subjects.Kinds {
				if k == "*" || (subKind != "" && k == subKind) {
					matched = true
					break
				}
			}
		} else {
			matched = true
		}

		if !matched && subName != "" && b.Name == subName {
			matched = true
		}

		if matched {
			for _, c := range b.Spec.Controls {
				key := c.Canonical.Namespace + ":" + c.Canonical.ID
				if !seen[key] {
					seen[key] = true
					controls = append(controls, assurance.ControlRef{
						Namespace: c.Canonical.Namespace,
						ID:        c.Canonical.ID,
						Version:   c.Canonical.Version,
					})
				}
			}
		}
	}

	if len(controls) == 0 {
		controls = append(controls, assurance.ControlRef{
			Namespace: "ckodex",
			ID:        "container.least-privilege",
		})
	}

	return controls, nil
}
