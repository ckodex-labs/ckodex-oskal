package kubernetes

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
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

// ResolveControls requires an actual live workload and exactly one coherent binding.
func (r *ControlResolver) ResolveControls(ctx context.Context, subject assurance.SubjectRef) ([]assurance.ControlRef, error) {
	resolved, err := binding.NewResolver(r.client).ContextForSubject(ctx, subject)
	if err != nil {
		return nil, err
	}
	return resolved.Controls, nil
}
