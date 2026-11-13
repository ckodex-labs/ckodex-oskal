package ports

import (
	"context"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// PrincipalResolver derives the actor from verified transport credentials or
// the local workload identity. Implementations must never trust request claims.
type PrincipalResolver interface {
	AuthenticatedPrincipal(context.Context) (string, error)
}

// ExecutionBroker owns admission, a single effect invocation, and durable
// completion. An uncertain execution remains reserved for operator inspection.
type ExecutionBroker interface {
	Execute(context.Context, assurance.ExecutionRequest, func(context.Context) ([]byte, error)) (*assurance.ExecutionReceipt, error)
}
