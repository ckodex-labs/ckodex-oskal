package kubernetes

import (
	"context"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestControlResolver(t *testing.T) {
	resolver := NewControlResolver(nil)
	ctx := context.Background()

	sub := assurance.SubjectRef{
		Scheme: "k8s",
		ID:     "payments/payments-api",
		Attributes: map[string]string{
			"namespace": "payments",
			"name":      "payments-api",
			"kind":      "Deployment",
		},
	}

	controls, err := resolver.ResolveControls(ctx, sub)
	if err == nil || len(controls) != 0 {
		t.Fatalf("missing authoritative reader fabricated controls: %+v %v", controls, err)
	}
}
