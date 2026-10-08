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
	if err != nil {
		t.Fatalf("ResolveControls failed: %v", err)
	}

	if len(controls) == 0 {
		t.Fatal("expected at least 1 resolved control")
	}

	if controls[0].ID != "container.least-privilege" {
		t.Fatalf("unexpected control ID: %s", controls[0].ID)
	}
}
