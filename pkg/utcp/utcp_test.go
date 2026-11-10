package utcp_test

import (
	"context"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/pkg/utcp"
)

func TestPublicGoUTCPSDK(t *testing.T) {
	ctx := context.Background()
	client, err := utcp.NewClient("")
	if err != nil {
		t.Fatalf("failed to create utcp client: %v", err)
	}

	tools := client.ListTools()
	if len(tools) == 0 {
		t.Fatal("expected non-empty UTCP tool list")
	}

	found := client.SearchTools("oscal", []string{"validate"}, 5)
	if len(found) == 0 || found[0].Name != "validate_oscal" {
		t.Fatalf("expected validate_oscal as top search result, got: %+v", found)
	}

	res, err := client.CallTool(ctx, "get_assurance_state", map[string]interface{}{
		"subject": "k8s://prod/payments/Deployment/payments-api",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if res.ToolName != "get_assurance_state" {
		t.Fatalf("unexpected tool name: %s", res.ToolName)
	}
}
