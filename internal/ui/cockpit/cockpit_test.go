package cockpit

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestCockpitRenderSnapshot(t *testing.T) {
	buf := new(bytes.Buffer)
	cockpit := NewCockpit(CockpitConfig{
		Once:   true,
		Writer: buf,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := cockpit.Run(ctx); err != nil {
		t.Fatalf("cockpit.Run failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "OSKAL ASSURANCE COCKPIT") {
		t.Fatalf("expected title in cockpit output:\n%s", out)
	}
	if !strings.Contains(out, "payments-api") {
		t.Fatalf("expected payments-api in workload list:\n%s", out)
	}
	if !strings.Contains(out, "CRYPTOGRAPHIC MERKLE LINEAGE") {
		t.Fatalf("expected Merkle lineage section:\n%s", out)
	}

	// Verify 100% pure ASCII (0x00 - 0x7F)
	for idx, b := range buf.Bytes() {
		if b > 127 {
			t.Fatalf("non-ASCII character detected at offset %d: %d", idx, b)
		}
	}
}
