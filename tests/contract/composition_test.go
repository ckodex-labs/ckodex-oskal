package contract

import (
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestCompositeClaimRequiresActualRuntimeAndIsolationEvidence(t *testing.T) {
	contract := assurance.EvidenceContract{
		ID: "workload-runtime-and-isolation",
		Requirements: []assurance.EvidenceRequirement{
			{ID: "runtime", EvidenceType: "workload.runtime.process.euid.nonroot", Required: true},
			{ID: "isolation", EvidenceType: "network.flow.isolation", Required: true},
		},
		OnMissingRequiredState: assurance.AssuranceStateUnknown,
	}
	result := contract.Evaluate(nil, assurance.AssuranceEpoch{}, time.Now())
	if result.State != assurance.AssuranceStateUnknown || len(result.MissingRequirements) != 2 {
		t.Fatalf("missing runtime and isolation sources must remain UNKNOWN: %+v", result)
	}
	if result.Completeness.IsComplete() {
		t.Fatal("missing source evidence was reported complete")
	}
}
