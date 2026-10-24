package scaffold

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
)

func TestGenerateScaffoldProfiles(t *testing.T) {
	profiles := []string{"nist-sp-800-53", "pci-dss", "soc-2", "iso-27001"}

	for _, p := range profiles {
		plan, err := GenerateScaffold(p, "finance", "billing-service")
		if err != nil {
			t.Fatalf("GenerateScaffold(%s) failed: %v", p, err)
		}
		if plan == nil {
			t.Fatalf("GenerateScaffold(%s) returned nil plan", p)
		}
		if len(plan.ControlBindings) == 0 {
			t.Fatalf("GenerateScaffold(%s) expected at least 1 ControlBinding", p)
		}
		if len(plan.EvidenceContracts) == 0 {
			t.Fatalf("GenerateScaffold(%s) expected at least 1 EvidenceContract", p)
		}
		if plan.ComponentDefinition == nil {
			t.Fatalf("GenerateScaffold(%s) expected ComponentDefinition", p)
		}
	}
}

func TestScaffoldComponentDefinitionValidatesStrictNIST(t *testing.T) {
	v, err := oscal.DefaultValidator()
	if err != nil {
		t.Fatalf("failed to initialize validator: %v", err)
	}

	plan, err := GenerateScaffold("nist-sp-800-53", "prod", "payments-api")
	if err != nil {
		t.Fatalf("GenerateScaffold failed: %v", err)
	}

	cdJSON, err := plan.RenderComponentDefinitionJSON()
	if err != nil {
		t.Fatalf("RenderComponentDefinitionJSON failed: %v", err)
	}

	report, err := v.Validate(cdJSON, "component-definition")
	if err != nil {
		t.Fatalf("validation execution failed: %v", err)
	}
	if !report.Valid {
		t.Fatalf("scaffolded ComponentDefinition failed NIST v1.2.3 schema validation: %+v", report.Errors)
	}
}

func TestScaffoldWriteToDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "scaffold-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	plan, err := GenerateScaffold("nist-sp-800-53", "prod", "auth-service")
	if err != nil {
		t.Fatalf("GenerateScaffold failed: %v", err)
	}

	if err := plan.WriteToDirectory(tmpDir); err != nil {
		t.Fatalf("WriteToDirectory failed: %v", err)
	}

	crdsFile := filepath.Join(tmpDir, "auth-service-crds.yaml")
	cdFile := filepath.Join(tmpDir, "auth-service-oscal-cd.json")
	celFile := filepath.Join(tmpDir, "auth-service-cel-rules.yaml")

	if _, err := os.Stat(crdsFile); err != nil {
		t.Fatalf("expected CRDs file %s to exist", crdsFile)
	}
	if _, err := os.Stat(cdFile); err != nil {
		t.Fatalf("expected CD file %s to exist", cdFile)
	}
	if _, err := os.Stat(celFile); err != nil {
		t.Fatalf("expected CEL file %s to exist", celFile)
	}

	crdContent, err := os.ReadFile(crdsFile)
	if err != nil {
		t.Fatalf("failed to read CRD file: %v", err)
	}
	if !strings.Contains(string(crdContent), "kind: ControlBinding") || !strings.Contains(string(crdContent), "kind: EvidenceContract") {
		t.Fatalf("CRD file missing expected kinds:\n%s", string(crdContent))
	}
}
