package oscal_test

import (
	"context"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	proj "github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
	recoscal "github.com/ckodex-labs/ckodex-oskal/internal/reconciler/oscal"
)

func TestIngestComponentDefinition(t *testing.T) {
	sampleCompDef := []byte(`{
		"component-definition": {
			"uuid": "8b9487b3-c11f-4d4e-b552-84b2c1598501",
			"metadata": {
				"title": "Ingress Security Component Definition",
				"published": "2026-09-25T12:00:00Z",
				"last-modified": "2026-09-25T12:00:00Z",
				"version": "1.0.0",
				"oscal-version": "1.2.3"
			},
			"components": [
				{
					"uuid": "comp-envoy-ingress-001",
					"type": "software",
					"title": "Envoy Ingress Gateway",
					"description": "Hardened edge reverse proxy",
					"control-implementations": [
						{
							"uuid": "ci-01",
							"source": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
							"description": "Access Control Implementations",
							"implemented-requirements": [
								{
									"uuid": "ir-01",
									"control-id": "AC-6",
									"description": "Least privilege admission enforcement",
									"props": [
										{"name": "evidence-type", "value": "admission"},
										{"name": "producer", "value": "kubernetes-validating-admission"},
										{"name": "freshness", "value": "12h"}
									]
								},
								{
									"uuid": "ir-02",
									"control-id": "SC-7",
									"description": "Boundary protection",
									"props": [
										{"name": "evidence-type", "value": "network-policy"},
										{"name": "producer", "value": "cilium"}
									]
								}
							]
						}
					]
				}
			]
		}
	}`)

	res, err := recoscal.IngestOSCAL(sampleCompDef, "production")
	if err != nil {
		t.Fatalf("unexpected error during IngestOSCAL: %v", err)
	}

	if res.SourceType != "ComponentDefinition" {
		t.Errorf("expected SourceType ComponentDefinition, got %s", res.SourceType)
	}
	if len(res.ControlBindings) != 1 {
		t.Fatalf("expected 1 ControlBinding, got %d", len(res.ControlBindings))
	}
	if len(res.EvidenceContracts) != 1 {
		t.Fatalf("expected 1 EvidenceContract, got %d", len(res.EvidenceContracts))
	}

	cb := res.ControlBindings[0]
	if cb.Namespace != "production" {
		t.Errorf("expected namespace 'production', got %s", cb.Namespace)
	}
	if cb.Name != "envoy-ingress-gateway-binding" {
		t.Errorf("expected binding name envoy-ingress-gateway-binding, got %s", cb.Name)
	}
	if len(cb.Spec.Controls) != 2 {
		t.Errorf("expected 2 controls in binding, got %d", len(cb.Spec.Controls))
	}
	if cb.Spec.Controls[0].Canonical.ID != "AC-6" || cb.Spec.Controls[1].Canonical.ID != "SC-7" {
		t.Errorf("unexpected controls in binding: %v", cb.Spec.Controls)
	}

	ec := res.EvidenceContracts[0]
	if ec.Name != "envoy-ingress-gateway-contract" {
		t.Errorf("expected contract name envoy-ingress-gateway-contract, got %s", ec.Name)
	}
	if len(ec.Spec.Requirements) != 2 {
		t.Errorf("expected 2 requirements in contract, got %d", len(ec.Spec.Requirements))
	}
	if ec.Spec.Requirements[0].Freshness.Duration != 12*time.Hour {
		t.Errorf("expected freshness duration 12h, got %v", ec.Spec.Requirements[0].Freshness.Duration)
	}
}

func TestIngestSystemSecurityPlanYAML(t *testing.T) {
	sampleSSPYAML := []byte(`
system-security-plan:
  uuid: "9c8491b4-e22f-4e5e-a663-95c3d2609602"
  metadata:
    title: "Financial Transaction Processing Core SSP"
    published: "2026-09-25T12:00:00Z"
    last-modified: "2026-09-25T12:00:00Z"
    version: "2.1.0"
    oscal-version: "1.2.3"
  system-characteristics:
    system-name: "fin-core-engine"
    deployment-model: "private-cloud"
  control-implementation:
    description: "Financial core controls"
    implemented-requirements:
      - uuid: "ir-fin-01"
        control-id: "CM-8"
        description: "Information system component inventory"
        props:
          - name: "evidence-type"
            value: "sbom"
          - name: "producer"
            value: "syft"
      - uuid: "ir-fin-02"
        control-id: "SI-4"
        description: "Information system monitoring and threat detection"
        props:
          - name: "evidence-type"
            value: "runtime"
          - name: "producer"
            value: "tetragon"
`)

	res, err := recoscal.IngestOSCAL(sampleSSPYAML, "finance")
	if err != nil {
		t.Fatalf("unexpected error during IngestOSCAL YAML: %v", err)
	}

	if res.SourceType != "SystemSecurityPlan" {
		t.Errorf("expected SourceType SystemSecurityPlan, got %s", res.SourceType)
	}
	if len(res.ControlBindings) != 1 {
		t.Fatalf("expected 1 ControlBinding, got %d", len(res.ControlBindings))
	}
	if len(res.EvidenceContracts) != 1 {
		t.Fatalf("expected 1 EvidenceContract, got %d", len(res.EvidenceContracts))
	}

	cb := res.ControlBindings[0]
	if cb.Name != "fin-core-engine-binding" {
		t.Errorf("expected binding name fin-core-engine-binding, got %s", cb.Name)
	}
	if len(cb.Spec.Controls) != 2 {
		t.Errorf("expected 2 controls in binding, got %d", len(cb.Spec.Controls))
	}
	if cb.Spec.Controls[0].Canonical.ID != "CM-8" {
		t.Errorf("expected first control CM-8, got %s", cb.Spec.Controls[0].Canonical.ID)
	}
}

func TestProjectorToIngestRoundtrip(t *testing.T) {
	// 1. Generate Component Definition with Projector
	projector := proj.NewProjector()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "k8s://banking/Deployment/ledger-service"}
	evaluations := []assurance.ClaimEvaluation{
		{
			ID:      "eval-01",
			Control: assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"},
			Subject: sub,
			State:   assurance.AssuranceStateAssured,
		},
		{
			ID:      "eval-02",
			Control: assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "SC-7"},
			Subject: sub,
			State:   assurance.AssuranceStateAssured,
		},
	}

	compDefBytes, err := projector.ProjectComponentDefinition(context.Background(), "ledger-service", evaluations)
	if err != nil {
		t.Fatalf("projector failed to create component definition: %v", err)
	}

	// 2. Ingest back into Kubernetes CRD objects
	res, err := recoscal.IngestOSCAL(compDefBytes, "banking")
	if err != nil {
		t.Fatalf("failed to ingest projected component definition: %v", err)
	}

	if len(res.ControlBindings) != 1 {
		t.Fatalf("expected 1 ControlBinding, got %d", len(res.ControlBindings))
	}
	if len(res.EvidenceContracts) != 1 {
		t.Fatalf("expected 1 EvidenceContract, got %d", len(res.EvidenceContracts))
	}

	cb := res.ControlBindings[0]
	if len(cb.Spec.Controls) != 2 {
		t.Errorf("expected 2 controls in roundtrip binding, got %d", len(cb.Spec.Controls))
	}
}
