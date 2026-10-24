package scaffold

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	proj "github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
)

// Supported compliance profiles.
const (
	ProfileNistSP80053 = "nist-sp-800-53"
	ProfilePciDss      = "pci-dss"
	ProfileSoc2        = "soc-2"
	ProfileIso27001    = "iso-27001"
)

// ScaffoldPlan contains generated compliance artifacts for a profile.
type ScaffoldPlan struct {
	Profile             string                               `json:"profile"`
	Namespace           string                               `json:"namespace"`
	WorkloadName        string                               `json:"workload_name"`
	ControlBindings     []assurancev1alpha1.ControlBinding   `json:"control_bindings"`
	EvidenceContracts   []assurancev1alpha1.EvidenceContract `json:"evidence_contracts"`
	ComponentDefinition *proj.ComponentDefinitionWrapper     `json:"component_definition"`
	CelPolicies         []CelPolicyTemplate                  `json:"cel_policies"`
}

// CelPolicyTemplate represents a CEL admission validation rule scaffold.
type CelPolicyTemplate struct {
	Name       string `json:"name"`
	ControlID  string `json:"control_id"`
	Expression string `json:"expression"`
	Message    string `json:"message"`
}

// NormalizeProfile parses and standardizes user profile names.
func NormalizeProfile(raw string) (string, error) {
	norm := strings.ToLower(strings.TrimSpace(raw))
	norm = strings.ReplaceAll(norm, "_", "-")
	switch norm {
	case "nist", "nist-sp-800-53", "800-53", "nist-800-53":
		return ProfileNistSP80053, nil
	case "pci", "pci-dss":
		return ProfilePciDss, nil
	case "soc2", "soc-2":
		return ProfileSoc2, nil
	case "iso", "iso-27001", "iso27001":
		return ProfileIso27001, nil
	default:
		return "", fmt.Errorf("unsupported compliance profile %q (supported: nist-sp-800-53, pci-dss, soc-2, iso-27001)", raw)
	}
}

// GenerateScaffold creates a fully-populated ScaffoldPlan for the specified profile.
func GenerateScaffold(profile string, namespace string, workload string) (*ScaffoldPlan, error) {
	normProf, err := NormalizeProfile(profile)
	if err != nil {
		return nil, err
	}

	if namespace == "" {
		namespace = "default"
	}
	if workload == "" {
		workload = "example-app"
	}

	plan := &ScaffoldPlan{
		Profile:      normProf,
		Namespace:    namespace,
		WorkloadName: workload,
	}

	switch normProf {
	case ProfileNistSP80053:
		buildNistScaffold(plan)
	case ProfilePciDss:
		buildPciDssScaffold(plan)
	case ProfileSoc2:
		buildSoc2Scaffold(plan)
	case ProfileIso27001:
		buildIsoScaffold(plan)
	}

	buildComponentDefinition(plan)
	return plan, nil
}

func buildNistScaffold(plan *ScaffoldPlan) {
	// Evidence Contracts
	ecAdmission := assurancev1alpha1.EvidenceContract{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "assurance.ckodex.io/v1alpha1",
			Kind:       "EvidenceContract",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-nist-admission-contract", plan.WorkloadName),
			Namespace: plan.Namespace,
			Labels: map[string]string{
				"assurance.ckodex.io/profile": ProfileNistSP80053,
				"assurance.ckodex.io/target":  plan.WorkloadName,
			},
		},
		Spec: assurancev1alpha1.EvidenceContractSpec{
			Requirements: []assurancev1alpha1.ContractRequirement{
				{
					ID:                "req-admission-valid",
					Type:              "k8s:admission:review",
					Required:          true,
					Freshness:         metav1.Duration{Duration: 15 * time.Minute},
					AcceptedProducers: []string{"spiffe://assurance.ckodex.io/ns/ckodex-system/sa/oskal-webhook"},
				},
				{
					ID:                "req-sigstore-attestation",
					Type:              "sigstore:cosign:attestation",
					Required:          true,
					Freshness:         metav1.Duration{Duration: 24 * time.Hour},
					AcceptedProducers: []string{"spiffe://assurance.ckodex.io/ns/ckodex-system/sa/oskal-signer"},
				},
			},
			OnMissingRequiredEvidence: assurancev1alpha1.MissingEvidencePolicy{
				State: "Unknown",
			},
		},
	}
	plan.EvidenceContracts = append(plan.EvidenceContracts, ecAdmission)

	// Control Binding: AC-6 (Least Privilege) & CM-6 (Config Settings)
	cb := assurancev1alpha1.ControlBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "assurance.ckodex.io/v1alpha1",
			Kind:       "ControlBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-nist-controls", plan.WorkloadName),
			Namespace: plan.Namespace,
			Labels: map[string]string{
				"assurance.ckodex.io/profile": ProfileNistSP80053,
				"assurance.ckodex.io/target":  plan.WorkloadName,
			},
		},
		Spec: assurancev1alpha1.ControlBindingSpec{
			Controls: []assurancev1alpha1.ControlBindingItem{
				{
					Canonical: assurancev1alpha1.CanonicalControlRef{
						Namespace: "nist-sp-800-53",
						ID:        "AC-6",
						Version:   "Rev5",
					},
					Mappings: []assurancev1alpha1.FrameworkMapping{
						{Framework: "NIST-SP-800-53", Control: "AC-6", Version: "5"},
					},
				},
				{
					Canonical: assurancev1alpha1.CanonicalControlRef{
						Namespace: "nist-sp-800-53",
						ID:        "CM-6",
						Version:   "Rev5",
					},
					Mappings: []assurancev1alpha1.FrameworkMapping{
						{Framework: "NIST-SP-800-53", Control: "CM-6", Version: "5"},
					},
				},
				{
					Canonical: assurancev1alpha1.CanonicalControlRef{
						Namespace: "nist-sp-800-53",
						ID:        "SC-28",
						Version:   "Rev5",
					},
					Mappings: []assurancev1alpha1.FrameworkMapping{
						{Framework: "NIST-SP-800-53", Control: "SC-28", Version: "5"},
					},
				},
			},
			Subjects: assurancev1alpha1.SubjectSelector{
				Kinds: []string{"Deployment", "StatefulSet"},
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": plan.WorkloadName},
				},
			},
			Requirements: []assurancev1alpha1.RequirementBinding{
				{
					ID:               "binding-admission-least-privilege",
					EvidenceContract: ecAdmission.Name,
					Implementations: []assurancev1alpha1.ImplementationBindingRef{
						{
							Purpose:  "preventive",
							Provider: "kubernetes-validating-admission",
							Ref: assurancev1alpha1.ImplementationTargetRef{
								Name:      "validating-webhook-configuration",
								Namespace: "ckodex-system",
							},
						},
					},
				},
			},
		},
	}
	plan.ControlBindings = append(plan.ControlBindings, cb)

	// CEL Admission Rules
	plan.CelPolicies = append(plan.CelPolicies,
		CelPolicyTemplate{
			Name:       "disallow-privileged-containers",
			ControlID:  "AC-6",
			Expression: "!has(spec.template.spec.containers) || spec.template.spec.containers.all(c, !has(c.securityContext) || !has(c.securityContext.privileged) || c.securityContext.privileged == false)",
			Message:    "AC-6: Privileged containers are strictly prohibited",
		},
		CelPolicyTemplate{
			Name:       "disallow-privilege-escalation",
			ControlID:  "AC-6",
			Expression: "!has(spec.template.spec.containers) || spec.template.spec.containers.all(c, !has(c.securityContext) || !has(c.securityContext.allowPrivilegeEscalation) || c.securityContext.allowPrivilegeEscalation == false)",
			Message:    "AC-6: allowPrivilegeEscalation must be false",
		},
		CelPolicyTemplate{
			Name:       "enforce-run-as-non-root",
			ControlID:  "SC-28",
			Expression: "!has(spec.template.spec.containers) || spec.template.spec.containers.all(c, has(c.securityContext) && has(c.securityContext.runAsNonRoot) && c.securityContext.runAsNonRoot == true)",
			Message:    "SC-28: Containers must explicitly set runAsNonRoot=true",
		},
	)
}

func buildPciDssScaffold(plan *ScaffoldPlan) {
	ec := assurancev1alpha1.EvidenceContract{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "assurance.ckodex.io/v1alpha1",
			Kind:       "EvidenceContract",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-pci-contract", plan.WorkloadName),
			Namespace: plan.Namespace,
			Labels: map[string]string{
				"assurance.ckodex.io/profile": ProfilePciDss,
				"assurance.ckodex.io/target":  plan.WorkloadName,
			},
		},
		Spec: assurancev1alpha1.EvidenceContractSpec{
			Requirements: []assurancev1alpha1.ContractRequirement{
				{
					ID:                "pci-req-6-4",
					Type:              "k8s:admission:review",
					Required:          true,
					Freshness:         metav1.Duration{Duration: 10 * time.Minute},
					AcceptedProducers: []string{"spiffe://assurance.ckodex.io/ns/ckodex-system/sa/oskal-webhook"},
				},
			},
		},
	}
	plan.EvidenceContracts = append(plan.EvidenceContracts, ec)

	cb := assurancev1alpha1.ControlBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "assurance.ckodex.io/v1alpha1",
			Kind:       "ControlBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-pci-controls", plan.WorkloadName),
			Namespace: plan.Namespace,
			Labels: map[string]string{
				"assurance.ckodex.io/profile": ProfilePciDss,
			},
		},
		Spec: assurancev1alpha1.ControlBindingSpec{
			Controls: []assurancev1alpha1.ControlBindingItem{
				{
					Canonical: assurancev1alpha1.CanonicalControlRef{
						Namespace: "pci-dss",
						ID:        "Req-6.4",
						Version:   "v4.0",
					},
					Mappings: []assurancev1alpha1.FrameworkMapping{
						{Framework: "PCI-DSS", Control: "6.4", Version: "4.0"},
					},
				},
				{
					Canonical: assurancev1alpha1.CanonicalControlRef{
						Namespace: "pci-dss",
						ID:        "Req-7.1",
						Version:   "v4.0",
					},
					Mappings: []assurancev1alpha1.FrameworkMapping{
						{Framework: "PCI-DSS", Control: "7.1", Version: "4.0"},
					},
				},
			},
			Subjects: assurancev1alpha1.SubjectSelector{
				Kinds: []string{"Deployment"},
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": plan.WorkloadName},
				},
			},
			Requirements: []assurancev1alpha1.RequirementBinding{
				{
					ID:               "binding-pci-admission",
					EvidenceContract: ec.Name,
					Implementations: []assurancev1alpha1.ImplementationBindingRef{
						{
							Purpose:  "preventive",
							Provider: "kubernetes-validating-admission",
						},
					},
				},
			},
		},
	}
	plan.ControlBindings = append(plan.ControlBindings, cb)

	plan.CelPolicies = append(plan.CelPolicies,
		CelPolicyTemplate{
			Name:       "pci-disallow-host-mounts",
			ControlID:  "Req-6.4",
			Expression: "!has(spec.template.spec.volumes) || spec.template.spec.volumes.all(v, !has(v.hostPath))",
			Message:    "PCI-DSS 6.4: hostPath volumes are strictly forbidden",
		},
	)
}

func buildSoc2Scaffold(plan *ScaffoldPlan) {
	ec := assurancev1alpha1.EvidenceContract{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "assurance.ckodex.io/v1alpha1",
			Kind:       "EvidenceContract",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-soc2-contract", plan.WorkloadName),
			Namespace: plan.Namespace,
		},
		Spec: assurancev1alpha1.EvidenceContractSpec{
			Requirements: []assurancev1alpha1.ContractRequirement{
				{
					ID:                "soc2-req-cc6-1",
					Type:              "k8s:admission:review",
					Required:          true,
					Freshness:         metav1.Duration{Duration: 30 * time.Minute},
					AcceptedProducers: []string{"spiffe://assurance.ckodex.io/ns/ckodex-system/sa/oskal-webhook"},
				},
			},
		},
	}
	plan.EvidenceContracts = append(plan.EvidenceContracts, ec)

	cb := assurancev1alpha1.ControlBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "assurance.ckodex.io/v1alpha1",
			Kind:       "ControlBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-soc2-controls", plan.WorkloadName),
			Namespace: plan.Namespace,
		},
		Spec: assurancev1alpha1.ControlBindingSpec{
			Controls: []assurancev1alpha1.ControlBindingItem{
				{
					Canonical: assurancev1alpha1.CanonicalControlRef{
						Namespace: "soc-2",
						ID:        "CC6.1",
					},
				},
				{
					Canonical: assurancev1alpha1.CanonicalControlRef{
						Namespace: "soc-2",
						ID:        "CC6.6",
					},
				},
			},
			Subjects: assurancev1alpha1.SubjectSelector{
				Kinds: []string{"Deployment"},
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": plan.WorkloadName},
				},
			},
		},
	}
	plan.ControlBindings = append(plan.ControlBindings, cb)

	plan.CelPolicies = append(plan.CelPolicies,
		CelPolicyTemplate{
			Name:       "soc2-boundary-protection",
			ControlID:  "CC6.6",
			Expression: "!has(spec.template.spec.hostNetwork) || spec.template.spec.hostNetwork == false",
			Message:    "SOC 2 CC6.6: hostNetwork is prohibited to preserve logical boundaries",
		},
	)
}

func buildIsoScaffold(plan *ScaffoldPlan) {
	ec := assurancev1alpha1.EvidenceContract{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "assurance.ckodex.io/v1alpha1",
			Kind:       "EvidenceContract",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-iso-contract", plan.WorkloadName),
			Namespace: plan.Namespace,
		},
		Spec: assurancev1alpha1.EvidenceContractSpec{
			Requirements: []assurancev1alpha1.ContractRequirement{
				{
					ID:        "iso-req-change-control",
					Type:      "k8s:admission:review",
					Required:  true,
					Freshness: metav1.Duration{Duration: 1 * time.Hour},
				},
			},
		},
	}
	plan.EvidenceContracts = append(plan.EvidenceContracts, ec)

	cb := assurancev1alpha1.ControlBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "assurance.ckodex.io/v1alpha1",
			Kind:       "ControlBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-iso-controls", plan.WorkloadName),
			Namespace: plan.Namespace,
		},
		Spec: assurancev1alpha1.ControlBindingSpec{
			Controls: []assurancev1alpha1.ControlBindingItem{
				{
					Canonical: assurancev1alpha1.CanonicalControlRef{
						Namespace: "iso-27001",
						ID:        "A.12.1.2",
					},
				},
			},
			Subjects: assurancev1alpha1.SubjectSelector{
				Kinds: []string{"Deployment"},
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": plan.WorkloadName},
				},
			},
		},
	}
	plan.ControlBindings = append(plan.ControlBindings, cb)
}

func buildComponentDefinition(plan *ScaffoldPlan) {
	now := time.Now().UTC()
	docUUID := uuid.New().String()
	compUUID := uuid.New().String()

	cd := &proj.ComponentDefinitionWrapper{}
	cd.ComponentDefinition.UUID = docUUID
	cd.ComponentDefinition.Metadata = proj.OscalMetadata{
		Title:        fmt.Sprintf("OSCAL Component Definition for %s (%s)", plan.WorkloadName, plan.Profile),
		Published:    now,
		LastModified: now,
		Version:      "1.0.0",
		OscalVersion: "1.2.3",
	}
	cd.ComponentDefinition.DefinedComponents = []proj.OscalDefinedComponent{
		{
			UUID:        compUUID,
			Type:        "software",
			Title:       plan.WorkloadName,
			Description: fmt.Sprintf("Scaffolded component definition adhering to %s profile", plan.Profile),
			Purpose:     "Continuous assurance governed microservice workload",
		},
	}
	plan.ComponentDefinition = cd
}

// RenderManifestsYAML combines all Kubernetes CRD manifests into standard multi-document YAML.
func (p *ScaffoldPlan) RenderManifestsYAML() (string, error) {
	var documents []string

	for _, ec := range p.EvidenceContracts {
		y, err := yaml.Marshal(ec)
		if err != nil {
			return "", fmt.Errorf("failed to marshal EvidenceContract %s: %w", ec.Name, err)
		}
		documents = append(documents, string(y))
	}

	for _, cb := range p.ControlBindings {
		y, err := yaml.Marshal(cb)
		if err != nil {
			return "", fmt.Errorf("failed to marshal ControlBinding %s: %w", cb.Name, err)
		}
		documents = append(documents, string(y))
	}

	return strings.Join(documents, "\n---\n") + "\n", nil
}

// RenderComponentDefinitionJSON returns the OSCAL Component Definition JSON.
func (p *ScaffoldPlan) RenderComponentDefinitionJSON() ([]byte, error) {
	return json.MarshalIndent(p.ComponentDefinition, "", "  ")
}

// WriteToDirectory writes all scaffold artifacts into individual files in the target directory.
func (p *ScaffoldPlan) WriteToDirectory(outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory %s: %w", outDir, err)
	}

	manifests, err := p.RenderManifestsYAML()
	if err != nil {
		return err
	}
	crdsPath := filepath.Join(outDir, fmt.Sprintf("%s-crds.yaml", p.WorkloadName))
	if err := os.WriteFile(crdsPath, []byte(manifests), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", crdsPath, err)
	}

	cdJSON, err := p.RenderComponentDefinitionJSON()
	if err != nil {
		return err
	}
	cdPath := filepath.Join(outDir, fmt.Sprintf("%s-oscal-cd.json", p.WorkloadName))
	if err := os.WriteFile(cdPath, cdJSON, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", cdPath, err)
	}

	if len(p.CelPolicies) > 0 {
		celPath := filepath.Join(outDir, fmt.Sprintf("%s-cel-rules.yaml", p.WorkloadName))
		celBytes, err := yaml.Marshal(map[string]interface{}{
			"apiVersion": "assurance.ckodex.io/v1alpha1",
			"kind":       "CelPolicySet",
			"metadata": map[string]string{
				"name":      fmt.Sprintf("%s-cel-rules", p.WorkloadName),
				"namespace": p.Namespace,
			},
			"spec": map[string]interface{}{
				"policies": p.CelPolicies,
			},
		})
		if err != nil {
			return err
		}
		if err := os.WriteFile(celPath, celBytes, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", celPath, err)
		}
	}

	return nil
}
