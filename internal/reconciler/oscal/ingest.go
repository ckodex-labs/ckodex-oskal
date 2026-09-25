package oscal

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	proj "github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
)

// IngestionResult contains the generated Kubernetes assurance resources from an OSCAL document.
type IngestionResult struct {
	SourceType        string
	SourceUUID        string
	Title             string
	ControlBindings   []assurancev1alpha1.ControlBinding
	EvidenceContracts []assurancev1alpha1.EvidenceContract
}

// IngestOSCAL parses an OSCAL document (JSON or YAML) and returns the corresponding ControlBindings and EvidenceContracts.
func IngestOSCAL(data []byte, targetNamespace string) (*IngestionResult, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty OSCAL data provided")
	}

	if targetNamespace == "" {
		targetNamespace = "default"
	}

	// Convert YAML to JSON if needed
	jsonData := data
	if !isJSON(data) {
		converted, err := yaml.YAMLToJSON(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse YAML to JSON: %w", err)
		}
		jsonData = converted
	}

	// Try Component Definition first
	var compDef proj.ComponentDefinitionWrapper
	if err := json.Unmarshal(jsonData, &compDef); err == nil && compDef.ComponentDefinition.UUID != "" {
		return ingestComponentDefinition(&compDef, targetNamespace)
	}

	// Try System Security Plan (SSP)
	var ssp proj.SSPWrapper
	if err := json.Unmarshal(jsonData, &ssp); err == nil && ssp.SystemSecurityPlan.UUID != "" {
		return ingestSSP(&ssp, targetNamespace)
	}

	return nil, fmt.Errorf("unrecognized or unsupported OSCAL document (expected component-definition or system-security-plan)")
}

func isJSON(data []byte) bool {
	trimmed := strings.TrimSpace(string(data))
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

func ingestComponentDefinition(doc *proj.ComponentDefinitionWrapper, targetNamespace string) (*IngestionResult, error) {
	cd := doc.ComponentDefinition
	res := &IngestionResult{
		SourceType: "ComponentDefinition",
		SourceUUID: cd.UUID,
		Title:      cd.Metadata.Title,
	}

	for _, comp := range cd.DefinedComponents {
		compSlug := SanitizeK8sName(comp.Title)
		if compSlug == "" {
			compSlug = SanitizeK8sName(comp.UUID)
		}

		var bindings []assurancev1alpha1.ControlBindingItem
		var reqBindings []assurancev1alpha1.RequirementBinding
		var contractReqs []assurancev1alpha1.ContractRequirement

		for _, ci := range comp.ControlImplementations {
			for _, req := range ci.ImplementedRequirements {
				ctrlItem := assurancev1alpha1.ControlBindingItem{
					Canonical: assurancev1alpha1.CanonicalControlRef{
						Namespace: "nist-sp-800-53",
						ID:        req.ControlID,
					},
					Mappings: []assurancev1alpha1.FrameworkMapping{
						{
							Framework: "NIST SP 800-53",
							Control:   req.ControlID,
							Version:   "Rev 5",
						},
					},
				}
				bindings = append(bindings, ctrlItem)

				// Determine evidence requirement from props or defaults
				evType := "admission"
				freshnessDuration := 24 * time.Hour
				producer := "oskal-engine"

				for _, prop := range req.Props {
					switch strings.ToLower(prop.Name) {
					case "evidence-type", "type":
						evType = prop.Value
					case "producer", "source":
						producer = prop.Value
					case "freshness", "max-age":
						if d, err := time.ParseDuration(prop.Value); err == nil {
							freshnessDuration = d
						}
					}
				}

				reqID := fmt.Sprintf("req-%s-%s", strings.ToLower(req.ControlID), evType)
				contractReqs = append(contractReqs, assurancev1alpha1.ContractRequirement{
					ID:                reqID,
					Type:              evType,
					Required:          true,
					Freshness:         metav1.Duration{Duration: freshnessDuration},
					AcceptedProducers: []string{producer},
				})

				reqBindings = append(reqBindings, assurancev1alpha1.RequirementBinding{
					ID: reqID,
					Implementations: []assurancev1alpha1.ImplementationBindingRef{
						{
							Purpose:  "preventive",
							Provider: producer,
							Ref: assurancev1alpha1.ImplementationTargetRef{
								Name:      compSlug,
								Namespace: targetNamespace,
							},
						},
					},
					EvidenceContract: fmt.Sprintf("%s-contract", compSlug),
				})
			}
		}

		if len(bindings) > 0 {
			contract := assurancev1alpha1.EvidenceContract{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "assurance.ckodex.io/v1alpha1",
					Kind:       "EvidenceContract",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-contract", compSlug),
					Namespace: targetNamespace,
					Labels: map[string]string{
						"assurance.ckodex.io/source":      "oskal-ingest",
						"assurance.ckodex.io/source-type": "component-definition",
						"assurance.ckodex.io/component":   compSlug,
					},
				},
				Spec: assurancev1alpha1.EvidenceContractSpec{
					Requirements: contractReqs,
					OnMissingRequiredEvidence: assurancev1alpha1.MissingEvidencePolicy{
						State: "Unknown",
					},
				},
			}
			res.EvidenceContracts = append(res.EvidenceContracts, contract)

			binding := assurancev1alpha1.ControlBinding{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "assurance.ckodex.io/v1alpha1",
					Kind:       "ControlBinding",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-binding", compSlug),
					Namespace: targetNamespace,
					Labels: map[string]string{
						"assurance.ckodex.io/source":      "oskal-ingest",
						"assurance.ckodex.io/source-type": "component-definition",
						"assurance.ckodex.io/component":   compSlug,
					},
				},
				Spec: assurancev1alpha1.ControlBindingSpec{
					Controls: bindings,
					Subjects: assurancev1alpha1.SubjectSelector{
						Kinds: []string{"Deployment", "StatefulSet", "DaemonSet"},
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app.kubernetes.io/name": compSlug,
							},
						},
					},
					Requirements: reqBindings,
				},
			}
			res.ControlBindings = append(res.ControlBindings, binding)
		}
	}

	return res, nil
}

func ingestSSP(doc *proj.SSPWrapper, targetNamespace string) (*IngestionResult, error) {
	ssp := doc.SystemSecurityPlan
	res := &IngestionResult{
		SourceType: "SystemSecurityPlan",
		SourceUUID: ssp.UUID,
		Title:      ssp.Metadata.Title,
	}

	systemSlug := SanitizeK8sName(ssp.SystemCharacteristics.SystemName)
	if systemSlug == "" {
		systemSlug = SanitizeK8sName(ssp.Metadata.Title)
	}
	if systemSlug == "" {
		systemSlug = "oskal-system"
	}

	var bindings []assurancev1alpha1.ControlBindingItem
	var reqBindings []assurancev1alpha1.RequirementBinding
	var contractReqs []assurancev1alpha1.ContractRequirement

	for _, req := range ssp.ControlImplementation.ImplementedRequirements {
		ctrlItem := assurancev1alpha1.ControlBindingItem{
			Canonical: assurancev1alpha1.CanonicalControlRef{
				Namespace: "nist-sp-800-53",
				ID:        req.ControlID,
			},
			Mappings: []assurancev1alpha1.FrameworkMapping{
				{
					Framework: "NIST SP 800-53",
					Control:   req.ControlID,
					Version:   "Rev 5",
				},
			},
		}
		bindings = append(bindings, ctrlItem)

		evType := "compliance"
		freshnessDuration := 24 * time.Hour
		producer := "oskal-ssp-auditor"

		for _, prop := range req.Props {
			switch strings.ToLower(prop.Name) {
			case "evidence-type", "type":
				evType = prop.Value
			case "producer", "source":
				producer = prop.Value
			case "freshness", "max-age":
				if d, err := time.ParseDuration(prop.Value); err == nil {
					freshnessDuration = d
				}
			}
		}

		reqID := fmt.Sprintf("req-%s-%s", strings.ToLower(req.ControlID), evType)
		contractReqs = append(contractReqs, assurancev1alpha1.ContractRequirement{
			ID:                reqID,
			Type:              evType,
			Required:          true,
			Freshness:         metav1.Duration{Duration: freshnessDuration},
			AcceptedProducers: []string{producer},
		})

		reqBindings = append(reqBindings, assurancev1alpha1.RequirementBinding{
			ID: reqID,
			Implementations: []assurancev1alpha1.ImplementationBindingRef{
				{
					Purpose:  "detective",
					Provider: producer,
					Ref: assurancev1alpha1.ImplementationTargetRef{
						Name:      systemSlug,
						Namespace: targetNamespace,
					},
				},
			},
			EvidenceContract: fmt.Sprintf("%s-contract", systemSlug),
		})
	}

	if len(bindings) > 0 {
		contract := assurancev1alpha1.EvidenceContract{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "assurance.ckodex.io/v1alpha1",
				Kind:       "EvidenceContract",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-contract", systemSlug),
				Namespace: targetNamespace,
				Labels: map[string]string{
					"assurance.ckodex.io/source":      "oskal-ingest",
					"assurance.ckodex.io/source-type": "ssp",
					"assurance.ckodex.io/system":      systemSlug,
				},
			},
			Spec: assurancev1alpha1.EvidenceContractSpec{
				Requirements: contractReqs,
				OnMissingRequiredEvidence: assurancev1alpha1.MissingEvidencePolicy{
					State: "Unknown",
				},
			},
		}
		res.EvidenceContracts = append(res.EvidenceContracts, contract)

		binding := assurancev1alpha1.ControlBinding{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "assurance.ckodex.io/v1alpha1",
				Kind:       "ControlBinding",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-binding", systemSlug),
				Namespace: targetNamespace,
				Labels: map[string]string{
					"assurance.ckodex.io/source":      "oskal-ingest",
					"assurance.ckodex.io/source-type": "ssp",
					"assurance.ckodex.io/system":      systemSlug,
				},
			},
			Spec: assurancev1alpha1.ControlBindingSpec{
				Controls: bindings,
				Subjects: assurancev1alpha1.SubjectSelector{
					Kinds: []string{"Deployment", "StatefulSet", "DaemonSet"},
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app.kubernetes.io/part-of": systemSlug,
						},
					},
				},
				Requirements: reqBindings,
			},
		}
		res.ControlBindings = append(res.ControlBindings, binding)
	}

	return res, nil
}

// SanitizeK8sName converts a string into a valid Kubernetes DNS subdomain/label name.
func SanitizeK8sName(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
			b.WriteRune(ch)
		} else if ch == ' ' || ch == '_' || ch == '.' {
			b.WriteRune('-')
		}
	}
	res := strings.Trim(b.String(), "-")
	if len(res) > 63 {
		res = res[:63]
	}
	if res == "" {
		res = "resource"
	}
	return res
}
