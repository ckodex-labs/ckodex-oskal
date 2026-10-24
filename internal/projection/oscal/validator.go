package oscal

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"sigs.k8s.io/yaml"
)

//go:embed schemas/*.json
var embeddedSchemas embed.FS

// DocumentType represents the standard NIST OSCAL document type.
type DocumentType string

const (
	DocTypeAssessmentResults   DocumentType = "assessment-results"
	DocTypeComponentDefinition DocumentType = "component-definition"
	DocTypeSSP                 DocumentType = "system-security-plan"
	DocTypeAssessmentPlan      DocumentType = "assessment-plan"
	DocTypePOAM                DocumentType = "plan-of-action-and-milestones"
)

var schemaFileMap = map[DocumentType]string{
	DocTypeAssessmentResults:   "schemas/oscal_assessment-results_schema.json",
	DocTypeComponentDefinition: "schemas/oscal_component_schema.json",
	DocTypeSSP:                 "schemas/oscal_ssp_schema.json",
	DocTypeAssessmentPlan:      "schemas/oscal_assessment-plan_schema.json",
	DocTypePOAM:                "schemas/oscal_poam_schema.json",
}

// ValidationError represents an exact path-level schema failure.
type ValidationError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// ValidationReport contains the full validation result and metadata.
type ValidationReport struct {
	Valid        bool              `json:"valid"`
	DocumentType DocumentType      `json:"document_type"`
	OscalVersion string            `json:"oscal_version,omitempty"`
	Duration     time.Duration     `json:"duration_ns"`
	Errors       []ValidationError `json:"errors,omitempty"`
}

// Validator validates OSCAL documents against NIST v1.2.3 JSON schemas.
type Validator struct {
	mu      sync.RWMutex
	schemas map[DocumentType]*jsonschema.Schema
}

var (
	defaultValidator     *Validator
	defaultValidatorOnce sync.Once
)

// DefaultValidator returns a singleton Validator instance with cached schemas.
func DefaultValidator() (*Validator, error) {
	var initErr error
	defaultValidatorOnce.Do(func() {
		v := &Validator{
			schemas: make(map[DocumentType]*jsonschema.Schema),
		}
		if err := v.compileAll(); err != nil {
			initErr = err
			return
		}
		defaultValidator = v
	})
	if initErr != nil {
		return nil, initErr
	}
	return defaultValidator, nil
}

// NewValidator initializes a new Validator and compiles the embedded schemas.
func NewValidator() (*Validator, error) {
	v := &Validator{
		schemas: make(map[DocumentType]*jsonschema.Schema),
	}
	if err := v.compileAll(); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Validator) compileAll() error {
	for docType, filename := range schemaFileMap {
		content, err := embeddedSchemas.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("failed to read embedded schema %s: %w", filename, err)
		}

		compiler := jsonschema.NewCompiler()
		baseName := filepath.Base(filename)
		if err := compiler.AddResource(baseName, bytes.NewReader(content)); err != nil {
			return fmt.Errorf("failed to add schema resource %s: %w", baseName, err)
		}

		schema, err := compiler.Compile(baseName)
		if err != nil {
			return fmt.Errorf("failed to compile schema %s: %w", baseName, err)
		}
		v.schemas[docType] = schema
	}
	return nil
}

// DetectDocumentType detects the OSCAL document type from parsed JSON/YAML data.
func DetectDocumentType(data []byte) (DocumentType, []byte, error) {
	jsonData := data
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return "", nil, fmt.Errorf("empty document payload")
	}

	// Convert YAML to JSON if not starting with '{'
	if trimmed[0] != '{' {
		converted, err := yaml.YAMLToJSON(data)
		if err != nil {
			return "", nil, fmt.Errorf("failed to convert YAML to JSON: %w", err)
		}
		jsonData = converted
	}

	var root map[string]interface{}
	if err := json.Unmarshal(jsonData, &root); err != nil {
		return "", nil, fmt.Errorf("failed to parse JSON structure: %w", err)
	}

	if _, ok := root["assessment-results"]; ok {
		return DocTypeAssessmentResults, jsonData, nil
	}
	if _, ok := root["component-definition"]; ok {
		return DocTypeComponentDefinition, jsonData, nil
	}
	if _, ok := root["system-security-plan"]; ok {
		return DocTypeSSP, jsonData, nil
	}
	if _, ok := root["assessment-plan"]; ok {
		return DocTypeAssessmentPlan, jsonData, nil
	}
	if _, ok := root["plan-of-action-and-milestones"]; ok {
		return DocTypePOAM, jsonData, nil
	}

	return "", nil, fmt.Errorf("unrecognized OSCAL root document element")
}

// NormalizeDocumentType standardizes user-provided document type strings.
func NormalizeDocumentType(raw string) (DocumentType, error) {
	norm := strings.ToLower(strings.TrimSpace(raw))
	norm = strings.ReplaceAll(norm, "_", "-")
	switch norm {
	case "assessment-results", "ar":
		return DocTypeAssessmentResults, nil
	case "component-definition", "component", "cd":
		return DocTypeComponentDefinition, nil
	case "system-security-plan", "ssp":
		return DocTypeSSP, nil
	case "assessment-plan", "ap":
		return DocTypeAssessmentPlan, nil
	case "plan-of-action-and-milestones", "poam":
		return DocTypePOAM, nil
	default:
		return "", fmt.Errorf("unknown OSCAL document type: %s (supported: assessment-results, component-definition, ssp, assessment-plan, poam)", raw)
	}
}

// Validate validates an OSCAL payload against the given or auto-detected document type.
func (v *Validator) Validate(data []byte, docTypeOverride string) (*ValidationReport, error) {
	start := time.Now()

	var targetType DocumentType
	var jsonData []byte

	if docTypeOverride != "" && strings.ToLower(docTypeOverride) != "auto" {
		dt, err := NormalizeDocumentType(docTypeOverride)
		if err != nil {
			return nil, err
		}
		targetType = dt

		trimmed := bytes.TrimSpace(data)
		if len(trimmed) == 0 {
			return nil, fmt.Errorf("empty document payload")
		}
		if trimmed[0] != '{' {
			converted, err := yaml.YAMLToJSON(data)
			if err != nil {
				return nil, fmt.Errorf("failed to convert YAML to JSON: %w", err)
			}
			jsonData = converted
		} else {
			jsonData = data
		}
	} else {
		dt, converted, err := DetectDocumentType(data)
		if err != nil {
			return nil, err
		}
		targetType = dt
		jsonData = converted
	}

	v.mu.RLock()
	schema, ok := v.schemas[targetType]
	v.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no compiled schema available for document type: %s", targetType)
	}

	var parsed interface{}
	dec := json.NewDecoder(bytes.NewReader(jsonData))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to decode JSON for validation: %w", err)
	}

	oscalVersion := extractOscalVersion(parsed, targetType)

	report := &ValidationReport{
		DocumentType: targetType,
		OscalVersion: oscalVersion,
	}

	if err := schema.Validate(parsed); err != nil {
		report.Valid = false
		report.Errors = extractErrors(err)
	} else {
		report.Valid = true
	}

	report.Duration = time.Since(start)
	return report, nil
}

func extractOscalVersion(v interface{}, dt DocumentType) string {
	m, ok := v.(map[string]interface{})
	if !ok {
		return ""
	}
	doc, ok := m[string(dt)].(map[string]interface{})
	if !ok {
		return ""
	}
	meta, ok := doc["metadata"].(map[string]interface{})
	if !ok {
		return ""
	}
	ver, ok := meta["oscal-version"].(string)
	if !ok {
		return ""
	}
	return ver
}

func extractErrors(err error) []ValidationError {
	var result []ValidationError
	valErr, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return []ValidationError{{Path: "/", Message: err.Error()}}
	}

	collectValidationErrors(valErr, &result)
	if len(result) == 0 {
		result = append(result, ValidationError{
			Path:    valErr.InstanceLocation,
			Message: valErr.Message,
		})
	}
	return result
}

func collectValidationErrors(ve *jsonschema.ValidationError, acc *[]ValidationError) {
	if len(ve.Causes) == 0 {
		loc := ve.InstanceLocation
		if loc == "" {
			loc = "/"
		}
		msg := ve.Message
		if msg == "" {
			msg = "validation constraint violated"
		}
		*acc = append(*acc, ValidationError{
			Path:    loc,
			Message: msg,
		})
		return
	}

	for _, cause := range ve.Causes {
		collectValidationErrors(cause, acc)
	}
}
