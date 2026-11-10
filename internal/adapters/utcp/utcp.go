package utcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/workcell"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/diagnostics"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/explain"
	proj "github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/ckodex-labs/ckodex-oskal/internal/scaffold"
)

const (
	// UTCPVersion is the supported Universal Tool Calling Protocol specification version.
	UTCPVersion = "1.0.1"
	// ManualVersion is the default OSKAL UTCP manual schema version.
	ManualVersion = "1.0.0"
	// DefaultFreshnessWindow is the canonical 15-minute maximum evidence age across OSKAL.
	DefaultFreshnessWindow = 15 * time.Minute
	// MaxRegisteredManuals bounds dynamic manual registrations per Registry (Constitution Section 30).
	MaxRegisteredManuals = 256
	// MaxRegisteredTools bounds total registered tools per Registry (Constitution Section 30).
	MaxRegisteredTools = 4096
	// MaxHTTPConcurrentRequests bounds simultaneous UTCP HTTP server requests before shedding load.
	MaxHTTPConcurrentRequests = 128
	// MaxCallBodyBytes bounds POST /tools/call request payload size (4 MiB).
	MaxCallBodyBytes = 4 << 20
	// MaxSearchBodyBytes bounds POST /tools/search request payload size (1 MiB).
	MaxSearchBodyBytes = 1 << 20
)

// AllowedTransports lists the CKODEX-governed UTCP transport types.
// Note: "websocket" is explicitly forbidden by CKODEX Constitution Section 10.
var AllowedTransports = []string{
	"cli",
	"http",
	"streamable_http",
	"grpc",
	"sse",
	"mcp",
	"text",
}

// Info describes the service publishing the UTCP manual.
type Info struct {
	Title       string `json:"title" yaml:"title"`
	Version     string `json:"version" yaml:"version"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Homepage    string `json:"homepage,omitempty" yaml:"homepage,omitempty"`
}

// AuthConfig describes optional authentication metadata for a UTCP call template or provider.
type AuthConfig struct {
	AuthType string `json:"auth_type" yaml:"auth_type"` // "api_key", "bearer", "oauth2", "spiffe", "none"
	VarName  string `json:"var_name,omitempty" yaml:"var_name,omitempty"`
	Location string `json:"location,omitempty" yaml:"location,omitempty"` // "header", "query", "env", "mtls"
}

// CLICommand represents a single command step in a UTCP v1.0 CLI CallTemplate
// compatible with python-utcp and typescript-utcp.
type CLICommand struct {
	Command             string `json:"command" yaml:"command"`
	AppendToFinalOutput *bool  `json:"append_to_final_output,omitempty" yaml:"append_to_final_output,omitempty"`
}

// CallTemplate defines how an agent directly invokes a native tool endpoint in UTCP v1.0+
// while preserving v0.1 provider_type compatibility fields for go-utcp, rs-utcp, typescript-utcp, and python-utcp.
type CallTemplate struct {
	CallTemplateType string            `json:"call_template_type" yaml:"call_template_type"`
	ProviderType     string            `json:"provider_type,omitempty" yaml:"provider_type,omitempty"`
	Name             string            `json:"name,omitempty" yaml:"name,omitempty"`
	URL              string            `json:"url,omitempty" yaml:"url,omitempty"`
	HTTPMethod       string            `json:"http_method,omitempty" yaml:"http_method,omitempty"`
	ContentType      string            `json:"content_type,omitempty" yaml:"content_type,omitempty"`
	BodyField        string            `json:"body_field,omitempty" yaml:"body_field,omitempty"`
	Command          string            `json:"command,omitempty" yaml:"command,omitempty"`
	Commands         []CLICommand      `json:"commands,omitempty" yaml:"commands,omitempty"`
	CommandName      string            `json:"command_name,omitempty" yaml:"command_name,omitempty"`
	Args             []string          `json:"args,omitempty" yaml:"args,omitempty"`
	ParamStyle       string            `json:"param_style,omitempty" yaml:"param_style,omitempty"`
	OutputFormat     string            `json:"output_format,omitempty" yaml:"output_format,omitempty"`
	WorkingDir       string            `json:"working_dir,omitempty" yaml:"working_dir,omitempty"`
	GRPCService      string            `json:"grpc_service,omitempty" yaml:"grpc_service,omitempty"`
	GRPCMethod       string            `json:"grpc_method,omitempty" yaml:"grpc_method,omitempty"`
	TargetAddr       string            `json:"target_addr,omitempty" yaml:"target_addr,omitempty"`
	Headers          map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Auth             *AuthConfig       `json:"auth,omitempty" yaml:"auth,omitempty"`
}

// Tool represents a single UTCP tool definition compatible with utcp-specification,
// go-utcp, rs-utcp, typescript-utcp, python-utcp, and utcp-mcp.
type Tool struct {
	Name                string                 `json:"name" yaml:"name"`
	Description         string                 `json:"description" yaml:"description"`
	Tags                []string               `json:"tags,omitempty" yaml:"tags,omitempty"`
	Inputs              map[string]interface{} `json:"inputs" yaml:"inputs"`
	Outputs             map[string]interface{} `json:"outputs,omitempty" yaml:"outputs,omitempty"`
	InputSchema         map[string]interface{} `json:"input_schema,omitempty" yaml:"input_schema,omitempty"`
	OutputSchema        map[string]interface{} `json:"output_schema,omitempty" yaml:"output_schema,omitempty"`
	CallTemplate        CallTemplate           `json:"call_template" yaml:"call_template"`
	ToolCallTemplate    *CallTemplate          `json:"tool_call_template,omitempty" yaml:"tool_call_template,omitempty"`
	ToolProvider        *CallTemplate          `json:"tool_provider,omitempty" yaml:"tool_provider,omitempty"`
	AverageResponseSize int64                  `json:"average_response_size,omitempty" yaml:"average_response_size,omitempty"`
	RequiredCapability  string                 `json:"required_capability,omitempty" yaml:"required_capability,omitempty"`
}

// UTCPManual is the root Universal Tool Calling Protocol manual document.
// Includes Version ("version") for go-utcp manual vs OpenAPI detection alongside
// UTCPVersion ("utcp_version") and ManualVersion ("manual_version") for v1.0.1.
type UTCPManual struct {
	Version                       string   `json:"version" yaml:"version"`
	UTCPVersion                   string   `json:"utcp_version" yaml:"utcp_version"`
	ManualVersion                 string   `json:"manual_version" yaml:"manual_version"`
	Info                          Info     `json:"info" yaml:"info"`
	AllowedCommunicationProtocols []string `json:"allowed_communication_protocols,omitempty" yaml:"allowed_communication_protocols,omitempty"`
	Tools                         []Tool   `json:"tools" yaml:"tools"`
}

// ProviderConfig defines how a UTCP client discovers or loads a manual/provider across SDKs.
type ProviderConfig struct {
	Name               string            `json:"name" yaml:"name"`
	ProviderType       string            `json:"provider_type" yaml:"provider_type"`
	CallTemplateType   string            `json:"call_template_type,omitempty" yaml:"call_template_type,omitempty"`
	URL                string            `json:"url,omitempty" yaml:"url,omitempty"`
	HTTPMethod         string            `json:"http_method,omitempty" yaml:"http_method,omitempty"`
	ContentType        string            `json:"content_type,omitempty" yaml:"content_type,omitempty"`
	FilePath           string            `json:"file_path,omitempty" yaml:"file_path,omitempty"`
	Command            string            `json:"command,omitempty" yaml:"command,omitempty"`
	Commands           []CLICommand      `json:"commands,omitempty" yaml:"commands,omitempty"`
	CommandName        string            `json:"command_name,omitempty" yaml:"command_name,omitempty"`
	Args               []string          `json:"args,omitempty" yaml:"args,omitempty"`
	Headers            map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Auth               *AuthConfig       `json:"auth,omitempty" yaml:"auth,omitempty"`
	LeaseID            string            `json:"lease_id,omitempty" yaml:"lease_id,omitempty"`
	PrevReceiptHash    string            `json:"prev_receipt_hash,omitempty" yaml:"prev_receipt_hash,omitempty"`
	RequiredCapability string            `json:"required_capability,omitempty" yaml:"required_capability,omitempty"`
}

type leaseContextKey struct{}

type leaseMetadata struct {
	LeaseID         string
	PrevReceiptHash string
}

// WithLease attaches a CapabilityLease ID and prior receipt hash to a context for governed UTCP registry operations.
func WithLease(ctx context.Context, leaseID, prevReceiptHash string) context.Context {
	return context.WithValue(ctx, leaseContextKey{}, leaseMetadata{
		LeaseID:         leaseID,
		PrevReceiptHash: prevReceiptHash,
	})
}

func leaseFromContext(ctx context.Context) (string, string) {
	if ctx == nil {
		return "", ""
	}
	if meta, ok := ctx.Value(leaseContextKey{}).(leaseMetadata); ok {
		return meta.LeaseID, meta.PrevReceiptHash
	}
	return "", ""
}

// ManualOptions customizes how the OSKAL UTCP manual is generated.
type ManualOptions struct {
	PrimaryTransport string // "cli" (default), "http", "grpc", "mcp"
	BaseURL          string // default "http://localhost:8090"
	GRPCAddr         string // default "localhost:9090"
	BinaryPath       string // default "oskal"
}

// DefaultManualOptions returns safe defaults for local and cluster UTCP discovery.
func DefaultManualOptions() ManualOptions {
	return ManualOptions{
		PrimaryTransport: "cli",
		BaseURL:          "http://localhost:8090",
		GRPCAddr:         "localhost:9090",
		BinaryPath:       "oskal",
	}
}

// BuildOSKALManual constructs a complete, multi-SDK compatible UTCP v1.0.1 manual for OSKAL.
func BuildOSKALManual(opts ManualOptions) UTCPManual {
	if opts.PrimaryTransport == "" {
		opts.PrimaryTransport = "cli"
	}
	if opts.BaseURL == "" {
		opts.BaseURL = "http://localhost:8090"
	}
	if opts.GRPCAddr == "" {
		opts.GRPCAddr = "localhost:9090"
	}
	if opts.BinaryPath == "" {
		opts.BinaryPath = "oskal"
	}

	makeTemplate := func(toolName string, argKeys []string, grpcService, grpcMethod string) CallTemplate {
		switch strings.ToLower(opts.PrimaryTransport) {
		case "http", "streamable_http":
			return CallTemplate{
				CallTemplateType: opts.PrimaryTransport,
				ProviderType:     opts.PrimaryTransport,
				Name:             "oskal_http",
				URL:              strings.TrimRight(opts.BaseURL, "/") + "/tools/call",
				HTTPMethod:       "POST",
				ContentType:      "application/json",
				Headers: map[string]string{
					"X-UTCP-Tool": toolName,
				},
			}
		case "grpc":
			return CallTemplate{
				CallTemplateType: "grpc",
				ProviderType:     "grpc",
				Name:             "oskal_grpc",
				TargetAddr:       opts.GRPCAddr,
				GRPCService:      grpcService,
				GRPCMethod:       grpcMethod,
				Auth: &AuthConfig{
					AuthType: "spiffe",
					Location: "mtls",
				},
			}
		case "mcp":
			return CallTemplate{
				CallTemplateType: "mcp",
				ProviderType:     "mcp",
				Name:             "oskal_mcp",
				CommandName:      opts.BinaryPath,
				Args:             []string{"mcp"},
			}
		default:
			cmdParts := []string{opts.BinaryPath, "utcp", "call", toolName}
			for _, k := range argKeys {
				cmdParts = append(cmdParts, "--"+k, "UTCP_ARG_"+k+"_UTCP_END")
			}
			cmdStr := strings.Join(cmdParts, " ")
			appendTrue := true
			return CallTemplate{
				CallTemplateType: "cli",
				ProviderType:     "cli",
				Name:             "oskal_cli",
				Command:          cmdStr,
				Commands: []CLICommand{
					{
						Command:             cmdStr,
						AppendToFinalOutput: &appendTrue,
					},
				},
				CommandName:  opts.BinaryPath,
				Args:         []string{"utcp", "call", toolName},
				ParamStyle:   "named",
				OutputFormat: "json",
			}
		}
	}

	decorateTool := func(t Tool) Tool {
		t.InputSchema = t.Inputs
		t.OutputSchema = t.Outputs
		cp := t.CallTemplate
		t.ToolCallTemplate = &cp
		t.ToolProvider = &cp
		return t
	}

	tools := []Tool{
		decorateTool(Tool{
			Name:        "get_assurance_state",
			Description: "Retrieve the continuous assurance 6D state vector <P, V, C, E, L, tau> for a Kubernetes workload subject.",
			Tags:        []string{"assurance", "state", "vector", "kubernetes", "compliance"},
			Inputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"subject": map[string]interface{}{
						"type":        "string",
						"description": "Subject URI (e.g. k8s://prod/payments/Deployment/payments-api)",
					},
				},
				"required": []string{"subject"},
			},
			Outputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"subject":       map[string]interface{}{"type": "string"},
					"state":         map[string]interface{}{"type": "string"},
					"evidence_root": map[string]interface{}{"type": "string"},
					"freshness":     map[string]interface{}{"type": "string"},
					"vector_state":  map[string]interface{}{"type": "object"},
				},
			},
			CallTemplate:        makeTemplate("get_assurance_state", []string{"subject"}, "ckodex.assurance.services.v1.AssuranceService", "GetAssuranceState"),
			AverageResponseSize: 512,
			RequiredCapability:  "tool:read-evidence",
		}),
		decorateTool(Tool{
			Name:        "explain_claim",
			Description: "Explain why an assurance claim is justified or failing using a deterministic reverse-traceable decision graph.",
			Tags:        []string{"assurance", "explain", "decision-trace", "evidence", "nist"},
			Inputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"subject": map[string]interface{}{
						"type":        "string",
						"description": "Subject URI (e.g. k8s://prod/payments/Deployment/payments-api)",
					},
					"control": map[string]interface{}{
						"type":        "string",
						"description": "Control identifier (e.g. nist-sp-800-53:AC-6)",
						"default":     "nist-sp-800-53:AC-6",
					},
				},
				"required": []string{"subject"},
			},
			Outputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"rendered_text":   map[string]interface{}{"type": "string"},
					"assurance_state": map[string]interface{}{"type": "string"},
				},
			},
			CallTemplate:        makeTemplate("explain_claim", []string{"subject", "control"}, "ckodex.assurance.services.v1.AssuranceService", "ExplainClaim"),
			AverageResponseSize: 1536,
			RequiredCapability:  "tool:read-evidence",
		}),
		decorateTool(Tool{
			Name:        "validate_oscal",
			Description: "Validate a NIST OSCAL v1.2.3 document (AR, CD, SSP, AP, POAM) against embedded JSON schemas.",
			Tags:        []string{"oscal", "validate", "nist", "schema", "compliance"},
			Inputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"content": map[string]interface{}{
						"type":        "string",
						"description": "Raw OSCAL JSON or YAML string",
					},
					"schema": map[string]interface{}{
						"type":        "string",
						"description": "Optional schema type override: auto, assessment-results, component-definition, ssp, assessment-plan, poam",
						"default":     "auto",
					},
				},
				"required": []string{"content"},
			},
			Outputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"valid":         map[string]interface{}{"type": "boolean"},
					"document_type": map[string]interface{}{"type": "string"},
					"oscal_version": map[string]interface{}{"type": "string"},
				},
			},
			CallTemplate:        makeTemplate("validate_oscal", []string{"content", "schema"}, "assurance.services.v1.OSCALProjectionService", "ValidateOSCAL"),
			AverageResponseSize: 384,
			RequiredCapability:  "tool:validate-oscal",
		}),
		decorateTool(Tool{
			Name:        "detect_drift",
			Description: "Detect semantic decoherence and drift between observed runtime state and recorded epoch digests.",
			Tags:        []string{"drift", "decoherence", "reconcile", "epoch", "assurance"},
			Inputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"subject": map[string]interface{}{
						"type":        "string",
						"description": "Subject URI (e.g. k8s://prod/payments/Deployment/payments-api)",
					},
				},
				"required": []string{"subject"},
			},
			Outputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"subject":          map[string]interface{}{"type": "string"},
					"status":           map[string]interface{}{"type": "string"},
					"assurance_status": map[string]interface{}{"type": "string"},
					"drift_dimensions": map[string]interface{}{"type": "integer"},
				},
			},
			CallTemplate:        makeTemplate("detect_drift", []string{"subject"}, "ckodex.assurance.services.v1.AssuranceService", "GetAssuranceState"),
			AverageResponseSize: 512,
			RequiredCapability:  "tool:read-evidence",
		}),
		decorateTool(Tool{
			Name:        "scaffold_compliance",
			Description: "Scaffold Kubernetes ControlBinding, EvidenceContract, and OSCAL Component Definition manifests.",
			Tags:        []string{"scaffold", "kubernetes", "crd", "nist-sp-800-53", "pci-dss", "soc2", "iso27001"},
			Inputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"profile": map[string]interface{}{
						"type":        "string",
						"description": "Compliance profile (nist-sp-800-53, pci-dss, soc-2, iso-27001)",
					},
					"workload": map[string]interface{}{
						"type":        "string",
						"description": "Target workload name",
						"default":     "example-app",
					},
					"namespace": map[string]interface{}{
						"type":        "string",
						"description": "Target Kubernetes namespace",
						"default":     "default",
					},
				},
				"required": []string{"profile"},
			},
			Outputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"manifests_yaml": map[string]interface{}{"type": "string"},
				},
			},
			CallTemplate:        makeTemplate("scaffold_compliance", []string{"profile", "workload", "namespace"}, "assurance.services.v1.OSCALProjectionService", "ScaffoldCompliance"),
			AverageResponseSize: 4096,
			RequiredCapability:  "tool:scaffold-policy",
		}),
		decorateTool(Tool{
			Name:        "project_oscal",
			Description: "Project continuous assurance state into a standard NIST OSCAL v1.2.3 document (AR, CD, SSP, AP, POAM).",
			Tags:        []string{"oscal", "export", "projection", "ssp", "assessment-results", "poam"},
			Inputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"subject": map[string]interface{}{
						"type":        "string",
						"description": "Subject URI",
					},
					"document_type": map[string]interface{}{
						"type":        "string",
						"description": "Document type: assessment-results, component-definition, ssp, assessment-plan, poam",
					},
				},
				"required": []string{"subject", "document_type"},
			},
			Outputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"oscal_json": map[string]interface{}{"type": "string"},
				},
			},
			CallTemplate:        makeTemplate("project_oscal", []string{"subject", "document_type"}, "assurance.services.v1.OSCALProjectionService", "ProjectAssessmentResults"),
			AverageResponseSize: 8192,
			RequiredCapability:  "tool:read-evidence",
		}),
		decorateTool(Tool{
			Name:        "run_doctor",
			Description: "Run deep system preflight diagnostics across Kubernetes, SPIFFE/SPIRE, Sigstore, CAS, and NIST OSCAL schemas.",
			Tags:        []string{"doctor", "diagnostics", "preflight", "health", "day2"},
			Inputs: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			Outputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"overall_status": map[string]interface{}{"type": "string"},
					"checks":         map[string]interface{}{"type": "array"},
				},
			},
			CallTemplate:        makeTemplate("run_doctor", nil, "assurance.services.v1.DiagnosticsService", "RunDoctor"),
			AverageResponseSize: 2048,
			RequiredCapability:  "tool:query-metrics",
		}),
		decorateTool(Tool{
			Name:        "inspect_subject",
			Description: "Reconstruct all 4 Truth Channels (Telemetry, Execution, Decision, Evidence) for a governed workload subject.",
			Tags:        []string{"inspect", "truth-channels", "forensics", "evidence", "trace"},
			Inputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"subject": map[string]interface{}{
						"type":        "string",
						"description": "Subject URI (e.g. k8s://prod/payments/Deployment/payments-api)",
					},
					"control": map[string]interface{}{
						"type":        "string",
						"description": "Control ID (e.g. nist-sp-800-53:AC-6)",
						"default":     "nist-sp-800-53:AC-6",
					},
				},
				"required": []string{"subject"},
			},
			Outputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"subject":         map[string]interface{}{"type": "string"},
					"assurance_state": map[string]interface{}{"type": "string"},
					"telemetry":       map[string]interface{}{"type": "object"},
					"execution":       map[string]interface{}{"type": "object"},
					"decision":        map[string]interface{}{"type": "object"},
					"evidence":        map[string]interface{}{"type": "object"},
				},
			},
			CallTemplate:        makeTemplate("inspect_subject", []string{"subject", "control"}, "assurance.services.v1.DiagnosticsService", "InspectSubject"),
			AverageResponseSize: 3072,
			RequiredCapability:  "tool:read-evidence",
		}),
	}

	return UTCPManual{
		Version:       ManualVersion,
		UTCPVersion:   UTCPVersion,
		ManualVersion: ManualVersion,
		Info: Info{
			Title:       "CKODEX OSKAL Continuous Assurance UTCP Manual",
			Version:     "v1.0.0",
			Description: "Universal Tool Calling Protocol (UTCP) manual for CKODEX OSKAL Continuous Kubernetes Assurance & NIST OSCAL v1.2.3 Runtime.",
			Homepage:    "https://github.com/ckodex-labs/ckodex-oskal",
		},
		AllowedCommunicationProtocols: AllowedTransports,
		Tools:                         tools,
	}
}

// ValidateManual validates a UTCP manual against utcp-specification v1.0.x and CKODEX transport invariants.
func ValidateManual(manual UTCPManual) error {
	if strings.TrimSpace(manual.UTCPVersion) == "" {
		return errors.New("utcp manual missing required field 'utcp_version'")
	}
	if strings.TrimSpace(manual.ManualVersion) == "" {
		return errors.New("utcp manual missing required field 'manual_version'")
	}
	if len(manual.Tools) == 0 {
		return errors.New("utcp manual must declare at least one tool in 'tools'")
	}

	allowedProtoSet := make(map[string]bool)
	for _, proto := range manual.AllowedCommunicationProtocols {
		pLower := strings.ToLower(strings.TrimSpace(proto))
		if pLower == "websocket" || pLower == "ws" {
			return fmt.Errorf("ANTI_WEBSOCKET_FORBIDDEN: protocol '%s' violates CKODEX Constitution Section 10", proto)
		}
		if pLower != "" {
			allowedProtoSet[pLower] = true
		}
	}

	seen := make(map[string]bool)
	for i, t := range manual.Tools {
		if strings.TrimSpace(t.Name) == "" {
			return fmt.Errorf("tool[%d] missing required 'name'", i)
		}
		if seen[t.Name] {
			return fmt.Errorf("duplicate tool name '%s' in utcp manual", t.Name)
		}
		seen[t.Name] = true

		if strings.TrimSpace(t.Description) == "" {
			return fmt.Errorf("tool '%s' missing required 'description'", t.Name)
		}
		if len(t.Inputs) == 0 && len(t.InputSchema) == 0 {
			return fmt.Errorf("tool '%s' missing required 'inputs' or 'input_schema'", t.Name)
		}

		tmpl := t.EffectiveCallTemplate()
		tType := strings.ToLower(strings.TrimSpace(tmpl.CallTemplateType))
		if tType == "" {
			tType = strings.ToLower(strings.TrimSpace(tmpl.ProviderType))
		}
		if tType == "" {
			return fmt.Errorf("tool '%s' missing required 'call_template.call_template_type' or 'provider_type'", t.Name)
		}
		if tType == "websocket" || tType == "ws" {
			return fmt.Errorf("ANTI_WEBSOCKET_FORBIDDEN: tool '%s' uses forbidden transport '%s' (CKODEX Constitution Section 10)", t.Name, tType)
		}
		if !isAllowedTransport(tType) {
			return fmt.Errorf("tool '%s' uses unsupported transport '%s'", t.Name, tType)
		}
		if len(allowedProtoSet) > 0 && !allowedProtoSet[tType] {
			return fmt.Errorf("tool '%s' transport '%s' is not in manual allowed_communication_protocols %v", t.Name, tType, manual.AllowedCommunicationProtocols)
		}
	}

	return nil
}

// EffectiveCallTemplate resolves the active call template across v1.0 and v0.1 fields.
func (t Tool) EffectiveCallTemplate() CallTemplate {
	if t.CallTemplate.CallTemplateType != "" || t.CallTemplate.ProviderType != "" {
		return t.CallTemplate
	}
	if t.ToolCallTemplate != nil && (t.ToolCallTemplate.CallTemplateType != "" || t.ToolCallTemplate.ProviderType != "") {
		return *t.ToolCallTemplate
	}
	if t.ToolProvider != nil {
		return *t.ToolProvider
	}
	return t.CallTemplate
}

func isAllowedTransport(t string) bool {
	for _, a := range AllowedTransports {
		if a == t {
			return true
		}
	}
	return false
}

// ToolCallResult encapsulates the result of a governed UTCP tool execution and its optional CheckReceipt.
type ToolCallResult struct {
	ToolName    string                  `json:"tool_name"`
	Transport   string                  `json:"transport"`
	Output      interface{}             `json:"output"`
	Receipt     *assurance.CheckReceipt `json:"receipt,omitempty"`
	EvaluatedAt time.Time               `json:"evaluated_at"`
}

// Registry manages registered UTCP manuals, providers, tool discovery, and governed tool execution.
type Registry struct {
	mu          sync.RWMutex
	manuals     map[string]UTCPManual
	providers   map[string]ProviderConfig
	tools       map[string]Tool
	evidenceDir string
	broker      *workcell.EffectBroker
	validator   *proj.Validator
	projector   *proj.Projector
	explainer   *explain.Explainer
}

// NewRegistry creates a UTCP Registry pre-populated with the built-in OSKAL UTCP manual.
func NewRegistry(evidenceDir string, broker *workcell.EffectBroker) (*Registry, error) {
	val, err := proj.DefaultValidator()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OSCAL validator for UTCP registry: %w", err)
	}
	r := &Registry{
		manuals:     make(map[string]UTCPManual),
		providers:   make(map[string]ProviderConfig),
		tools:       make(map[string]Tool),
		evidenceDir: evidenceDir,
		broker:      broker,
		validator:   val,
		projector:   proj.NewProjector(),
		explainer:   explain.NewExplainer(),
	}
	defaultManual := BuildOSKALManual(DefaultManualOptions())
	_ = r.registerManualInternal("oskal", defaultManual)
	return r, nil
}

func (r *Registry) registerManualInternal(name string, manual UTCPManual) error {
	if err := ValidateManual(manual); err != nil {
		return err
	}
	if name == "" {
		name = manual.Info.Title
		if name == "" {
			name = "default"
		}
	}
	if manual.Version == "" {
		manual.Version = manual.ManualVersion
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.manuals[name]; !exists && len(r.manuals) >= MaxRegisteredManuals {
		return fmt.Errorf("utcp registry capacity exceeded: maximum %d manuals allowed", MaxRegisteredManuals)
	}
	newTools := 0
	for _, t := range manual.Tools {
		if _, exists := r.tools[t.Name]; !exists {
			newTools++
		}
	}
	if len(r.tools)+newTools > MaxRegisteredTools {
		return fmt.Errorf("utcp registry tool capacity exceeded: maximum %d tools allowed", MaxRegisteredTools)
	}

	r.manuals[name] = manual
	for _, t := range manual.Tools {
		if len(t.Inputs) == 0 && len(t.InputSchema) > 0 {
			t.Inputs = t.InputSchema
		}
		if len(t.InputSchema) == 0 && len(t.Inputs) > 0 {
			t.InputSchema = t.Inputs
		}
		r.tools[t.Name] = t
	}
	return nil
}

// RegisterManual validates and registers a UTCPManual in the registry.
// When the registry is governed by an EffectBroker, a valid CapabilityLease is required via RegisterManualWithLease.
func (r *Registry) RegisterManual(name string, manual UTCPManual) error {
	return r.RegisterManualWithLease(context.Background(), name, manual, "", "")
}

// RegisterManualWithLease validates and registers a UTCPManual gated by the registry's EffectBroker when present.
func (r *Registry) RegisterManualWithLease(ctx context.Context, name string, manual UTCPManual, leaseID, prevReceiptHash string) error {
	if r.broker != nil {
		if leaseID == "" {
			leaseID, prevReceiptHash = leaseFromContext(ctx)
		}
		payload, _ := json.Marshal(map[string]interface{}{"name": name, "utcp_version": manual.UTCPVersion})
		if _, err := r.broker.RequestExecution(ctx, leaseID, "utcp:register-manual", payload, prevReceiptHash); err != nil {
			return fmt.Errorf("UTCP capability lease gate denied manual registration '%s': %w", name, err)
		}
	}
	return r.registerManualInternal(name, manual)
}

func validateHTTPProviderURL(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("invalid provider URL '%s': %w", rawURL, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" {
		return fmt.Errorf("provider URL '%s' must use http:// or https:// scheme with a non-empty host", rawURL)
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return fmt.Errorf("provider URL '%s' has empty hostname", rawURL)
	}
	// Block cloud instance metadata and link-local / unspecified SSRF targets (Constitution Section 25).
	if host == "metadata.google.internal" || host == "metadata" || host == "100.100.100.200" {
		return fmt.Errorf("SSRF_BLOCKED: provider URL '%s' targets restricted cloud metadata endpoint", rawURL)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("SSRF_BLOCKED: provider URL '%s' targets forbidden link-local or unspecified IP %s", rawURL, ip.String())
		}
	}
	return nil
}

func newSafeHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("exceeded maximum of 3 HTTP redirects")
			}
			return validateHTTPProviderURL(req.URL.String())
		},
	}
}

func isRetryableHTTPStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// doHTTPWithRetry executes an HTTP request with bounded retries, exponential backoff, and jitter (Constitution Section 30).
// Non-idempotent methods default to maxAttempts=1 unless explicitly overridden.
func doHTTPWithRetry(ctx context.Context, client *http.Client, buildReq func() (*http.Request, error), maxAttempts int) (*http.Response, error) {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		req, err := buildReq()
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err == nil {
			if !isRetryableHTTPStatus(resp.StatusCode) || attempt == maxAttempts {
				return resp, nil
			}
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("transient HTTP status %d", resp.StatusCode)
		} else {
			lastErr = err
			if attempt == maxAttempts {
				return nil, lastErr
			}
		}

		backoff := 40 * time.Millisecond * time.Duration(1<<(attempt-1))
		jitter := time.Duration(rand.Int63n(int64(20 * time.Millisecond)))
		timer := time.NewTimer(backoff + jitter)
		if ctx != nil {
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		} else {
			<-timer.C
		}
	}
	return nil, lastErr
}

// RegisterToolProvider registers a UTCP provider and loads its manual if reachable via file or HTTP.
func (r *Registry) RegisterToolProvider(ctx context.Context, cfg ProviderConfig) error {
	if strings.TrimSpace(cfg.Name) == "" {
		return errors.New("provider config requires a non-empty 'name'")
	}
	pType := strings.ToLower(strings.TrimSpace(cfg.ProviderType))
	if pType == "" {
		pType = strings.ToLower(strings.TrimSpace(cfg.CallTemplateType))
	}
	if pType == "websocket" || pType == "ws" {
		return fmt.Errorf("ANTI_WEBSOCKET_FORBIDDEN: provider '%s' uses forbidden transport '%s'", cfg.Name, pType)
	}
	if !isAllowedTransport(pType) {
		return fmt.Errorf("provider '%s' uses unsupported provider_type '%s'", cfg.Name, pType)
	}

	if r.broker != nil {
		leaseID := cfg.LeaseID
		prevHash := cfg.PrevReceiptHash
		if leaseID == "" {
			leaseID, prevHash = leaseFromContext(ctx)
		}
		capName := cfg.RequiredCapability
		if capName == "" {
			capName = "utcp:register-provider"
		}
		payload, _ := json.Marshal(map[string]interface{}{
			"name":          cfg.Name,
			"provider_type": pType,
			"url":           cfg.URL,
			"file_path":     cfg.FilePath,
		})
		if _, err := r.broker.RequestExecution(ctx, leaseID, capName, payload, prevHash); err != nil {
			return fmt.Errorf("UTCP capability lease gate denied provider registration '%s': %w", cfg.Name, err)
		}
	}

	if cfg.FilePath != "" {
		data, err := os.ReadFile(cfg.FilePath)
		if err != nil {
			return fmt.Errorf("failed to read UTCP manual file %s: %w", cfg.FilePath, err)
		}
		var m UTCPManual
		if err := json.Unmarshal(data, &m); err != nil {
			return fmt.Errorf("failed to parse UTCP manual file %s: %w", cfg.FilePath, err)
		}
		if err := r.registerManualInternal(cfg.Name, m); err != nil {
			return err
		}
	} else if (pType == "http" || pType == "streamable_http") && cfg.URL != "" {
		if err := validateHTTPProviderURL(cfg.URL); err != nil {
			return err
		}
		client := newSafeHTTPClient(5 * time.Second)
		resp, err := doHTTPWithRetry(ctx, client, func() (*http.Request, error) {
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, cfg.URL, nil)
			if reqErr != nil {
				return nil, reqErr
			}
			for k, v := range cfg.Headers {
				req.Header.Set(k, v)
			}
			return req, nil
		}, 3)
		if err != nil {
			return fmt.Errorf("failed to fetch UTCP manual from %s: %w", cfg.URL, err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("UTCP manual endpoint %s returned HTTP %d", cfg.URL, resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		if err != nil {
			return fmt.Errorf("failed to read UTCP manual response from %s: %w", cfg.URL, err)
		}
		var m UTCPManual
		if err := json.Unmarshal(body, &m); err != nil {
			return fmt.Errorf("failed to decode UTCP manual JSON from %s: %w", cfg.URL, err)
		}
		if err := r.registerManualInternal(cfg.Name, m); err != nil {
			return err
		}
	}

	r.mu.Lock()
	r.providers[cfg.Name] = cfg
	r.mu.Unlock()
	return nil
}

// DeregisterManual removes a registered manual/provider and its tools, enforcing CapabilityLease governance when broker is set.
func (r *Registry) DeregisterManual(ctx context.Context, name, leaseID, prevReceiptHash string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("manual_name is required")
	}
	if r.broker != nil {
		if leaseID == "" {
			leaseID, prevReceiptHash = leaseFromContext(ctx)
		}
		payload, _ := json.Marshal(map[string]interface{}{"name": name})
		if _, err := r.broker.RequestExecution(ctx, leaseID, "utcp:deregister-manual", payload, prevReceiptHash); err != nil {
			return fmt.Errorf("UTCP capability lease gate denied manual deregistration '%s': %w", name, err)
		}
	}
	r.deregisterUnlocked(name)
	return nil
}

// DeregisterToolProvider removes a provider and its manual from the registry.
func (r *Registry) DeregisterToolProvider(name string) {
	if r.broker != nil {
		_ = r.DeregisterManual(context.Background(), name, "", "")
		return
	}
	r.deregisterUnlocked(name)
}

func (r *Registry) deregisterUnlocked(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.providers, name)
	if m, ok := r.manuals[name]; ok {
		for _, t := range m.Tools {
			delete(r.tools, t.Name)
		}
		delete(r.manuals, name)
	}
}

// resolveTool resolves both unprefixed ("get_assurance_state") and namespaced
// ("oskal.get_assurance_state", "ckodex_oskal.get_assurance_state", "<provider>.<tool>") tool names.
func (r *Registry) resolveTool(toolName string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	trimmed := strings.TrimSpace(toolName)
	if t, ok := r.tools[trimmed]; ok {
		return t, true
	}
	if idx := strings.LastIndex(trimmed, "."); idx > 0 && idx < len(trimmed)-1 {
		prefix := trimmed[:idx]
		shortName := trimmed[idx+1:]
		if t, ok := r.tools[shortName]; ok {
			_, inManuals := r.manuals[prefix]
			_, inProviders := r.providers[prefix]
			if inManuals || inProviders || isKnownOSKALNamespace(prefix) {
				return t, true
			}
		}
	}
	return Tool{}, false
}

func isKnownOSKALNamespace(prefix string) bool {
	switch strings.ToLower(strings.TrimSpace(prefix)) {
	case "oskal", "ckodex_oskal", "ckodex_oskal_http", "ckodex_oskal_cli", "oskal_http", "oskal_cli", "oskal_grpc", "oskal_mcp":
		return true
	default:
		return false
	}
}

// GetTool looks up a tool by exact or namespaced name ("<manual>.<tool>").
func (r *Registry) GetTool(toolName string) (Tool, bool) {
	return r.resolveTool(toolName)
}

// RequiredVariablesForTool returns the list of required variable/input keys and auth variables for a tool.
func (r *Registry) RequiredVariablesForTool(toolName string) ([]string, error) {
	tool, ok := r.resolveTool(toolName)
	if !ok {
		return nil, fmt.Errorf("utcp tool '%s' not found in registry", toolName)
	}
	seen := make(map[string]bool)
	var keys []string
	addKey := func(k string) {
		k = strings.TrimSpace(k)
		if k != "" && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}

	schema := tool.Inputs
	if len(schema) == 0 {
		schema = tool.InputSchema
	}
	if reqSlice, ok := schema["required"].([]string); ok {
		for _, k := range reqSlice {
			addKey(k)
		}
	} else if reqIface, ok := schema["required"].([]interface{}); ok {
		for _, item := range reqIface {
			if ks, ok := item.(string); ok {
				addKey(ks)
			}
		}
	}
	tmpl := tool.EffectiveCallTemplate()
	if tmpl.Auth != nil && tmpl.Auth.VarName != "" {
		addKey(tmpl.Auth.VarName)
	}
	if keys == nil {
		keys = []string{}
	}
	return keys, nil
}

// ListTools returns all registered UTCP tools sorted deterministically by name.
func (r *Registry) ListTools() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

// SearchTools searches registered UTCP tools by keyword query and optional tags, returning ranked matches.
func (r *Registry) SearchTools(query string, tags []string, limit int) []Tool {
	all := r.ListTools()
	q := strings.ToLower(strings.TrimSpace(query))
	tokens := strings.Fields(q)

	type scored struct {
		tool  Tool
		score int
	}
	var matches []scored

	for _, t := range all {
		score := 0
		nameLower := strings.ToLower(t.Name)
		descLower := strings.ToLower(t.Description)

		if q == "" && len(tags) == 0 {
			score = 1
		}
		if q != "" {
			if nameLower == q {
				score += 100
			} else if strings.Contains(nameLower, q) {
				score += 50
			}
			if strings.Contains(descLower, q) {
				score += 25
			}
			for _, tok := range tokens {
				if strings.Contains(nameLower, tok) {
					score += 20
				}
				if strings.Contains(descLower, tok) {
					score += 10
				}
				for _, tag := range t.Tags {
					if strings.Contains(strings.ToLower(tag), tok) {
						score += 15
					}
				}
			}
		}

		for _, reqTag := range tags {
			rt := strings.ToLower(strings.TrimSpace(reqTag))
			if rt == "" {
				continue
			}
			for _, toolTag := range t.Tags {
				if strings.EqualFold(toolTag, rt) {
					score += 30
				}
			}
		}

		if score > 0 {
			matches = append(matches, scored{tool: t, score: score})
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].score != matches[j].score {
			return matches[i].score > matches[j].score
		}
		return matches[i].tool.Name < matches[j].tool.Name
	})

	if limit > 0 && len(matches) > limit {
		matches = matches[:limit]
	}

	res := make([]Tool, len(matches))
	for i, m := range matches {
		res[i] = m.tool
	}
	return res
}

// CallTool executes a registered UTCP tool directly and enforces CapabilityLease governance whenever r.broker is configured.
func (r *Registry) CallTool(
	ctx context.Context,
	toolName string,
	args map[string]interface{},
	leaseID string,
	prevReceiptHash string,
) (*ToolCallResult, error) {
	tool, ok := r.resolveTool(toolName)
	if !ok {
		return nil, fmt.Errorf("utcp tool '%s' not found in registry", toolName)
	}
	if args == nil {
		args = make(map[string]interface{})
	}

	var checkRcpt *assurance.CheckReceipt
	if r.broker != nil {
		if leaseID == "" {
			leaseID, prevReceiptHash = leaseFromContext(ctx)
		}
		capName := tool.RequiredCapability
		if capName == "" {
			capName = "utcp:" + tool.Name
		}
		payload, _ := json.Marshal(args)
		rcpt, err := r.broker.RequestExecution(ctx, leaseID, capName, payload, prevReceiptHash)
		if err != nil {
			return nil, fmt.Errorf("UTCP capability lease gate denied execution of '%s': %w", tool.Name, err)
		}
		checkRcpt = rcpt
	}

	output, err := r.executeNativeTool(ctx, tool, args)
	if err != nil {
		return nil, err
	}

	tmpl := tool.EffectiveCallTemplate()
	transport := tmpl.CallTemplateType
	if transport == "" {
		transport = tmpl.ProviderType
	}

	return &ToolCallResult{
		ToolName:    tool.Name,
		Transport:   transport,
		Output:      output,
		Receipt:     checkRcpt,
		EvaluatedAt: time.Now().UTC(),
	}, nil
}

func (r *Registry) loadSubjectEnvelopes(ctx context.Context, sub assurance.SubjectRef) []assurance.EvidenceEnvelope {
	if r.evidenceDir == "" {
		return nil
	}
	repo, err := storage.NewFilesystemEvidenceRepository(r.evidenceDir)
	if err != nil {
		return nil
	}
	envelopes, err := repo.ListBySubject(ctx, sub)
	if err != nil {
		return nil
	}
	return envelopes
}

func isEnvelopeViolation(obsType string) bool {
	lower := strings.ToLower(strings.TrimSpace(obsType))
	return strings.Contains(lower, "violation") ||
		strings.Contains(lower, "denied") ||
		strings.Contains(lower, "fail") ||
		strings.Contains(lower, "adverse")
}

func countEpochDivergences(envelopes []assurance.EvidenceEnvelope) int {
	var basePol, baseImp, baseAuth string
	polDrift, impDrift, authDrift := false, false, false
	now := time.Now().UTC()
	for _, env := range envelopes {
		if env.CapturedAt.IsZero() || env.CapturedAt.After(now.Add(1*time.Minute)) {
			continue
		}
		if env.Epoch.PolicyDigest != "" {
			if basePol == "" {
				basePol = env.Epoch.PolicyDigest
			} else if env.Epoch.PolicyDigest != basePol {
				polDrift = true
			}
		}
		if env.Epoch.ImplementationDigest != "" {
			if baseImp == "" {
				baseImp = env.Epoch.ImplementationDigest
			} else if env.Epoch.ImplementationDigest != baseImp {
				impDrift = true
			}
		}
		if env.Epoch.AuthorityDigest != "" {
			if baseAuth == "" {
				baseAuth = env.Epoch.AuthorityDigest
			} else if env.Epoch.AuthorityDigest != baseAuth {
				authDrift = true
			}
		}
	}
	dims := 0
	if polDrift {
		dims++
	}
	if impDrift {
		dims++
	}
	if authDrift {
		dims++
	}
	return dims
}

func (r *Registry) buildEvaluation(sub assurance.SubjectRef, ctrl assurance.ControlRef, envelopes []assurance.EvidenceEnvelope) assurance.ClaimEvaluation {
	now := time.Now().UTC()
	var validEnvelopes []assurance.EvidenceEnvelope
	isStale := false
	isViolation := false
	for _, env := range envelopes {
		if env.CapturedAt.IsZero() || env.CapturedAt.After(now.Add(1*time.Minute)) {
			continue
		}
		if isEnvelopeViolation(env.ObservationType) {
			isViolation = true
		}
		if now.Sub(env.CapturedAt) > DefaultFreshnessWindow {
			isStale = true
		}
		validEnvelopes = append(validEnvelopes, env)
	}
	if len(validEnvelopes) == 0 {
		return assurance.ClaimEvaluation{
			ID:           fmt.Sprintf("eval-unknown-%s", ctrl.ID),
			Subject:      sub,
			Control:      ctrl,
			State:        assurance.AssuranceStateUnknown,
			Epoch:        assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeStringDigest(sub.URI())},
			Completeness: assurance.EvidenceCompleteness{Required: 1, Verified: 0, Missing: 1},
			EvaluatedAt:  now,
		}
	}
	var evRefs []assurance.EvidenceRef
	for _, env := range validEnvelopes {
		evRefs = append(evRefs, env.Artifact)
	}
	evRoot := receipts.ComputeEvidenceRoot(evRefs)
	state := assurance.AssuranceStateAssured
	comp := assurance.EvidenceCompleteness{Required: len(evRefs), Present: len(evRefs), Verified: len(evRefs)}
	if isViolation {
		state = assurance.AssuranceStateFailed
		comp = assurance.EvidenceCompleteness{Required: len(evRefs), Present: len(evRefs), Verified: 0, Missing: 1}
	} else if isStale {
		state = assurance.AssuranceStateStale
		comp = assurance.EvidenceCompleteness{Required: len(evRefs), Present: len(evRefs), Verified: 0, Stale: len(evRefs)}
	}
	return assurance.ClaimEvaluation{
		ID:      fmt.Sprintf("eval-%s", ctrl.ID),
		Subject: sub,
		Control: ctrl,
		State:   state,
		Epoch: assurance.AssuranceEpoch{
			SubjectDigest:        assurance.ComputeStringDigest(sub.URI()),
			ImplementationDigest: assurance.ComputeStringDigest("kubernetes:admission-policy"),
			PolicyDigest:         assurance.ComputeStringDigest(sub.URI() + ":" + evRoot),
			AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/operator"),
			EnvironmentDigest:    assurance.ComputeStringDigest("cluster:local"),
		},
		Evidence:     evRefs,
		Completeness: comp,
		EvidenceRoot: evRoot,
		EvaluatedAt:  now,
		ValidUntil:   now.Add(5 * time.Minute),
	}
}

func (r *Registry) executeNativeTool(ctx context.Context, tool Tool, args map[string]interface{}) (interface{}, error) {
	switch tool.Name {
	case "get_assurance_state":
		subRaw, _ := args["subject"].(string)
		if subRaw == "" {
			return nil, errors.New("subject argument is required")
		}
		sub := parseSubjectRef(subRaw)
		ctrl := assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
		envelopes := r.loadSubjectEnvelopes(ctx, sub)
		eval := r.buildEvaluation(sub, ctrl, envelopes)

		switch eval.State {
		case assurance.AssuranceStateAssured:
			return map[string]interface{}{
				"subject":       sub.URI(),
				"state":         "ASSURED",
				"status":        "Verified evidence present in CAS",
				"evidence_root": eval.EvidenceRoot,
				"freshness":     "current",
				"vector_state": map[string]string{
					"presence":  "PRESENT",
					"valence":   "POSITIVE",
					"coherence": "COHERENT",
					"evidence":  "VERIFIED",
					"lifecycle": "ACTIVE",
				},
				"last_evaluated": eval.EvaluatedAt.Format(time.RFC3339),
			}, nil
		case assurance.AssuranceStateFailed:
			return map[string]interface{}{
				"subject":       sub.URI(),
				"state":         "FAILED",
				"status":        "Adverse or violation evidence observed in CAS",
				"evidence_root": eval.EvidenceRoot,
				"freshness":     "current",
				"vector_state": map[string]string{
					"presence":  "PRESENT",
					"valence":   "NEGATIVE",
					"coherence": "DECOHERENT",
					"evidence":  "VERIFIED",
					"lifecycle": "DEGRADED",
				},
				"last_evaluated": eval.EvaluatedAt.Format(time.RFC3339),
			}, nil
		case assurance.AssuranceStateStale:
			return map[string]interface{}{
				"subject":       sub.URI(),
				"state":         "STALE",
				"status":        "Evidence in CAS exceeded maximum freshness window",
				"evidence_root": eval.EvidenceRoot,
				"freshness":     "stale",
				"vector_state": map[string]string{
					"presence":  "PRESENT",
					"valence":   "MIXED",
					"coherence": "COHERENT",
					"evidence":  "STALE",
					"lifecycle": "DEGRADED",
				},
				"last_evaluated": eval.EvaluatedAt.Format(time.RFC3339),
			}, nil
		default:
			return map[string]interface{}{
				"subject":       sub.URI(),
				"state":         "UNKNOWN",
				"status":        "Absence of verified evidence (Section 15: EMPTY != NEGATIVE)",
				"evidence_root": "none",
				"freshness":     "unknown",
				"vector_state": map[string]string{
					"presence":  "EMPTY",
					"valence":   "NEUTRAL",
					"coherence": "COHERENT",
					"evidence":  "UNKNOWN",
					"lifecycle": "UNKNOWN",
				},
				"last_evaluated": eval.EvaluatedAt.Format(time.RFC3339),
			}, nil
		}

	case "explain_claim":
		subRaw, _ := args["subject"].(string)
		if subRaw == "" {
			return nil, errors.New("subject argument is required")
		}
		sub := parseSubjectRef(subRaw)
		ctrlID := "AC-6"
		ctrlNS := "nist-sp-800-53"
		if rawCtrl, ok := args["control"].(string); ok && rawCtrl != "" {
			parts := strings.SplitN(rawCtrl, ":", 2)
			if len(parts) == 2 {
				ctrlNS = parts[0]
				ctrlID = parts[1]
			} else {
				ctrlID = rawCtrl
			}
		}
		ctrl := assurance.ControlRef{Namespace: ctrlNS, ID: ctrlID}
		envelopes := r.loadSubjectEnvelopes(ctx, sub)
		eval := r.buildEvaluation(sub, ctrl, envelopes)
		graph := r.explainer.BuildExplainGraph(ctx, sub, ctrl, eval)
		return map[string]interface{}{
			"subject":         sub.URI(),
			"control":         ctrl.Canonical(),
			"assurance_state": graph.AssuranceState.String(),
			"rendered_text":   graph.RenderText(),
		}, nil

	case "validate_oscal":
		content, _ := args["content"].(string)
		if content == "" {
			return nil, errors.New("content argument is required")
		}
		schemaOverride, _ := args["schema"].(string)
		report, err := r.validator.Validate([]byte(content), schemaOverride)
		if err != nil {
			return nil, err
		}
		return report, nil

	case "detect_drift":
		subRaw, _ := args["subject"].(string)
		if subRaw == "" {
			return nil, errors.New("subject argument is required")
		}
		sub := parseSubjectRef(subRaw)
		ctrl := assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
		envelopes := r.loadSubjectEnvelopes(ctx, sub)
		eval := r.buildEvaluation(sub, ctrl, envelopes)
		epochDriftDims := countEpochDivergences(envelopes)
		if epochDriftDims > 0 && eval.State == assurance.AssuranceStateAssured {
			return map[string]interface{}{
				"subject":          sub.URI(),
				"status":           "DECOHERENT",
				"assurance_status": "FAILED",
				"drift_dimensions": epochDriftDims,
				"reason":           "Epoch digest divergence detected across active evidence envelopes",
			}, nil
		}
		switch eval.State {
		case assurance.AssuranceStateAssured:
			return map[string]interface{}{
				"subject":          sub.URI(),
				"status":           "IN_SYNC",
				"assurance_status": "ASSURED",
				"drift_dimensions": 0,
			}, nil
		case assurance.AssuranceStateFailed:
			dims := epochDriftDims
			if dims == 0 {
				dims = 1
			}
			return map[string]interface{}{
				"subject":          sub.URI(),
				"status":           "DECOHERENT",
				"assurance_status": "FAILED",
				"drift_dimensions": dims,
				"reason":           "Adverse or violation evidence observed in CAS",
			}, nil
		case assurance.AssuranceStateStale:
			return map[string]interface{}{
				"subject":          sub.URI(),
				"status":           "DRIFT_DETECTED",
				"assurance_status": "STALE",
				"drift_dimensions": 1,
			}, nil
		default:
			return map[string]interface{}{
				"subject":          sub.URI(),
				"status":           "UNKNOWN",
				"assurance_status": "UNKNOWN",
				"drift_dimensions": 0,
				"reason":           "Absence of verified baseline evidence",
			}, nil
		}

	case "scaffold_compliance":
		profile, _ := args["profile"].(string)
		if profile == "" {
			return nil, errors.New("profile argument is required")
		}
		workload, _ := args["workload"].(string)
		namespace, _ := args["namespace"].(string)
		plan, err := scaffold.GenerateScaffold(profile, namespace, workload)
		if err != nil {
			return nil, err
		}
		yamlStr, err := plan.RenderManifestsYAML()
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"profile":        profile,
			"manifests_yaml": yamlStr,
		}, nil

	case "project_oscal":
		subRaw, _ := args["subject"].(string)
		docType, _ := args["document_type"].(string)
		if subRaw == "" || docType == "" {
			return nil, errors.New("subject and document_type arguments are required")
		}
		sub := parseSubjectRef(subRaw)
		ctrl := assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
		envelopes := r.loadSubjectEnvelopes(ctx, sub)
		eval := r.buildEvaluation(sub, ctrl, envelopes)

		var projected []byte
		var err error
		normDoc, _ := proj.NormalizeDocumentType(docType)
		switch normDoc {
		case proj.DocTypeAssessmentResults:
			projected, err = r.projector.ProjectAssessmentResults(ctx, sub, []assurance.ClaimEvaluation{eval}, nil)
		case proj.DocTypeComponentDefinition:
			projected, err = r.projector.ProjectComponentDefinition(ctx, sub.ID, []assurance.ClaimEvaluation{eval})
		case proj.DocTypeSSP:
			projected, err = r.projector.ProjectSSP(ctx, sub.ID, []assurance.ClaimEvaluation{eval})
		case proj.DocTypeAssessmentPlan:
			contract := assurance.EvidenceContract{
				ID: fmt.Sprintf("contract-%s", sub.ID),
				Requirements: []assurance.EvidenceRequirement{
					{ID: "req-1", EvidenceType: "admission", Required: true, MaxAge: DefaultFreshnessWindow},
				},
			}
			projected, err = r.projector.ProjectAssessmentPlan(ctx, sub, contract, []assurance.ControlRef{ctrl})
		case proj.DocTypePOAM:
			var findings []assurance.Finding
			if eval.State != assurance.AssuranceStateAssured {
				findings = append(findings, assurance.Finding{
					ID:           fmt.Sprintf("finding-%s-%s", ctrl.ID, strings.ToLower(eval.State.String())),
					Subject:      sub,
					Control:      ctrl,
					Severity:     "HIGH",
					Title:        fmt.Sprintf("Control %s Assurance State is %s", ctrl.Canonical(), eval.State),
					Description:  fmt.Sprintf("Subject %s does not have current verified evidence for %s.", sub.URI(), ctrl.Canonical()),
					DiscoveredAt: eval.EvaluatedAt,
				})
			}
			projected, err = r.projector.ProjectPOAM(ctx, sub, findings)
		default:
			return nil, fmt.Errorf("unsupported OSCAL projection document type: %s", docType)
		}
		if err != nil {
			return nil, err
		}
		return json.RawMessage(projected), nil

	case "run_doctor":
		return diagnostics.RunDoctor(ctx, r.evidenceDir), nil

	case "inspect_subject":
		subRaw, _ := args["subject"].(string)
		if subRaw == "" {
			return nil, errors.New("subject argument is required")
		}
		sub := parseSubjectRef(subRaw)
		ctrlID := "AC-6"
		ctrlNS := "nist-sp-800-53"
		if rawCtrl, ok := args["control"].(string); ok && rawCtrl != "" {
			parts := strings.SplitN(rawCtrl, ":", 2)
			if len(parts) == 2 {
				ctrlNS = parts[0]
				ctrlID = parts[1]
			} else {
				ctrlID = rawCtrl
			}
		}
		ctrl := assurance.ControlRef{Namespace: ctrlNS, ID: ctrlID}
		envelopes := r.loadSubjectEnvelopes(ctx, sub)
		eval := r.buildEvaluation(sub, ctrl, envelopes)
		return diagnostics.InspectSubject(ctx, sub, eval, envelopes), nil

	default:
		tmpl := tool.EffectiveCallTemplate()
		tType := strings.ToLower(strings.TrimSpace(tmpl.CallTemplateType))
		if tType == "" {
			tType = strings.ToLower(strings.TrimSpace(tmpl.ProviderType))
		}
		if (tType == "http" || tType == "streamable_http") && tmpl.URL != "" {
			return executeRemoteHTTPTool(ctx, tool.Name, tmpl, args)
		}
		return nil, fmt.Errorf("unsupported native execution for tool '%s'", tool.Name)
	}
}

func executeRemoteHTTPTool(ctx context.Context, toolName string, tmpl CallTemplate, args map[string]interface{}) (interface{}, error) {
	if err := validateHTTPProviderURL(tmpl.URL); err != nil {
		return nil, err
	}
	targetURL := tmpl.URL
	remainingArgs := make(map[string]interface{}, len(args))
	for k, v := range args {
		placeholder := "{" + k + "}"
		if strings.Contains(targetURL, placeholder) {
			targetURL = strings.ReplaceAll(targetURL, placeholder, url.PathEscape(fmt.Sprintf("%v", v)))
		} else {
			remainingArgs[k] = v
		}
	}

	method := strings.ToUpper(strings.TrimSpace(tmpl.HTTPMethod))
	if method == "" {
		method = http.MethodPost
	}

	var bodyBytes []byte
	hasBody := false
	if method == http.MethodGet || method == http.MethodDelete {
		u, err := url.Parse(targetURL)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		for k, v := range remainingArgs {
			q.Set(k, fmt.Sprintf("%v", v))
		}
		u.RawQuery = q.Encode()
		targetURL = u.String()
	} else {
		payload := interface{}(remainingArgs)
		if tmpl.BodyField != "" {
			if bfVal, ok := remainingArgs[tmpl.BodyField]; ok {
				payload = bfVal
				u, err := url.Parse(targetURL)
				if err != nil {
					return nil, err
				}
				q := u.Query()
				for k, v := range remainingArgs {
					if k == tmpl.BodyField {
						continue
					}
					q.Set(k, fmt.Sprintf("%v", v))
				}
				u.RawQuery = q.Encode()
				targetURL = u.String()
			}
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		bodyBytes = b
		hasBody = true
	}

	contentType := tmpl.ContentType
	if contentType == "" {
		contentType = "application/json"
	}

	attempts := 1
	if method == http.MethodGet || method == http.MethodHead {
		attempts = 3
	}
	client := newSafeHTTPClient(10 * time.Second)
	resp, err := doHTTPWithRetry(ctx, client, func() (*http.Request, error) {
		var rdr io.Reader
		if hasBody {
			rdr = bytes.NewReader(bodyBytes)
		}
		req, reqErr := http.NewRequestWithContext(ctx, method, targetURL, rdr)
		if reqErr != nil {
			return nil, reqErr
		}
		if hasBody {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("X-UTCP-Tool", toolName)
		for k, v := range tmpl.Headers {
			req.Header.Set(k, v)
		}
		return req, nil
	}, attempts)
	if err != nil {
		return nil, fmt.Errorf("remote HTTP tool '%s' request failed: %w", toolName, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed reading response from remote HTTP tool '%s': %w", toolName, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("remote HTTP tool '%s' returned status %d: %s", toolName, resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	var parsed interface{}
	if err := json.Unmarshal(respBytes, &parsed); err == nil {
		if m, ok := parsed.(map[string]interface{}); ok {
			if out, hasOut := m["output"]; hasOut && m["tool_name"] != nil {
				return out, nil
			}
		}
		return parsed, nil
	}
	return map[string]interface{}{"raw": string(respBytes)}, nil
}

func parseSubjectRef(raw string) assurance.SubjectRef {
	if strings.Contains(raw, "://") {
		parts := strings.SplitN(raw, "://", 2)
		return assurance.SubjectRef{Scheme: parts[0], ID: parts[1]}
	}
	return assurance.SubjectRef{Scheme: "k8s", ID: raw}
}

// HTTPServer exposes the standard UTCP discovery endpoint (GET /utcp, GET /.well-known/utcp.json)
// and direct HTTP tool invocation endpoints (POST /tools/call, POST /tools/search).
type HTTPServer struct {
	registry *Registry
	baseURL  string
	sem      chan struct{}
}

// NewHTTPServer constructs a native UTCP HTTP discovery and execution server.
func NewHTTPServer(registry *Registry, baseURL string) *HTTPServer {
	if baseURL == "" {
		baseURL = "http://localhost:8090"
	}
	return &HTTPServer{
		registry: registry,
		baseURL:  baseURL,
		sem:      make(chan struct{}, MaxHTTPConcurrentRequests),
	}
}

// Handler returns the http.Handler serving UTCP discovery and direct tool calls.
func (s *HTTPServer) Handler() http.Handler {
	mux := http.NewServeMux()

	handleManual := func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		manual := BuildOSKALManual(ManualOptions{
			PrimaryTransport: "http",
			BaseURL:          s.baseURL,
		})
		if s.registry != nil {
			builtIn := make(map[string]bool, len(manual.Tools))
			for _, t := range manual.Tools {
				builtIn[t.Name] = true
			}
			for _, regTool := range s.registry.ListTools() {
				if !builtIn[regTool.Name] {
					manual.Tools = append(manual.Tools, regTool)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(manual)
	}

	mux.HandleFunc("/utcp", handleManual)
	mux.HandleFunc("/.well-known/utcp.json", handleManual)

	mux.HandleFunc("/tools", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tools": s.registry.ListTools(),
		})
	})

	mux.HandleFunc("/tools/search", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost && req.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			Query           string   `json:"query"`
			TaskDescription string   `json:"task_description"`
			Tags            []string `json:"tags"`
			Limit           int      `json:"limit"`
			MaxResults      int      `json:"max_results"`
		}
		if req.Method == http.MethodGet {
			payload.Query = req.URL.Query().Get("q")
			if payload.Query == "" {
				payload.Query = req.URL.Query().Get("query")
			}
		} else {
			req.Body = http.MaxBytesReader(w, req.Body, MaxSearchBodyBytes)
			var maxBytesErr *http.MaxBytesError
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil && !errors.Is(err, io.EOF) {
				if errors.As(err, &maxBytesErr) {
					http.Error(w, "request body exceeds maximum search payload size (1 MiB)", http.StatusRequestEntityTooLarge)
					return
				}
				http.Error(w, fmt.Sprintf("invalid search JSON body: %v", err), http.StatusBadRequest)
				return
			}
		}
		q := payload.Query
		if q == "" {
			q = payload.TaskDescription
		}
		limit := payload.Limit
		if limit <= 0 {
			limit = payload.MaxResults
		}
		matches := s.registry.SearchTools(q, payload.Tags, limit)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tools": matches,
		})
	})

	mux.HandleFunc("/tools/call", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		req.Body = http.MaxBytesReader(w, req.Body, MaxCallBodyBytes)
		rawBody, err := io.ReadAll(req.Body)
		if err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				http.Error(w, "request body exceeds maximum call payload size (4 MiB)", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
			return
		}

		tName := strings.TrimSpace(req.Header.Get("X-UTCP-Tool"))
		if tName == "" {
			tName = strings.TrimSpace(req.URL.Query().Get("tool_name"))
		}
		if tName == "" {
			tName = strings.TrimSpace(req.URL.Query().Get("name"))
		}

		leaseID := strings.TrimSpace(req.Header.Get("X-UTCP-Lease-ID"))
		if leaseID == "" {
			leaseID = strings.TrimSpace(req.URL.Query().Get("lease_id"))
		}
		prevReceiptHash := strings.TrimSpace(req.Header.Get("X-UTCP-Prev-Receipt-Hash"))
		if prevReceiptHash == "" {
			prevReceiptHash = strings.TrimSpace(req.URL.Query().Get("prev_receipt_hash"))
		}

		args := make(map[string]interface{})
		for k, vals := range req.URL.Query() {
			if len(vals) == 0 {
				continue
			}
			switch k {
			case "tool_name", "lease_id", "prev_receipt_hash":
				continue
			case "name":
				if req.Header.Get("X-UTCP-Tool") == "" && req.URL.Query().Get("tool_name") == "" {
					continue
				}
			}
			args[k] = vals[0]
		}

		trimmedBody := bytes.TrimSpace(rawBody)
		if len(trimmedBody) > 0 {
			var bodyFieldKey string
			if tName != "" {
				if resolved, ok := s.registry.GetTool(tName); ok {
					bodyFieldKey = strings.TrimSpace(resolved.EffectiveCallTemplate().BodyField)
				}
			}

			var bodyMap map[string]interface{}
			if err := json.Unmarshal(trimmedBody, &bodyMap); err != nil {
				if bodyFieldKey != "" {
					var genericVal interface{}
					if json.Unmarshal(trimmedBody, &genericVal) == nil {
						args[bodyFieldKey] = genericVal
					} else {
						args[bodyFieldKey] = string(trimmedBody)
					}
				} else {
					http.Error(w, fmt.Sprintf("invalid JSON body: %v", err), http.StatusBadRequest)
					return
				}
			} else {
				if v, ok := bodyMap["tool_name"].(string); ok && strings.TrimSpace(v) != "" {
					tName = strings.TrimSpace(v)
				} else if v, ok := bodyMap["name"].(string); ok && strings.TrimSpace(v) != "" && tName == "" {
					tName = strings.TrimSpace(v)
				}
				if v, ok := bodyMap["lease_id"].(string); ok && strings.TrimSpace(v) != "" {
					leaseID = strings.TrimSpace(v)
				}
				if v, ok := bodyMap["prev_receipt_hash"].(string); ok && strings.TrimSpace(v) != "" {
					prevReceiptHash = strings.TrimSpace(v)
				}

				if bodyFieldKey == "" && tName != "" {
					if resolved, ok := s.registry.GetTool(tName); ok {
						bodyFieldKey = strings.TrimSpace(resolved.EffectiveCallTemplate().BodyField)
					}
				}

				if nested, ok := bodyMap["arguments"].(map[string]interface{}); ok {
					for k, v := range nested {
						args[k] = v
					}
				} else if nested, ok := bodyMap["tool_args"].(map[string]interface{}); ok {
					for k, v := range nested {
						args[k] = v
					}
				} else if nested, ok := bodyMap["body"].(map[string]interface{}); ok && len(bodyMap) == 1 {
					for k, v := range nested {
						args[k] = v
					}
				} else if bodyFieldKey != "" && bodyMap[bodyFieldKey] == nil && bodyMap["tool_name"] == nil && bodyMap["arguments"] == nil && bodyMap["tool_args"] == nil {
					args[bodyFieldKey] = bodyMap
					for k, v := range bodyMap {
						if k == "lease_id" || k == "prev_receipt_hash" {
							continue
						}
						args[k] = v
					}
				} else {
					for k, v := range bodyMap {
						switch k {
						case "tool_name", "arguments", "tool_args", "lease_id", "prev_receipt_hash":
							continue
						case "name":
							if _, hasToolName := bodyMap["tool_name"]; !hasToolName && req.Header.Get("X-UTCP-Tool") == "" {
								continue
							}
						}
						args[k] = v
					}
				}
			}
		}

		res, err := s.registry.CallTool(req.Context(), tName, args, leaseID, prevReceiptHash)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": err.Error(),
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-OSKAL-Mode", "DEGRADED_CONTAINED")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error": fmt.Sprintf("internal UTCP handler panic recovered: %v", rec),
				})
			}
		}()

		if req.URL.Path != "/healthz" && s.sem != nil {
			select {
			case s.sem <- struct{}{}:
				defer func() { <-s.sem }()
			default:
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error": "server concurrency limit reached; retry after backpressure clears",
				})
				return
			}
		}

		mux.ServeHTTP(w, req)
	})
}

// SDKBundle holds generated configuration and integration code for all official UTCP SDKs.
type SDKBundle struct {
	Language    string `json:"language"`
	Repository  string `json:"repository"`
	ConfigJSON  string `json:"config_json"`
	CodeSnippet string `json:"code_snippet"`
}

// GenerateSDKConfigs produces ready-to-run provider configurations and client snippets for:
// - go-utcp (github.com/universal-tool-calling-protocol/go-utcp)
// - rs-utcp (github.com/universal-tool-calling-protocol/rs-utcp)
// - typescript-utcp (github.com/universal-tool-calling-protocol/typescript-utcp)
// - python-utcp (github.com/universal-tool-calling-protocol/python-utcp)
// - utcp-mcp (github.com/universal-tool-calling-protocol/utcp-mcp)
func GenerateSDKConfigs(baseURL, binaryPath string) []SDKBundle {
	if baseURL == "" {
		baseURL = "http://localhost:8090"
	}
	if binaryPath == "" {
		binaryPath = "oskal"
	}
	trimmedBase := strings.TrimRight(baseURL, "/")
	manualCmd := binaryPath + " utcp manual"
	appendTrue := true

	templates := []ProviderConfig{
		{
			Name:             "ckodex_oskal",
			ProviderType:     "http",
			CallTemplateType: "http",
			URL:              trimmedBase + "/utcp",
			HTTPMethod:       "GET",
			ContentType:      "application/json",
		},
		{
			Name:             "ckodex_oskal_cli",
			ProviderType:     "cli",
			CallTemplateType: "cli",
			Command:          manualCmd,
			Commands: []CLICommand{
				{
					Command:             manualCmd,
					AppendToFinalOutput: &appendTrue,
				},
			},
			CommandName: binaryPath,
			Args:        []string{"utcp", "manual"},
		},
	}

	providersDoc := map[string]interface{}{
		"version":               ManualVersion,
		"utcp_version":          UTCPVersion,
		"manual_call_templates": templates,
		"providers":             templates,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	_ = enc.Encode(providersDoc)
	cfgJSON := strings.TrimSpace(buf.String())

	return []SDKBundle{
		{
			Language:   "go",
			Repository: "https://github.com/universal-tool-calling-protocol/go-utcp",
			ConfigJSON: cfgJSON,
			CodeSnippet: fmt.Sprintf(`package main

import (
	"context"
	"fmt"

	"github.com/ckodex-labs/ckodex-oskal/pkg/utcp"
)

func main() {
	ctx := context.Background()
	client, _ := utcp.NewClient("")
	_ = client.RegisterToolProvider(ctx, utcp.ProviderConfig{
		Name:             "ckodex_oskal",
		ProviderType:     "http",
		CallTemplateType: "http",
		URL:              "%s/utcp",
		HTTPMethod:       "GET",
	})
	res, _ := client.CallTool(ctx, "ckodex_oskal.get_assurance_state", map[string]interface{}{
		"subject": "k8s://prod/payments/Deployment/payments-api",
	})
	fmt.Printf("UTCP State: %%+v\n", res.Output)
}`, trimmedBase),
		},
		{
			Language:   "rust",
			Repository: "https://github.com/universal-tool-calling-protocol/rs-utcp",
			ConfigJSON: cfgJSON,
			CodeSnippet: fmt.Sprintf(`// Cargo.toml: rs-utcp = "0.1", tokio = { version = "1", features = ["full"] }, serde_json = "1"
use rs_utcp::{UtcpClient, UtcpClientConfig};
use rs_utcp::providers::http::HttpProvider;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = UtcpClientConfig::default();
    let client = UtcpClient::new(config).await?;
    let provider = HttpProvider::new(
        "ckodex_oskal".to_string(),
        "%s/utcp".to_string(),
        "GET".to_string(),
    );
    client.register_tool_provider(Box::new(provider)).await?;
    let result = client.call_tool(
        "ckodex_oskal.get_assurance_state",
        json!({ "subject": "k8s://prod/payments/Deployment/payments-api" }),
    ).await?;
    println!("OSKAL Assurance State: {}", result);
    Ok(())
}`, trimmedBase),
		},
		{
			Language:   "typescript",
			Repository: "https://github.com/universal-tool-calling-protocol/typescript-utcp",
			ConfigJSON: cfgJSON,
			CodeSnippet: fmt.Sprintf(`// npm install @utcp/sdk @utcp/http
import { UtcpClient } from "@utcp/sdk";

async function run() {
  const client = await UtcpClient.create(process.cwd(), {
    manual_call_templates: [
      {
        name: "ckodex_oskal",
        call_template_type: "http",
        url: "%s/utcp",
        http_method: "GET",
      },
    ],
  });
  const state = await client.callTool("ckodex_oskal.get_assurance_state", {
    subject: "k8s://prod/payments/Deployment/payments-api",
  });
  console.log("OSKAL Assurance State:", state);
}
run();`, trimmedBase),
		},
		{
			Language:   "python",
			Repository: "https://github.com/universal-tool-calling-protocol/python-utcp",
			ConfigJSON: cfgJSON,
			CodeSnippet: fmt.Sprintf(`# pip install utcp utcp-http
import asyncio
from utcp.utcp_client import UtcpClient
from utcp_http.http_call_template import HttpCallTemplate

async def main():
    client = await UtcpClient.create(config={
        "manual_call_templates": [
            HttpCallTemplate(
                name="ckodex_oskal",
                call_template_type="http",
                url="%s/utcp",
                http_method="GET",
            )
        ]
    })
    result = await client.call_tool("ckodex_oskal.get_assurance_state", {
        "subject": "k8s://prod/payments/Deployment/payments-api",
    })
    print("OSKAL Assurance State:", result)

asyncio.run(main())`, trimmedBase),
		},
		{
			Language:   "utcp-mcp",
			Repository: "https://github.com/universal-tool-calling-protocol/utcp-mcp",
			ConfigJSON: cfgJSON,
			CodeSnippet: fmt.Sprintf(`{
  "mcpServers": {
    "oskal-utcp-mcp": {
      "command": "%s",
      "args": ["mcp"]
    }
  }
}`, binaryPath),
		},
	}
}
