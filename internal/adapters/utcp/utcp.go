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
	"github.com/ckodex-labs/ckodex-oskal/internal/application/diagnostics"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/evaluation"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	proj "github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
	"github.com/ckodex-labs/ckodex-oskal/internal/scaffold"
	"github.com/google/uuid"
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
					},
				},
				"required": []string{"subject", "control"},
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
			Inputs:      proj.ProjectionRequestSchema(),
			Outputs: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"oscal_json": map[string]interface{}{"type": "string"},
				},
			},
			CallTemplate:        makeTemplate("project_oscal", []string{"subject", "document_type", "projection_context", "control"}, "assurance.services.v1.OSCALProjectionService", "ProjectAssessmentResults"),
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
			RequiredCapability:  "utcp:run-doctor",
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
					},
				},
				"required": []string{"subject", "control"},
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
			Version:     "v1.0.1",
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
		if strings.ContainsAny(t.Name, "./") {
			return errors.New("tool names must not contain dots or slashes")
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

// ToolCallResult encapsulates the result of a governed UTCP tool execution and its completion receipt when an effect executes.
type ToolCallResult struct {
	ToolName    string                      `json:"tool_name"`
	Transport   string                      `json:"transport"`
	Output      interface{}                 `json:"output"`
	Receipt     *assurance.ExecutionReceipt `json:"receipt,omitempty"`
	EvaluatedAt time.Time                   `json:"evaluated_at"`
}

// Registry manages registered UTCP manuals, providers, tool discovery, and governed tool execution.
type Registry struct {
	mu            sync.RWMutex
	manuals       map[string]UTCPManual
	providers     map[string]ProviderConfig
	tools         map[string]Tool
	owners        map[string]string
	evidenceDir   string
	archiveLimits storage.ArchiveLimits
	broker        ports.ExecutionBroker
	validator     *proj.Validator
}

// NewRegistry creates a UTCP Registry pre-populated with the built-in OSKAL UTCP manual.
func NewRegistry(evidenceDir string, broker ports.ExecutionBroker) (*Registry, error) {
	return NewRegistryWithLimits(evidenceDir, broker, storage.DefaultArchiveLimits())
}

// NewRegistryWithLimits applies one explicit budget to all local archive access.
func NewRegistryWithLimits(evidenceDir string, broker ports.ExecutionBroker, limits storage.ArchiveLimits) (*Registry, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	val, err := proj.DefaultValidator()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OSCAL validator for UTCP registry: %w", err)
	}
	r := &Registry{
		manuals:       make(map[string]UTCPManual),
		providers:     make(map[string]ProviderConfig),
		tools:         make(map[string]Tool),
		owners:        make(map[string]string),
		evidenceDir:   evidenceDir,
		archiveLimits: limits,
		broker:        broker,
		validator:     val,
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

	if _, exists := r.manuals[name]; exists {
		return errors.New("manual already registered; deregister before replacement")
	}
	if len(r.manuals) >= MaxRegisteredManuals {
		return fmt.Errorf("utcp registry capacity exceeded: maximum %d manuals allowed", MaxRegisteredManuals)
	}
	newTools := 0
	for _, t := range manual.Tools {
		if _, exists := r.tools[name+"."+t.Name]; !exists {
			newTools++
		}
		if _, exists := r.tools[t.Name]; !exists {
			newTools++
		}
	}
	if len(r.tools)+newTools > MaxRegisteredTools {
		return fmt.Errorf("utcp registry tool capacity exceeded: maximum %d tools allowed", MaxRegisteredTools)
	}

	r.manuals[name] = manual
	builtInTools := make(map[string]bool)
	if name != "oskal" {
		if oskalManual, ok := r.manuals["oskal"]; ok {
			for _, bt := range oskalManual.Tools {
				builtInTools[bt.Name] = true
			}
		}
	}
	for _, t := range manual.Tools {
		if len(t.Inputs) == 0 && len(t.InputSchema) > 0 {
			t.Inputs = t.InputSchema
		}
		if len(t.InputSchema) == 0 && len(t.Inputs) > 0 {
			t.InputSchema = t.Inputs
		}
		if name != "" {
			r.tools[name+"."+t.Name] = t
			r.owners[name+"."+t.Name] = name
		}
		if name == "oskal" || !builtInTools[t.Name] {
			r.tools[t.Name] = t
			r.owners[t.Name] = name
		}
	}
	return nil
}

// RegisterManual validates and registers a UTCPManual in the registry.
// A valid CapabilityLease and execution broker are required via RegisterManualWithLease.
func (r *Registry) RegisterManual(name string, manual UTCPManual) error {
	return r.RegisterManualWithLease(context.Background(), name, manual, "", "")
}

// RegisterManualWithLease validates and registers a UTCPManual under a durable execution lease.
func (r *Registry) RegisterManualWithLease(ctx context.Context, name string, manual UTCPManual, leaseID, prevReceiptHash string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		name = strings.TrimSpace(manual.Info.Title)
	}
	if name == "" || strings.ContainsAny(name, "./") || isKnownOSKALNamespace(name) {
		return errors.New("manual requires a non-reserved canonical name without dots or slashes")
	}
	if err := ValidateManual(manual); err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		Name   string
		Manual UTCPManual
	}{name, manual})
	if err != nil {
		return err
	}
	// Freeze all nested caller-owned maps before admission and execution.
	var snapshot struct {
		Name   string
		Manual UTCPManual
	}
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return err
	}
	_, err = r.executeEffect(ctx, "manual", name, "utcp:register-manual", payload, leaseID, prevReceiptHash, func(context.Context) ([]byte, error) {
		if err := r.registerManualInternal(name, snapshot.Manual); err != nil {
			return nil, err
		}
		return []byte(name), nil
	})
	return err
}

// executeEffect is the sole external-effect boundary. leaseID binds namespace,
// name and UID; authentication is obtained independently inside the broker.
func (r *Registry) executeEffect(ctx context.Context, kind, name, capability string, payload []byte, leaseID, previous string, effect func(context.Context) ([]byte, error)) (*assurance.ExecutionReceipt, error) {
	if r.broker == nil {
		return nil, errors.New("UTCP capability lease gate denied: execution broker is required")
	}
	if leaseID == "" {
		leaseID, previous = leaseFromContext(ctx)
	}
	identity := strings.Split(leaseID, "/")
	if len(identity) != 3 || identity[0] == "" || identity[1] == "" || identity[2] == "" {
		return nil, errors.New("UTCP capability lease gate denied: lease_id must be namespace/name/UID")
	}
	request := assurance.ExecutionRequest{LeaseNamespace: identity[0], LeaseName: identity[1], LeaseUID: identity[2], Resource: "utcp://registry/" + kind + "/" + url.PathEscape(name), Capability: capability, Payload: payload, RequestID: uuid.NewString(), PreviousAdmissionHash: previous}
	receipt, err := r.broker.Execute(ctx, request, effect)
	if err != nil {
		return nil, fmt.Errorf("UTCP governed execution: %w", err)
	}
	return receipt, nil
}

func isBlockedMetadataOrLinkLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, blocked := range []string{
		"169.254.169.254",
		"100.100.100.200",
		"168.63.129.16",
		"fd00:ec2::254",
	} {
		if bIP := net.ParseIP(blocked); bIP != nil && ip.Equal(bIP) {
			return true
		}
	}
	return false
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
	if host == "metadata.google.internal" || host == "metadata" || host == "100.100.100.200" || host == "169.254.169.254" || host == "168.63.129.16" || host == "fd00:ec2::254" {
		return fmt.Errorf("SSRF_BLOCKED: provider URL '%s' targets restricted cloud metadata endpoint", rawURL)
	}
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedMetadataOrLinkLocalIP(ip) {
			return fmt.Errorf("SSRF_BLOCKED: provider URL '%s' targets forbidden metadata, link-local, or unspecified IP %s", rawURL, ip.String())
		}
	}
	return nil
}

func newSafeHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if ip := net.ParseIP(host); ip != nil {
				if isBlockedMetadataOrLinkLocalIP(ip) {
					return nil, fmt.Errorf("SSRF_BLOCKED: target IP %s is blocked", ip.String())
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(addrs) == 0 {
				return nil, fmt.Errorf("no IP addresses resolved for host %s", host)
			}
			for _, a := range addrs {
				if isBlockedMetadataOrLinkLocalIP(a.IP) {
					return nil, fmt.Errorf("SSRF_BLOCKED: host %s resolved to blocked IP %s", host, a.IP.String())
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0].IP.String(), port))
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
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
	cfg.Name = strings.TrimSpace(cfg.Name)
	if cfg.Name == "" || strings.ContainsAny(cfg.Name, "./") {
		return errors.New("provider config requires a non-empty 'name'")
	}
	if isKnownOSKALNamespace(cfg.Name) {
		return errors.New("cannot overwrite reserved built-in 'oskal' manual")
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

	payload, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	var snapshot ProviderConfig
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return err
	}
	_, err = r.executeEffect(ctx, "provider", cfg.Name, "utcp:register-provider", payload, cfg.LeaseID, cfg.PrevReceiptHash, func(ctx context.Context) ([]byte, error) {
		if err := r.registerProvider(ctx, snapshot, pType); err != nil {
			return nil, err
		}
		r.mu.RLock()
		defer r.mu.RUnlock()
		return json.Marshal(struct {
			Provider ProviderConfig
			Manual   UTCPManual
		}{snapshot, r.manuals[snapshot.Name]})
	})
	return err
}

func (r *Registry) registerProvider(ctx context.Context, cfg ProviderConfig, pType string) error {

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
	if len(r.providers) >= MaxRegisteredManuals {
		r.mu.Unlock()
		return errors.New("provider registry capacity exceeded")
	}
	r.providers[cfg.Name] = cfg
	r.mu.Unlock()
	return nil
}

// DeregisterManual removes a manual and its tools only under a durable lease.
func (r *Registry) DeregisterManual(ctx context.Context, name, leaseID, prevReceiptHash string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("manual_name is required")
	}
	if strings.EqualFold(name, "oskal") {
		return errors.New("cannot deregister reserved built-in 'oskal' manual")
	}
	payload, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		return err
	}
	_, err = r.executeEffect(ctx, "manual", name, "utcp:deregister-manual", payload, leaseID, prevReceiptHash, func(context.Context) ([]byte, error) {
		r.deregisterUnlocked(name)
		return []byte(name), nil
	})
	return err
}

// DeregisterToolProvider fails closed without explicit lease metadata.
func (r *Registry) DeregisterToolProvider(name string) error {
	return r.DeregisterManual(context.Background(), name, "", "")
}

func (r *Registry) deregisterUnlocked(name string) {
	if strings.EqualFold(strings.TrimSpace(name), "oskal") {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	builtInTools := make(map[string]bool)
	if oskalManual, ok := r.manuals["oskal"]; ok {
		for _, bt := range oskalManual.Tools {
			builtInTools[bt.Name] = true
		}
	}
	delete(r.providers, name)
	if m, ok := r.manuals[name]; ok {
		for _, t := range m.Tools {
			delete(r.tools, name+"."+t.Name)
			delete(r.owners, name+"."+t.Name)
			if !builtInTools[t.Name] && r.owners[t.Name] == name {
				delete(r.tools, t.Name)
				delete(r.owners, t.Name)
			}
		}
		delete(r.manuals, name)
	}
}

// resolveTool resolves both unprefixed ("get_assurance_state") and namespaced
// ("oskal.get_assurance_state", "ckodex_oskal.get_assurance_state", "<provider>.<tool>") tool names.
func (r *Registry) resolveTool(toolName string) (Tool, bool) {
	tool, _, ok := r.resolveToolOwner(toolName)
	return tool, ok
}

func (r *Registry) resolveToolOwner(toolName string) (Tool, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	key := strings.TrimSpace(toolName)
	if idx := strings.LastIndex(key, "."); idx > 0 && isKnownOSKALNamespace(key[:idx]) {
		key = "oskal." + key[idx+1:]
	}
	tool, ok := r.tools[key]
	if !ok {
		return Tool{}, "", false
	}
	// Return an independent snapshot; discovery callers cannot mutate definitions.
	encoded, err := json.Marshal(tool)
	if err != nil {
		return Tool{}, "", false
	}
	var snapshot Tool
	if json.Unmarshal(encoded, &snapshot) != nil {
		return Tool{}, "", false
	}
	return snapshot, r.owners[key], true
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

	seen := make(map[string]bool, len(r.tools))
	out := make([]Tool, 0, len(r.tools))
	for k, t := range r.tools {
		if !strings.Contains(k, ".") && !seen[t.Name] {
			seen[t.Name] = true
			out = append(out, t)
		}
	}
	for _, t := range r.tools {
		if !seen[t.Name] {
			seen[t.Name] = true
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	var snapshot []Tool
	if json.Unmarshal(encoded, &snapshot) != nil {
		return nil
	}
	return snapshot
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

// CallTool runs fixed local analysis directly and gates every external effect through a durable lease.
func (r *Registry) CallTool(
	ctx context.Context,
	toolName string,
	args map[string]interface{},
	leaseID string,
	prevReceiptHash string,
) (*ToolCallResult, error) {
	tool, owner, ok := r.resolveToolOwner(toolName)
	if !ok {
		return nil, fmt.Errorf("utcp tool '%s' not found in registry", toolName)
	}
	if args == nil {
		args = make(map[string]interface{})
	}

	var checkRcpt *assurance.ExecutionReceipt
	var output interface{}
	var err error
	if owner == "oskal" && tool.Name != "run_doctor" {
		// The immutable built-in catalog contains local analysis and rendering only.
		output, err = r.executeNativeTool(ctx, tool, args)
	} else {
		payload, encodeErr := json.Marshal(struct {
			Tool      Tool
			Arguments map[string]interface{}
		}{tool, args})
		if encodeErr != nil {
			return nil, encodeErr
		}
		var snapshot struct {
			Tool      Tool
			Arguments map[string]interface{}
		}
		if err := json.Unmarshal(payload, &snapshot); err != nil {
			return nil, err
		}
		capability := "utcp:execute-tool"
		if owner == "oskal" {
			capability = "utcp:run-doctor"
		}
		checkRcpt, err = r.executeEffect(ctx, "tool", owner+"."+tool.Name, capability, payload, leaseID, prevReceiptHash, func(ctx context.Context) ([]byte, error) {
			if owner == "oskal" {
				var executeErr error
				output, executeErr = r.executeNativeTool(ctx, snapshot.Tool, snapshot.Arguments)
				if executeErr != nil {
					return nil, executeErr
				}
				return json.Marshal(output)
			}
			tmpl := snapshot.Tool.EffectiveCallTemplate()
			typ := tmpl.CallTemplateType
			if typ == "" {
				typ = tmpl.ProviderType
			}
			if typ != "http" && typ != "streamable_http" {
				return nil, fmt.Errorf("unsupported external execution transport %q", typ)
			}
			var executeErr error
			output, executeErr = executeRemoteHTTPTool(ctx, snapshot.Tool.Name, tmpl, snapshot.Arguments)
			if executeErr != nil {
				return nil, executeErr
			}
			return json.Marshal(output)
		})
	}
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

func (r *Registry) loadSubjectEnvelopes(ctx context.Context, sub assurance.SubjectRef) ([]assurance.EvidenceEnvelope, error) {
	if r.evidenceDir == "" {
		return nil, nil
	}
	repo, err := storage.OpenFilesystemEvidenceRepositoryWithLimits(r.evidenceDir, r.archiveLimits)
	if err != nil {
		return nil, err
	}
	envelopes, err := repo.ListBySubject(ctx, sub)
	if err != nil {
		return nil, err
	}
	return envelopes, nil
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
	return evaluation.UnverifiedEvaluation(sub, ctrl, envelopes, time.Now().UTC())
}

func (r *Registry) executeNativeTool(ctx context.Context, tool Tool, args map[string]interface{}) (interface{}, error) {
	switch tool.Name {
	case "get_assurance_state":
		raw, _ := args["subject"].(string)
		if raw == "" {
			return nil, fmt.Errorf("subject argument is required")
		}
		sub := parseSubjectRef(raw)
		envelopes, err := r.loadSubjectEnvelopes(ctx, sub)
		if err != nil {
			return nil, err
		}
		eval := r.buildEvaluation(sub, assurance.ControlRef{}, envelopes)
		state := map[string]any{"subject": sub.URI(), "state": "UNKNOWN", "status": "Supplied material is unverified; no authoritative contract, producer verification or current epoch was supplied", "evidence_root": "", "freshness": "UNKNOWN", "supplied_envelopes": eval.Completeness.Present, "verified_envelopes": 0, "vector_state": map[string]string{"presence": materialPresence(envelopes), "valence": "NEUTRAL", "coherence": "UNKNOWN", "evidence": "UNKNOWN", "lifecycle": "UNKNOWN"}}
		return state, nil

	case "explain_claim":
		subRaw, _ := args["subject"].(string)
		if subRaw == "" {
			return nil, errors.New("subject argument is required")
		}
		sub := parseSubjectRef(subRaw)
		rawControl, _ := args["control"].(string)
		ctrl, err := evaluation.ParseControlReference(rawControl)
		if err != nil {
			return nil, err
		}
		envelopes, err := r.loadSubjectEnvelopes(ctx, sub)
		if err != nil {
			return nil, err
		}
		eval := r.buildEvaluation(sub, ctrl, envelopes)
		explanation := evaluation.UnverifiedExplanation(eval)
		return map[string]interface{}{
			"subject":         sub.URI(),
			"control":         ctrl.Canonical(),
			"assurance_state": eval.State.String(),
			"rendered_text":   explanation,
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
		raw, _ := args["subject"].(string)
		if raw == "" {
			return nil, fmt.Errorf("subject argument is required")
		}
		sub := parseSubjectRef(raw)
		envelopes, err := r.loadSubjectEnvelopes(ctx, sub)
		if err != nil {
			return nil, err
		}
		dimensions := countEpochDivergences(envelopes)
		result := map[string]any{"subject": sub.URI(), "status": "UNKNOWN", "assurance_status": "UNKNOWN", "raw_metadata_divergence_dimensions": dimensions, "reason": "Unverified material is not an authoritative current baseline"}
		return result, nil

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
		raw, err := json.Marshal(args)
		if err != nil {
			return nil, err
		}
		request, err := proj.DecodeProjectionRequest(raw)
		if err != nil {
			return nil, err
		}
		sub, err := request.SubjectRef()
		if err != nil {
			return nil, err
		}
		controls, err := request.ControlRefs()
		if err != nil {
			return nil, err
		}
		envelopes, err := r.loadSubjectEnvelopes(ctx, sub)
		if err != nil {
			return nil, err
		}
		var evaluations []assurance.ClaimEvaluation
		for _, control := range controls {
			evaluations = append(evaluations, evaluation.UnverifiedEvaluation(sub, control, envelopes, time.Now().UTC()))
		}
		projected, err := request.Project(ctx, evaluations)
		if err != nil {
			return nil, err
		}
		return json.RawMessage(projected), nil
	case "run_doctor":
		return diagnostics.RunDoctorWithLimits(ctx, r.evidenceDir, r.archiveLimits), nil

	case "inspect_subject":
		subRaw, _ := args["subject"].(string)
		if subRaw == "" {
			return nil, errors.New("subject argument is required")
		}
		sub := parseSubjectRef(subRaw)
		rawControl, _ := args["control"].(string)
		ctrl, err := evaluation.ParseControlReference(rawControl)
		if err != nil {
			return nil, err
		}
		envelopes, err := r.loadSubjectEnvelopes(ctx, sub)
		if err != nil {
			return nil, err
		}
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
	if err := validateHTTPProviderURL(targetURL); err != nil {
		return nil, err
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

	client := newSafeHTTPClient(10 * time.Second)
	// Redirects and transport retries can repeat an authority-bearing effect.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if transport, ok := client.Transport.(*http.Transport); ok {
		transport.DisableKeepAlives = true
	}
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
	}, 1)
	if err != nil {
		return nil, fmt.Errorf("remote HTTP tool '%s' request failed: %w", toolName, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024+1))
	if err != nil {
		return nil, fmt.Errorf("failed reading response from remote HTTP tool '%s': %w", toolName, err)
	}
	if len(respBytes) > 5*1024*1024 {
		return nil, errors.New("external tool response exceeds 5 MiB")
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

	return withTransportTLS(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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
	}))
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

func materialPresence(envelopes []assurance.EvidenceEnvelope) string {
	if len(envelopes) > 0 {
		return "PRESENT"
	}
	return "EMPTY"
}
