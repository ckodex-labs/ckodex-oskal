package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/utcp"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/diagnostics"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/evaluation"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	proj "github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
	"github.com/ckodex-labs/ckodex-oskal/internal/scaffold"
)

// JSON-RPC 2.0 structures
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      interface{}   `json:"id,omitempty"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *jsonRPCError `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// MCP Protocol structures
type mcpInitializeResult struct {
	ProtocolVersion string            `json:"protocolVersion"`
	Capabilities    mcpServerCaps     `json:"capabilities"`
	ServerInfo      mcpImplementation `json:"serverInfo"`
}

type mcpServerCaps struct {
	Tools map[string]interface{} `json:"tools"`
}

type mcpImplementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type mcpTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

type mcpToolsListResult struct {
	Tools []mcpTool `json:"tools"`
}

type mcpCallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type mcpToolContentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpCallToolResult struct {
	Content []mcpToolContentItem `json:"content"`
	IsError bool                 `json:"isError,omitempty"`
}

// Server provides the Model Context Protocol stdio interface for OSKAL and the utcp-mcp bridge.
type Server struct {
	mu           sync.Mutex
	in           io.Reader
	out          io.Writer
	evidenceDir  string
	validator    *proj.Validator
	utcpRegistry *utcp.Registry
}

// NewServer initializes an MCP Server instance with native UTCP bridge capabilities.
func NewServer(in io.Reader, out io.Writer, evidenceDir string) (*Server, error) {
	return NewServerWithBroker(in, out, evidenceDir, nil)
}

// NewServerWithBroker initializes an MCP Server whose UTCP registry operations are governed by a durable execution broker.
func NewServerWithBroker(in io.Reader, out io.Writer, evidenceDir string, broker ports.ExecutionBroker) (*Server, error) {
	val, err := proj.DefaultValidator()
	if err != nil {
		return nil, fmt.Errorf("failed to init validator for MCP: %w", err)
	}
	utcpReg, err := utcp.NewRegistry(evidenceDir, broker)
	if err != nil {
		return nil, fmt.Errorf("failed to init UTCP registry for MCP: %w", err)
	}

	return &Server{
		in:           in,
		out:          out,
		evidenceDir:  evidenceDir,
		validator:    val,
		utcpRegistry: utcpReg,
	}, nil
}

// Run executes the stdio JSON-RPC loop until EOF or error.
func (s *Server) Run(ctx context.Context) error {
	scanner := bufio.NewScanner(s.in)
	// Allow large messages (e.g. whole OSCAL documents up to 10MB)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Bytes()
		if len(bytesTrim(line)) == 0 {
			continue
		}

		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.sendError(nil, -32700, "Parse error: "+err.Error())
			continue
		}

		s.handleRequest(ctx, req)
	}

	return scanner.Err()
}

func bytesTrim(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

func (s *Server) handleRequest(ctx context.Context, req jsonRPCRequest) {
	defer func() {
		if r := recover(); r != nil {
			if req.ID != nil {
				s.sendError(req.ID, -32603, fmt.Sprintf("internal MCP handler panic recovered: %v", r))
			}
		}
	}()

	// Notifications (no ID)
	if req.ID == nil {
		return
	}

	switch req.Method {
	case "initialize":
		res := mcpInitializeResult{
			ProtocolVersion: "2024-11-05",
			Capabilities: mcpServerCaps{
				Tools: map[string]interface{}{},
			},
			ServerInfo: mcpImplementation{
				Name:    "oskal-mcp",
				Version: "v1.0.0",
			},
		}
		s.sendResult(req.ID, res)

	case "ping":
		s.sendResult(req.ID, map[string]interface{}{})

	case "tools/list":
		s.sendResult(req.ID, s.listTools())

	case "tools/call":
		var params mcpCallToolParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.sendError(req.ID, -32602, "Invalid params: "+err.Error())
			return
		}
		res, err := s.callTool(ctx, params.Name, params.Arguments)
		if err != nil {
			s.sendResult(req.ID, mcpCallToolResult{
				Content: []mcpToolContentItem{{Type: "text", Text: err.Error()}},
				IsError: true,
			})
			return
		}
		s.sendResult(req.ID, res)

	default:
		s.sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func (s *Server) sendResult(id interface{}, result interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	data, _ := json.Marshal(resp)
	_, _ = fmt.Fprintln(s.out, string(data))
}

func (s *Server) sendError(id interface{}, code int, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &jsonRPCError{
			Code:    code,
			Message: message,
		},
	}
	data, _ := json.Marshal(resp)
	_, _ = fmt.Fprintln(s.out, string(data))
}

func (s *Server) listTools() mcpToolsListResult {
	return mcpToolsListResult{
		Tools: []mcpTool{
			{
				Name:        "get_assurance_state",
				Description: "Retrieve the continuous assurance state vector <P, V, A, C, E, L, tau> for a Kubernetes workload subject.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"subject": map[string]interface{}{
							"type":        "string",
							"description": "Subject URI (e.g. k8s://prod/payments/Deployment/payments-api)",
						},
					},
					"required": []string{"subject"},
				},
			},
			{
				Name:        "explain_claim",
				Description: "Explain why an assurance claim is justified or failing using a causal decision graph (Section 51).",
				InputSchema: map[string]interface{}{
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
			},
			{
				Name:        "validate_oscal",
				Description: "Validate an OSCAL document (AR, CD, SSP, AP, POAM) against strict NIST v1.2.3 JSON schemas.",
				InputSchema: map[string]interface{}{
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
			},
			{
				Name:        "detect_drift",
				Description: "Detect semantic drift between observed runtime evidence and recorded epoch digests.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"subject": map[string]interface{}{
							"type":        "string",
							"description": "Subject URI (e.g. k8s://prod/payments/Deployment/payments-api)",
						},
					},
					"required": []string{"subject"},
				},
			},
			{
				Name:        "scaffold_compliance",
				Description: "Scaffold Kubernetes ControlBinding, EvidenceContract, and OSCAL Component Definition manifests.",
				InputSchema: map[string]interface{}{
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
			},
			{
				Name:        "project_oscal",
				Description: "Project continuous assurance state into a standard NIST OSCAL v1.2.3 document.",
				InputSchema: proj.ProjectionRequestSchema(),
			},
			{
				Name:        "run_doctor",
				Description: "Run deep system preflight diagnostics (Kubernetes, SPIRE, Sigstore, CAS, NIST schemas).",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"lease_id":          map[string]interface{}{"type": "string", "description": "Lease identity namespace/name/UID"},
						"prev_receipt_hash": map[string]interface{}{"type": "string", "description": "Previous admission hash; empty for the first turn"},
					},
					"required": []string{"lease_id"},
				},
			},
			{
				Name:        "inspect_subject",
				Description: "Inspect all 4 Truth Channels (Telemetry, Execution, Decision, Evidence) for a workload subject (Section 13).",
				InputSchema: map[string]interface{}{
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
			},
			{
				Name:        "utcp_get_manual",
				Description: "Return the Universal Tool Calling Protocol (UTCP v1.0.1) manual for direct native tool invocation.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"transport": map[string]interface{}{
							"type":        "string",
							"description": "Primary transport template type: cli, http, grpc, mcp",
							"default":     "cli",
						},
					},
				},
			},
			{
				Name:        "search_tools",
				Description: "UTCP-MCP bridge: search registered UTCP manuals and tools by task_description or keyword query and tags.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"task_description": map[string]interface{}{
							"type":        "string",
							"description": "Description of the task to find relevant UTCP tools for",
						},
						"query": map[string]interface{}{
							"type":        "string",
							"description": "Search query keywords",
						},
						"tags": map[string]interface{}{
							"type":        "array",
							"items":       map[string]interface{}{"type": "string"},
							"description": "Optional tag filters",
						},
						"max_results": map[string]interface{}{
							"type":        "integer",
							"description": "Maximum number of tools to return",
							"default":     10,
						},
						"limit": map[string]interface{}{
							"type":        "integer",
							"description": "Maximum number of tools to return",
							"default":     10,
						},
					},
				},
			},
			{
				Name:        "list_tools",
				Description: "UTCP-MCP bridge: list all registered UTCP tools and their native call templates.",
				InputSchema: map[string]interface{}{
					"type":       "object",
					"properties": map[string]interface{}{},
				},
			},
			{
				Name:        "call_tool",
				Description: "UTCP-MCP bridge: execute a registered UTCP tool by tool_name and arguments/tool_args.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"tool_name": map[string]interface{}{
							"type":        "string",
							"description": "Name of the UTCP tool to invoke",
						},
						"arguments": map[string]interface{}{
							"type":        "object",
							"description": "Arguments object passed to the UTCP tool",
						},
						"tool_args": map[string]interface{}{
							"type":        "object",
							"description": "Arguments object passed to the UTCP tool (alias for arguments)",
						},
						"lease_id": map[string]interface{}{
							"type":        "string",
							"description": "Lease identity namespace/name/UID for governed execution",
						},
						"prev_receipt_hash": map[string]interface{}{
							"type":        "string",
							"description": "Previous admission hash; empty only for the first turn",
						},
					},
					"required": []string{"tool_name"},
				},
			},
			{
				Name:        "register_manual",
				Description: "UTCP-MCP bridge: dynamically validate and register a UTCP manual or manual_call_template.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"name": map[string]interface{}{
							"type":        "string",
							"description": "Manual namespace or provider identifier",
						},
						"manual_name": map[string]interface{}{
							"type":        "string",
							"description": "Manual namespace alias",
						},
						"manual_call_template": map[string]interface{}{
							"type":        "object",
							"description": "UTCP manual call template object (utcp-mcp standard)",
						},
						"manual": map[string]interface{}{
							"type":        "object",
							"description": "UTCPManual JSON object",
						},
						"manual_json": map[string]interface{}{
							"type":        "string",
							"description": "Raw UTCPManual JSON string",
						},
						"lease_id": map[string]interface{}{
							"type":        "string",
							"description": "Lease identity namespace/name/UID for governed registration",
						},
						"prev_receipt_hash": map[string]interface{}{
							"type":        "string",
							"description": "Previous admission hash; empty only for the first turn",
						},
					},
				},
			},
			{
				Name:        "deregister_manual",
				Description: "UTCP-MCP bridge: deregister a UTCP manual or tool provider by manual_name.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"manual_name": map[string]interface{}{
							"type":        "string",
							"description": "Name of the manual or provider to deregister",
						},
						"name": map[string]interface{}{
							"type":        "string",
							"description": "Alias for manual_name",
						},
						"lease_id": map[string]interface{}{
							"type":        "string",
							"description": "Lease identity namespace/name/UID for governed deregistration",
						},
						"prev_receipt_hash": map[string]interface{}{
							"type":        "string",
							"description": "Previous admission hash; empty only for the first turn",
						},
					},
				},
			},
			{
				Name:        "register_tool_provider",
				Description: "UTCP-MCP bridge: register an external UTCP tool provider (http, cli, grpc, mcp, text).",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"name": map[string]interface{}{
							"type":        "string",
							"description": "Provider name",
						},
						"provider_type": map[string]interface{}{
							"type":        "string",
							"description": "Transport type: http, cli, grpc, mcp, text",
						},
						"url": map[string]interface{}{
							"type":        "string",
							"description": "Optional HTTP UTCP discovery endpoint URL (e.g. http://localhost:8090/utcp)",
						},
						"file_path": map[string]interface{}{
							"type":        "string",
							"description": "Optional local file path to a UTCP manual JSON document",
						},
						"lease_id": map[string]interface{}{
							"type":        "string",
							"description": "Lease identity namespace/name/UID for governed provider registration",
						},
						"prev_receipt_hash": map[string]interface{}{
							"type":        "string",
							"description": "Previous admission hash; empty only for the first turn",
						},
					},
					"required": []string{"name", "provider_type"},
				},
			},
			{
				Name:        "get_required_keys_for_tool",
				Description: "UTCP-MCP bridge: list required input and authentication variables for a registered UTCP tool.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"tool_name": map[string]interface{}{
							"type":        "string",
							"description": "Name of the UTCP tool",
						},
					},
					"required": []string{"tool_name"},
				},
			},
			{
				Name:        "tool_info",
				Description: "UTCP-MCP bridge: return complete schema and call_template metadata for a registered UTCP tool.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"tool_name": map[string]interface{}{
							"type":        "string",
							"description": "Name of the UTCP tool",
						},
					},
					"required": []string{"tool_name"},
				},
			},
		},
	}
}

func (s *Server) loadSubjectEnvelopes(ctx context.Context, sub assurance.SubjectRef) ([]assurance.EvidenceEnvelope, error) {
	if s.evidenceDir == "" {
		return nil, nil
	}
	repo, err := storage.OpenFilesystemEvidenceRepository(s.evidenceDir)
	if err != nil {
		return nil, err
	}
	envelopes, err := repo.ListBySubject(ctx, sub)
	if err != nil {
		return nil, err
	}
	return envelopes, nil
}

func detectMCPEpochDrift(envelopes []assurance.EvidenceEnvelope) (bool, bool, bool) {
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
	return polDrift, impDrift, authDrift
}

func (s *Server) buildEvaluation(sub assurance.SubjectRef, ctrl assurance.ControlRef, envelopes []assurance.EvidenceEnvelope) assurance.ClaimEvaluation {
	return evaluation.UnverifiedEvaluation(sub, ctrl, envelopes, time.Now().UTC())
}

func (s *Server) callTool(ctx context.Context, name string, args map[string]interface{}) (*mcpCallToolResult, error) {
	switch name {
	case "get_assurance_state":
		raw, _ := args["subject"].(string)
		if raw == "" {
			return nil, fmt.Errorf("subject argument is required")
		}
		sub := parseSubjectRef(raw)
		envelopes, err := s.loadSubjectEnvelopes(ctx, sub)
		if err != nil {
			return nil, err
		}
		eval := s.buildEvaluation(sub, assurance.ControlRef{}, envelopes)
		state := map[string]any{"subject": sub.URI(), "state": "UNKNOWN", "status": "Supplied material is unverified; no authoritative contract, producer verification or current epoch was supplied", "evidence_root": "", "freshness": "UNKNOWN", "supplied_envelopes": eval.Completeness.Present, "verified_envelopes": 0, "vector_state": map[string]string{"presence": materialPresence(envelopes), "valence": "NEUTRAL", "coherence": "UNKNOWN", "evidence": "UNKNOWN", "lifecycle": "UNKNOWN"}}
		data, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return nil, err
		}
		return &mcpCallToolResult{Content: []mcpToolContentItem{{Type: "text", Text: string(data)}}}, nil

	case "explain_claim":
		subRaw, _ := args["subject"].(string)
		if subRaw == "" {
			return nil, fmt.Errorf("subject argument is required")
		}
		sub := parseSubjectRef(subRaw)

		rawControl, _ := args["control"].(string)
		ctrl, err := evaluation.ParseControlReference(rawControl)
		if err != nil {
			return nil, err
		}
		envelopes, err := s.loadSubjectEnvelopes(ctx, sub)
		if err != nil {
			return nil, err
		}
		eval := s.buildEvaluation(sub, ctrl, envelopes)
		explanation := evaluation.UnverifiedExplanation(eval)
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: explanation}},
		}, nil

	case "validate_oscal":
		content, _ := args["content"].(string)
		if content == "" {
			return nil, fmt.Errorf("content argument is required")
		}
		schemaOverride, _ := args["schema"].(string)
		report, err := s.validator.Validate([]byte(content), schemaOverride)
		if err != nil {
			return nil, fmt.Errorf("validation execution failed: %w", err)
		}
		buf, _ := json.MarshalIndent(report, "", "  ")
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
		}, nil

	case "detect_drift":
		raw, _ := args["subject"].(string)
		if raw == "" {
			return nil, fmt.Errorf("subject argument is required")
		}
		sub := parseSubjectRef(raw)
		envelopes, err := s.loadSubjectEnvelopes(ctx, sub)
		if err != nil {
			return nil, err
		}
		pol, imp, auth := detectMCPEpochDrift(envelopes)
		dimensions := 0
		for _, different := range []bool{pol, imp, auth} {
			if different {
				dimensions++
			}
		}
		result := map[string]any{"subject": sub.URI(), "status": "UNKNOWN", "assurance_status": "UNKNOWN", "raw_metadata_divergence_dimensions": dimensions, "reason": "Unverified material is not an authoritative current baseline"}
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, err
		}
		return &mcpCallToolResult{Content: []mcpToolContentItem{{Type: "text", Text: string(data)}}}, nil

	case "scaffold_compliance":
		profile, _ := args["profile"].(string)
		if profile == "" {
			return nil, fmt.Errorf("profile argument is required")
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
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: yamlStr}},
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
		envelopes, err := s.loadSubjectEnvelopes(ctx, sub)
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
		return &mcpCallToolResult{Content: []mcpToolContentItem{{Type: "text", Text: string(projected)}}}, nil
	case "run_doctor":
		leaseID, _ := args["lease_id"].(string)
		previous, _ := args["prev_receipt_hash"].(string)
		result, err := s.utcpRegistry.CallTool(ctx, "oskal.run_doctor", args, leaseID, previous)
		if err != nil {
			return nil, err
		}
		buf, _ := json.MarshalIndent(result, "", "  ")
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
		}, nil

	case "inspect_subject":
		return s.toolInspectSubject(ctx, args)

	case "utcp_get_manual":
		transport, _ := args["transport"].(string)
		opts := utcp.DefaultManualOptions()
		if transport != "" {
			opts.PrimaryTransport = transport
		}
		manual := utcp.BuildOSKALManual(opts)
		buf, _ := json.MarshalIndent(manual, "", "  ")
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
		}, nil

	case "search_tools":
		query, _ := args["query"].(string)
		if query == "" {
			query, _ = args["task_description"].(string)
		}
		limit := 10
		if l, ok := args["limit"].(float64); ok && l > 0 {
			limit = int(l)
		} else if mr, ok := args["max_results"].(float64); ok && mr > 0 {
			limit = int(mr)
		}
		var tags []string
		if rawTags, ok := args["tags"].([]interface{}); ok {
			for _, rt := range rawTags {
				if ts, ok := rt.(string); ok {
					tags = append(tags, ts)
				}
			}
		} else if strTags, ok := args["tags"].([]string); ok {
			tags = append(tags, strTags...)
		}
		matches := s.utcpRegistry.SearchTools(query, tags, limit)
		buf, _ := json.MarshalIndent(map[string]interface{}{
			"tools": matches,
			"count": len(matches),
		}, "", "  ")
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
		}, nil

	case "list_tools":
		tools := s.utcpRegistry.ListTools()
		buf, _ := json.MarshalIndent(map[string]interface{}{
			"tools": tools,
			"count": len(tools),
		}, "", "  ")
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
		}, nil

	case "call_tool":
		tName, _ := args["tool_name"].(string)
		if tName == "" {
			tName, _ = args["name"].(string)
		}
		if tName == "" {
			return nil, fmt.Errorf("tool_name argument is required")
		}
		tArgs, _ := args["tool_args"].(map[string]interface{})
		if len(tArgs) == 0 {
			tArgs, _ = args["arguments"].(map[string]interface{})
		}
		leaseID, _ := args["lease_id"].(string)
		prevHash, _ := args["prev_receipt_hash"].(string)
		res, err := s.utcpRegistry.CallTool(ctx, tName, tArgs, leaseID, prevHash)
		if err != nil {
			return nil, err
		}
		buf, _ := json.MarshalIndent(res, "", "  ")
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
		}, nil

	case "register_manual":
		name, _ := args["name"].(string)
		if name == "" {
			name, _ = args["manual_name"].(string)
		}
		leaseID, _ := args["lease_id"].(string)
		prevHash, _ := args["prev_receipt_hash"].(string)

		if rawTmpl, ok := args["manual_call_template"].(map[string]interface{}); ok && len(rawTmpl) > 0 {
			rawBytes, _ := json.Marshal(rawTmpl)
			if _, hasTools := rawTmpl["tools"]; hasTools {
				var m utcp.UTCPManual
				if err := json.Unmarshal(rawBytes, &m); err != nil {
					return nil, fmt.Errorf("invalid manual_call_template manual JSON: %w", err)
				}
				if err := s.utcpRegistry.RegisterManualWithLease(ctx, name, m, leaseID, prevHash); err != nil {
					return nil, err
				}
				buf, _ := json.MarshalIndent(map[string]interface{}{
					"success":          true,
					"status":           "REGISTERED",
					"manual_name":      name,
					"utcp_version":     m.UTCPVersion,
					"registered_tools": len(m.Tools),
				}, "", "  ")
				return &mcpCallToolResult{
					Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
				}, nil
			}
			var cfg utcp.ProviderConfig
			if err := json.Unmarshal(rawBytes, &cfg); err != nil {
				return nil, fmt.Errorf("invalid manual_call_template provider config: %w", err)
			}
			if cfg.Name == "" {
				cfg.Name = name
			}
			if cfg.ProviderType == "" {
				cfg.ProviderType = cfg.CallTemplateType
			}
			cfg.LeaseID = leaseID
			cfg.PrevReceiptHash = prevHash
			if err := s.utcpRegistry.RegisterToolProvider(ctx, cfg); err != nil {
				return nil, err
			}
			buf, _ := json.MarshalIndent(map[string]interface{}{
				"success":     true,
				"status":      "REGISTERED",
				"manual_name": cfg.Name,
			}, "", "  ")
			return &mcpCallToolResult{
				Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
			}, nil
		}

		var rawManual string
		if sVal, ok := args["manual_json"].(string); ok && sVal != "" {
			rawManual = sVal
		} else if objVal, ok := args["manual"].(map[string]interface{}); ok && len(objVal) > 0 {
			b, _ := json.Marshal(objVal)
			rawManual = string(b)
		}
		if rawManual == "" {
			return nil, fmt.Errorf("manual_json, manual, or manual_call_template argument is required")
		}
		var m utcp.UTCPManual
		if err := json.Unmarshal([]byte(rawManual), &m); err != nil {
			return nil, fmt.Errorf("invalid UTCP manual JSON: %w", err)
		}
		if err := s.utcpRegistry.RegisterManualWithLease(ctx, name, m, leaseID, prevHash); err != nil {
			return nil, err
		}
		buf, _ := json.MarshalIndent(map[string]interface{}{
			"success":          true,
			"status":           "REGISTERED",
			"utcp_version":     m.UTCPVersion,
			"registered_tools": len(m.Tools),
		}, "", "  ")
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
		}, nil

	case "deregister_manual":
		manualName, _ := args["manual_name"].(string)
		if manualName == "" {
			manualName, _ = args["name"].(string)
		}
		if strings.TrimSpace(manualName) == "" {
			return nil, fmt.Errorf("manual_name argument is required")
		}
		leaseID, _ := args["lease_id"].(string)
		prevHash, _ := args["prev_receipt_hash"].(string)
		if err := s.utcpRegistry.DeregisterManual(ctx, manualName, leaseID, prevHash); err != nil {
			return nil, err
		}
		buf, _ := json.MarshalIndent(map[string]interface{}{
			"success":     true,
			"manual_name": manualName,
			"message":     fmt.Sprintf("Manual '%s' deregistered", manualName),
		}, "", "  ")
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
		}, nil

	case "register_tool_provider":
		pName, _ := args["name"].(string)
		pType, _ := args["provider_type"].(string)
		pURL, _ := args["url"].(string)
		pFile, _ := args["file_path"].(string)
		leaseID, _ := args["lease_id"].(string)
		prevHash, _ := args["prev_receipt_hash"].(string)
		err := s.utcpRegistry.RegisterToolProvider(ctx, utcp.ProviderConfig{
			Name:            pName,
			ProviderType:    pType,
			URL:             pURL,
			FilePath:        pFile,
			LeaseID:         leaseID,
			PrevReceiptHash: prevHash,
		})
		if err != nil {
			return nil, err
		}
		buf, _ := json.MarshalIndent(map[string]interface{}{
			"status":        "PROVIDER_REGISTERED",
			"name":          pName,
			"provider_type": pType,
		}, "", "  ")
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
		}, nil

	case "get_required_keys_for_tool":
		tName, _ := args["tool_name"].(string)
		if strings.TrimSpace(tName) == "" {
			return nil, fmt.Errorf("tool_name argument is required")
		}
		reqVars, err := s.utcpRegistry.RequiredVariablesForTool(tName)
		if err != nil {
			return nil, err
		}
		buf, _ := json.MarshalIndent(map[string]interface{}{
			"success":            true,
			"tool_name":          tName,
			"required_variables": reqVars,
		}, "", "  ")
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
		}, nil

	case "tool_info":
		tName, _ := args["tool_name"].(string)
		if strings.TrimSpace(tName) == "" {
			return nil, fmt.Errorf("tool_name argument is required")
		}
		tool, ok := s.utcpRegistry.GetTool(tName)
		if !ok {
			return nil, fmt.Errorf("utcp tool '%s' not found in registry", tName)
		}
		buf, _ := json.MarshalIndent(map[string]interface{}{
			"success": true,
			"tool":    tool,
		}, "", "  ")
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
		}, nil

	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

func (s *Server) toolInspectSubject(ctx context.Context, args map[string]interface{}) (*mcpCallToolResult, error) {
	subRaw, _ := args["subject"].(string)
	if subRaw == "" {
		return nil, fmt.Errorf("subject argument is required")
	}
	sub := parseSubjectRef(subRaw)
	rawControl, _ := args["control"].(string)
	ctrl, err := evaluation.ParseControlReference(rawControl)
	if err != nil {
		return nil, err
	}
	envelopes, err := s.loadSubjectEnvelopes(ctx, sub)
	if err != nil {
		return nil, err
	}
	eval := s.buildEvaluation(sub, ctrl, envelopes)
	report := diagnostics.InspectSubject(ctx, sub, eval, envelopes)
	buf, _ := json.MarshalIndent(report, "", "  ")
	return &mcpCallToolResult{
		Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
	}, nil
}

func parseSubjectRef(raw string) assurance.SubjectRef {
	if strings.Contains(raw, "://") {
		parts := strings.SplitN(raw, "://", 2)
		return assurance.SubjectRef{Scheme: parts[0], ID: parts[1]}
	}
	return assurance.SubjectRef{Scheme: "k8s", ID: raw}
}

func materialPresence(envelopes []assurance.EvidenceEnvelope) string {
	if len(envelopes) > 0 {
		return "PRESENT"
	}
	return "EMPTY"
}
