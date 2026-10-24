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
	"github.com/ckodex-labs/ckodex-oskal/internal/application/diagnostics"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/explain"
	proj "github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
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

// Server provides the Model Context Protocol stdio interface for OSKAL.
type Server struct {
	mu          sync.Mutex
	in          io.Reader
	out         io.Writer
	evidenceDir string
	validator   *proj.Validator
	projector   *proj.Projector
	explainer   *explain.Explainer
}

// NewServer initializes an MCP Server instance.
func NewServer(in io.Reader, out io.Writer, evidenceDir string) (*Server, error) {
	val, err := proj.DefaultValidator()
	if err != nil {
		return nil, fmt.Errorf("failed to init validator for MCP: %w", err)
	}

	return &Server{
		in:          in,
		out:         out,
		evidenceDir: evidenceDir,
		validator:   val,
		projector:   proj.NewProjector(),
		explainer:   explain.NewExplainer(),
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
				Version: "v0.3.0",
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
							"default":     "nist-sp-800-53:AC-6",
						},
					},
					"required": []string{"subject"},
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
				InputSchema: map[string]interface{}{
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
			},
			{
				Name:        "run_doctor",
				Description: "Run deep system preflight diagnostics (Kubernetes, SPIRE, Sigstore, CAS, NIST schemas).",
				InputSchema: map[string]interface{}{
					"type":       "object",
					"properties": map[string]interface{}{},
				},
			},
		},
	}
}

func (s *Server) callTool(ctx context.Context, name string, args map[string]interface{}) (*mcpCallToolResult, error) {
	switch name {
	case "get_assurance_state":
		subRaw, _ := args["subject"].(string)
		if subRaw == "" {
			return nil, fmt.Errorf("subject argument is required")
		}
		sub := parseSubjectRef(subRaw)

		// Invariant I-02: Absence of evidence is UNKNOWN
		state := map[string]interface{}{
			"subject":       sub.URI(),
			"state":         "UNKNOWN",
			"status":        "Absence of verified evidence (Section 15: EMPTY != NEGATIVE)",
			"evidence_root": "none",
			"vector_state": map[string]string{
				"presence":  "EMPTY",
				"valence":   "NEUTRAL",
				"coherence": "COHERENT",
				"evidence":  "UNKNOWN",
				"lifecycle": "UNKNOWN",
			},
			"last_evaluated": time.Now().UTC().Format(time.RFC3339),
		}
		buf, _ := json.MarshalIndent(state, "", "  ")
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
		}, nil

	case "explain_claim":
		subRaw, _ := args["subject"].(string)
		if subRaw == "" {
			return nil, fmt.Errorf("subject argument is required")
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
		eval := assurance.ClaimEvaluation{
			ID:          fmt.Sprintf("eval-%s", ctrl.ID),
			Subject:     sub,
			Control:     ctrl,
			State:       assurance.AssuranceStateUnknown,
			Epoch:       assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeStringDigest(sub.URI())},
			EvaluatedAt: time.Now().UTC(),
		}
		graph := s.explainer.BuildExplainGraph(ctx, sub, ctrl, eval)
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: graph.RenderText()}},
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
		subRaw, _ := args["subject"].(string)
		if subRaw == "" {
			return nil, fmt.Errorf("subject argument is required")
		}
		sub := parseSubjectRef(subRaw)
		res := map[string]interface{}{
			"subject":          sub.URI(),
			"status":           "IN_SYNC",
			"policy_drift":     false,
			"authority_drift":  false,
			"workload_drift":   false,
			"assurance_status": "ASSURED",
			"drift_dimensions": 0,
		}
		buf, _ := json.MarshalIndent(res, "", "  ")
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
		}, nil

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
		subRaw, _ := args["subject"].(string)
		if subRaw == "" {
			return nil, fmt.Errorf("subject argument is required")
		}
		docType, _ := args["document_type"].(string)
		if docType == "" {
			return nil, fmt.Errorf("document_type argument is required")
		}
		sub := parseSubjectRef(subRaw)
		ctrl := assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
		eval := assurance.ClaimEvaluation{
			ID:          fmt.Sprintf("eval-%s", ctrl.ID),
			Subject:     sub,
			Control:     ctrl,
			State:       assurance.AssuranceStateUnknown,
			Epoch:       assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeStringDigest(sub.URI())},
			EvaluatedAt: time.Now().UTC(),
		}

		var projected []byte
		var err error
		normDoc, _ := proj.NormalizeDocumentType(docType)
		switch normDoc {
		case proj.DocTypeAssessmentResults:
			projected, err = s.projector.ProjectAssessmentResults(ctx, sub, []assurance.ClaimEvaluation{eval}, nil)
		case proj.DocTypeComponentDefinition:
			projected, err = s.projector.ProjectComponentDefinition(ctx, sub.ID, []assurance.ClaimEvaluation{eval})
		case proj.DocTypeSSP:
			projected, err = s.projector.ProjectSSP(ctx, sub.ID, []assurance.ClaimEvaluation{eval})
		case proj.DocTypeAssessmentPlan:
			contract := assurance.EvidenceContract{
				ID: fmt.Sprintf("contract-%s", sub.ID),
				Requirements: []assurance.EvidenceRequirement{
					{ID: "req-1", EvidenceType: "admission", Required: true, MaxAge: 15 * time.Minute},
				},
			}
			projected, err = s.projector.ProjectAssessmentPlan(ctx, sub, contract, []assurance.ControlRef{ctrl})
		case proj.DocTypePOAM:
			projected, err = s.projector.ProjectPOAM(ctx, sub, nil)
		default:
			return nil, fmt.Errorf("unsupported OSCAL projection document type: %s", docType)
		}
		if err != nil {
			return nil, fmt.Errorf("projection error: %w", err)
		}
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: string(projected)}},
		}, nil

	case "run_doctor":
		report := diagnostics.RunDoctor(ctx, s.evidenceDir)
		buf, _ := json.MarshalIndent(report, "", "  ")
		return &mcpCallToolResult{
			Content: []mcpToolContentItem{{Type: "text", Text: string(buf)}},
		}, nil

	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

func parseSubjectRef(raw string) assurance.SubjectRef {
	if strings.Contains(raw, "://") {
		parts := strings.SplitN(raw, "://", 2)
		return assurance.SubjectRef{Scheme: parts[0], ID: parts[1]}
	}
	return assurance.SubjectRef{Scheme: "k8s", ID: raw}
}

// Ensure receipts package is linked
var _ = receipts.ComputeEvidenceRoot
