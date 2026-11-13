package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	proj "github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
)

func TestMCPServerLifecycleAndTools(t *testing.T) {
	inBuf := new(bytes.Buffer)
	outBuf := new(bytes.Buffer)

	srv, err := NewServer(inBuf, outBuf, "")
	if err != nil {
		t.Fatalf("failed to create MCP server: %v", err)
	}

	// 1. initialize
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}` + "\n"
	// 2. ping
	pingReq := `{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n"
	// 3. tools/list
	listReq := `{"jsonrpc":"2.0","id":3,"method":"tools/list"}` + "\n"
	// 4. tools/call validate_oscal
	projector := proj.NewProjector()
	sub := assurance.SubjectRef{Scheme: "k8s", ID: "prod/payments/Deployment/payments-api"}
	now := time.Now().UTC()
	eval := assurance.ClaimEvaluation{
		ID:      "eval-01",
		Control: assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"},
		Subject: sub,
		State:   assurance.AssuranceStateAssured,
		Epoch: assurance.AssuranceEpoch{
			SubjectDigest:        assurance.ComputeStringDigest(sub.URI()),
			ImplementationDigest: assurance.ComputeStringDigest("kubernetes:workload"),
			PolicyDigest:         assurance.ComputeStringDigest("cel:policy:restricted"),
			AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
			EnvironmentDigest:    assurance.ComputeStringDigest("cluster:local"),
		},
		Evidence: []assurance.EvidenceRef{
			{
				URI:       "s3://evidence/ev-01.json",
				Digest:    assurance.ComputeStringDigest("data"),
				MediaType: "application/json",
			},
		},
		Completeness: assurance.EvidenceCompleteness{Required: 1, Verified: 1},
		EvidenceRoot: assurance.ComputeStringDigest("root-01"),
		EvaluatedAt:  now,
		ValidUntil:   now.Add(5 * time.Minute),
	}
	validBytes, err := projector.ProjectAssessmentResults(context.Background(), sub, []assurance.ClaimEvaluation{eval}, nil)
	if err != nil {
		t.Fatalf("failed to project AR: %v", err)
	}
	validDoc := string(validBytes)
	valCallReq := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"validate_oscal","arguments":{"content":` + string(mustJSON(validDoc)) + `}}}` + "\n"
	// 5. tools/call scaffold_compliance
	scaffoldCallReq := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"scaffold_compliance","arguments":{"profile":"nist-sp-800-53","workload":"payments-api"}}}` + "\n"
	// 6. tools/call get_assurance_state
	stateCallReq := `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get_assurance_state","arguments":{"subject":"k8s://prod/payments/Deployment/payments-api"}}}` + "\n"
	// 7. tools/call run_doctor
	doctorCallReq := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"run_doctor","arguments":{}}}` + "\n"

	inBuf.WriteString(initReq + pingReq + listReq + valCallReq + scaffoldCallReq + stateCallReq + doctorCallReq)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := srv.Run(ctx); err != nil {
		t.Fatalf("srv.Run failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(outBuf.String()), "\n")
	if len(lines) != 7 {
		t.Fatalf("expected 7 responses, got %d:\n%s", len(lines), outBuf.String())
	}

	// Verify line 1 (initialize)
	var resp1 jsonRPCResponse
	if err := json.Unmarshal([]byte(lines[0]), &resp1); err != nil {
		t.Fatalf("failed to parse init resp: %v", err)
	}
	if resp1.ID.(float64) != 1 || resp1.Error != nil {
		t.Fatalf("init error: %+v", resp1)
	}

	// Verify line 3 (tools/list has 17 tools: 8 native OSKAL + 9 utcp-mcp bridge tools)
	var resp3 struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[2]), &resp3); err != nil {
		t.Fatalf("failed to parse tools/list resp: %v", err)
	}
	if len(resp3.Result.Tools) != 17 {
		t.Fatalf("expected 17 tools (8 native + 9 utcp-mcp bridge), got %d", len(resp3.Result.Tools))
	}

	// Verify line 4 (validate_oscal valid=true)
	var resp4 struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[3]), &resp4); err != nil {
		t.Fatalf("failed to parse validate_oscal resp: %v", err)
	}
	if resp4.Result.IsError || !strings.Contains(resp4.Result.Content[0].Text, `"valid": true`) {
		t.Fatalf("validate_oscal unexpected result: %+v", resp4)
	}

	// Verify pure ASCII in all responses
	for idx, line := range lines {
		for _, b := range []byte(line) {
			if b > 127 {
				t.Fatalf("non-ASCII character %d in line %d: %s", b, idx+1, line)
			}
		}
	}

	// Verify detect_drift returns UNKNOWN without evidence (Invariant I-02)
	driftRes, err := srv.callTool(context.Background(), "detect_drift", map[string]interface{}{
		"subject": "k8s://prod/payments/Deployment/payments-api",
	})
	if err != nil {
		t.Fatalf("detect_drift failed: %v", err)
	}
	if !strings.Contains(driftRes.Content[0].Text, `"assurance_status": "UNKNOWN"`) {
		t.Fatalf("expected detect_drift without evidence to return UNKNOWN, got:\n%s", driftRes.Content[0].Text)
	}

	// Verify UTCP-MCP bridge tools (utcp_get_manual, search_tools, list_tools, call_tool, tool_info, get_required_keys_for_tool, register_manual, deregister_manual)
	manualRes, err := srv.callTool(context.Background(), "utcp_get_manual", map[string]interface{}{
		"transport": "http",
	})
	if err != nil || !strings.Contains(manualRes.Content[0].Text, `"utcp_version": "1.0.1"`) {
		t.Fatalf("utcp_get_manual failed: err=%v, out=%+v", err, manualRes)
	}

	// F-07: search_tools with task_description and max_results
	searchRes, err := srv.callTool(context.Background(), "search_tools", map[string]interface{}{
		"task_description": "explain_claim",
		"max_results":      float64(5),
	})
	if err != nil || !strings.Contains(searchRes.Content[0].Text, `"explain_claim"`) {
		t.Fatalf("search_tools with task_description failed: err=%v, out=%+v", err, searchRes)
	}

	// F-07: tool_info
	infoRes, err := srv.callTool(context.Background(), "tool_info", map[string]interface{}{
		"tool_name": "ckodex_oskal.get_assurance_state",
	})
	if err != nil || infoRes.IsError || !strings.Contains(infoRes.Content[0].Text, `"get_assurance_state"`) {
		t.Fatalf("tool_info failed: err=%v, out=%+v", err, infoRes)
	}

	// F-07: get_required_keys_for_tool
	reqKeysRes, err := srv.callTool(context.Background(), "get_required_keys_for_tool", map[string]interface{}{
		"tool_name": "get_assurance_state",
	})
	if err != nil || reqKeysRes.IsError || !strings.Contains(reqKeysRes.Content[0].Text, `"required_variables"`) {
		t.Fatalf("get_required_keys_for_tool failed: err=%v, out=%+v", err, reqKeysRes)
	}

	// F-07: register_manual with manual object and deregister_manual
	regRes, err := srv.callTool(context.Background(), "register_manual", map[string]interface{}{
		"name": "external",
		"manual": map[string]interface{}{
			"version":        "1.0.0",
			"utcp_version":   "1.0.1",
			"manual_version": "1.0.0",
			"name":           "custom_sec_manual",
			"tools": []interface{}{
				map[string]interface{}{
					"name":        "custom_sec_scan",
					"description": "Custom scanner",
					"inputs":      map[string]interface{}{"type": "object"},
					"outputs":     map[string]interface{}{"type": "object"},
					"tool_call_template": map[string]interface{}{
						"name":               "custom_sec_manual",
						"call_template_type": "cli",
						"command_name":       "echo",
					},
				},
			},
		},
	})
	if err == nil {
		t.Fatalf("register_manual failed: err=%v, out=%+v", err, regRes)
	}

	deregRes, err := srv.callTool(context.Background(), "deregister_manual", map[string]interface{}{
		"manual_name": "custom_sec_manual",
	})
	if err == nil {
		t.Fatalf("deregister_manual failed: err=%v, out=%+v", err, deregRes)
	}

	// F-07: call_tool with "arguments"
	callBridgeRes, err := srv.callTool(context.Background(), "call_tool", map[string]interface{}{
		"tool_name": "get_assurance_state",
		"arguments": map[string]interface{}{
			"subject": "k8s://prod/payments/Deployment/payments-api",
		},
	})
	if err != nil || !strings.Contains(callBridgeRes.Content[0].Text, `"UNKNOWN"`) {
		t.Fatalf("call_tool bridge failed: err=%v, out=%+v", err, callBridgeRes)
	}
}

func TestMCPServerGovernedBrokerEnforcement(t *testing.T) {
	inBuf := new(bytes.Buffer)
	outBuf := new(bytes.Buffer)

	srv, err := NewServerWithBroker(inBuf, outBuf, "", nil)
	if err != nil {
		t.Fatalf("failed to create governed MCP server: %v", err)
	}

	// Unleased register_manual must fail when broker is configured (F-10)
	_, err = srv.callTool(context.Background(), "register_manual", map[string]interface{}{
		"name": "external",
		"manual": map[string]interface{}{
			"version":        "1.0.0",
			"utcp_version":   "1.0.1",
			"manual_version": "1.0.0",
			"name":           "unleased_manual",
			"tools": []interface{}{
				map[string]interface{}{
					"name":        "unleased_tool",
					"description": "Unleased tool",
					"inputs":      map[string]interface{}{"type": "object"},
					"outputs":     map[string]interface{}{"type": "object"},
					"tool_call_template": map[string]interface{}{
						"name":               "unleased_manual",
						"call_template_type": "cli",
						"command_name":       "echo",
					},
				},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "lease") {
		t.Fatalf("expected unleased register_manual to be rejected by lease gate, got: %v", err)
	}

	// Unleased deregister_manual must fail when broker is configured (F-10)
	_, err = srv.callTool(context.Background(), "deregister_manual", map[string]interface{}{
		"manual_name": "ckodex_oskal",
	})
	if err == nil || !strings.Contains(err.Error(), "lease") {
		t.Fatalf("expected unleased deregister_manual to be rejected by lease gate, got: %v", err)
	}

	// Unleased register_tool_provider must fail when broker is configured (F-10)
	_, err = srv.callTool(context.Background(), "register_tool_provider", map[string]interface{}{
		"name":          "ext_prov",
		"provider_type": "cli",
		"command_name":  "echo",
	})
	if err == nil || !strings.Contains(err.Error(), "lease") {
		t.Fatalf("expected unleased register_tool_provider to be rejected by lease gate, got: %v", err)
	}
}

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}
