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

	// Verify line 3 (tools/list has 7 tools)
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
	if len(resp3.Result.Tools) != 7 {
		t.Fatalf("expected 7 tools, got %d", len(resp3.Result.Tools))
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
}

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}
