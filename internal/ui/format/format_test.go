package format

import (
	"bytes"
	"strings"
	"testing"
)

func TestNormalizeFormat(t *testing.T) {
	cases := []struct {
		input    string
		expected OutputFormat
		wantErr  bool
	}{
		{"", FormatTable, false},
		{"table", FormatTable, false},
		{"tbl", FormatTable, false},
		{"tree", FormatTree, false},
		{"json", FormatJSON, false},
		{"yaml", FormatYAML, false},
		{"yml", FormatYAML, false},
		{"invalid", "", true},
	}

	for _, c := range cases {
		f, err := NormalizeFormat(c.input)
		if (err != nil) != c.wantErr {
			t.Fatalf("NormalizeFormat(%q) err=%v, wantErr=%v", c.input, err, c.wantErr)
		}
		if f != c.expected {
			t.Fatalf("NormalizeFormat(%q) = %v, expected %v", c.input, f, c.expected)
		}
	}
}

func TestRenderTable(t *testing.T) {
	buf := new(bytes.Buffer)
	headers := []string{"CHECK", "STATUS", "REASON"}
	rows := [][]string{
		{"kubernetes", "PASS", "Connected to API server"},
		{"sigstore", "PASS", "Cosign root verified"},
	}

	if err := RenderTable(buf, headers, rows); err != nil {
		t.Fatalf("RenderTable failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "CHECK") || !strings.Contains(out, "kubernetes") {
		t.Fatalf("unexpected table output: %s", out)
	}

	// Verify pure ASCII
	for _, b := range buf.Bytes() {
		if b > 127 {
			t.Fatalf("non-ASCII character detected: %d", b)
		}
	}
}

func TestRenderTree(t *testing.T) {
	buf := new(bytes.Buffer)
	root := &TreeNode{
		Title:   "Subject",
		Details: "payments-api",
		Children: []*TreeNode{
			{
				Title:   "Control",
				Details: "AC-6",
				Children: []*TreeNode{
					{Title: "Evidence", Details: "admission.json (verified)"},
				},
			},
			{
				Title:   "Control",
				Details: "SC-28",
			},
		},
	}

	if err := RenderTree(buf, root); err != nil {
		t.Fatalf("RenderTree failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "payments-api") || !strings.Contains(out, "+-- Control: AC-6") {
		t.Fatalf("unexpected tree output:\n%s", out)
	}

	// Verify pure ASCII
	for _, b := range buf.Bytes() {
		if b > 127 {
			t.Fatalf("non-ASCII character detected: %d", b)
		}
	}
}

func TestRenderStructured(t *testing.T) {
	data := map[string]string{"status": "ok", "framework": "nist"}
	bufJSON := new(bytes.Buffer)
	if err := RenderStructured(bufJSON, data, FormatJSON); err != nil {
		t.Fatalf("RenderStructured JSON failed: %v", err)
	}
	if !strings.Contains(bufJSON.String(), `"status": "ok"`) {
		t.Fatalf("unexpected JSON output: %s", bufJSON.String())
	}

	bufYAML := new(bytes.Buffer)
	if err := RenderStructured(bufYAML, data, FormatYAML); err != nil {
		t.Fatalf("RenderStructured YAML failed: %v", err)
	}
	if !strings.Contains(bufYAML.String(), "status: ok") {
		t.Fatalf("unexpected YAML output: %s", bufYAML.String())
	}
}
