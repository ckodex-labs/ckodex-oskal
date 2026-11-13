package opa

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestExplicitDecisionContractRequired(t *testing.T) {
	for _, allow := range []string{"", "null", "{}", "\"true\"", "false"} {
		_, err := NewDecoder(Config{DecisionPath: "oskal/authz/allow", BundleName: "oskal", AllowResult: json.RawMessage(allow), DenyResult: json.RawMessage("false"), Producer: assurance.AuthorityRef{Scheme: "local-test", Subject: "contract-test"}})
		if err == nil {
			t.Fatalf("invalid or ambiguous allow/deny contract admitted: %s", allow)
		}
	}
}

func TestRejectDuplicateKeysAndExcessiveNesting(t *testing.T) {
	for _, raw := range []string{`[{"input":{"secret":"unmasked"},"input":{"subject":{}}}]`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34), `[] {}`} {
		if err := uniqueJSON([]byte(raw)); err == nil {
			t.Fatal("ambiguous or unbounded JSON was admitted")
		}
	}
}

func TestCompressedAndExpandedBatchBounds(t *testing.T) {
	decoder, err := NewDecoder(Config{DecisionPath: "oskal/authz/allow", BundleName: "oskal", AllowResult: json.RawMessage("true"), DenyResult: json.RawMessage("false"), Producer: assurance.AuthorityRef{Scheme: "local-test", Subject: "bounds-test"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.DecodeBatch(bytes.NewReader(make([]byte, MaxCompressedBytes+1))); err == nil {
		t.Fatal("oversized compressed body admitted")
	}
	var buffer bytes.Buffer
	zip := gzip.NewWriter(&buffer)
	if _, err := zip.Write(bytes.Repeat([]byte(" "), MaxUncompressedBytes+1)); err != nil {
		t.Fatal(err)
	}
	if err := zip.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.DecodeBatch(&buffer); err == nil {
		t.Fatal("compressed expansion exceeded configured bound")
	}
}
