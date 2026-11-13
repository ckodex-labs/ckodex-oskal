package signedrecords_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
)

type detail struct {
	Name string `json:"name"`
}
type record struct {
	Version int               `json:"version"`
	At      time.Time         `json:"at"`
	Detail  detail            `json:"detail"`
	Items   []detail          `json:"items"`
	Labels  map[string]string `json:"labels"`
}

func TestDecodeJSONStrictTypedRecords(t *testing.T) {
	valid := []byte(`{"version":1,"at":"2026-11-13T00:00:00Z","detail":{"name":"\ud83d\ude80"},"items":[{"name":"one"}],"labels":{"source":"observed"}}`)
	var result record
	if err := signedrecords.DecodeJSON(valid, &result, 1024); err != nil {
		t.Fatal(err)
	}
	if result.Version != 1 || result.Detail.Name != "🚀" || result.At.IsZero() || result.Items[0].Name != "one" {
		t.Fatal("typed record changed")
	}
	cases := map[string][]byte{
		"duplicate-root":         []byte(`{"version":1,"version":2}`),
		"duplicate-escaped":      []byte(`{"version":1,"\u0076ersion":2}`),
		"duplicate-nested":       []byte(`{"detail":{"name":"one","name":"two"}}`),
		"duplicate-in-array":     []byte(`{"items":[{"name":"one","name":"two"}]}`),
		"unknown-root":           []byte(`{"unknown":1}`),
		"unknown-nested":         []byte(`{"detail":{"unknown":1}}`),
		"case-alias":             []byte(`{"Version":1}`),
		"two-semantic-fields":    []byte(`{"version":1,"Version":2}`),
		"trailing-document":      []byte(`{} {}`),
		"trailing-garbage":       []byte(`{} x`),
		"wrong-type":             []byte(`{"version":"one"}`),
		"surrogate-high":         []byte(`{"detail":{"name":"\ud800"}}`),
		"surrogate-low":          []byte(`{"detail":{"name":"\udc00"}}`),
		"surrogate-pair-invalid": []byte(`{"detail":{"name":"\ud800\u0061"}}`),
		"invalid-utf8":           append([]byte(`{"detail":{"name":"`), append([]byte{0xff}, []byte(`"}}`)...)...),
		"deep":                   []byte(strings.Repeat(`[`, signedrecords.MaxJSONDepth+1) + `0` + strings.Repeat(`]`, signedrecords.MaxJSONDepth+1)),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			out := record{Version: 99}
			if err := signedrecords.DecodeJSON(raw, &out, 4096); err == nil {
				t.Fatal("invalid record accepted")
			}
			if out.Version != 99 {
				t.Fatal("rejected input partially mutated destination")
			}
		})
	}
	if err := signedrecords.DecodeJSON(valid, &result, len(valid)-1); err == nil {
		t.Fatal("byte budget ignored")
	}
	for _, dst := range []any{nil, record{}, (*record)(nil)} {
		if err := signedrecords.DecodeJSON(valid, dst, 1024); err == nil {
			t.Fatal("invalid destination accepted")
		}
	}
	var dynamic map[string]any
	if err := signedrecords.DecodeJSON([]byte(`{"n":9007199254740993}`), &dynamic, 1024); err != nil {
		t.Fatal(err)
	}
	if number, ok := dynamic["n"].(json.Number); !ok || number.String() != "9007199254740993" {
		t.Fatal("dynamic JSON number lost precision")
	}
	var escaped detail
	if err := signedrecords.DecodeJSON([]byte(`{"name":"\\ud800"}`), &escaped, 1024); err != nil || escaped.Name != `\ud800` {
		t.Fatal("literal escape sequence changed")
	}
}

func TestVerifyThenDecodeDoesNotCanonicalizePayload(t *testing.T) {
	body := []byte(" {\n \"version\" : 1, \"detail\":{\"name\":\"native\"} }\n")
	raw, pub := signed(t, body)
	payload, err := signedrecords.Verify(t.Context(), raw, recordType, pub, 1024)
	if err != nil {
		t.Fatal(err)
	}
	var value record
	if err := signedrecords.DecodeJSON(payload, &value, 1024); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, body) || value.Version != 1 {
		t.Fatal("authenticated bytes changed during typed parsing")
	}
}

func TestDecodeJSONPreservesFixedArrayMeaning(t *testing.T) {
	type measurement struct {
		PCR [4]byte `json:"pcr"`
	}
	for _, raw := range []string{`{"pcr":[1,2,3]}`, `{"pcr":[1,2,3,4,5]}`, `{"pcr":null}`} {
		value := measurement{PCR: [4]byte{9, 9, 9, 9}}
		if err := signedrecords.DecodeJSON([]byte(raw), &value, 1024); err == nil {
			t.Fatal("fixed array was padded, truncated or replaced with zeroes")
		}
		if value.PCR != ([4]byte{9, 9, 9, 9}) {
			t.Fatal("rejected fixed array mutated destination")
		}
	}
	var value measurement
	if err := signedrecords.DecodeJSON([]byte(`{"pcr":[0,1,254,255]}`), &value, 1024); err != nil || value.PCR != ([4]byte{0, 1, 254, 255}) {
		t.Fatalf("exact fixed array rejected: %v", err)
	}
	var values []int
	large := []byte("[" + strings.Repeat("0,", signedrecords.MaxJSONValues) + "0]")
	if err := signedrecords.DecodeJSON(large, &values, signedrecords.MaxPayloadBytes); !errors.Is(err, signedrecords.ErrLimit) {
		t.Fatalf("JSON value count did not enforce resource bound: %v", err)
	}
}
