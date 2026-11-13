// Package opa decodes the official gzip decision-log service format. Transport
// authentication belongs to the caller; log-supplied identity is never authority.
package opa

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/policyreports"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	corev1 "k8s.io/api/core/v1"
)

const MaxCompressedBytes = 1 << 20
const MaxUncompressedBytes = 4 << 20
const MaxBatchEvents = 128

type Config struct {
	DecisionPath string
	BundleName   string
	AllowResult  json.RawMessage
	DenyResult   json.RawMessage
	Producer     assurance.AuthorityRef
}

type Decoder struct {
	config Config
	allow  bool
}

func NewDecoder(config Config) (*Decoder, error) {
	if strings.Trim(config.DecisionPath, "/") == "" || config.BundleName == "" {
		return nil, fmt.Errorf("explicit OPA decision path and bundle name are required")
	}
	if err := config.Producer.Validate(); err != nil {
		return nil, err
	}
	var allow, deny bool
	boolean := func(raw []byte) bool {
		raw = bytes.TrimSpace(raw)
		return bytes.Equal(raw, []byte("true")) || bytes.Equal(raw, []byte("false"))
	}
	if !boolean(config.AllowResult) || !boolean(config.DenyResult) || json.Unmarshal(config.AllowResult, &allow) != nil || json.Unmarshal(config.DenyResult, &deny) != nil || allow == deny {
		return nil, fmt.Errorf("explicit distinct boolean OPA allow and deny result mappings are required")
	}
	config.DecisionPath = strings.Trim(config.DecisionPath, "/")
	return &Decoder{config: config, allow: allow}, nil
}

// DecodeBatch validates the entire bounded batch before returning any events.
// It rejects unmasked input and unexpected fields instead of storing or logging
// them. Configure OPA's system.log.mask to keep only input.subject metadata.
func (d *Decoder) DecodeBatch(reader io.Reader) ([]policyreports.Capture, error) {
	compressed, err := io.ReadAll(io.LimitReader(reader, MaxCompressedBytes+1))
	if err != nil {
		return nil, err
	}
	if len(compressed) > MaxCompressedBytes {
		return nil, fmt.Errorf("OPA compressed batch exceeds bound")
	}
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("invalid OPA gzip batch")
	}
	defer func() { _ = gz.Close() }()
	plain, err := io.ReadAll(io.LimitReader(gz, MaxUncompressedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read OPA gzip batch: %w", err)
	}
	if len(plain) > MaxUncompressedBytes {
		return nil, fmt.Errorf("OPA uncompressed batch exceeds bound")
	}
	if err := uniqueJSON(plain); err != nil {
		return nil, err
	}
	var batch []json.RawMessage
	if err := json.Unmarshal(plain, &batch); err != nil {
		return nil, fmt.Errorf("OPA batch must be a JSON array")
	}
	if len(batch) == 0 || len(batch) > MaxBatchEvents {
		return nil, fmt.Errorf("OPA batch event count is outside bounds")
	}
	captures := make([]policyreports.Capture, 0, len(batch))
	for _, raw := range batch {
		capture, err := d.decode(raw)
		if err != nil {
			return nil, err
		}
		captures = append(captures, capture)
	}
	return captures, nil
}

func (d *Decoder) Ingest(ctx context.Context, reader io.Reader, writer ports.CapturedEventWriter) error {
	if writer == nil {
		return fmt.Errorf("OPA event writer is required")
	}
	captures, err := d.DecodeBatch(reader)
	if err != nil {
		return err
	}
	for _, capture := range captures {
		if err := writer.WriteCapturedEvent(ctx, capture.Event); err != nil {
			return err
		}
	}
	return nil
}

func (d *Decoder) decode(raw []byte) (policyreports.Capture, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return policyreports.Capture{}, fmt.Errorf("invalid OPA decision event")
	}
	for field := range fields {
		switch field {
		case "decision_id", "path", "result", "bundles", "timestamp", "input", "erased", "masked", "labels", "metrics", "req_id", "trace_id", "span_id", "requested_by":
		default:
			return policyreports.Capture{}, fmt.Errorf("OPA decision contains fields outside masked capture allowlist")
		}
	}
	var event struct {
		DecisionID string          `json:"decision_id"`
		Path       string          `json:"path"`
		Result     json.RawMessage `json:"result"`
		Bundles    map[string]struct {
			Revision string `json:"revision"`
		} `json:"bundles"`
		Timestamp   time.Time                  `json:"timestamp"`
		Input       map[string]json.RawMessage `json:"input"`
		Labels      map[string]string          `json:"labels"`
		Metrics     map[string]float64         `json:"metrics"`
		Erased      []string                   `json:"erased"`
		Masked      []string                   `json:"masked"`
		RequestID   json.Number                `json:"req_id"`
		TraceID     string                     `json:"trace_id"`
		SpanID      string                     `json:"span_id"`
		RequestedBy string                     `json:"requested_by"`
	}
	if err := json.Unmarshal(raw, &event); err != nil {
		return policyreports.Capture{}, fmt.Errorf("OPA decision has invalid typed fields")
	}
	if event.DecisionID == "" || strings.Trim(event.Path, "/") != d.config.DecisionPath {
		return policyreports.Capture{}, fmt.Errorf("OPA decision identity or configured path is missing or mismatched")
	}
	if event.Bundles[d.config.BundleName].Revision == "" {
		return policyreports.Capture{}, fmt.Errorf("OPA configured bundle revision is missing")
	}
	if len(event.Input) != 1 || event.Input["subject"] == nil {
		return policyreports.Capture{}, fmt.Errorf("OPA input must contain only allowlisted subject metadata")
	}
	for label := range event.Labels {
		if label != "id" && label != "version" && label != "app" {
			return policyreports.Capture{}, fmt.Errorf("OPA labels contain fields outside capture allowlist")
		}
	}
	var subjectFields map[string]json.RawMessage
	if err := json.Unmarshal(event.Input["subject"], &subjectFields); err != nil {
		return policyreports.Capture{}, fmt.Errorf("OPA subject metadata is invalid")
	}
	for field := range subjectFields {
		switch field {
		case "apiVersion", "kind", "namespace", "name", "uid":
		default:
			return policyreports.Capture{}, fmt.Errorf("OPA subject contains fields outside capture allowlist")
		}
	}
	var ref corev1.ObjectReference
	if err := json.Unmarshal(event.Input["subject"], &ref); err != nil {
		return policyreports.Capture{}, fmt.Errorf("OPA subject metadata is invalid")
	}
	subject, err := policyreports.Subject(ref)
	if err != nil {
		return policyreports.Capture{}, err
	}
	trimmed := bytes.TrimSpace(event.Result)
	if !bytes.Equal(trimmed, []byte("true")) && !bytes.Equal(trimmed, []byte("false")) {
		return policyreports.Capture{}, fmt.Errorf("OPA configured boolean decision returned another result type")
	}
	var result bool
	if err := json.Unmarshal(trimmed, &result); err != nil {
		return policyreports.Capture{}, err
	}
	classification := "deny"
	if result == d.allow {
		classification = "allow"
	}
	metadata := map[string]string{"decisionID": event.DecisionID, "decisionPath": d.config.DecisionPath, "bundleName": d.config.BundleName, "policyRevision": event.Bundles[d.config.BundleName].Revision, "policyRevisionStatus": "PRESENT", "resultMapping": classification, "inputRetention": "SUBJECT_METADATA_ONLY"}
	return policyreports.NewCapture(raw, metadata, nil, subject, event.Timestamp, d.config.Producer, "policy.opa.decision."+classification+".observed")
}

// Duplicate keys could hide unmasked input from validation while retaining it in
// raw evidence. Reject duplicates and excessive nesting before decoding.
func uniqueJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return fmt.Errorf("OPA JSON nesting exceeds bound")
		}
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("invalid OPA JSON")
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				if len(seen) >= 256 {
					return fmt.Errorf("OPA JSON object exceeds field bound")
				}
				keyToken, err := decoder.Token()
				if err != nil {
					return fmt.Errorf("invalid OPA JSON object")
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return fmt.Errorf("OPA JSON contains duplicate object keys")
				}
				seen[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			count := 0
			for decoder.More() {
				count++
				if count > MaxBatchEvents {
					return fmt.Errorf("OPA JSON array exceeds element bound")
				}
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("invalid OPA JSON delimiter")
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("invalid OPA JSON closure")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("OPA JSON contains trailing data")
	}
	return nil
}
