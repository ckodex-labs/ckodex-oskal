// Package policyreports decodes the published PolicyReport and OpenReports APIs.
package policyreports

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const MaxSnapshotBytes = 4 << 20

// ResultFact preserves the engine's result. RevisionStatus is UNKNOWN unless the
// source actually identifies a revision; policy names are never revisions.
type ResultFact struct {
	Source         string            `json:"source"`
	Policy         string            `json:"policy"`
	Rule           string            `json:"rule,omitempty"`
	Result         string            `json:"result"`
	Timestamp      metav1.Timestamp  `json:"timestamp"`
	Properties     map[string]string `json:"properties,omitempty"`
	PolicyRevision string            `json:"policyRevision,omitempty"`
	RevisionStatus string            `json:"revisionStatus"`
}

// Record is an evidence capture record, not an upstream Kubernetes API. The
// original API bytes survive byte-for-byte in SourceBytes (JSON base64 encoding).
type Record struct {
	Schema      string            `json:"schema"`
	SourceBytes []byte            `json:"sourceBytes"`
	Metadata    map[string]string `json:"metadata"`
	Results     []ResultFact      `json:"results,omitempty"`
}

type Capture struct {
	Event  ports.CapturedEvent
	Record Record
}

type result struct {
	ResultFact
	Resources        []corev1.ObjectReference `json:"resources,omitempty"`
	ResourceSelector *metav1.LabelSelector    `json:"resourceSelector,omitempty"`
}

type report struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Source            string                  `json:"source"`
	Scope             *corev1.ObjectReference `json:"scope"`
	ScopeSelector     *metav1.LabelSelector   `json:"scopeSelector"`
	Results           []result                `json:"results"`
}

// Subject requires concrete Kubernetes object identity; selectors and names alone
// cannot bind a historical observation to a current epoch.
func Subject(ref corev1.ObjectReference) (assurance.SubjectRef, error) {
	if ref.APIVersion == "" || ref.Kind == "" || ref.Name == "" || ref.UID == "" {
		return assurance.SubjectRef{}, fmt.Errorf("policy observation requires apiVersion, kind, name and resource UID")
	}
	id := ref.Kind + "/" + ref.Name
	if ref.Namespace != "" {
		id = ref.Namespace + "/" + id
	}
	return assurance.SubjectRef{Scheme: "k8s", ID: id, Attributes: map[string]string{
		"apiVersion": ref.APIVersion, "kind": ref.Kind, "namespace": ref.Namespace, "name": ref.Name, "uid": string(ref.UID),
	}}, nil
}

// NewCapture stores explicit provenance gaps alongside the unmodified source.
func NewCapture(raw []byte, metadata map[string]string, facts []ResultFact, subject assurance.SubjectRef, capturedAt time.Time, producer assurance.AuthorityRef, observationType string) (Capture, error) {
	if len(raw) == 0 || len(raw) > MaxSnapshotBytes {
		return Capture{}, fmt.Errorf("policy snapshot size is outside bounds")
	}
	if err := producer.Validate(); err != nil {
		return Capture{}, err
	}
	if err := subject.Validate(); err != nil {
		return Capture{}, err
	}
	if capturedAt.IsZero() {
		return Capture{}, fmt.Errorf("policy observation timestamp is missing")
	}
	record := Record{Schema: "assurance.ckodex.io/policy-capture/v1alpha1", SourceBytes: append([]byte(nil), raw...), Metadata: metadata, Results: facts}
	payload, err := json.Marshal(record)
	if err != nil {
		return Capture{}, err
	}
	if len(payload) > MaxSnapshotBytes {
		return Capture{}, fmt.Errorf("policy capture record exceeds byte bound")
	}
	return Capture{Record: record, Event: ports.CapturedEvent{Subject: subject, Type: observationType, CapturedAt: capturedAt, Producer: producer,
		Payload: payload, MediaType: "application/vnd.ckodex.policy-capture+json", ControlRefs: []assurance.ControlRef{{Namespace: "policy-engine", ID: "decision.observed"}},
	}}, nil
}

// Decode supports the exact published GVKs only. An empty report, summary counts,
// warning, error or skip cannot create a positive compliance assertion.
func Decode(raw []byte, producer assurance.AuthorityRef) ([]Capture, error) {
	if len(raw) == 0 || len(raw) > MaxSnapshotBytes {
		return nil, fmt.Errorf("policy report size is outside bounds")
	}
	var r report
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("decode policy report: %w", err)
	}
	valid := (r.APIVersion == "wgpolicyk8s.io/v1alpha2" && (r.Kind == "PolicyReport" || r.Kind == "ClusterPolicyReport")) ||
		(r.APIVersion == "openreports.io/v1alpha1" && (r.Kind == "Report" || r.Kind == "ClusterReport"))
	if !valid {
		return nil, fmt.Errorf("unsupported policy report GVK %q %q", r.APIVersion, r.Kind)
	}
	if r.UID == "" || r.ResourceVersion == "" || r.Name == "" {
		return nil, fmt.Errorf("policy report metadata lacks authoritative identity or resourceVersion")
	}
	if len(r.Results) == 0 {
		return nil, fmt.Errorf("policy report contains no result evidence")
	}
	if len(r.Results) > 1024 {
		return nil, fmt.Errorf("policy report exceeds result bound")
	}
	type group struct {
		subject assurance.SubjectRef
		facts   []ResultFact
		oldest  time.Time
	}
	groups := map[string]*group{}
	var order []string
	for _, row := range r.Results {
		f := row.ResultFact
		if f.Source == "" {
			f.Source = r.Source
		}
		if f.Source == "" || f.Policy == "" {
			return nil, fmt.Errorf("policy result lacks source or policy identity")
		}
		switch f.Result {
		case "pass", "fail", "warn", "error", "skip":
		default:
			return nil, fmt.Errorf("unsupported policy result")
		}
		if f.Timestamp.Seconds <= 0 || f.Timestamp.Seconds > 253402300799 || f.Timestamp.Nanos < 0 || f.Timestamp.Nanos >= 1e9 {
			return nil, fmt.Errorf("policy result timestamp is missing or invalid")
		}
		// Neither standard API guarantees a policy revision field. Preserve all
		// original properties, but never interpret arbitrary properties as proof.
		f.PolicyRevision = ""
		f.RevisionStatus = "UNKNOWN"
		refs := row.Resources
		if row.ResourceSelector != nil {
			return nil, fmt.Errorf("selector-only result cannot bind concrete resource identity")
		}
		if len(refs) == 0 {
			if r.Scope == nil || r.ScopeSelector != nil {
				return nil, fmt.Errorf("policy report has no concrete resource scope")
			}
			refs = []corev1.ObjectReference{*r.Scope}
		}
		for _, ref := range refs {
			subject, err := Subject(ref)
			if err != nil {
				return nil, err
			}
			key := subject.URI() + "|" + string(ref.UID)
			g := groups[key]
			if g == nil {
				if len(groups) >= 256 {
					return nil, fmt.Errorf("policy report exceeds concrete subject bound")
				}
				g = &group{subject: subject}
				groups[key] = g
				order = append(order, key)
			}
			g.facts = append(g.facts, f)
			if len(g.facts) > 1024 {
				return nil, fmt.Errorf("policy report exceeds per-subject result bound")
			}
			stamp := time.Unix(f.Timestamp.Seconds, int64(f.Timestamp.Nanos)).UTC()
			if g.oldest.IsZero() || stamp.Before(g.oldest) {
				g.oldest = stamp
			}
		}
	}
	var captures []Capture
	for _, key := range order {
		g := groups[key]
		capture, err := NewCapture(raw, map[string]string{"apiVersion": r.APIVersion, "kind": r.Kind, "reportUID": string(r.UID), "resourceVersion": r.ResourceVersion, "policyRevisionStatus": "UNKNOWN"}, g.facts, g.subject, g.oldest, producer, "policy.report.snapshot")
		if err != nil {
			return nil, err
		}
		captures = append(captures, capture)
	}
	return captures, nil
}
