package openreports

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// OpenReportFinding represents a finding from an external scanner or policy engine (Section 24).
type OpenReportFinding struct {
	Rule       string            `json:"rule"`
	Source     string            `json:"source"`   // "kyverno", "trivy", "kube-bench", "gatekeeper"
	Result     string            `json:"result"`   // "pass", "fail", "warn", "error", "skip"
	Severity   string            `json:"severity"` // "critical", "high", "medium", "low", "info"
	Message    string            `json:"message"`
	Timestamp  time.Time         `json:"timestamp"`
	Properties map[string]string `json:"properties,omitempty"`
}

// OpenReportSubject identifies the target resource evaluated in the report.
type OpenReportSubject struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
}

// OpenReportSpec defines the content of an OpenReports resource.
type OpenReportSpec struct {
	Subject  OpenReportSubject   `json:"subject"`
	Findings []OpenReportFinding `json:"findings"`
}

// OpenReport represents the OpenReports Kubernetes resource (namespaced or cluster-scoped).
type OpenReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OpenReportSpec `json:"spec"`
}

// Adapter normalizes OpenReports scanner findings into canonical Assurance Core types.
type Adapter struct {
	observerIdentity assurance.AuthorityRef
}

// NewAdapter creates a new OpenReports adapter.
func NewAdapter(identity assurance.AuthorityRef) *Adapter {
	if identity.Scheme == "" {
		identity = assurance.AuthorityRef{
			Scheme:      "spiffe",
			Subject:     "prod/ns/ckodex-evidence/sa/openreports-normalizer",
			TrustDomain: "prod",
		}
	}
	return &Adapter{observerIdentity: identity}
}

// NormalizeSubject converts an OpenReportSubject into a canonical SubjectRef.
func (a *Adapter) NormalizeSubject(sub OpenReportSubject) assurance.SubjectRef {
	id := fmt.Sprintf("%s/%s/%s", sub.Namespace, sub.Kind, sub.Name)
	if sub.Namespace == "" {
		id = fmt.Sprintf("%s/%s", sub.Kind, sub.Name)
	}
	return assurance.SubjectRef{
		Scheme: "k8s",
		ID:     id,
		Attributes: map[string]string{
			"apiVersion": sub.APIVersion,
			"kind":       sub.Kind,
			"namespace":  sub.Namespace,
			"name":       sub.Name,
			"uid":        sub.UID,
		},
	}
}

// NormalizeSeverity maps scanner-specific severity strings to canonical severity.
func NormalizeSeverity(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "INFORMATIONAL"
	}
}

// IngestReport processes an OpenReport and extracts normalized observations and findings.
// Crucial: Provider-specific types are completely consumed here and never leak into Assurance Core.
func (a *Adapter) IngestReport(
	report OpenReport,
	epoch assurance.AssuranceEpoch,
	now time.Time,
) ([]assurance.Observation, []assurance.Finding, []assurance.EvidenceEnvelope) {
	subjectRef := a.NormalizeSubject(report.Spec.Subject)

	var observations []assurance.Observation
	var findings []assurance.Finding
	var envelopes []assurance.EvidenceEnvelope

	for i, f := range report.Spec.Findings {
		obsID := fmt.Sprintf("obs-openrep-%s-%d", report.Name, i)
		evidenceDig := assurance.ComputeStringDigest(fmt.Sprintf("%s|%s|%s|%s|%d", f.Source, f.Rule, f.Result, f.Message, f.Timestamp.Unix()))

		evRef := assurance.EvidenceRef{
			URI:       fmt.Sprintf("openreports://%s/%s/%d", report.Namespace, report.Name, i),
			Digest:    evidenceDig,
			MediaType: "application/vnd.openreports.finding+json",
		}

		obs := assurance.Observation{
			ID:         obsID,
			Subject:    subjectRef,
			Type:       fmt.Sprintf("scanner.%s", strings.ToLower(f.Source)),
			ObservedAt: f.Timestamp,
			Observer:   a.observerIdentity,
			Evidence:   []assurance.EvidenceRef{evRef},
			Attributes: map[string]string{
				"rule":     f.Rule,
				"source":   f.Source,
				"result":   f.Result,
				"severity": f.Severity,
			},
		}
		observations = append(observations, obs)

		// Map to finding if result indicates non-compliance / violation
		switch strings.ToLower(f.Result) {
		case "fail", "error":
			findingID := fmt.Sprintf("find-openrep-%s-%d", report.Name, i)
			finding := assurance.Finding{
				ID:           findingID,
				Subject:      subjectRef,
				Control:      assurance.ControlRef{Namespace: "external-scanner", ID: f.Rule},
				Severity:     NormalizeSeverity(f.Severity),
				Title:        fmt.Sprintf("[%s] %s", f.Source, f.Rule),
				Description:  f.Message,
				DiscoveredAt: f.Timestamp,
				EvidenceRefs: []assurance.EvidenceRef{evRef},
			}
			findings = append(findings, finding)
		case "pass":
			// Generate positive evidence envelope
			env := assurance.EvidenceEnvelope{
				Schema:          "assurance.ckodex.io/evidence/v1alpha1",
				ID:              fmt.Sprintf("ev-openrep-%s-%d", report.Name, i),
				Subject:         subjectRef,
				ObservationType: fmt.Sprintf("scanner.%s", strings.ToLower(f.Source)),
				CapturedAt:      f.Timestamp,
				Producer:        a.observerIdentity,
				Artifact:        evRef,
				IntegrityDigest: evidenceDig,
				Epoch:           epoch,
				ControlRefs: []assurance.ControlRef{
					{Namespace: "external-scanner", ID: f.Rule},
				},
			}
			envelopes = append(envelopes, env)
		}
	}

	return observations, findings, envelopes
}

// ComputeReportDigest computes a content-addressed digest of an OpenReport.
func ComputeReportDigest(report OpenReport) string {
	var sb strings.Builder
	sb.WriteString(report.Name)
	sb.WriteString("|")
	sb.WriteString(report.Spec.Subject.Kind)
	sb.WriteString("|")
	sb.WriteString(report.Spec.Subject.Name)
	sb.WriteString("|")
	for _, f := range report.Spec.Findings {
		fmt.Fprintf(&sb, "%s:%s:%s;", f.Source, f.Rule, f.Result)
	}
	h := sha256.Sum256([]byte(sb.String()))
	return "sha256:" + hex.EncodeToString(h[:])
}
