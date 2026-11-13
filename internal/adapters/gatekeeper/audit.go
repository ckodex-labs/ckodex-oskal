// Package gatekeeper captures actual Constraint audit status without inferring
// workload identity or complete coverage from its capped violation list.
package gatekeeper

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/policyreports"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Violation struct {
	Group              string   `json:"group"`
	Version            string   `json:"version"`
	Kind               string   `json:"kind"`
	Name               string   `json:"name"`
	Namespace          string   `json:"namespace,omitempty"`
	Message            string   `json:"message"`
	EnforcementAction  string   `json:"enforcementAction"`
	EnforcementActions []string `json:"enforcementActions,omitempty"`
}

type AuditStatus struct {
	AuditTimestamp  string      `json:"auditTimestamp"`
	TotalViolations *int64      `json:"totalViolations"`
	Violations      []Violation `json:"violations"`
}

// DecodeConstraint binds evidence to the constraint UID. Native status violations
// contain no resource UID and cannot prove a named workload's current epoch.
func DecodeConstraint(raw []byte, producer assurance.AuthorityRef) (policyreports.Capture, error) {
	if len(raw) == 0 || len(raw) > policyreports.MaxSnapshotBytes {
		return policyreports.Capture{}, fmt.Errorf("constraint snapshot size is outside bounds")
	}
	var object struct {
		metav1.TypeMeta   `json:",inline"`
		metav1.ObjectMeta `json:"metadata"`
		Status            AuditStatus `json:"status"`
	}
	if err := json.Unmarshal(raw, &object); err != nil {
		return policyreports.Capture{}, fmt.Errorf("decode constraint audit: %w", err)
	}
	if object.APIVersion != "constraints.gatekeeper.sh/v1beta1" || object.Kind == "" {
		return policyreports.Capture{}, fmt.Errorf("unsupported Gatekeeper constraint GVK")
	}
	if object.ResourceVersion == "" || object.Generation <= 0 {
		return policyreports.Capture{}, fmt.Errorf("constraint resourceVersion or generation is missing")
	}
	subject, err := policyreports.Subject(corev1.ObjectReference{APIVersion: object.APIVersion, Kind: object.Kind, Name: object.Name, Namespace: object.Namespace, UID: object.UID})
	if err != nil {
		return policyreports.Capture{}, err
	}
	stamp, err := time.Parse(time.RFC3339Nano, object.Status.AuditTimestamp)
	if err != nil {
		return policyreports.Capture{}, fmt.Errorf("constraint audit timestamp is missing or invalid")
	}
	if object.Status.TotalViolations == nil || *object.Status.TotalViolations < 0 || *object.Status.TotalViolations < int64(len(object.Status.Violations)) {
		return policyreports.Capture{}, fmt.Errorf("constraint audit violation count is missing or inconsistent")
	}
	metadata := map[string]string{"apiVersion": object.APIVersion, "kind": object.Kind, "constraintUID": string(object.UID), "resourceVersion": object.ResourceVersion,
		"currentGeneration": strconv.FormatInt(object.Generation, 10), "auditedPolicyRevisionStatus": "UNKNOWN", "policyRevisionStatus": "UNKNOWN",
		"totalViolations": strconv.FormatInt(*object.Status.TotalViolations, 10), "reportedViolations": strconv.Itoa(len(object.Status.Violations)),
		"truncated": strconv.FormatBool(*object.Status.TotalViolations > int64(len(object.Status.Violations))), "workloadIdentityStatus": "UNKNOWN"}
	return policyreports.NewCapture(raw, metadata, nil, subject, stamp, producer, "policy.gatekeeper.audit.observed")
}
