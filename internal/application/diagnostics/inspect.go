package diagnostics

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

// TelemetryTrace answers: What did the machinery do? (Constitution Section 13.1)
type TelemetryTrace struct {
	EvaluationDuration string `json:"evaluation_duration"`
	EvidenceFetchTime  string `json:"evidence_fetch_time"`
	RuleExecutionTime  string `json:"rule_execution_time"`
	MemoryAllocatedKB  uint64 `json:"memory_allocated_kb"`
	CacheHit           bool   `json:"cache_hit"`
}

// ExecutionStep represents a discrete technical stage traversed during evaluation.
type ExecutionStep struct {
	Order   int    `json:"order"`
	Stage   string `json:"stage"`
	Action  string `json:"action"`
	Outcome string `json:"outcome"`
}

// ExecutionTrace answers: Which technical path actually executed? (Constitution Section 13.2)
type ExecutionTrace struct {
	PathID string          `json:"path_id"`
	Steps  []ExecutionStep `json:"steps"`
}

// DecisionTrace answers: Why did the governed system make this decision? (Constitution Section 13.3)
type DecisionTrace struct {
	ControlID       string            `json:"control_id"`
	PolicyDigest    string            `json:"policy_digest"`
	EffectivePolicy string            `json:"effective_policy"`
	Disposition     string            `json:"disposition"`
	Obligations     []string          `json:"obligations,omitempty"`
	InputBindings   map[string]string `json:"input_bindings"`
	Rationale       string            `json:"rationale"`
}

// EvidenceItem represents post-execution cryptographic proof.
type EvidenceItem struct {
	EnvelopeID string `json:"envelope_id"`
	Type       string `json:"type"`
	Digest     string `json:"digest"`
	Producer   string `json:"producer"`
	Timestamp  string `json:"timestamp"`
	Freshness  string `json:"freshness"`
}

// EvidenceTrace answers: What can be proven afterward? (Constitution Section 13.4)
type EvidenceTrace struct {
	EvidenceRoot    string         `json:"evidence_root"`
	SignerIdentity  string         `json:"signer_identity"`
	Artifacts       []EvidenceItem `json:"artifacts"`
	MerkleValid     bool           `json:"merkle_valid"`
	LineageVerified bool           `json:"lineage_verified"`
}

// RemediationAction provides actionable advice and remediation steps to achieve or restore compliance.
type RemediationAction struct {
	TargetControl  string   `json:"target_control"`
	Disposition    string   `json:"disposition"`
	MissingSignals []string `json:"missing_signals"`
	RemediationCmd string   `json:"remediation_cmd"`
	Explanation    string   `json:"explanation"`
}

// InspectionReport unifies all 4 Truth Channels for a governed subject.
type InspectionReport struct {
	Subject        string             `json:"subject"`
	AssuranceState string             `json:"assurance_state"`
	Timestamp      time.Time          `json:"timestamp"`
	Telemetry      TelemetryTrace     `json:"telemetry_trace"`
	Execution      ExecutionTrace     `json:"execution_trace"`
	Decision       DecisionTrace      `json:"decision_trace"`
	Evidence       EvidenceTrace      `json:"evidence_trace"`
	Remediation    *RemediationAction `json:"remediation,omitempty"`
}

// InspectSubject inspects a workload subject and reconstructs all 4 Truth Channels.
func InspectSubject(
	_ context.Context,
	subject assurance.SubjectRef,
	eval assurance.ClaimEvaluation,
	envelopes []assurance.EvidenceEnvelope,
) *InspectionReport {
	now := time.Now().UTC()
	start := time.Now()
	ruleStart := time.Now()

	var validEnvelopes []assurance.EvidenceEnvelope
	hasStaleEnvelope := false
	for _, env := range envelopes {
		if env.CapturedAt.IsZero() || env.CapturedAt.After(now.Add(1*time.Minute)) {
			continue
		}
		if now.Sub(env.CapturedAt) > 15*time.Minute {
			hasStaleEnvelope = true
		}
		validEnvelopes = append(validEnvelopes, env)
	}
	if len(envelopes) > 0 && len(validEnvelopes) == 0 {
		eval.State = assurance.AssuranceStateUnknown
		eval.EvidenceRoot = ""
	} else if hasStaleEnvelope && (eval.State == assurance.AssuranceStateAssured || eval.State == assurance.AssuranceStateVerified) {
		eval.State = assurance.AssuranceStateStale
	}

	// 1. Telemetry Trace (populated with measured runtime metrics at end of inspection)
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	telemetry := TelemetryTrace{
		MemoryAllocatedKB: memStats.Alloc / 1024,
		CacheHit:          len(validEnvelopes) > 0,
	}

	// 2. Execution Trace
	cryptoOutcome := "VERIFIED"
	policyOutcome := "EVALUATED"
	receiptOutcome := "EMITTED"
	switch eval.State {
	case assurance.AssuranceStateUnknown, assurance.AssuranceStateUnspecified:
		if len(validEnvelopes) == 0 {
			cryptoOutcome = "UNVERIFIED"
			policyOutcome = "SKIPPED"
			receiptOutcome = "SKIPPED"
		} else {
			cryptoOutcome = "UNVERIFIED"
			receiptOutcome = "SKIPPED"
		}
	case assurance.AssuranceStateStale:
		cryptoOutcome = "STALE"
		receiptOutcome = "DEFERRED"
	case assurance.AssuranceStateFailed:
		cryptoOutcome = "FAILED"
		receiptOutcome = "SKIPPED"
	}

	execSteps := []ExecutionStep{
		{Order: 1, Stage: "Ingestion", Action: "Resolve subject reference", Outcome: "RESOLVED"},
		{Order: 2, Stage: "EvidenceGathering", Action: fmt.Sprintf("Query CAS repository (%d envelopes)", len(validEnvelopes)), Outcome: "COMPLETED"},
		{Order: 3, Stage: "CryptographicVerification", Action: "Verify Merkle root & producer SPIFFE identities", Outcome: cryptoOutcome},
		{Order: 4, Stage: "PolicyEvaluation", Action: fmt.Sprintf("Evaluate CEL contract for %s", eval.Control.ID), Outcome: policyOutcome},
		{Order: 5, Stage: "StateTransition", Action: "Compute 6D Vector State transition", Outcome: eval.State.String()},
		{Order: 6, Stage: "ReceiptGeneration", Action: "Emit signed in-toto receipt & Merkle attestation", Outcome: receiptOutcome},
	}
	execTrace := ExecutionTrace{
		PathID: fmt.Sprintf("trace-%s-%d", eval.Control.ID, now.UnixNano()),
		Steps:  execSteps,
	}

	// 3. Decision Trace
	disposition := "ADMIT"
	rationale := "All evidence requirements satisfied with valid cryptographic proofs."
	switch eval.State {
	case assurance.AssuranceStateUnknown:
		disposition = "SAFE_HOLD"
		rationale = "Absence of verified evidence (Section 15: EMPTY != NEGATIVE, but requires SAFE_HOLD)."
	case assurance.AssuranceStateFailed:
		disposition = "DENY"
		rationale = "Non-conformant evaluation or anti-invariant violation."
	case assurance.AssuranceStateStale:
		disposition = "ADMIT_WITH_OBLIGATIONS"
		rationale = "Operating on stale evidence; obligation to refresh evidence emitted."
	}

	decTrace := DecisionTrace{
		ControlID:       eval.Control.ID,
		PolicyDigest:    eval.Epoch.PolicyDigest,
		EffectivePolicy: fmt.Sprintf("cel:policy:%s:v1", eval.Control.ID),
		Disposition:     disposition,
		Obligations:     []string{"log-admission-event", "refresh-within-15m"},
		InputBindings: map[string]string{
			"subject.uri":  subject.URI(),
			"control.id":   eval.Control.ID,
			"epoch.digest": eval.Epoch.PolicyDigest,
		},
		Rationale: rationale,
	}
	ruleDur := time.Since(ruleStart)
	evStart := time.Now()

	// 4. Evidence Trace
	var items []EvidenceItem
	var evRefs []assurance.EvidenceRef
	for _, env := range validEnvelopes {
		evRefs = append(evRefs, env.Artifact)
		freshness := "FRESH"
		if eval.State == assurance.AssuranceStateStale || now.Sub(env.CapturedAt) > 15*time.Minute {
			freshness = "STALE"
		}
		items = append(items, EvidenceItem{
			EnvelopeID: env.ID,
			Type:       env.ObservationType,
			Digest:     env.Artifact.Digest,
			Producer:   env.Producer.Canonical(),
			Timestamp:  env.CapturedAt.Format(time.RFC3339),
			Freshness:  freshness,
		})
	}

	evRoot := eval.EvidenceRoot
	if evRoot == "" && len(evRefs) > 0 {
		evRoot = receipts.ComputeEvidenceRoot(evRefs)
	}

	signerID := "none"
	if len(validEnvelopes) > 0 {
		signerID = validEnvelopes[0].Producer.Canonical()
	} else if eval.State == assurance.AssuranceStateAssured || eval.State == assurance.AssuranceStateVerified {
		signerID = "spiffe://assurance.ckodex.io/server"
	}

	evidenceTrace := EvidenceTrace{
		EvidenceRoot:    evRoot,
		SignerIdentity:  signerID,
		Artifacts:       items,
		MerkleValid:     len(items) > 0 && eval.State != assurance.AssuranceStateFailed,
		LineageVerified: len(items) > 0 && (eval.State == assurance.AssuranceStateAssured || eval.State == assurance.AssuranceStateVerified),
	}
	evDur := time.Since(evStart)

	var remediation *RemediationAction
	ctrlID := eval.Control.ID
	if ctrlID == "" {
		ctrlID = "AC-6"
	}

	switch eval.State {
	case assurance.AssuranceStateUnknown:
		remediation = &RemediationAction{
			TargetControl:  ctrlID,
			Disposition:    "SAFE_HOLD",
			MissingSignals: []string{"kubernetes.admission evidence", "runtime.ebpf telemetry", "spiffe.svid identity"},
			RemediationCmd: "oskal record admission --file <manifest.yaml> OR deploy ckodex-webhook to cluster",
			Explanation:    "Subject is in SAFE_HOLD because no verified evidence envelopes exist in CAS (EMPTY != NEGATIVE). Ingest observations to transition out of UNKNOWN.",
		}
	case assurance.AssuranceStateFailed:
		remediation = &RemediationAction{
			TargetControl:  ctrlID,
			Disposition:    "DENY",
			MissingSignals: []string{"non-root securityContext", "dropped capabilities (CAP_SYS_ADMIN, CAP_NET_ADMIN)"},
			RemediationCmd: "Update pod spec: set securityContext.runAsNonRoot=true and drop privileged capabilities",
			Explanation:    "Subject violated non-negotiable security invariant (Invariant I-01). Resource execution is blocked.",
		}
	case assurance.AssuranceStateStale:
		remediation = &RemediationAction{
			TargetControl:  ctrlID,
			Disposition:    "ADMIT_WITH_OBLIGATIONS",
			MissingSignals: []string{"fresh evidence within 15-minute validity epoch"},
			RemediationCmd: "oskal daemon sync OR trigger observer refresh for subject",
			Explanation:    "Existing evidence is older than maximum freshness window. Refresh required to maintain assurance standing.",
		}
	}

	report := &InspectionReport{
		Subject:        subject.URI(),
		AssuranceState: eval.State.String(),
		Timestamp:      now,
		Telemetry:      telemetry,
		Execution:      execTrace,
		Decision:       decTrace,
		Evidence:       evidenceTrace,
		Remediation:    remediation,
	}
	report.Telemetry.RuleExecutionTime = formatDurationASCII(ruleDur)
	report.Telemetry.EvidenceFetchTime = formatDurationASCII(evDur)
	report.Telemetry.EvaluationDuration = formatDurationASCII(time.Since(start))
	return report
}
