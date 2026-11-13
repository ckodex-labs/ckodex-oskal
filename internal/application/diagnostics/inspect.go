package diagnostics

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

// TelemetryTrace answers: What did the machinery do? (Constitution Section 13.1)
type TelemetryTrace struct {
	Scope              string `json:"scope"`
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
	EvidenceRoot   string         `json:"evidence_root"`
	SignerIdentity string         `json:"signer_identity"`
	Artifacts      []EvidenceItem `json:"artifacts"`
	// Legacy compatibility: no Merkle inclusion proof is available; use RootConsistency.
	MerkleValid bool `json:"merkle_valid"`
	// Legacy compatibility: a receipt does not establish observation lineage.
	LineageVerified              bool        `json:"lineage_verified"`
	RootConsistency              CheckStatus `json:"root_consistency"`
	ReceiptVerification          CheckStatus `json:"receipt_verification"`
	ReceiptBinding               CheckStatus `json:"receipt_binding"`
	ProducerIdentityVerification CheckStatus `json:"producer_identity_verification"`
	LineageVerification          CheckStatus `json:"lineage_verification"`
	VerificationDetail           string      `json:"verification_detail"`
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

// InspectSubject describes supplied evaluation facts. It does not reconstruct
// historical execution, authenticate producers, or infer the existence of receipts.
func InspectSubject(ctx context.Context, subject assurance.SubjectRef, eval assurance.ClaimEvaluation, envelopes []assurance.EvidenceEnvelope) *InspectionReport {
	start := time.Now()
	now := start.UTC()
	var items []EvidenceItem
	for _, env := range envelopes {
		if env.CapturedAt.IsZero() || env.CapturedAt.After(now) {
			continue
		}
		items = append(items, EvidenceItem{
			EnvelopeID: env.ID, Type: env.ObservationType,
			Digest: env.Artifact.Digest, Producer: env.Producer.Canonical(),
			Timestamp: env.CapturedAt.Format(time.RFC3339), Freshness: "UNKNOWN",
		})
	}
	if len(items) == 0 && (eval.State == assurance.AssuranceStateAssured || eval.State == assurance.AssuranceStateVerified) {
		eval.State = assurance.AssuranceStateUnknown
		eval.EvidenceRoot = ""
	}
	evidence := EvidenceTrace{
		EvidenceRoot: eval.EvidenceRoot, SignerIdentity: "UNKNOWN", Artifacts: items,
		RootConsistency: StatusUnknown, ReceiptVerification: StatusUnknown,
		ReceiptBinding: StatusUnknown, ProducerIdentityVerification: StatusUnknown,
		LineageVerification: StatusUnknown,
		VerificationDetail:  "No receipt or trusted verification key supplied. Observation payload integrity and producer identity have not been verified by inspection.",
	}
	if len(eval.Evidence) > 0 && eval.EvidenceRoot != "" {
		evidence.RootConsistency = StatusFail
		if receipts.ComputeEvidenceRoot(eval.Evidence) == eval.EvidenceRoot {
			evidence.RootConsistency = StatusPass
		}
	}
	if evidence.RootConsistency == StatusFail {
		evidence.VerificationDetail = "Supplied evidence reference digests contradict the reported aggregate root; preserve the inputs and investigate."
		if eval.State != assurance.AssuranceStateFailed {
			eval.State = assurance.AssuranceStateUnknown
		}
	}
	disposition := "SAFE_HOLD"
	rationale := "The supplied evaluation does not establish an admission decision."
	switch eval.State {
	case assurance.AssuranceStateAssured, assurance.AssuranceStateVerified:
		disposition = "ADMIT"
		rationale = "The supplied evaluation reports its evidence requirements satisfied; inspection has not authenticated that evaluation or its observations."
	case assurance.AssuranceStateUnknown:
		rationale = "The supplied evaluation lacks sufficient eligible evidence. UNKNOWN does not establish a violation."
	case assurance.AssuranceStateFailed:
		disposition = "DENY"
		rationale = "The supplied evaluation reports a failed control; inspect its decision trace and governing contract for the cause."
	case assurance.AssuranceStateStale:
		disposition = "ADMIT_WITH_OBLIGATIONS"
		rationale = "The supplied evaluation reports stale evidence. The governing policy determines any obligations."
	}
	policy := eval.Epoch.PolicyDigest
	if policy == "" {
		policy = "UNKNOWN"
	}
	report := &InspectionReport{
		Subject: subject.URI(), AssuranceState: eval.State.String(), Timestamp: now,
		Execution: ExecutionTrace{PathID: eval.ID, Steps: []ExecutionStep{
			{Order: 1, Stage: "Inspection", Action: fmt.Sprintf("Describe %d supplied evidence envelopes", len(items)), Outcome: "OBSERVED"},
			{Order: 2, Stage: "HistoricalExecution", Action: "Original execution trace was not supplied", Outcome: "UNKNOWN"},
			{Order: 3, Stage: "ReceiptVerification", Action: "No receipt or trusted verification key supplied", Outcome: "UNKNOWN"},
		}},
		Decision: DecisionTrace{
			ControlID: eval.Control.ID, PolicyDigest: eval.Epoch.PolicyDigest,
			EffectivePolicy: policy, Disposition: disposition,
			InputBindings: map[string]string{
				"subject.uri": subject.URI(), "control.id": eval.Control.ID,
				"epoch.digest": eval.Epoch.CompositeDigest(),
			},
			Rationale: rationale,
		},
		Evidence: evidence,
	}
	if ctx.Err() != nil {
		report.Evidence.VerificationDetail = "Inspection interrupted: " + ctx.Err().Error()
	}
	if disposition != "ADMIT" {
		report.Remediation = &RemediationAction{TargetControl: eval.Control.ID, Disposition: disposition, Explanation: "Inspect the governing EvidenceContract and evaluation decision trace; refresh missing or stale observations or investigate reported violations. No recovery operation has been executed."}
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	report.Telemetry.MemoryAllocatedKB = mem.Alloc / 1024
	report.Telemetry.Scope = "inspection"
	report.Telemetry.EvidenceFetchTime = "UNKNOWN"
	report.Telemetry.RuleExecutionTime = "UNKNOWN"
	report.Telemetry.EvaluationDuration = formatDurationASCII(time.Since(start))
	return report
}

// InspectStoredSubject verifies a persisted receipt using an explicit trust anchor.
// The key must be trusted by the caller, not inferred from the receipt or archive.
// A valid receipt authenticates the evaluator assertion, not the observations.
func InspectStoredSubject(ctx context.Context, subject assurance.SubjectRef, eval assurance.ClaimEvaluation, envelopes []assurance.EvidenceEnvelope, repo ports.ReceiptRepository, receiptID, trustedPublicKey string) (*InspectionReport, error) {
	report := InspectSubject(ctx, subject, eval, envelopes)
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if trustedPublicKey == "" {
		return report, fmt.Errorf("an explicitly trusted receipt public key is required")
	}
	if repo == nil {
		return report, fmt.Errorf("receipt repository is required")
	}
	receipt, err := repo.GetReceipt(ctx, receiptID)
	if err != nil {
		return report, fmt.Errorf("read inspection receipt: %w", err)
	}
	ok, err := receipts.VerifyIndependentReceipt(receipt, trustedPublicKey)
	if err != nil || !ok {
		report.Evidence.ReceiptVerification = StatusFail
		report.Evidence.VerificationDetail = "Receipt signature verification failed under the supplied trust anchor."
		if err != nil {
			return report, fmt.Errorf("verify inspection receipt: %w", err)
		}
		return report, fmt.Errorf("invalid inspection receipt signature")
	}
	report.Evidence.ReceiptVerification = StatusPass
	report.Evidence.SignerIdentity = receipt.Evaluator.Canonical()
	report.Evidence.ReceiptBinding = StatusFail
	stateMatches := receipt.State == eval.State || (receipt.State == assurance.AssuranceStateAssured && eval.State == assurance.AssuranceStateVerified)
	if report.Evidence.RootConsistency == StatusFail ||
		receipt.Subject.Digest() != subject.Digest() ||
		receipt.Control.Canonical() != eval.Control.Canonical() ||
		receipt.Epoch.CompositeDigest() != eval.Epoch.CompositeDigest() ||
		receipt.EvidenceRoot != eval.EvidenceRoot || !stateMatches ||
		receipt.EvaluatedAt.IsZero() || receipt.EvaluatedAt.After(time.Now().UTC()) {
		report.Evidence.VerificationDetail = "Valid receipt signature, but receipt does not bind this subject, control, state, epoch, evidence root or valid evaluation time."
		return report, fmt.Errorf("inspection receipt binding mismatch")
	}
	report.Evidence.ReceiptBinding = StatusPass
	report.Evidence.VerificationDetail = "Receipt signature and evaluation binding verified under the explicit trust anchor. Observation payload integrity, producer identity and lineage remain UNKNOWN."
	report.Execution.Steps[2] = ExecutionStep{Order: 3, Stage: "ReceiptVerification", Action: "Read stored receipt; verify signature and evaluation binding under explicit trust anchor", Outcome: "VERIFIED"}
	return report, nil
}
