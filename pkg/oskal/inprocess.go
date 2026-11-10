package oskal

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/explain"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	evidencev1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/evidence/v1"
	receiptv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/receipt/v1"
)

// DefaultFreshnessWindow is the standard 15-minute maximum evidence freshness window.
const DefaultFreshnessWindow = 15 * time.Minute

func isObservationViolation(obs *evidencev1.Observation) bool {
	if obs == nil {
		return false
	}
	if assurance.IsAdverseObservationType(obs.Type) {
		return true
	}
	for k, v := range obs.Attributes {
		kl := strings.ToLower(strings.TrimSpace(k))
		vl := strings.ToLower(strings.TrimSpace(v))
		switch kl {
		case "status", "disposition", "result", "outcome", "state":
			if vl == "violation" || vl == "failed" || vl == "fail" || vl == "denied" || vl == "deny" {
				return true
			}
		case "valence":
			if vl == "negative" {
				return true
			}
		case "violation", "failed", "denied":
			if vl == "true" || vl == "1" {
				return true
			}
		}
	}
	return false
}

func evaluateObservations(obsList []*evidencev1.Observation, now time.Time) (AssuranceState, string, []assurance.EvidenceRef, string, int) {
	var validRefs []assurance.EvidenceRef
	validObsCount := 0
	hasViolation := false
	hasStale := false

	for _, obs := range obsList {
		if obs == nil || obs.ObservedAt == nil {
			continue
		}
		obsTime := obs.ObservedAt.AsTime()
		if obsTime.IsZero() || obsTime.After(now.Add(1*time.Minute)) {
			continue
		}
		isViol := isObservationViolation(obs)
		if !isViol && len(obs.Evidence) == 0 {
			continue
		}
		validObsCount++
		if isViol {
			hasViolation = true
		}
		if now.Sub(obsTime) > DefaultFreshnessWindow {
			hasStale = true
		}
		for _, ev := range obs.Evidence {
			if ev == nil {
				continue
			}
			validRefs = append(validRefs, assurance.EvidenceRef{
				URI:       ev.Uri,
				Digest:    ev.Digest,
				MediaType: ev.MediaType,
			})
		}
	}

	if validObsCount == 0 {
		return StateUnknown, "unknown", nil, "none", 0
	}

	evRoot := "none"
	if len(validRefs) > 0 {
		evRoot = receipts.ComputeEvidenceRoot(validRefs)
	}
	if hasViolation {
		return StateFailed, "current", validRefs, evRoot, validObsCount
	}
	if hasStale {
		return StateStale, "stale", validRefs, evRoot, validObsCount
	}
	return StateAssured, "current", validRefs, evRoot, validObsCount
}

// InProcessClient is an in-memory embedded implementation of the OSKAL Client interface.
// It allows consumers to evaluate claims, store observations, and verify receipts
// without requiring an external running gRPC daemon.
type InProcessClient struct {
	mu           sync.RWMutex
	observations map[string][]*evidencev1.Observation
	subjectOrder []string
	receipts     map[string]*receiptv1.ControlReceipt
	receiptOrder []string
	explainer    *explain.Explainer
	receiptMgr   *receipts.ReceiptManager
}

// InProcessOption configures the in-process client.
type InProcessOption func(*InProcessClient)

// WithEvaluatorAuthority sets the authority used for signing and issuing receipts locally.
func WithEvaluatorAuthority(auth AuthorityRef) InProcessOption {
	return func(c *InProcessClient) {
		mgr, err := receipts.NewReceiptManager(auth)
		if err == nil {
			c.receiptMgr = mgr
		}
	}
}

// WithReceiptManager injects a pre-configured ReceiptManager into the in-process client.
func WithReceiptManager(mgr *ReceiptManager) InProcessOption {
	return func(c *InProcessClient) {
		if mgr != nil {
			c.receiptMgr = mgr.inner
		}
	}
}

// NewInProcessClient initializes an embedded in-memory OSKAL client.
func NewInProcessClient(opts ...InProcessOption) *InProcessClient {
	c := &InProcessClient{
		observations: make(map[string][]*evidencev1.Observation),
		receipts:     make(map[string]*receiptv1.ControlReceipt),
		explainer:    explain.NewExplainer(),
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.receiptMgr == nil {
		mgr, _ := receipts.NewReceiptManager(assurance.AuthorityRef{
			Scheme:  "spiffe",
			Subject: "local/in-process/sa/oskal-evaluator",
		})
		c.receiptMgr = mgr
	}
	return c
}

// Close is a no-op for in-process client.
func (c *InProcessClient) Close() error {
	return nil
}

// GetAssuranceState queries the in-memory evaluated assurance state for a subject.
func (c *InProcessClient) GetAssuranceState(ctx context.Context, subject SubjectRef) (*StateResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now().UTC()
	subKey := subject.Scheme + "://" + subject.ID
	obsList := c.observations[subKey]

	state, freshness, _, evRoot, _ := evaluateObservations(obsList, now)

	// Invariant I-02: Absence of valid evidence is UNKNOWN, never PASS
	if state == StateUnknown {
		return &StateResponse{
			Subject:       subject,
			State:         StateUnknown,
			EvidenceRoot:  "none",
			LastEvaluated: now,
			Freshness:     "unknown",
		}, nil
	}

	policyDigest := assurance.ComputeStringDigest(subKey + ":" + evRoot)

	return &StateResponse{
		Subject:      subject,
		State:        state,
		EvidenceRoot: evRoot,
		Epoch: &AssuranceEpoch{
			SubjectDigest:        assurance.ComputeStringDigest(subKey),
			ImplementationDigest: assurance.ComputeStringDigest("kubernetes:workload-specification"),
			PolicyDigest:         policyDigest,
			AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
			EnvironmentDigest:    assurance.ComputeStringDigest("cluster:kubernetes"),
		},
		LastEvaluated: now,
		Freshness:     freshness,
	}, nil
}

// EvaluateSubject evaluates all specified controls for a given subject.
func (c *InProcessClient) EvaluateSubject(ctx context.Context, subject SubjectRef, controls []ControlRef) (*EvaluationResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	subKey := subject.Scheme + "://" + subject.ID
	obsList := c.observations[subKey]
	now := time.Now().UTC()

	targetState, _, _, evRoot, validObsCount := evaluateObservations(obsList, now)
	completeness := EvidenceCompleteness{Required: len(controls)}

	switch targetState {
	case StateAssured:
		completeness.Present = validObsCount
		completeness.Verified = validObsCount
	case StateStale:
		completeness.Present = validObsCount
		completeness.Stale = validObsCount
	case StateFailed:
		completeness.Present = validObsCount
		completeness.Missing = len(controls)
	default:
		completeness.Missing = len(controls)
	}

	var evals []ClaimEvaluation
	for _, ctrl := range controls {
		evals = append(evals, ClaimEvaluation{
			ID:      fmt.Sprintf("eval-%s-%s", subject.ID, ctrl.ID),
			Subject: subject,
			Control: ctrl,
			State:   targetState,
			Epoch: AssuranceEpoch{
				SubjectDigest:        assurance.ComputeStringDigest(subKey),
				ImplementationDigest: assurance.ComputeStringDigest("kubernetes:workload-specification"),
				PolicyDigest:         assurance.ComputeStringDigest(subKey + ":" + evRoot),
				AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
				EnvironmentDigest:    assurance.ComputeStringDigest("cluster:kubernetes"),
			},
			Completeness: completeness,
			EvidenceRoot: evRoot,
			EvaluatedAt:  now,
			ValidUntil:   now.Add(5 * time.Minute),
		})
	}

	return &EvaluationResponse{
		Subject:      subject,
		SummaryState: targetState,
		Evaluations:  evals,
		EvaluatedAt:  now,
	}, nil
}

// ExplainClaim generates an explainability graph for a subject and control (Section 51).
func (c *InProcessClient) ExplainClaim(ctx context.Context, subject SubjectRef, control ControlRef) (*ExplainResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now().UTC()
	subKey := subject.Scheme + "://" + subject.ID
	obsList := c.observations[subKey]

	targetState, _, evRefs, evRoot, validObsCount := evaluateObservations(obsList, now)
	comp := EvidenceCompleteness{Required: 1}
	switch targetState {
	case StateAssured:
		comp.Present = validObsCount
		comp.Verified = validObsCount
	case StateStale:
		comp.Present = validObsCount
		comp.Stale = validObsCount
	default:
		comp.Missing = 1
	}

	eval := ClaimEvaluation{
		ID:           "eval-01",
		Subject:      subject,
		Control:      control,
		State:        targetState,
		Evidence:     evRefs,
		Completeness: comp,
		EvidenceRoot: evRoot,
		Epoch: AssuranceEpoch{
			SubjectDigest:        assurance.ComputeStringDigest(subKey),
			ImplementationDigest: assurance.ComputeStringDigest("kubernetes:workload-specification"),
			PolicyDigest:         assurance.ComputeStringDigest(subKey + ":" + evRoot),
			AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
			EnvironmentDigest:    assurance.ComputeStringDigest("cluster:kubernetes"),
		},
		EvaluatedAt: now,
		ValidUntil:  now.Add(5 * time.Minute),
	}

	graph := c.explainer.BuildExplainGraph(ctx, subject, control, eval)

	return &ExplainResponse{
		Subject:          subject,
		Control:          control,
		CanonicalControl: graph.CanonicalControl,
		AssuranceState:   targetState,
		EvidenceRoot:     evRoot,
		Graph:            graph,
		RenderedText:     graph.RenderText(),
	}, nil
}

// SubmitObservation ingests an observation in-memory.
func (c *InProcessClient) SubmitObservation(ctx context.Context, obs *ProtoObservation) (string, error) {
	if obs == nil || obs.Subject == nil {
		return "", fmt.Errorf("observation and subject cannot be nil")
	}
	if obs.Id == "" {
		obs.Id = fmt.Sprintf("obs-%d", time.Now().UnixNano())
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	const (
		maxObservationsPerSubject = 1000
		maxTrackedSubjects        = 4096
	)
	subKey := obs.Subject.Scheme + "://" + obs.Subject.Id
	if _, exists := c.observations[subKey]; !exists {
		if len(c.observations) >= maxTrackedSubjects && len(c.subjectOrder) > 0 {
			evictKey := c.subjectOrder[0]
			c.subjectOrder = c.subjectOrder[1:]
			delete(c.observations, evictKey)
		}
		c.subjectOrder = append(c.subjectOrder, subKey)
	}
	list := append(c.observations[subKey], obs)
	if len(list) > maxObservationsPerSubject {
		list = list[len(list)-maxObservationsPerSubject:]
	}
	c.observations[subKey] = list
	return obs.Id, nil
}

// SubmitReceipt verifies and stores a signed control receipt.
func (c *InProcessClient) SubmitReceipt(ctx context.Context, rcpt *ProtoReceipt) (bool, string, error) {
	if rcpt == nil {
		return false, "receipt cannot be nil", fmt.Errorf("receipt is nil")
	}
	if rcpt.Subject == nil || rcpt.Control == nil || rcpt.Evaluator == nil || rcpt.EvaluatedAt == nil {
		return false, "receipt missing required fields", fmt.Errorf("receipt requires non-nil subject, control, evaluator, and evaluated_at")
	}

	coreReceipt := assurance.ControlReceipt{
		Subject: assurance.SubjectRef{
			Scheme: rcpt.Subject.GetScheme(),
			ID:     rcpt.Subject.GetId(),
		},
		Control: assurance.ControlRef{
			Namespace: rcpt.Control.GetNamespace(),
			ID:        rcpt.Control.GetId(),
			Version:   rcpt.Control.GetVersion(),
		},
		State:        mapProtoState(rcpt.State),
		EvidenceRoot: rcpt.EvidenceRoot,
		Evaluator: assurance.AuthorityRef{
			Scheme:      rcpt.Evaluator.GetScheme(),
			Subject:     rcpt.Evaluator.GetSubject(),
			TrustDomain: rcpt.Evaluator.GetTrustDomain(),
		},
		EvaluatedAt: rcpt.EvaluatedAt.AsTime(),
		Signature:   rcpt.Signature,
	}

	if rcpt.Epoch != nil {
		coreReceipt.Epoch = assurance.AssuranceEpoch{
			SubjectDigest:        rcpt.Epoch.SubjectDigest,
			ImplementationDigest: rcpt.Epoch.ImplementationDigest,
			PolicyDigest:         rcpt.Epoch.PolicyDigest,
			AuthorityDigest:      rcpt.Epoch.AuthorityDigest,
			EnvironmentDigest:    rcpt.Epoch.EnvironmentDigest,
		}
	}

	verified, _ := receipts.VerifyIndependentReceipt(coreReceipt, c.receiptMgr.PublicKey())
	if !verified {
		return false, "signature or digest verification failed", nil
	}

	const maxStoredReceipts = 8192
	digest := coreReceipt.Digest()
	c.mu.Lock()
	if _, exists := c.receipts[digest]; !exists {
		if len(c.receipts) >= maxStoredReceipts && len(c.receiptOrder) > 0 {
			evictDigest := c.receiptOrder[0]
			c.receiptOrder = c.receiptOrder[1:]
			delete(c.receipts, evictDigest)
		}
		c.receiptOrder = append(c.receiptOrder, digest)
	}
	c.receipts[digest] = rcpt
	c.mu.Unlock()

	return true, "Receipt verified and accepted", nil
}
