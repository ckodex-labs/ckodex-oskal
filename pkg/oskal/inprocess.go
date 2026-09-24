package oskal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/explain"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	evidencev1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/evidence/v1"
	receiptv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/receipt/v1"
)

// InProcessClient is an in-memory embedded implementation of the OSKAL Client interface.
// It allows consumers to evaluate claims, store observations, and verify receipts
// without requiring an external running gRPC daemon.
type InProcessClient struct {
	mu           sync.RWMutex
	observations map[string][]*evidencev1.Observation
	receipts     map[string]*receiptv1.ControlReceipt
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

	subKey := subject.Scheme + "://" + subject.ID
	obsList := c.observations[subKey]

	// Invariant I-02: Absence of evidence is UNKNOWN, never PASS
	if len(obsList) == 0 {
		return &StateResponse{
			Subject:       subject,
			State:         StateUnknown,
			EvidenceRoot:  "none",
			LastEvaluated: time.Now().UTC(),
			Freshness:     "unknown",
		}, nil
	}

	var evRefs []assurance.EvidenceRef
	for _, obs := range obsList {
		for _, ev := range obs.Evidence {
			evRefs = append(evRefs, assurance.EvidenceRef{
				URI:       ev.Uri,
				Digest:    ev.Digest,
				MediaType: ev.MediaType,
			})
		}
	}
	evRoot := receipts.ComputeEvidenceRoot(evRefs)
	policyDigest := assurance.ComputeStringDigest(subKey + ":" + evRoot)

	return &StateResponse{
		Subject:      subject,
		State:        StateAssured,
		EvidenceRoot: evRoot,
		Epoch: &AssuranceEpoch{
			SubjectDigest:        assurance.ComputeStringDigest(subKey),
			ImplementationDigest: "sha256:imp",
			PolicyDigest:         policyDigest,
			AuthorityDigest:      "sha256:auth",
			EnvironmentDigest:    "sha256:env",
		},
		LastEvaluated: time.Now().UTC(),
		Freshness:     "current",
	}, nil
}

// EvaluateSubject evaluates all specified controls for a given subject.
func (c *InProcessClient) EvaluateSubject(ctx context.Context, subject SubjectRef, controls []ControlRef) (*EvaluationResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	subKey := subject.Scheme + "://" + subject.ID
	obsList := c.observations[subKey]
	now := time.Now().UTC()

	hasEvidence := len(obsList) > 0
	targetState := StateUnknown
	evRoot := "none"
	completeness := EvidenceCompleteness{Required: len(controls)}

	if hasEvidence {
		targetState = StateAssured
		var evRefs []assurance.EvidenceRef
		for _, obs := range obsList {
			for _, ev := range obs.Evidence {
				evRefs = append(evRefs, assurance.EvidenceRef{
					Digest: ev.Digest,
				})
			}
		}
		evRoot = receipts.ComputeEvidenceRoot(evRefs)
		completeness.Present = len(obsList)
		completeness.Verified = len(obsList)
	} else {
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
				ImplementationDigest: "sha256:imp",
				PolicyDigest:         assurance.ComputeStringDigest(subKey + ":" + evRoot),
				AuthorityDigest:      "sha256:auth",
				EnvironmentDigest:    "sha256:env",
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

	subKey := subject.Scheme + "://" + subject.ID
	obsList := c.observations[subKey]

	targetState := StateUnknown
	evRoot := "none"
	var evRefs []assurance.EvidenceRef

	if len(obsList) > 0 {
		targetState = StateAssured
		for _, obs := range obsList {
			for _, ev := range obs.Evidence {
				evRefs = append(evRefs, assurance.EvidenceRef{
					Digest: ev.Digest,
				})
			}
		}
		evRoot = receipts.ComputeEvidenceRoot(evRefs)
	}

	eval := ClaimEvaluation{
		ID:           "eval-01",
		Subject:      subject,
		Control:      control,
		State:        targetState,
		Evidence:     evRefs,
		EvidenceRoot: evRoot,
		Epoch: AssuranceEpoch{
			SubjectDigest:        assurance.ComputeStringDigest(subKey),
			ImplementationDigest: "sha256:imp",
			PolicyDigest:         assurance.ComputeStringDigest(subKey + ":" + evRoot),
			AuthorityDigest:      "sha256:auth",
			EnvironmentDigest:    "sha256:env",
		},
		EvaluatedAt: time.Now().UTC(),
		ValidUntil:  time.Now().UTC().Add(5 * time.Minute),
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

	c.mu.Lock()
	defer c.mu.Unlock()

	subKey := obs.Subject.Scheme + "://" + obs.Subject.Id
	c.observations[subKey] = append(c.observations[subKey], obs)
	return obs.Id, nil
}

// SubmitReceipt verifies and stores a signed control receipt.
func (c *InProcessClient) SubmitReceipt(ctx context.Context, rcpt *ProtoReceipt) (bool, string, error) {
	if rcpt == nil {
		return false, "receipt cannot be nil", fmt.Errorf("receipt is nil")
	}

	coreReceipt := assurance.ControlReceipt{
		Subject: assurance.SubjectRef{
			Scheme: rcpt.Subject.GetScheme(),
			ID:     rcpt.Subject.GetId(),
		},
		Control: assurance.ControlRef{
			Namespace: rcpt.Control.GetNamespace(),
			ID:        rcpt.Control.GetId(),
		},
		State:        mapProtoState(rcpt.State),
		EvidenceRoot: rcpt.EvidenceRoot,
		Evaluator: assurance.AuthorityRef{
			Scheme:  rcpt.Evaluator.GetScheme(),
			Subject: rcpt.Evaluator.GetSubject(),
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

	c.mu.Lock()
	c.receipts[coreReceipt.Digest()] = rcpt
	c.mu.Unlock()

	return true, "Receipt verified and accepted", nil
}
