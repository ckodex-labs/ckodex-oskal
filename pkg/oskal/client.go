package oskal

import (
	"context"
	"fmt"
	"maps"
	"math/rand"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	commonv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/control/v1"
	evidencev1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/evidence/v1"
	servicesv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/services/v1"
)

// Client is the continuous assurance client interface for external dependencies.
type Client interface {
	// GetAssuranceState queries the current evaluated assurance state for a subject.
	GetAssuranceState(ctx context.Context, subject SubjectRef) (*StateResponse, error)

	// EvaluateSubject evaluates all specified controls for a given subject.
	EvaluateSubject(ctx context.Context, subject SubjectRef, controls []ControlRef) (*EvaluationResponse, error)

	// ExplainClaim generates an explainability graph for a subject and control (Section 51).
	ExplainClaim(ctx context.Context, subject SubjectRef, control ControlRef) (*ExplainResponse, error)

	// SubmitObservation ingests a concrete runtime or admission observation.
	SubmitObservation(ctx context.Context, obs *ProtoObservation) (string, error)

	// SubmitReceipt submits a cryptographically signed control receipt for verification.
	SubmitReceipt(ctx context.Context, rcpt *ProtoReceipt) (bool, string, error)

	// Close terminates active network connections.
	Close() error
}

type grpcClient struct {
	conn        *grpc.ClientConn
	grpcClient  servicesv1.AssuranceServiceClient
	timeout     time.Duration
	maxAttempts int
	baseBackoff time.Duration
}

// ClientOption configures an OSKAL client.
type ClientOption func(*clientOptions)

type clientOptions struct {
	dialOptions []grpc.DialOption
	timeout     time.Duration
	maxAttempts int
	baseBackoff time.Duration
}

// WithInsecure explicitly selects plaintext gRPC for local development.
func WithInsecure() ClientOption {
	return func(o *clientOptions) {
		o.dialOptions = append(o.dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
}

// WithDialOptions adds custom gRPC dial options.
func WithDialOptions(opts ...grpc.DialOption) ClientOption {
	return func(o *clientOptions) {
		o.dialOptions = append(o.dialOptions, opts...)
	}
}

// WithTimeout sets a default per-RPC timeout.
func WithTimeout(d time.Duration) ClientOption {
	return func(o *clientOptions) {
		o.timeout = d
	}
}

// WithRetry configures bounded retry with exponential backoff and jitter for idempotent read RPCs (Constitution Section 30).
func WithRetry(maxAttempts int, baseBackoff time.Duration) ClientOption {
	return func(o *clientOptions) {
		if maxAttempts < 1 {
			maxAttempts = 1
		}
		if maxAttempts > 5 {
			maxAttempts = 5
		}
		o.maxAttempts = maxAttempts
		o.baseBackoff = baseBackoff
	}
}

// NewClient connects to an OSKAL AssuranceService gRPC daemon at the specified target address.
func NewClient(ctx context.Context, target string, opts ...ClientOption) (Client, error) {
	options := clientOptions{
		timeout:     10 * time.Second,
		maxAttempts: 2,
		baseBackoff: 25 * time.Millisecond,
	}
	for _, opt := range opts {
		opt(&options)
	}

	if len(options.dialOptions) == 0 {
		return nil, fmt.Errorf("explicit transport credentials are required; configure TLS with WithDialOptions or explicitly opt into WithInsecure")
	}

	conn, err := grpc.NewClient(target, options.dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial OSKAL AssuranceService at %s: %w", target, err)
	}

	return &grpcClient{
		conn:        conn,
		grpcClient:  servicesv1.NewAssuranceServiceClient(conn),
		timeout:     options.timeout,
		maxAttempts: options.maxAttempts,
		baseBackoff: options.baseBackoff,
	}, nil
}

func (c *grpcClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *grpcClient) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.timeout > 0 {
		return context.WithTimeout(ctx, c.timeout)
	}
	return ctx, func() {}
}

func isTransientGRPCError(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch st.Code() {
	case codes.Unavailable, codes.ResourceExhausted:
		return true
	default:
		return false
	}
}

func (c *grpcClient) doIdempotentRPC(ctx context.Context, fn func(context.Context) error) error {
	attempts := c.maxAttempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rpcCtx, cancel := c.withTimeout(ctx)
		lastErr = fn(rpcCtx)
		cancel()
		if lastErr == nil || attempt == attempts || !isTransientGRPCError(lastErr) {
			return lastErr
		}
		backoff := c.baseBackoff * time.Duration(1<<(attempt-1))
		if backoff <= 0 {
			backoff = 25 * time.Millisecond
		}
		if backoff > 2*time.Second {
			backoff = 2 * time.Second
		}
		// Bounded 0..50% jitter
		jitter := time.Duration(rand.Int63n(int64(backoff/2) + 1))
		timer := time.NewTimer(backoff + jitter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}

func (c *grpcClient) GetAssuranceState(ctx context.Context, subject SubjectRef) (*StateResponse, error) {
	var resp *servicesv1.GetAssuranceStateResponse
	err := c.doIdempotentRPC(ctx, func(rpcCtx context.Context) error {
		var callErr error
		resp, callErr = c.grpcClient.GetAssuranceState(rpcCtx, &servicesv1.GetAssuranceStateRequest{
			Subject: &commonv1.SubjectRef{
				Scheme:     subject.Scheme,
				Id:         subject.ID,
				Attributes: maps.Clone(subject.Attributes),
			},
		})
		return callErr
	})
	if err != nil {
		return nil, err
	}

	state := mapProtoState(resp.State)
	freshness := "unknown"
	var lastEvaluated time.Time
	if state == StateStale {
		freshness = "stale"
	}
	if len(resp.Evaluations) > 0 {
		current := true
		for _, e := range resp.Evaluations {
			if e == nil || e.EvaluatedAt == nil || e.ValidUntil == nil {
				current = false
				continue
			}
			observed := e.EvaluatedAt.AsTime()
			if lastEvaluated.IsZero() || observed.Before(lastEvaluated) {
				lastEvaluated = observed
			}
			if !time.Now().Before(e.ValidUntil.AsTime()) {
				current = false
			}
		}
		if current {
			freshness = "current"
		}
	}

	var epoch *AssuranceEpoch
	if resp.Epoch != nil {
		epoch = &AssuranceEpoch{
			SubjectDigest:        resp.Epoch.SubjectDigest,
			ImplementationDigest: resp.Epoch.ImplementationDigest,
			PolicyDigest:         resp.Epoch.PolicyDigest,
			AuthorityDigest:      resp.Epoch.AuthorityDigest,
			EnvironmentDigest:    resp.Epoch.EnvironmentDigest,
		}
	}

	return &StateResponse{
		Subject:       subjectFromProto(resp.Subject),
		State:         state,
		EvidenceRoot:  resp.EvidenceRoot,
		Epoch:         epoch,
		LastEvaluated: lastEvaluated,
		Freshness:     freshness,
		RawResponse:   resp.State,
	}, nil
}

func (c *grpcClient) EvaluateSubject(ctx context.Context, subject SubjectRef, controls []ControlRef) (*EvaluationResponse, error) {
	var protoCtrls []*controlv1.ControlRef
	for _, ctrl := range controls {
		protoCtrls = append(protoCtrls, &controlv1.ControlRef{
			Namespace: ctrl.Namespace,
			Id:        ctrl.ID,
			Version:   ctrl.Version,
		})
	}

	var resp *servicesv1.EvaluateSubjectResponse
	err := c.doIdempotentRPC(ctx, func(rpcCtx context.Context) error {
		var callErr error
		resp, callErr = c.grpcClient.EvaluateSubject(rpcCtx, &servicesv1.EvaluateSubjectRequest{
			Subject: &commonv1.SubjectRef{
				Scheme:     subject.Scheme,
				Id:         subject.ID,
				Attributes: maps.Clone(subject.Attributes),
			},
			Controls: protoCtrls,
		})
		return callErr
	})
	if err != nil {
		return nil, err
	}

	var evals []ClaimEvaluation
	for _, evalProto := range resp.Evaluations {
		if evalProto == nil {
			continue
		}
		ctrl := ControlRef{}
		if evalProto.Control != nil {
			ctrl = ControlRef{Namespace: evalProto.Control.Namespace, ID: evalProto.Control.Id, Version: evalProto.Control.Version}
		}
		var epoch AssuranceEpoch
		if evalProto.Epoch != nil {
			epoch = AssuranceEpoch{
				SubjectDigest:        evalProto.Epoch.SubjectDigest,
				ImplementationDigest: evalProto.Epoch.ImplementationDigest,
				PolicyDigest:         evalProto.Epoch.PolicyDigest,
				AuthorityDigest:      evalProto.Epoch.AuthorityDigest,
				EnvironmentDigest:    evalProto.Epoch.EnvironmentDigest,
			}
		}
		completeness := EvidenceCompleteness{}
		if evalProto.Completeness != nil {
			completeness = EvidenceCompleteness{
				Required: int(evalProto.Completeness.Required),
				Present:  int(evalProto.Completeness.Present),
				Verified: int(evalProto.Completeness.Verified),
				Stale:    int(evalProto.Completeness.Stale),
				Missing:  int(evalProto.Completeness.Missing),
			}
		}
		var evalAt, validUntil time.Time
		if evalProto.EvaluatedAt != nil {
			evalAt = evalProto.EvaluatedAt.AsTime()
		}
		if evalProto.ValidUntil != nil {
			validUntil = evalProto.ValidUntil.AsTime()
		}

		var vec assurance.AssuranceVector
		if evalProto.Vector != nil {
			vec = assurance.AssuranceVector{
				Applicability: mapProtoValence(evalProto.Vector.Applicability),
				Conformance:   mapProtoValence(evalProto.Vector.Conformance),
				Provenance:    mapProtoValence(evalProto.Vector.Provenance),
				Integrity:     mapProtoValence(evalProto.Vector.Integrity),
				Authority:     mapProtoValence(evalProto.Vector.Authority),
				Identity:      mapProtoValence(evalProto.Vector.Identity),
				Runtime:       mapProtoValence(evalProto.Vector.Runtime),
				Freshness:     mapProtoValence(evalProto.Vector.Freshness),
				Completeness:  mapProtoValence(evalProto.Vector.Completeness),
				Coherence:     mapProtoCoherence(evalProto.Vector.Coherence),
			}
		}

		evals = append(evals, ClaimEvaluation{
			ID:           evalProto.Id,
			Subject:      subjectFromProto(evalProto.Subject),
			Control:      ctrl,
			State:        mapProtoState(evalProto.State),
			Vector:       vec,
			Epoch:        epoch,
			Completeness: completeness,
			EvidenceRoot: evalProto.EvidenceRoot,
			EvaluatedAt:  evalAt,
			ValidUntil:   validUntil,
			Evidence:     evidenceFromProto(evalProto.Evidence),
			Trace:        append([]string(nil), evalProto.Trace...),
		})
	}

	return &EvaluationResponse{
		Subject:      subjectFromProto(resp.Subject),
		SummaryState: mapProtoState(resp.SummaryState),
		Evaluations:  evals,
		EvaluatedAt:  oldestEvaluationTime(evals),
	}, nil
}

func (c *grpcClient) ExplainClaim(ctx context.Context, subject SubjectRef, control ControlRef) (*ExplainResponse, error) {
	var resp *servicesv1.ExplainClaimResponse
	err := c.doIdempotentRPC(ctx, func(rpcCtx context.Context) error {
		var callErr error
		resp, callErr = c.grpcClient.ExplainClaim(rpcCtx, &servicesv1.ExplainClaimRequest{
			Subject: &commonv1.SubjectRef{
				Scheme:     subject.Scheme,
				Id:         subject.ID,
				Attributes: maps.Clone(subject.Attributes),
			},
			Control: &controlv1.ControlRef{
				Namespace: control.Namespace,
				Id:        control.ID,
				Version:   control.Version,
			},
		})
		return callErr
	})
	if err != nil {
		return nil, err
	}

	var atoms []ExplainAtomicReq
	for _, a := range resp.AtomicRequirements {
		if a == nil {
			continue
		}
		atoms = append(atoms, ExplainAtomicReq{
			ID:        a.Id,
			Satisfied: a.Satisfied,
			Details:   a.Description,
		})
	}

	var imps []ExplainImplementation
	for _, imp := range resp.Implementations {
		if imp == nil {
			continue
		}
		imps = append(imps, ExplainImplementation{
			Requirement: imp.Id,
			Provider:    imp.Provider,
			Digest:      imp.Digest,
		})
	}

	state := mapProtoState(resp.AssuranceState)

	var evItems []ExplainEvidenceItem
	for _, ev := range resp.Evidence {
		if ev == nil {
			continue
		}
		evItems = append(evItems, ExplainEvidenceItem{
			Type:   ev.MediaType,
			Digest: ev.Digest,
			// References do not supply a producer or per-item verification.
		})
	}

	completeness := EvidenceCompleteness{}
	if resp.Completeness != nil {
		verified := int(resp.Completeness.Verified)

		completeness = EvidenceCompleteness{
			Required: int(resp.Completeness.Required),
			Present:  int(resp.Completeness.Present),
			Verified: verified,
			Stale:    int(resp.Completeness.Stale),
			Missing:  int(resp.Completeness.Missing),
		}
	}

	var epoch AssuranceEpoch
	if resp.Epoch != nil {
		epoch = AssuranceEpoch{
			SubjectDigest:        resp.Epoch.SubjectDigest,
			ImplementationDigest: resp.Epoch.ImplementationDigest,
			PolicyDigest:         resp.Epoch.PolicyDigest,
			AuthorityDigest:      resp.Epoch.AuthorityDigest,
			EnvironmentDigest:    resp.Epoch.EnvironmentDigest,
		}
	}

	graph := ExplainGraph{
		Subject:            subjectFromProto(resp.Subject),
		Control:            controlFromProto(resp.Control),
		CanonicalControl:   resp.CanonicalControl,
		Applicability:      resp.Applicability,
		AtomicRequirements: atoms,
		Implementations:    imps,
		Evidence:           evItems,
		Completeness:       completeness,
		Freshness:          resp.Freshness,
		Authority:          resp.Authority,
		Epoch:              epoch,
		AssuranceState:     state,
		EvidenceRoot:       resp.EvidenceRoot,
		Projections:        resp.Projections,
	}

	return &ExplainResponse{
		Evidence:         evidenceFromProto(resp.Evidence),
		Subject:          subjectFromProto(resp.Subject),
		Control:          controlFromProto(resp.Control),
		CanonicalControl: resp.CanonicalControl,
		AssuranceState:   state,
		EvidenceRoot:     resp.EvidenceRoot,
		Graph:            graph,
		RenderedText:     resp.RenderedText,
	}, nil
}

func (c *grpcClient) SubmitObservation(ctx context.Context, obs *ProtoObservation) (string, error) {
	rpcCtx, cancel := c.withTimeout(ctx)
	defer cancel()

	resp, err := c.grpcClient.SubmitObservation(rpcCtx, &servicesv1.SubmitObservationRequest{
		Observation: obs,
	})
	if err != nil {
		return "", err
	}
	return resp.ObservationId, nil
}

func (c *grpcClient) SubmitReceipt(ctx context.Context, rcpt *ProtoReceipt) (bool, string, error) {
	rpcCtx, cancel := c.withTimeout(ctx)
	defer cancel()

	resp, err := c.grpcClient.SubmitReceipt(rpcCtx, &servicesv1.SubmitReceiptRequest{
		Receipt: rcpt,
	})
	if err != nil {
		return false, "", err
	}
	return resp.Verified, resp.Message, nil
}

func mapProtoState(st commonv1.AssuranceState) AssuranceState {
	switch st {
	case commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN:
		return assurance.AssuranceStateUnknown
	case commonv1.AssuranceState_ASSURANCE_STATE_OBSERVED:
		return assurance.AssuranceStateObserved
	case commonv1.AssuranceState_ASSURANCE_STATE_VERIFIED:
		return assurance.AssuranceStateVerified
	case commonv1.AssuranceState_ASSURANCE_STATE_ASSURED:
		return assurance.AssuranceStateAssured
	case commonv1.AssuranceState_ASSURANCE_STATE_STALE:
		return assurance.AssuranceStateStale
	case commonv1.AssuranceState_ASSURANCE_STATE_FAILED:
		return assurance.AssuranceStateFailed
	default:
		return assurance.AssuranceStateUnspecified
	}
}

func mapProtoValence(v commonv1.Valence) assurance.Valence {
	switch v {
	case commonv1.Valence_VALENCE_POSITIVE:
		return assurance.ValencePositive
	case commonv1.Valence_VALENCE_NEGATIVE:
		return assurance.ValenceNegative
	case commonv1.Valence_VALENCE_NEUTRAL:
		return assurance.ValenceNeutral
	case commonv1.Valence_VALENCE_MIXED:
		return assurance.ValenceMixed
	default:
		return assurance.ValenceUnresolved
	}
}

func mapProtoCoherence(c commonv1.Coherence) assurance.Coherence {
	switch c {
	case commonv1.Coherence_COHERENCE_COHERENT:
		return assurance.CoherenceCoherent
	case commonv1.Coherence_COHERENCE_PARTIALLY_COHERENT:
		return assurance.CoherencePartiallyCoherent
	case commonv1.Coherence_COHERENCE_DECOHERENT:
		return assurance.CoherenceDecoherent
	case commonv1.Coherence_COHERENCE_RECONCILING:
		return assurance.CoherenceReconciling
	default:
		return assurance.CoherenceCoherent
	}
}

func subjectFromProto(s *commonv1.SubjectRef) SubjectRef {
	if s == nil {
		return SubjectRef{}
	}
	return SubjectRef{Scheme: s.Scheme, ID: s.Id, Attributes: maps.Clone(s.Attributes)}
}
func controlFromProto(c *controlv1.ControlRef) ControlRef {
	if c == nil {
		return ControlRef{}
	}
	return ControlRef{Namespace: c.Namespace, ID: c.Id, Version: c.Version}
}
func evidenceFromProto(refs []*evidencev1.EvidenceRef) []EvidenceRef {
	var out []EvidenceRef
	for _, ref := range refs {
		if ref != nil {
			out = append(out, EvidenceRef{URI: ref.Uri, Digest: ref.Digest, MediaType: ref.MediaType})
		}
	}
	return out
}
func oldestEvaluationTime(evaluations []ClaimEvaluation) time.Time {
	var oldest time.Time
	for _, e := range evaluations {
		if e.EvaluatedAt.IsZero() {
			continue
		}
		if oldest.IsZero() || e.EvaluatedAt.Before(oldest) {
			oldest = e.EvaluatedAt
		}
	}
	return oldest
}
