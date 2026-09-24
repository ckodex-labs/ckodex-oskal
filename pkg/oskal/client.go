package oskal

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	commonv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/control/v1"
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
	conn       *grpc.ClientConn
	grpcClient servicesv1.AssuranceServiceClient
	timeout    time.Duration
}

// ClientOption configures an OSKAL client.
type ClientOption func(*clientOptions)

type clientOptions struct {
	dialOptions []grpc.DialOption
	timeout     time.Duration
}

// WithInsecure specifies insecure gRPC transport (useful for internal or local dev).
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

// NewClient connects to an OSKAL AssuranceService gRPC daemon at the specified target address.
func NewClient(ctx context.Context, target string, opts ...ClientOption) (Client, error) {
	options := clientOptions{
		timeout: 10 * time.Second,
	}
	for _, opt := range opts {
		opt(&options)
	}

	if len(options.dialOptions) == 0 {
		options.dialOptions = append(options.dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(target, options.dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial OSKAL AssuranceService at %s: %w", target, err)
	}

	return &grpcClient{
		conn:       conn,
		grpcClient: servicesv1.NewAssuranceServiceClient(conn),
		timeout:    options.timeout,
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

func (c *grpcClient) GetAssuranceState(ctx context.Context, subject SubjectRef) (*StateResponse, error) {
	rpcCtx, cancel := c.withTimeout(ctx)
	defer cancel()

	resp, err := c.grpcClient.GetAssuranceState(rpcCtx, &servicesv1.GetAssuranceStateRequest{
		Subject: &commonv1.SubjectRef{
			Scheme: subject.Scheme,
			Id:     subject.ID,
		},
	})
	if err != nil {
		return nil, err
	}

	state := mapProtoState(resp.State)
	freshness := "current"
	switch state {
	case StateUnknown:
		freshness = "unknown"
	case StateStale:
		freshness = "stale"
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
		Subject:       subject,
		State:         state,
		EvidenceRoot:  resp.EvidenceRoot,
		Epoch:         epoch,
		LastEvaluated: time.Now().UTC(),
		Freshness:     freshness,
		RawResponse:   resp.State,
	}, nil
}

func (c *grpcClient) EvaluateSubject(ctx context.Context, subject SubjectRef, controls []ControlRef) (*EvaluationResponse, error) {
	rpcCtx, cancel := c.withTimeout(ctx)
	defer cancel()

	var protoCtrls []*controlv1.ControlRef
	for _, ctrl := range controls {
		protoCtrls = append(protoCtrls, &controlv1.ControlRef{
			Namespace: ctrl.Namespace,
			Id:        ctrl.ID,
		})
	}

	resp, err := c.grpcClient.EvaluateSubject(rpcCtx, &servicesv1.EvaluateSubjectRequest{
		Subject: &commonv1.SubjectRef{
			Scheme: subject.Scheme,
			Id:     subject.ID,
		},
		Controls: protoCtrls,
	})
	if err != nil {
		return nil, err
	}

	var evals []ClaimEvaluation
	for _, evalProto := range resp.Evaluations {
		ctrl := ControlRef{}
		if evalProto.Control != nil {
			ctrl = ControlRef{Namespace: evalProto.Control.Namespace, ID: evalProto.Control.Id}
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

		evals = append(evals, ClaimEvaluation{
			ID:           evalProto.Id,
			Subject:      subject,
			Control:      ctrl,
			State:        mapProtoState(evalProto.State),
			Epoch:        epoch,
			Completeness: completeness,
			EvidenceRoot: evalProto.EvidenceRoot,
			EvaluatedAt:  evalProto.EvaluatedAt.AsTime(),
			ValidUntil:   evalProto.ValidUntil.AsTime(),
		})
	}

	return &EvaluationResponse{
		Subject:      subject,
		SummaryState: mapProtoState(resp.SummaryState),
		Evaluations:  evals,
		EvaluatedAt:  time.Now().UTC(),
	}, nil
}

func (c *grpcClient) ExplainClaim(ctx context.Context, subject SubjectRef, control ControlRef) (*ExplainResponse, error) {
	rpcCtx, cancel := c.withTimeout(ctx)
	defer cancel()

	resp, err := c.grpcClient.ExplainClaim(rpcCtx, &servicesv1.ExplainClaimRequest{
		Subject: &commonv1.SubjectRef{
			Scheme: subject.Scheme,
			Id:     subject.ID,
		},
		Control: &controlv1.ControlRef{
			Namespace: control.Namespace,
			Id:        control.ID,
		},
	})
	if err != nil {
		return nil, err
	}

	var atoms []ExplainAtomicReq
	for _, a := range resp.AtomicRequirements {
		atoms = append(atoms, ExplainAtomicReq{
			ID:        a.Id,
			Satisfied: a.Satisfied,
			Details:   a.Description,
		})
	}

	var imps []ExplainImplementation
	for _, imp := range resp.Implementations {
		imps = append(imps, ExplainImplementation{
			Requirement: imp.Id,
			Provider:    imp.Provider,
			Digest:      imp.Digest,
		})
	}

	var evItems []ExplainEvidenceItem
	for _, ev := range resp.Evidence {
		evItems = append(evItems, ExplainEvidenceItem{
			Type:     ev.MediaType,
			Verified: true,
			Producer: ev.Uri,
		})
	}

	completeness := EvidenceCompleteness{}
	if resp.Completeness != nil {
		completeness = EvidenceCompleteness{
			Required: int(resp.Completeness.Required),
			Present:  int(resp.Completeness.Present),
			Verified: int(resp.Completeness.Verified),
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
		Subject:            subject,
		Control:            control,
		CanonicalControl:   resp.CanonicalControl,
		Applicability:      resp.Applicability,
		AtomicRequirements: atoms,
		Implementations:    imps,
		Evidence:           evItems,
		Completeness:       completeness,
		Freshness:          resp.Freshness,
		Authority:          resp.Authority,
		Epoch:              epoch,
		AssuranceState:     mapProtoState(resp.AssuranceState),
		EvidenceRoot:       resp.EvidenceRoot,
		Projections:        resp.Projections,
	}

	return &ExplainResponse{
		Subject:          subject,
		Control:          control,
		CanonicalControl: resp.CanonicalControl,
		AssuranceState:   mapProtoState(resp.AssuranceState),
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
