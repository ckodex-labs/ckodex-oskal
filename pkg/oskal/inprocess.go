package oskal

import (
	"context"
	"fmt"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/evaluation"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/ckodex-labs/ckodex-oskal/internal/service"
	servicesv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/services/v1"
	"google.golang.org/grpc"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const DefaultFreshnessWindow = 15 * time.Minute // Compatibility constant, not implicit policy.

type EvaluationConfig = service.EvaluationConfig

// LiveEvidenceSource supplies bounded current candidates and their invalidation
// revision. Durable archive presence alone must not restore source eligibility.
type LiveEvidenceSource interface {
	ports.EvidenceRepository
	ports.EvidenceRevisioner
}

type EvidenceVerifier = ports.EvidenceVerifier

// NewEvaluationConfig allows external SDK callers to assemble the live path
// without importing internal packages. It binds evaluator and revision reads to
// the same source object and requires an actual authority snapshot digest.
func NewEvaluationConfig(reader client.Reader, authorityDigest string, source LiveEvidenceSource, verifier EvidenceVerifier) (EvaluationConfig, error) {
	if reader == nil || source == nil || verifier == nil {
		return EvaluationConfig{}, fmt.Errorf("authoritative reader, live source and evidence verifier are required")
	}
	resolver, err := binding.NewResolver(reader).WithAuthorityDigest(authorityDigest)
	if err != nil {
		return EvaluationConfig{}, err
	}
	evaluator, err := evaluation.NewEvaluator(source, verifier)
	if err != nil {
		return EvaluationConfig{}, err
	}
	return EvaluationConfig{Resolver: resolver, Evaluator: evaluator, Sources: source}, nil
}

// InProcessClient uses the same bounded request and evaluation implementation as
// the gRPC server. The default has no live authority and returns UNKNOWN.
type InProcessClient struct {
	*grpcClient
	receiptMgr          *receipts.ReceiptManager
	initializationError error
}

type InProcessOption func(*InProcessClient)

// WithEvaluatorAuthority configures a local signing key for the supplied label.
// It does not authenticate a SPIFFE identity or authorize live evaluation.
func WithEvaluatorAuthority(auth AuthorityRef) InProcessOption {
	return func(c *InProcessClient) {
		if err := auth.Validate(); err != nil {
			c.initializationError = err
			return
		}
		c.receiptMgr, c.initializationError = receipts.NewReceiptManager(auth)
	}
}
func WithReceiptManager(manager *ReceiptManager) InProcessOption {
	return func(c *InProcessClient) {
		if manager != nil {
			c.receiptMgr = manager.inner
		}
	}
}

func NewInProcessClient(options ...InProcessOption) *InProcessClient {
	c := &InProcessClient{}
	for _, option := range options {
		option(c)
	}
	c.grpcClient = &grpcClient{grpcClient: &localTransport{server: service.NewServer(c.receiptMgr), err: c.initializationError}, maxAttempts: 1}
	return c
}

// NewInProcessClientWithEvaluation requires the same explicit authoritative
// dependencies as service.NewServerWithEvaluation; it never restores eligibility
// from archived observations or receipt presence.
func NewInProcessClientWithEvaluation(config EvaluationConfig, options ...InProcessOption) (*InProcessClient, error) {
	c := NewInProcessClient(options...)
	if c.initializationError != nil {
		return nil, c.initializationError
	}
	server, err := service.NewServerWithEvaluation(c.receiptMgr, config)
	if err != nil {
		return nil, err
	}
	c.grpcClient.grpcClient = &localTransport{server: server}
	return c, nil
}

type localTransport struct {
	server *service.Server
	err    error
}

func (t *localTransport) check() error {
	if t.err != nil {
		return fmt.Errorf("in-process client configuration: %w", t.err)
	}
	return nil
}
func (t *localTransport) SubmitObservation(ctx context.Context, req *servicesv1.SubmitObservationRequest, _ ...grpc.CallOption) (*servicesv1.SubmitObservationResponse, error) {
	if err := t.check(); err != nil {
		return nil, err
	}
	return t.server.SubmitObservation(ctx, req)
}
func (t *localTransport) EvaluateSubject(ctx context.Context, req *servicesv1.EvaluateSubjectRequest, _ ...grpc.CallOption) (*servicesv1.EvaluateSubjectResponse, error) {
	if err := t.check(); err != nil {
		return nil, err
	}
	return t.server.EvaluateSubject(ctx, req)
}
func (t *localTransport) ExplainClaim(ctx context.Context, req *servicesv1.ExplainClaimRequest, _ ...grpc.CallOption) (*servicesv1.ExplainClaimResponse, error) {
	if err := t.check(); err != nil {
		return nil, err
	}
	return t.server.ExplainClaim(ctx, req)
}
func (t *localTransport) GetAssuranceState(ctx context.Context, req *servicesv1.GetAssuranceStateRequest, _ ...grpc.CallOption) (*servicesv1.GetAssuranceStateResponse, error) {
	if err := t.check(); err != nil {
		return nil, err
	}
	return t.server.GetAssuranceState(ctx, req)
}
func (t *localTransport) SubmitReceipt(ctx context.Context, req *servicesv1.SubmitReceiptRequest, _ ...grpc.CallOption) (*servicesv1.SubmitReceiptResponse, error) {
	if err := t.check(); err != nil {
		return nil, err
	}
	return t.server.SubmitReceipt(ctx, req)
}
