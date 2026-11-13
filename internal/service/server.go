// Package service maps bounded protobuf requests onto the assessment application.
package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/assessment"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/explain"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	commonv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/control/v1"
	evidencev1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/evidence/v1"
	receiptv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/receipt/v1"
	servicesv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/services/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultFreshnessWindow = 15 * time.Minute // Retained API constant; no implicit policy.
	MaxTrackedSubjects     = 4096
	MaxStoredReceipts      = 8192
	MaxRequestBytes        = 64 << 10
	MaxObservationBytes    = 16 << 20
)

type EvaluationConfig = assessment.Config

type Server struct {
	servicesv1.UnimplementedAssuranceServiceServer
	mu               sync.Mutex
	receiptMgr       *receipts.ReceiptManager
	assessment       *assessment.Service
	observations     map[string][]*evidencev1.Observation
	observationBytes int
	receipts         map[string]*receiptv1.ControlReceipt
}

// NewServer has no live evaluation authority. Optional repositories are retained
// for source compatibility; archive presence is never proof of current standing.
// Submitted observations are bounded, process-local unverified metadata.
func NewServer(receiptMgr *receipts.ReceiptManager, _ ...ports.EvidenceRepository) *Server {
	return &Server{receiptMgr: receiptMgr, observations: make(map[string][]*evidencev1.Observation), receipts: make(map[string]*receiptv1.ControlReceipt)}
}

func NewServerWithEvaluation(receiptMgr *receipts.ReceiptManager, config EvaluationConfig, repos ...ports.EvidenceRepository) (*Server, error) {
	evaluator, err := assessment.New(config)
	if err != nil {
		return nil, err
	}
	server := NewServer(receiptMgr, repos...)
	server.assessment = evaluator
	return server, nil
}

// SubmitObservation never signs assertions or converts references into payloads.
// The protocol carries no signed envelope or payload, so it cannot admit evidence.
func (s *Server) SubmitObservation(ctx context.Context, req *servicesv1.SubmitObservationRequest) (*servicesv1.SubmitObservationResponse, error) {
	if err := validateObservation(ctx, req); err != nil {
		return nil, err
	}
	obs := proto.Clone(req.Observation).(*evidencev1.Observation)
	key := coreSubject(obs.Subject).URI()
	size := proto.Size(obs)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.observations[key]) >= 1000 || s.observationBytes+size > MaxObservationBytes {
		return nil, status.Error(codes.ResourceExhausted, "unverified observation buffer full; export or restart explicitly")
	}
	if _, exists := s.observations[key]; !exists && len(s.observations) >= MaxTrackedSubjects {
		return nil, status.Error(codes.ResourceExhausted, "subject buffer full")
	}
	s.observations[key] = append(s.observations[key], obs)
	s.observationBytes += size
	return &servicesv1.SubmitObservationResponse{ObservationId: obs.Id, Accepted: true, Message: "Stored unverified observation metadata in bounded process memory; not evidence admission, producer authentication or durable storage"}, nil
}

func (s *Server) assess(ctx context.Context, subject *commonv1.SubjectRef, controls []*controlv1.ControlRef) (assessment.Result, error) {
	if err := validateSubject(subject); err != nil {
		return assessment.Result{}, err
	}
	if len(controls) > 256 {
		return assessment.Result{}, status.Error(codes.InvalidArgument, "at most 256 controls are allowed")
	}
	var requested []assurance.ControlRef
	for _, control := range controls {
		if control == nil || coreControl(control).Validate() != nil || proto.Size(control) > 2048 {
			return assessment.Result{}, status.Error(codes.InvalidArgument, "invalid control")
		}
		requested = append(requested, coreControl(control))
	}
	if err := ctx.Err(); err != nil {
		return assessment.Result{}, status.FromContextError(err).Err()
	}
	if s.assessment != nil {
		result, err := s.assessment.Assess(ctx, coreSubject(subject), requested)
		if err != nil {
			return assessment.Result{}, status.Errorf(codes.FailedPrecondition, "live assessment unavailable: %v", err)
		}
		return result, nil
	}
	result := assessment.Result{State: assurance.AssuranceStateUnknown}
	result.Context.Subject = coreSubject(subject)
	for _, control := range requested {
		result.Evaluations = append(result.Evaluations, assurance.ClaimEvaluation{Subject: coreSubject(subject), Control: control, State: assurance.AssuranceStateUnknown, Vector: assurance.NewDefaultAssuranceVector(), Trace: []string{"Live assessment is not configured; provide an authoritative binding resolver, strict evaluator and source revision. Submitted observation metadata is unverified."}})
	}
	return result, nil
}

func (s *Server) EvaluateSubject(ctx context.Context, req *servicesv1.EvaluateSubjectRequest) (*servicesv1.EvaluateSubjectResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
	result, err := s.assess(ctx, req.Subject, req.Controls)
	if err != nil {
		return nil, err
	}
	out := &servicesv1.EvaluateSubjectResponse{Subject: protoSubject(result.Context.Subject), SummaryState: commonv1.AssuranceState(result.State)}
	for _, e := range result.Evaluations {
		out.Evaluations = append(out.Evaluations, protoEvaluation(e))
	}
	return out, nil
}

func (s *Server) ExplainClaim(ctx context.Context, req *servicesv1.ExplainClaimRequest) (*servicesv1.ExplainClaimResponse, error) {
	if req == nil || req.Control == nil {
		return nil, status.Error(codes.InvalidArgument, "subject and control required")
	}
	result, err := s.assess(ctx, req.Subject, []*controlv1.ControlRef{req.Control})
	if err != nil {
		return nil, err
	}
	evaluation := result.Evaluations[0]
	graph := explain.NewExplainer().BuildExplainGraph(ctx, evaluation.Subject, evaluation.Control, evaluation)
	return &servicesv1.ExplainClaimResponse{Subject: protoSubject(evaluation.Subject), Control: protoControl(evaluation.Control), CanonicalControl: graph.CanonicalControl, Applicability: graph.Applicability, Evidence: protoEvidence(evaluation.Evidence), Completeness: protoCompleteness(evaluation.Completeness), Freshness: graph.Freshness, Authority: graph.Authority, Epoch: protoEpoch(evaluation.Epoch), AssuranceState: commonv1.AssuranceState(evaluation.State), EvidenceRoot: evaluation.EvidenceRoot, RenderedText: explain.RenderText(graph, evaluation.Evidence)}, nil
}

func (s *Server) GetAssuranceState(ctx context.Context, req *servicesv1.GetAssuranceStateRequest) (*servicesv1.GetAssuranceStateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "subject required")
	}
	result, err := s.assess(ctx, req.Subject, nil)
	if err != nil {
		return nil, err
	}
	out := &servicesv1.GetAssuranceStateResponse{Subject: protoSubject(result.Context.Subject), State: commonv1.AssuranceState(result.State), Epoch: protoEpoch(result.Context.Epoch), EvidenceRoot: result.EvidenceRoot}
	for _, e := range result.Evaluations {
		out.Evaluations = append(out.Evaluations, protoEvaluation(e))
	}
	return out, nil
}

// SubmitReceipt checks a signature against the explicitly supplied key. A
// verified historical receipt is never imported into current live eligibility.
func (s *Server) SubmitReceipt(ctx context.Context, req *servicesv1.SubmitReceiptRequest) (*servicesv1.SubmitReceiptResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	if req == nil || req.Receipt == nil || proto.Size(req) > MaxRequestBytes {
		return nil, status.Error(codes.InvalidArgument, "bounded receipt required")
	}
	r := req.Receipt
	if err := validateSubject(r.Subject); err != nil {
		return nil, err
	}
	if r.Control == nil || coreControl(r.Control).Validate() != nil || r.Evaluator == nil || r.EvaluatedAt == nil || r.EvaluatedAt.CheckValid() != nil || r.Epoch == nil || r.State < commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN || r.State > commonv1.AssuranceState_ASSURANCE_STATE_FAILED {
		return nil, status.Error(codes.InvalidArgument, "receipt requires valid control, evaluator, timestamp, epoch and state")
	}
	authority := assurance.AuthorityRef{Scheme: r.Evaluator.Scheme, Subject: r.Evaluator.Subject, TrustDomain: r.Evaluator.TrustDomain}
	if authority.Validate() != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid receipt evaluator")
	}
	if s.receiptMgr == nil {
		return nil, status.Error(codes.FailedPrecondition, "receipt verification key is not configured")
	}
	core := assurance.ControlReceipt{Subject: coreSubject(r.Subject), Control: coreControl(r.Control), Evaluator: authority, State: assurance.AssuranceState(r.State), Epoch: coreEpoch(r.Epoch), EvidenceRoot: r.EvidenceRoot, EvaluatedAt: r.EvaluatedAt.AsTime(), Signature: r.Signature}
	valid, err := s.receiptMgr.VerifyReceipt(ctx, core)
	if err != nil || !valid {
		return &servicesv1.SubmitReceiptResponse{Verified: false, Message: "Receipt signature verification failed"}, nil
	}
	digest := core.Digest()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.receipts[digest]; !exists && len(s.receipts) >= MaxStoredReceipts {
		return nil, status.Error(codes.ResourceExhausted, "verified receipt buffer full")
	}
	s.receipts[digest] = proto.Clone(r).(*receiptv1.ControlReceipt)
	return &servicesv1.SubmitReceiptResponse{Verified: true, ReceiptDigest: digest, Message: "Receipt signature verified against configured key; retained in process memory, without changing current assurance"}, nil
}

func validateSubject(subject *commonv1.SubjectRef) error {
	if subject == nil || proto.Size(subject) > 8192 || len(subject.Attributes) > 64 || coreSubject(subject).Validate() != nil {
		return status.Error(codes.InvalidArgument, "subject must be valid and bounded")
	}
	return nil
}
func validateObservation(ctx context.Context, req *servicesv1.SubmitObservationRequest) error {
	if err := ctx.Err(); err != nil {
		return status.FromContextError(err).Err()
	}
	if req == nil || req.Observation == nil || proto.Size(req) > MaxRequestBytes {
		return status.Error(codes.InvalidArgument, "bounded observation required")
	}
	o := req.Observation
	if err := validateSubject(o.Subject); err != nil {
		return err
	}
	if o.Id == "" || len(o.Id) > 256 || o.Type == "" || len(o.Type) > 256 || o.ObservedAt == nil || o.ObservedAt.CheckValid() != nil || o.ObservedAt.AsTime().After(time.Now()) || len(o.Evidence) > 256 || len(o.Attributes) > 64 {
		return status.Error(codes.InvalidArgument, "observation requires bounded ID/type, non-future timestamp and metadata")
	}
	for _, ref := range o.Evidence {
		if ref == nil || ref.Uri == "" || len(ref.Uri) > 2048 || len(ref.Digest) > 256 || len(ref.MediaType) > 256 {
			return status.Error(codes.InvalidArgument, "invalid evidence reference metadata")
		}
	}
	if o.Observer != nil {
		a := assurance.AuthorityRef{Scheme: o.Observer.Scheme, Subject: o.Observer.Subject, TrustDomain: o.Observer.TrustDomain}
		if err := a.Validate(); err != nil {
			return status.Error(codes.InvalidArgument, fmt.Sprintf("invalid claimed observer: %v", err))
		}
	}
	return nil
}
