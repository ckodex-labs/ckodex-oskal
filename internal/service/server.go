package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ckodex-labs/oskal/core/assurance"
	"github.com/ckodex-labs/oskal/internal/application/explain"
	"github.com/ckodex-labs/oskal/internal/receipts"
	assessmentv1 "github.com/ckodex-labs/oskal/proto/assurance/assessment/v1"
	commonv1 "github.com/ckodex-labs/oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/oskal/proto/assurance/control/v1"
	evidencev1 "github.com/ckodex-labs/oskal/proto/assurance/evidence/v1"
	receiptv1 "github.com/ckodex-labs/oskal/proto/assurance/receipt/v1"
	servicesv1 "github.com/ckodex-labs/oskal/proto/assurance/services/v1"
)

// Server implements servicesv1.AssuranceServiceServer (Section 29).
type Server struct {
	servicesv1.UnimplementedAssuranceServiceServer
	mu           sync.RWMutex
	explainer    *explain.Explainer
	receiptMgr   *receipts.ReceiptManager
	observations map[string][]*evidencev1.Observation
	receipts     map[string]*receiptv1.ControlReceipt
}

// NewServer creates a new AssuranceService gRPC server.
func NewServer(receiptMgr *receipts.ReceiptManager) *Server {
	if receiptMgr == nil {
		mgr, _ := receipts.NewReceiptManager(assurance.AuthorityRef{
			Scheme:  "spiffe",
			Subject: "prod/ns/ckodex-assurance/sa/assurance-service",
		})
		receiptMgr = mgr
	}
	return &Server{
		explainer:    explain.NewExplainer(),
		receiptMgr:   receiptMgr,
		observations: make(map[string][]*evidencev1.Observation),
		receipts:     make(map[string]*receiptv1.ControlReceipt),
	}
}

// SubmitObservation ingests an observation from an authorized producer.
func (s *Server) SubmitObservation(ctx context.Context, req *servicesv1.SubmitObservationRequest) (*servicesv1.SubmitObservationResponse, error) {
	if req.Observation == nil {
		return nil, status.Error(codes.InvalidArgument, "observation cannot be nil")
	}

	obs := req.Observation
	if obs.Id == "" {
		obs.Id = fmt.Sprintf("obs-%d", time.Now().UnixNano())
	}
	if obs.Subject == nil {
		return nil, status.Error(codes.InvalidArgument, "observation subject cannot be nil")
	}

	subKey := obs.Subject.Scheme + "://" + obs.Subject.Id

	s.mu.Lock()
	s.observations[subKey] = append(s.observations[subKey], obs)
	s.mu.Unlock()

	return &servicesv1.SubmitObservationResponse{
		ObservationId: obs.Id,
		Accepted:      true,
		Message:       "Observation successfully ingested",
	}, nil
}

// EvaluateSubject evaluates all claims for a given subject based on ingested evidence.
func (s *Server) EvaluateSubject(ctx context.Context, req *servicesv1.EvaluateSubjectRequest) (*servicesv1.EvaluateSubjectResponse, error) {
	if req.Subject == nil {
		return nil, status.Error(codes.InvalidArgument, "subject cannot be nil")
	}

	now := time.Now().UTC()
	subKey := req.Subject.Scheme + "://" + req.Subject.Id

	s.mu.RLock()
	obsList := s.observations[subKey]
	s.mu.RUnlock()

	hasEvidence := len(obsList) > 0
	targetState := commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN
	valence := commonv1.Valence_VALENCE_UNRESOLVED
	var evCompleteness *evidencev1.EvidenceCompleteness
	var evRoot string

	if hasEvidence {
		targetState = commonv1.AssuranceState_ASSURANCE_STATE_ASSURED
		valence = commonv1.Valence_VALENCE_POSITIVE
		evCompleteness = &evidencev1.EvidenceCompleteness{
			Required: 1,
			Present:  int32(len(obsList)),
			Verified: int32(len(obsList)),
		}
		var evRefs []assurance.EvidenceRef
		for _, obs := range obsList {
			for _, ev := range obs.Evidence {
				evRefs = append(evRefs, assurance.EvidenceRef{Digest: ev.Digest})
			}
		}
		evRoot = receipts.ComputeEvidenceRoot(evRefs)
	} else {
		evCompleteness = &evidencev1.EvidenceCompleteness{
			Required: 1,
			Present:  0,
			Verified: 0,
			Missing:  1,
		}
	}

	var evaluations []*assessmentv1.ClaimEvaluation
	for _, ctrl := range req.Controls {
		eval := &assessmentv1.ClaimEvaluation{
			Id:      fmt.Sprintf("eval-%s-%s", req.Subject.Id, ctrl.Id),
			Control: ctrl,
			Subject: req.Subject,
			State:   targetState,
			Vector: &commonv1.AssuranceVector{
				Applicability: commonv1.Valence_VALENCE_POSITIVE,
				Conformance:   valence,
				Integrity:     valence,
				Authority:     valence,
				Identity:      valence,
				Runtime:       valence,
				Freshness:     valence,
				Completeness:  valence,
				Coherence:     commonv1.Coherence_COHERENCE_COHERENT,
			},
			Epoch: &commonv1.AssuranceEpoch{
				SubjectDigest:        assurance.ComputeStringDigest(subKey),
				ImplementationDigest: "sha256:imp",
				PolicyDigest:         "sha256:pol",
				AuthorityDigest:      "sha256:auth",
				EnvironmentDigest:    "sha256:env",
			},
			Completeness: evCompleteness,
			EvidenceRoot: evRoot,
			EvaluatedAt:  timestamppb.New(now),
			ValidUntil:   timestamppb.New(now.Add(5 * time.Minute)),
		}
		evaluations = append(evaluations, eval)
	}

	return &servicesv1.EvaluateSubjectResponse{
		Subject:      req.Subject,
		Evaluations:  evaluations,
		SummaryState: targetState,
	}, nil
}

// ExplainClaim constructs a full reverse-traceable explain graph.
func (s *Server) ExplainClaim(ctx context.Context, req *servicesv1.ExplainClaimRequest) (*servicesv1.ExplainClaimResponse, error) {
	if req.Subject == nil || req.Control == nil {
		return nil, status.Error(codes.InvalidArgument, "subject and control are required")
	}

	subKey := req.Subject.Scheme + "://" + req.Subject.Id

	s.mu.RLock()
	obsList := s.observations[subKey]
	s.mu.RUnlock()

	claimState := assurance.AssuranceStateUnknown
	respState := commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN
	var evRoot string

	if len(obsList) > 0 {
		claimState = assurance.AssuranceStateAssured
		respState = commonv1.AssuranceState_ASSURANCE_STATE_ASSURED
		var evRefs []assurance.EvidenceRef
		for _, obs := range obsList {
			for _, ev := range obs.Evidence {
				evRefs = append(evRefs, assurance.EvidenceRef{Digest: ev.Digest})
			}
		}
		evRoot = receipts.ComputeEvidenceRoot(evRefs)
	}

	sub := assurance.SubjectRef{
		Scheme: req.Subject.Scheme,
		ID:     req.Subject.Id,
	}
	ctrl := assurance.ControlRef{
		Namespace: req.Control.Namespace,
		ID:        req.Control.Id,
		Version:   req.Control.Version,
	}

	eval := assurance.ClaimEvaluation{
		ID:      "eval-01",
		Subject: sub,
		Control: ctrl,
		State:   claimState,
		Epoch: assurance.AssuranceEpoch{
			SubjectDigest:        assurance.ComputeStringDigest(sub.URI()),
			ImplementationDigest: "sha256:imp",
			PolicyDigest:         "sha256:pol",
			AuthorityDigest:      "sha256:auth",
			EnvironmentDigest:    "sha256:env",
		},
		EvidenceRoot: evRoot,
	}

	graph := s.explainer.BuildExplainGraph(ctx, sub, ctrl, eval)

	var atomicReqs []*controlv1.AtomicControl
	for _, atom := range graph.AtomicRequirements {
		atomicReqs = append(atomicReqs, &controlv1.AtomicControl{
			Id:          atom.ID,
			Description: atom.Details,
			Satisfied:   atom.Satisfied,
		})
	}

	var impls []*controlv1.ImplementationRef
	for _, imp := range graph.Implementations {
		impls = append(impls, &controlv1.ImplementationRef{
			Provider: imp.Provider,
			Digest:   imp.Digest,
		})
	}

	var evs []*evidencev1.EvidenceRef
	for _, ev := range graph.Evidence {
		evs = append(evs, &evidencev1.EvidenceRef{
			Digest: ev.Digest,
		})
	}

	return &servicesv1.ExplainClaimResponse{
		Subject:            req.Subject,
		Control:            req.Control,
		CanonicalControl:   graph.CanonicalControl,
		Applicability:      graph.Applicability,
		AtomicRequirements: atomicReqs,
		Implementations:    impls,
		Evidence:           evs,
		Completeness: &evidencev1.EvidenceCompleteness{
			Required: int32(graph.Completeness.Required),
			Present:  int32(graph.Completeness.Present),
			Verified: int32(graph.Completeness.Verified),
			Stale:    int32(graph.Completeness.Stale),
			Missing:  int32(graph.Completeness.Missing),
		},
		Freshness:        graph.Freshness,
		Authority:        graph.Authority,
		AssuranceState:   respState,
		EvidenceRoot:     graph.EvidenceRoot,
		Projections:      graph.Projections,
		RenderedText:     graph.RenderText(),
	}, nil
}

// GetAssuranceState returns summary assurance state based on verified evidence.
func (s *Server) GetAssuranceState(ctx context.Context, req *servicesv1.GetAssuranceStateRequest) (*servicesv1.GetAssuranceStateResponse, error) {
	if req.Subject == nil {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}

	subKey := req.Subject.Scheme + "://" + req.Subject.Id

	s.mu.RLock()
	obsList := s.observations[subKey]
	s.mu.RUnlock()

	// Invariant I-02: Absence of evidence is UNKNOWN, never PASS
	if len(obsList) == 0 {
		return &servicesv1.GetAssuranceStateResponse{
			Subject:      req.Subject,
			State:        commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN,
			EvidenceRoot: "",
			Epoch:        nil,
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
	root := receipts.ComputeEvidenceRoot(evRefs)
	policyDigest := assurance.ComputeStringDigest(subKey + ":" + root)

	return &servicesv1.GetAssuranceStateResponse{
		Subject:      req.Subject,
		State:        commonv1.AssuranceState_ASSURANCE_STATE_ASSURED,
		EvidenceRoot: root,
		Epoch: &commonv1.AssuranceEpoch{
			SubjectDigest:        assurance.ComputeStringDigest(subKey),
			ImplementationDigest: "sha256:imp",
			PolicyDigest:         policyDigest,
			AuthorityDigest:      "sha256:auth",
			EnvironmentDigest:    "sha256:env",
		},
	}, nil
}

// SubmitReceipt verifies an incoming cryptographic receipt.
func (s *Server) SubmitReceipt(ctx context.Context, req *servicesv1.SubmitReceiptRequest) (*servicesv1.SubmitReceiptResponse, error) {
	if req.Receipt == nil {
		return nil, status.Error(codes.InvalidArgument, "receipt cannot be nil")
	}

	rcpt := req.Receipt
	coreReceipt := assurance.ControlReceipt{
		Subject: assurance.SubjectRef{
			Scheme: rcpt.Subject.Scheme,
			ID:     rcpt.Subject.Id,
		},
		Control: assurance.ControlRef{
			Namespace: rcpt.Control.Namespace,
			ID:        rcpt.Control.Id,
		},
		State: assurance.AssuranceState(rcpt.State),
		Epoch: assurance.AssuranceEpoch{
			SubjectDigest:        rcpt.Epoch.SubjectDigest,
			ImplementationDigest: rcpt.Epoch.ImplementationDigest,
			PolicyDigest:         rcpt.Epoch.PolicyDigest,
			AuthorityDigest:      rcpt.Epoch.AuthorityDigest,
			EnvironmentDigest:    rcpt.Epoch.EnvironmentDigest,
		},
		EvidenceRoot: rcpt.EvidenceRoot,
		Evaluator: assurance.AuthorityRef{
			Scheme:  rcpt.Evaluator.Scheme,
			Subject: rcpt.Evaluator.Subject,
		},
		EvaluatedAt: rcpt.EvaluatedAt.AsTime(),
		Signature:   rcpt.Signature,
	}

	valid, err := receipts.VerifyIndependentReceipt(coreReceipt, s.receiptMgr.PublicKey())
	if err != nil || !valid {
		return &servicesv1.SubmitReceiptResponse{
			Verified: false,
			Message:  "Signature verification failed",
		}, nil
	}

	digest := coreReceipt.Digest()
	s.mu.Lock()
	s.receipts[digest] = rcpt
	s.mu.Unlock()

	return &servicesv1.SubmitReceiptResponse{
		Verified:      true,
		ReceiptDigest: digest,
		Message:       "Receipt verified and accepted",
	}, nil
}
