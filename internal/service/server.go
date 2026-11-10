package service

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/explain"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/ckodex-labs/ckodex-oskal/internal/verifier"
	assessmentv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/assessment/v1"
	commonv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/control/v1"
	evidencev1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/evidence/v1"
	receiptv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/receipt/v1"
	servicesv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/services/v1"
)

const (
	// DefaultFreshnessWindow is the standard 15-minute maximum evidence freshness window.
	DefaultFreshnessWindow = 15 * time.Minute
	// MaxTrackedSubjects bounds distinct subject keys retained in memory per Constitution Section 30.
	MaxTrackedSubjects = 4096
	// MaxStoredReceipts bounds verified receipts retained in memory per Constitution Section 30.
	MaxStoredReceipts = 8192
)

func isViolationObservation(obs *evidencev1.Observation) bool {
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

// Server implements servicesv1.AssuranceServiceServer (Section 29).
type Server struct {
	servicesv1.UnimplementedAssuranceServiceServer
	mu           sync.RWMutex
	explainer    *explain.Explainer
	receiptMgr   *receipts.ReceiptManager
	evidenceRepo ports.EvidenceRepository
	observations map[string][]*evidencev1.Observation
	subjectOrder []string
	receipts     map[string]*receiptv1.ControlReceipt
	receiptOrder []string
}

// NewServer creates a new AssuranceService gRPC server.
func NewServer(receiptMgr *receipts.ReceiptManager, evidenceRepos ...ports.EvidenceRepository) *Server {
	if receiptMgr == nil {
		mgr, _ := receipts.NewReceiptManager(assurance.AuthorityRef{
			Scheme:  "spiffe",
			Subject: "prod/ns/ckodex-assurance/sa/assurance-service",
		})
		receiptMgr = mgr
	}
	var repo ports.EvidenceRepository
	if len(evidenceRepos) > 0 && evidenceRepos[0] != nil {
		repo = evidenceRepos[0]
	} else {
		repo = storage.NewMemoryEvidenceRepository()
	}
	return &Server{
		explainer:    explain.NewExplainer(),
		receiptMgr:   receiptMgr,
		evidenceRepo: repo,
		observations: make(map[string][]*evidencev1.Observation),
		receipts:     make(map[string]*receiptv1.ControlReceipt),
	}
}

// SubmitObservation ingests an observation from an authorized producer.
func (s *Server) SubmitObservation(ctx context.Context, req *servicesv1.SubmitObservationRequest) (*servicesv1.SubmitObservationResponse, error) {
	if req == nil || req.Observation == nil {
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

	const maxObservationsPerSubject = 1000
	s.mu.Lock()
	if _, exists := s.observations[subKey]; !exists {
		if len(s.observations) >= MaxTrackedSubjects && len(s.subjectOrder) > 0 {
			evictKey := s.subjectOrder[0]
			s.subjectOrder = s.subjectOrder[1:]
			delete(s.observations, evictKey)
		}
		s.subjectOrder = append(s.subjectOrder, subKey)
	}
	list := append(s.observations[subKey], obs)
	if len(list) > maxObservationsPerSubject {
		list = list[len(list)-maxObservationsPerSubject:]
	}
	s.observations[subKey] = list
	s.mu.Unlock()

	// Ingest evidence envelopes into the content-addressed EvidenceRepository
	subRef := assurance.SubjectRef{
		Scheme: obs.Subject.Scheme,
		ID:     obs.Subject.Id,
	}
	var obsTime time.Time
	if obs.ObservedAt != nil {
		obsTime = obs.ObservedAt.AsTime()
	}
	for i, ev := range obs.Evidence {
		if ev == nil {
			continue
		}
		env := assurance.EvidenceEnvelope{
			ID:              fmt.Sprintf("env-%s-%d", obs.Id, i),
			ObservationType: obs.Type,
			Subject:         subRef,
			CapturedAt:      obsTime,
			Artifact: assurance.EvidenceRef{
				URI:       ev.Uri,
				Digest:    ev.Digest,
				MediaType: ev.MediaType,
			},
			Epoch: assurance.AssuranceEpoch{
				SubjectDigest:        assurance.ComputeStringDigest(subRef.URI()),
				ImplementationDigest: assurance.ComputeStringDigest("kubernetes:workload-specification"),
				PolicyDigest:         assurance.ComputeStringDigest(subKey + ":policy"),
				AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
				EnvironmentDigest:    assurance.ComputeStringDigest("cluster:kubernetes"),
			},
		}
		if obs.Observer != nil {
			env.Producer = assurance.AuthorityRef{
				Scheme:      obs.Observer.Scheme,
				Subject:     obs.Observer.Subject,
				TrustDomain: obs.Observer.TrustDomain,
			}
		}
		env.ControlRefs = verifier.DeriveControlRefs(obs.Type, env.Producer.Canonical(), obs.Attributes)
		_, _ = s.evidenceRepo.Put(ctx, env, bytes.NewReader([]byte(ev.Digest)))
	}

	return &servicesv1.SubmitObservationResponse{
		ObservationId: obs.Id,
		Accepted:      true,
		Message:       "Observation successfully ingested",
	}, nil
}

func (s *Server) evaluateSubjectEvidence(
	ctx context.Context,
	subRef assurance.SubjectRef,
	now time.Time,
) (commonv1.AssuranceState, assurance.AssuranceState, []assurance.EvidenceRef, string) {
	subKey := subRef.Scheme + "://" + subRef.ID

	s.mu.RLock()
	obsList := s.observations[subKey]
	s.mu.RUnlock()

	var validRefs []assurance.EvidenceRef
	validCount := 0
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
		isViol := isViolationObservation(obs)
		if !isViol && len(obs.Evidence) == 0 {
			continue
		}
		validCount++
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

	if validCount == 0 && len(obsList) == 0 && s.evidenceRepo != nil {
		if envs, err := s.evidenceRepo.ListBySubject(ctx, subRef); err == nil {
			for _, env := range envs {
				if env.CapturedAt.IsZero() || env.CapturedAt.After(now.Add(1*time.Minute)) {
					continue
				}
				validCount++
				if assurance.IsAdverseObservationType(env.ObservationType) {
					hasViolation = true
				}
				if now.Sub(env.CapturedAt) > DefaultFreshnessWindow {
					hasStale = true
				}
				validRefs = append(validRefs, env.Artifact)
			}
		}
	}

	if validCount == 0 {
		return commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN, assurance.AssuranceStateUnknown, nil, ""
	}

	evRoot := ""
	if len(validRefs) > 0 {
		evRoot = receipts.ComputeEvidenceRoot(validRefs)
	}

	if hasViolation {
		return commonv1.AssuranceState_ASSURANCE_STATE_FAILED, assurance.AssuranceStateFailed, validRefs, evRoot
	}
	if hasStale {
		return commonv1.AssuranceState_ASSURANCE_STATE_STALE, assurance.AssuranceStateStale, validRefs, evRoot
	}
	return commonv1.AssuranceState_ASSURANCE_STATE_ASSURED, assurance.AssuranceStateAssured, validRefs, evRoot
}

// EvaluateSubject evaluates all claims for a given subject based on ingested evidence.
func (s *Server) EvaluateSubject(ctx context.Context, req *servicesv1.EvaluateSubjectRequest) (*servicesv1.EvaluateSubjectResponse, error) {
	if req == nil || req.Subject == nil {
		return nil, status.Error(codes.InvalidArgument, "subject cannot be nil")
	}

	now := time.Now().UTC()
	subKey := req.Subject.Scheme + "://" + req.Subject.Id
	subRef := assurance.SubjectRef{
		Scheme: req.Subject.Scheme,
		ID:     req.Subject.Id,
	}

	s.mu.RLock()
	obsList := s.observations[subKey]
	s.mu.RUnlock()

	hasViolation := false
	for _, obs := range obsList {
		if obs != nil && obs.ObservedAt != nil {
			t := obs.ObservedAt.AsTime()
			if !t.IsZero() && !t.After(now.Add(1*time.Minute)) && isViolationObservation(obs) {
				hasViolation = true
			}
		}
	}

	envelopes, _ := s.evidenceRepo.ListBySubject(ctx, subRef)
	if len(envelopes) == 0 {
		for _, obs := range obsList {
			var obsTime time.Time
			if obs.ObservedAt != nil {
				obsTime = obs.ObservedAt.AsTime()
			}
			for i, ev := range obs.Evidence {
				envelopes = append(envelopes, assurance.EvidenceEnvelope{
					ID:              fmt.Sprintf("env-%s-%d", obs.Id, i),
					ObservationType: obs.Type,
					Subject:         subRef,
					CapturedAt:      obsTime,
					Artifact: assurance.EvidenceRef{
						URI:       ev.Uri,
						Digest:    ev.Digest,
						MediaType: ev.MediaType,
					},
					Epoch: assurance.AssuranceEpoch{
						SubjectDigest: assurance.ComputeStringDigest(subRef.URI()),
					},
				})
			}
		}
	}
	for _, env := range envelopes {
		if !env.CapturedAt.IsZero() && !env.CapturedAt.After(now.Add(1*time.Minute)) && assurance.IsAdverseObservationType(env.ObservationType) {
			hasViolation = true
		}
	}

	currentEpoch := assurance.AssuranceEpoch{
		SubjectDigest:        assurance.ComputeStringDigest(subRef.URI()),
		ImplementationDigest: assurance.ComputeStringDigest("kubernetes:workload-specification"),
		PolicyDigest:         assurance.ComputeStringDigest(subKey + ":policy"),
		AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
		EnvironmentDigest:    assurance.ComputeStringDigest("cluster:kubernetes"),
	}

	contract := assurance.EvidenceContract{
		ID:   "contract-default",
		Name: "Default Assurance Contract",
		Requirements: []assurance.EvidenceRequirement{
			{
				ID:           "admission-or-runtime",
				EvidenceType: "admission",
				Required:     true,
				MaxAge:       DefaultFreshnessWindow,
			},
		},
		OnMissingRequiredState: assurance.AssuranceStateUnknown,
	}

	contractResult := contract.Evaluate(envelopes, currentEpoch, now)
	if hasViolation {
		contractResult.State = assurance.AssuranceStateFailed
	}

	var targetState commonv1.AssuranceState
	var valence commonv1.Valence
	switch contractResult.State {
	case assurance.AssuranceStateVerified, assurance.AssuranceStateAssured:
		targetState = commonv1.AssuranceState_ASSURANCE_STATE_ASSURED
		valence = commonv1.Valence_VALENCE_POSITIVE
	case assurance.AssuranceStateFailed:
		targetState = commonv1.AssuranceState_ASSURANCE_STATE_FAILED
		valence = commonv1.Valence_VALENCE_NEGATIVE
	case assurance.AssuranceStateStale:
		targetState = commonv1.AssuranceState_ASSURANCE_STATE_STALE
		valence = commonv1.Valence_VALENCE_MIXED
	default:
		targetState = commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN
		valence = commonv1.Valence_VALENCE_UNRESOLVED
	}

	var evRefs []assurance.EvidenceRef
	for _, env := range envelopes {
		evRefs = append(evRefs, env.Artifact)
	}
	evRoot := receipts.ComputeEvidenceRoot(evRefs)
	if targetState != commonv1.AssuranceState_ASSURANCE_STATE_ASSURED {
		evRoot = ""
	}

	evCompleteness := &evidencev1.EvidenceCompleteness{
		Required: int32(contractResult.Completeness.Required),
		Present:  int32(contractResult.Completeness.Present),
		Verified: int32(contractResult.Completeness.Verified),
		Stale:    int32(contractResult.Completeness.Stale),
		Missing:  int32(contractResult.Completeness.Missing),
	}

	impDigest := ""
	polDigest := ""
	authDigest := ""
	envDigest := ""

	if targetState == commonv1.AssuranceState_ASSURANCE_STATE_ASSURED {
		impDigest = currentEpoch.ImplementationDigest
		polDigest = currentEpoch.PolicyDigest
		authDigest = currentEpoch.AuthorityDigest
		envDigest = currentEpoch.EnvironmentDigest
	}

	coherence := commonv1.Coherence_COHERENCE_COHERENT
	switch targetState {
	case commonv1.AssuranceState_ASSURANCE_STATE_FAILED:
		coherence = commonv1.Coherence_COHERENCE_DECOHERENT
	case commonv1.AssuranceState_ASSURANCE_STATE_STALE:
		coherence = commonv1.Coherence_COHERENCE_PARTIALLY_COHERENT
	}

	var evaluations []*assessmentv1.ClaimEvaluation
	for _, ctrl := range req.Controls {
		if ctrl == nil {
			continue
		}
		eval := &assessmentv1.ClaimEvaluation{
			Id:      fmt.Sprintf("eval-%s-%s", req.Subject.Id, ctrl.Id),
			Control: ctrl,
			Subject: req.Subject,
			State:   targetState,
			Vector: &commonv1.AssuranceVector{
				Applicability: commonv1.Valence_VALENCE_POSITIVE,
				Conformance:   valence,
				Provenance:    valence,
				Integrity:     valence,
				Authority:     valence,
				Identity:      valence,
				Runtime:       valence,
				Freshness:     valence,
				Completeness:  valence,
				Coherence:     coherence,
			},
			Epoch: &commonv1.AssuranceEpoch{
				SubjectDigest:        assurance.ComputeStringDigest(subKey),
				ImplementationDigest: impDigest,
				PolicyDigest:         polDigest,
				AuthorityDigest:      authDigest,
				EnvironmentDigest:    envDigest,
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
	if req == nil || req.Subject == nil || req.Control == nil {
		return nil, status.Error(codes.InvalidArgument, "subject and control are required")
	}

	now := time.Now().UTC()
	sub := assurance.SubjectRef{
		Scheme: req.Subject.Scheme,
		ID:     req.Subject.Id,
	}
	ctrl := assurance.ControlRef{
		Namespace: req.Control.Namespace,
		ID:        req.Control.Id,
		Version:   req.Control.Version,
	}

	respState, claimState, evRefs, evRoot := s.evaluateSubjectEvidence(ctx, sub, now)

	polDigest := ""
	impDigest := ""
	authDigest := ""
	envDigest := ""
	if evRoot != "" {
		polDigest = assurance.ComputeStringDigest(sub.URI() + ":" + evRoot)
		impDigest = assurance.ComputeStringDigest("kubernetes:workload-specification")
		authDigest = assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/server")
		envDigest = assurance.ComputeStringDigest("cluster:kubernetes")
	}

	var comp assurance.EvidenceCompleteness
	switch claimState {
	case assurance.AssuranceStateAssured:
		comp = assurance.EvidenceCompleteness{Required: len(evRefs), Present: len(evRefs), Verified: len(evRefs)}
	case assurance.AssuranceStateStale:
		comp = assurance.EvidenceCompleteness{Required: len(evRefs), Present: len(evRefs), Verified: 0, Stale: len(evRefs)}
	case assurance.AssuranceStateFailed:
		comp = assurance.EvidenceCompleteness{Required: 1, Present: len(evRefs), Verified: 0, Missing: 1}
	default:
		comp = assurance.EvidenceCompleteness{Required: 1, Present: 0, Verified: 0, Missing: 1}
	}

	eval := assurance.ClaimEvaluation{
		ID:      fmt.Sprintf("eval-%s", ctrl.ID),
		Subject: sub,
		Control: ctrl,
		State:   claimState,
		Epoch: assurance.AssuranceEpoch{
			SubjectDigest:        assurance.ComputeStringDigest(sub.URI()),
			ImplementationDigest: impDigest,
			PolicyDigest:         polDigest,
			AuthorityDigest:      authDigest,
			EnvironmentDigest:    envDigest,
		},
		Evidence:     evRefs,
		Completeness: comp,
		EvidenceRoot: evRoot,
		EvaluatedAt:  now,
		ValidUntil:   now.Add(5 * time.Minute),
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
			Id:       imp.Requirement,
			Provider: imp.Provider,
			Digest:   imp.Digest,
		})
	}

	var evs []*evidencev1.EvidenceRef
	for _, ev := range graph.Evidence {
		evs = append(evs, &evidencev1.EvidenceRef{
			Uri:       ev.Producer,
			Digest:    ev.Digest,
			MediaType: ev.Type,
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
		Freshness: graph.Freshness,
		Authority: graph.Authority,
		Epoch: &commonv1.AssuranceEpoch{
			SubjectDigest:        graph.Epoch.SubjectDigest,
			ImplementationDigest: graph.Epoch.ImplementationDigest,
			PolicyDigest:         graph.Epoch.PolicyDigest,
			AuthorityDigest:      graph.Epoch.AuthorityDigest,
			EnvironmentDigest:    graph.Epoch.EnvironmentDigest,
		},
		AssuranceState: respState,
		EvidenceRoot:   graph.EvidenceRoot,
		Projections:    graph.Projections,
		RenderedText:   graph.RenderText(),
	}, nil
}

// GetAssuranceState returns summary assurance state based on verified evidence.
func (s *Server) GetAssuranceState(ctx context.Context, req *servicesv1.GetAssuranceStateRequest) (*servicesv1.GetAssuranceStateResponse, error) {
	if req == nil || req.Subject == nil {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}

	now := time.Now().UTC()
	subRef := assurance.SubjectRef{
		Scheme: req.Subject.Scheme,
		ID:     req.Subject.Id,
	}
	subKey := subRef.Scheme + "://" + subRef.ID

	protoState, _, _, root := s.evaluateSubjectEvidence(ctx, subRef, now)

	// Invariant I-02: Absence of valid evidence is UNKNOWN, never PASS
	if protoState == commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN {
		return &servicesv1.GetAssuranceStateResponse{
			Subject:      req.Subject,
			State:        commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN,
			EvidenceRoot: "",
			Epoch:        nil,
		}, nil
	}

	policyDigest := assurance.ComputeStringDigest(subKey + ":" + root)
	return &servicesv1.GetAssuranceStateResponse{
		Subject:      req.Subject,
		State:        protoState,
		EvidenceRoot: root,
		Epoch: &commonv1.AssuranceEpoch{
			SubjectDigest:        assurance.ComputeStringDigest(subKey),
			ImplementationDigest: assurance.ComputeStringDigest("kubernetes:workload-specification"),
			PolicyDigest:         policyDigest,
			AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
			EnvironmentDigest:    assurance.ComputeStringDigest("cluster:kubernetes"),
		},
	}, nil
}

// SubmitReceipt verifies an incoming cryptographic receipt.
func (s *Server) SubmitReceipt(ctx context.Context, req *servicesv1.SubmitReceiptRequest) (*servicesv1.SubmitReceiptResponse, error) {
	if req == nil || req.Receipt == nil {
		return nil, status.Error(codes.InvalidArgument, "receipt cannot be nil")
	}

	rcpt := req.Receipt
	if rcpt.Subject == nil || rcpt.Control == nil || rcpt.Evaluator == nil || rcpt.EvaluatedAt == nil {
		return nil, status.Error(codes.InvalidArgument, "receipt requires non-nil subject, control, evaluator, and evaluated_at")
	}

	coreReceipt := assurance.ControlReceipt{
		Subject: assurance.SubjectRef{
			Scheme: rcpt.Subject.Scheme,
			ID:     rcpt.Subject.Id,
		},
		Control: assurance.ControlRef{
			Namespace: rcpt.Control.Namespace,
			ID:        rcpt.Control.Id,
			Version:   rcpt.Control.Version,
		},
		State:        assurance.AssuranceState(rcpt.State),
		EvidenceRoot: rcpt.EvidenceRoot,
		Evaluator: assurance.AuthorityRef{
			Scheme:      rcpt.Evaluator.Scheme,
			Subject:     rcpt.Evaluator.Subject,
			TrustDomain: rcpt.Evaluator.TrustDomain,
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

	valid, err := receipts.VerifyIndependentReceipt(coreReceipt, s.receiptMgr.PublicKey())
	if err != nil || !valid {
		return &servicesv1.SubmitReceiptResponse{
			Verified: false,
			Message:  "Signature verification failed",
		}, nil
	}

	digest := coreReceipt.Digest()
	s.mu.Lock()
	if _, exists := s.receipts[digest]; !exists {
		if len(s.receipts) >= MaxStoredReceipts && len(s.receiptOrder) > 0 {
			evictDigest := s.receiptOrder[0]
			s.receiptOrder = s.receiptOrder[1:]
			delete(s.receipts, evictDigest)
		}
		s.receiptOrder = append(s.receiptOrder, digest)
	}
	s.receipts[digest] = rcpt
	s.mu.Unlock()

	return &servicesv1.SubmitReceiptResponse{
		Verified:      true,
		ReceiptDigest: digest,
		Message:       "Receipt verified and accepted",
	}, nil
}
