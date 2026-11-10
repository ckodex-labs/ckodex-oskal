package oskal

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/service"
	commonv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/control/v1"
	evidencev1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/evidence/v1"
	receiptv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/receipt/v1"
	servicesv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/services/v1"
)

func TestInProcessClientLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	evaluatorAuth := AuthorityRef{
		Scheme:  "spiffe",
		Subject: "prod/ns/ckodex-assurance/sa/sdk-test-evaluator",
	}

	mgr, err := NewReceiptManager(evaluatorAuth)
	if err != nil {
		t.Fatalf("failed to create receipt manager: %v", err)
	}

	client := NewInProcessClient(WithReceiptManager(mgr))
	defer func() { _ = client.Close() }()

	subject := SubjectRef{Scheme: "k8s", ID: "payments/checkout-service"}
	ctrl := ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}

	// 1. Invariant I-02: Without observations, state must be UNKNOWN
	stUnknown, err := client.GetAssuranceState(ctx, subject)
	if err != nil {
		t.Fatalf("unexpected error getting initial state: %v", err)
	}
	if stUnknown.State != StateUnknown {
		t.Fatalf("expected StateUnknown without evidence, got %v", stUnknown.State)
	}
	if stUnknown.EvidenceRoot != "none" {
		t.Fatalf("expected evidence root 'none', got %s", stUnknown.EvidenceRoot)
	}

	// 2. Explain claim without evidence -> state UNKNOWN
	explainUnknown, err := client.ExplainClaim(ctx, subject, ctrl)
	if err != nil {
		t.Fatalf("unexpected error explaining claim: %v", err)
	}
	if explainUnknown.AssuranceState != StateUnknown {
		t.Fatalf("expected explain state UNKNOWN without evidence, got %v", explainUnknown.AssuranceState)
	}
	if explainUnknown.RenderedText == "" {
		t.Fatal("expected non-empty rendered explanation text")
	}

	// 3. Submit real observation
	obsID, err := client.SubmitObservation(ctx, &evidencev1.Observation{
		Id:   "obs-sdk-001",
		Type: "admission",
		Subject: &commonv1.SubjectRef{
			Scheme: subject.Scheme,
			Id:     subject.ID,
		},
		Evidence: []*evidencev1.EvidenceRef{
			{Uri: "evidence://cel/admission", Digest: ComputeStringDigest("sdk-evidence-01"), MediaType: "application/json"},
		},
		ObservedAt: timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("failed to submit observation: %v", err)
	}
	if obsID != "obs-sdk-001" {
		t.Fatalf("unexpected observation ID: %s", obsID)
	}

	// 4. Query state after observation -> state ASSURED
	stAssured, err := client.GetAssuranceState(ctx, subject)
	if err != nil {
		t.Fatalf("unexpected error getting assured state: %v", err)
	}
	if stAssured.State != StateAssured {
		t.Fatalf("expected StateAssured after observation, got %v", stAssured.State)
	}
	if stAssured.EvidenceRoot == "none" || stAssured.EvidenceRoot == "" {
		t.Fatalf("expected valid evidence root, got %s", stAssured.EvidenceRoot)
	}

	// 5. Evaluate subject claims
	evalResp, err := client.EvaluateSubject(ctx, subject, []ControlRef{ctrl})
	if err != nil {
		t.Fatalf("failed to evaluate subject: %v", err)
	}
	if evalResp.SummaryState != StateAssured {
		t.Fatalf("expected summary state ASSURED, got %v", evalResp.SummaryState)
	}
	if len(evalResp.Evaluations) != 1 {
		t.Fatalf("expected 1 evaluation, got %d", len(evalResp.Evaluations))
	}

	// 6. Submit cryptographic receipt
	epoch := AssuranceEpoch{
		SubjectDigest:        assurance.ComputeStringDigest(subject.ID),
		ImplementationDigest: assurance.ComputeStringDigest("kubernetes:workload"),
		PolicyDigest:         assurance.ComputeStringDigest("policy:nist-ac6"),
		AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
		EnvironmentDigest:    assurance.ComputeStringDigest("cluster:local"),
	}
	now := time.Now().UTC()
	coreReceipt, err := mgr.IssueReceipt(subject, ctrl, StateAssured, epoch, []EvidenceRef{
		{Digest: assurance.ComputeStringDigest("sdk-evidence-payload-123")},
	}, now)
	if err != nil {
		t.Fatalf("failed to issue receipt: %v", err)
	}

	protoRcpt := &receiptv1.ControlReceipt{
		Subject: &commonv1.SubjectRef{Scheme: subject.Scheme, Id: subject.ID},
		Control: &controlv1.ControlRef{Namespace: ctrl.Namespace, Id: ctrl.ID},
		State:   commonv1.AssuranceState_ASSURANCE_STATE_ASSURED,
		Epoch: &commonv1.AssuranceEpoch{
			SubjectDigest:        epoch.SubjectDigest,
			ImplementationDigest: epoch.ImplementationDigest,
			PolicyDigest:         epoch.PolicyDigest,
			AuthorityDigest:      epoch.AuthorityDigest,
			EnvironmentDigest:    epoch.EnvironmentDigest,
		},
		EvidenceRoot: coreReceipt.EvidenceRoot,
		Evaluator: &commonv1.AuthorityRef{
			Scheme:  coreReceipt.Evaluator.Scheme,
			Subject: coreReceipt.Evaluator.Subject,
		},
		EvaluatedAt: timestamppb.New(now),
		Signature:   coreReceipt.Signature,
	}

	verified, msg, err := client.SubmitReceipt(ctx, protoRcpt)
	if err != nil {
		t.Fatalf("submit receipt failed: %v", err)
	}
	if !verified {
		t.Fatalf("expected receipt to be verified: %s", msg)
	}

	// 7. Submit tampered receipt -> verify rejection
	tamperedProto := proto.Clone(protoRcpt).(*receiptv1.ControlReceipt)
	tamperedProto.EvidenceRoot = ComputeStringDigest("tampered-root")

	tamperedVerified, _, err := client.SubmitReceipt(ctx, tamperedProto)
	if err != nil {
		t.Fatalf("unexpected error on tampered receipt: %v", err)
	}
	if tamperedVerified {
		t.Fatal("expected tampered receipt to fail verification, but it passed")
	}
}

func TestClientInterfaceCompatibility(t *testing.T) {
	// Verify that InProcessClient satisfies the Client interface at compile-time
	var _ Client = (*InProcessClient)(nil)
	var _ Client = (*grpcClient)(nil)
}

func TestGRPCClientLifecycle(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()

	evaluatorAuth := AuthorityRef{
		Scheme:  "spiffe",
		Subject: "prod/ns/ckodex-assurance/sa/grpc-test-evaluator",
	}
	receiptMgr, err := NewReceiptManager(evaluatorAuth)
	if err != nil {
		t.Fatalf("failed to create receipt manager: %v", err)
	}

	srv := service.NewServer(receiptMgr.inner)
	servicesv1.RegisterAssuranceServiceServer(s, srv)

	go func() {
		if err := s.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			t.Errorf("server error: %v", err)
		}
	}()
	defer s.GracefulStop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewClient(ctx, "passthrough://bufnet",
		WithDialOptions(
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return lis.Dial()
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		),
	)
	if err != nil {
		t.Fatalf("failed to create gRPC client: %v", err)
	}
	defer func() { _ = client.Close() }()

	subject := SubjectRef{Scheme: "k8s", ID: "payments/checkout-service"}
	ctrl := ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}

	// 1. Initial state without evidence -> StateUnknown
	stUnknown, err := client.GetAssuranceState(ctx, subject)
	if err != nil {
		t.Fatalf("unexpected error getting initial state: %v", err)
	}
	if stUnknown.State != StateUnknown {
		t.Fatalf("expected StateUnknown, got %v", stUnknown.State)
	}

	// 2. Submit observation
	obsID, err := client.SubmitObservation(ctx, &evidencev1.Observation{
		Id:   "obs-grpc-01",
		Type: "admission",
		Subject: &commonv1.SubjectRef{
			Scheme: subject.Scheme,
			Id:     subject.ID,
		},
		Evidence: []*evidencev1.EvidenceRef{
			{Uri: "evidence://cel/admission", Digest: ComputeStringDigest("grpc-evidence-01"), MediaType: "application/json"},
		},
		ObservedAt: timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("failed to submit observation: %v", err)
	}
	if obsID != "obs-grpc-01" {
		t.Fatalf("unexpected obs ID: %s", obsID)
	}

	// 3. Query state after observation -> StateAssured
	stAssured, err := client.GetAssuranceState(ctx, subject)
	if err != nil {
		t.Fatalf("failed to get state: %v", err)
	}
	if stAssured.State != StateAssured {
		t.Fatalf("expected StateAssured, got %v", stAssured.State)
	}

	// 4. Explain claim
	explainResp, err := client.ExplainClaim(ctx, subject, ctrl)
	if err != nil {
		t.Fatalf("failed to explain claim: %v", err)
	}
	if explainResp.AssuranceState != StateAssured {
		t.Fatalf("expected explain state ASSURED, got %v", explainResp.AssuranceState)
	}
	// QA-07: Verify ExplainGraph round-trip fields over gRPC
	if explainResp.Graph.Epoch.SubjectDigest == "" {
		t.Fatal("expected non-empty Epoch.SubjectDigest on gRPC ExplainClaim round-trip")
	}
	if len(explainResp.Graph.Implementations) == 0 || explainResp.Graph.Implementations[0].Requirement == "" {
		t.Fatalf("expected non-empty Implementation.Requirement on gRPC ExplainClaim round-trip, got: %+v", explainResp.Graph.Implementations)
	}
	if len(explainResp.Graph.Evidence) == 0 || explainResp.Graph.Evidence[0].Digest == "" || !explainResp.Graph.Evidence[0].Verified {
		t.Fatalf("expected verified Evidence item with non-empty Digest on gRPC ExplainClaim round-trip, got: %+v", explainResp.Graph.Evidence)
	}

	// 5. Evaluate subject
	evalResp, err := client.EvaluateSubject(ctx, subject, []ControlRef{ctrl})
	if err != nil {
		t.Fatalf("failed to evaluate subject: %v", err)
	}
	if evalResp.SummaryState != StateAssured {
		t.Fatalf("expected summary state ASSURED, got %v", evalResp.SummaryState)
	}
	if len(evalResp.Evaluations) != 1 || evalResp.Evaluations[0].Vector.Provenance != assurance.ValencePositive {
		t.Fatalf("expected positive Provenance valence in EvaluateSubject vector (QA-15), got: %+v", evalResp.Evaluations)
	}
}

func TestInProcessClientFreshnessAndViolations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := NewInProcessClient()
	defer func() { _ = client.Close() }()

	ctrl := ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}

	// 1. Stale observation (> 15m old) -> StateStale (F-12)
	staleSub := SubjectRef{Scheme: "k8s", ID: "payments/stale-inproc"}
	_, err := client.SubmitObservation(ctx, &evidencev1.Observation{
		Id:   "obs-inproc-stale",
		Type: "admission",
		Subject: &commonv1.SubjectRef{
			Scheme: staleSub.Scheme,
			Id:     staleSub.ID,
		},
		Evidence: []*evidencev1.EvidenceRef{
			{Uri: "evidence://cel/stale", Digest: ComputeStringDigest("inproc-stale-01"), MediaType: "application/json"},
		},
		ObservedAt: timestamppb.New(time.Now().UTC().Add(-20 * time.Minute)),
	})
	if err != nil {
		t.Fatalf("failed to submit stale observation: %v", err)
	}

	stStale, err := client.GetAssuranceState(ctx, staleSub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stStale.State != StateStale || stStale.Freshness != "stale" {
		t.Fatalf("expected StateStale and freshness 'stale', got state=%v freshness=%s", stStale.State, stStale.Freshness)
	}

	evalStale, err := client.EvaluateSubject(ctx, staleSub, []ControlRef{ctrl})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evalStale.SummaryState != StateStale {
		t.Fatalf("expected EvaluateSubject SummaryState StateStale, got %v", evalStale.SummaryState)
	}

	expStale, err := client.ExplainClaim(ctx, staleSub, ctrl)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expStale.AssuranceState != StateStale {
		t.Fatalf("expected ExplainClaim StateStale, got %v", expStale.AssuranceState)
	}

	// 2. Violation observation -> StateFailed (F-12)
	violSub := SubjectRef{Scheme: "k8s", ID: "payments/viol-inproc"}
	_, err = client.SubmitObservation(ctx, &evidencev1.Observation{
		Id:   "obs-inproc-viol",
		Type: "admission",
		Subject: &commonv1.SubjectRef{
			Scheme: violSub.Scheme,
			Id:     violSub.ID,
		},
		Evidence: []*evidencev1.EvidenceRef{
			{Uri: "evidence://cel/viol", Digest: ComputeStringDigest("inproc-viol-01"), MediaType: "application/json"},
		},
		Attributes: map[string]string{
			"status": "failed",
		},
		ObservedAt: timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("failed to submit violation observation: %v", err)
	}

	stViol, err := client.GetAssuranceState(ctx, violSub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stViol.State != StateFailed {
		t.Fatalf("expected StateFailed for violation observation, got %v", stViol.State)
	}

	evalViol, err := client.EvaluateSubject(ctx, violSub, []ControlRef{ctrl})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evalViol.SummaryState != StateFailed {
		t.Fatalf("expected EvaluateSubject SummaryState StateFailed, got %v", evalViol.SummaryState)
	}

	expViol, err := client.ExplainClaim(ctx, violSub, ctrl)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expViol.AssuranceState != StateFailed {
		t.Fatalf("expected ExplainClaim StateFailed, got %v", expViol.AssuranceState)
	}

	// 3. Malformed ControlReceipt missing sub-messages must return error without panicking
	ok, _, err := client.SubmitReceipt(ctx, &receiptv1.ControlReceipt{})
	if err == nil || ok {
		t.Fatal("expected error for incomplete ControlReceipt in InProcessClient")
	}
}

func TestGRPCClientBoundedRetryRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var callCount int32
	lis := bufconn.Listen(1024 * 1024)
	grpcSrv := grpc.NewServer(grpc.UnaryInterceptor(func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if info.FullMethod == "/"+servicesv1.AssuranceService_ServiceDesc.ServiceName+"/GetAssuranceState" {
			if atomic.AddInt32(&callCount, 1) == 1 {
				return nil, status.Error(codes.Unavailable, "simulated transient network blip")
			}
		}
		return handler(ctx, req)
	}))
	servicesv1.RegisterAssuranceServiceServer(grpcSrv, service.NewServer(nil))
	go func() { _ = grpcSrv.Serve(lis) }()
	defer grpcSrv.Stop()

	client, err := NewClient(
		ctx,
		"passthrough:///bufnet",
		WithDialOptions(
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return lis.Dial()
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		),
		WithRetry(3, 10*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	st, err := client.GetAssuranceState(ctx, SubjectRef{Scheme: "k8s", ID: "payments/retry-target"})
	if err != nil {
		t.Fatalf("expected retry policy to recover from transient Unavailable error, got: %v", err)
	}
	if st.State != StateUnknown {
		t.Fatalf("expected StateUnknown, got %v", st.State)
	}
	if atomic.LoadInt32(&callCount) < 2 {
		t.Fatalf("expected at least 2 RPC attempts, got %d", atomic.LoadInt32(&callCount))
	}
}
