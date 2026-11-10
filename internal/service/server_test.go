package service

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	commonv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/control/v1"
	evidencev1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/evidence/v1"
	receiptv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/receipt/v1"
	servicesv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/services/v1"
)

const bufSize = 1024 * 1024

func setupTestGRPCServer(t *testing.T) (servicesv1.AssuranceServiceClient, *receipts.ReceiptManager, func()) {
	t.Helper()
	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()

	receiptMgr, err := receipts.NewReceiptManager(assurance.AuthorityRef{
		Scheme:  "spiffe",
		Subject: "prod/ns/ckodex-assurance/sa/test-evaluator",
	})
	if err != nil {
		t.Fatalf("failed to create receipt manager: %v", err)
	}

	srv := NewServer(receiptMgr)
	servicesv1.RegisterAssuranceServiceServer(s, srv)

	go func() {
		if err := s.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			t.Errorf("server exited with error: %v", err)
		}
	}()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial bufnet: %v", err)
	}

	client := servicesv1.NewAssuranceServiceClient(conn)

	cleanup := func() {
		_ = conn.Close()
		s.GracefulStop()
		_ = lis.Close()
	}

	return client, receiptMgr, cleanup
}

func TestSubmitObservation(t *testing.T) {
	client, _, cleanup := setupTestGRPCServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 1. Success case
	resp, err := client.SubmitObservation(ctx, &servicesv1.SubmitObservationRequest{
		Observation: &evidencev1.Observation{
			Id:   "obs-101",
			Type: "admission",
			Subject: &commonv1.SubjectRef{
				Scheme: "k8s",
				Id:     "payments/payments-api",
			},
			ObservedAt: timestamppb.Now(),
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Accepted || resp.ObservationId != "obs-101" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	// 2. Nil observation
	_, err = client.SubmitObservation(ctx, &servicesv1.SubmitObservationRequest{})
	if err == nil {
		t.Fatal("expected error for nil observation, got nil")
	}
}

func TestEvaluateSubject(t *testing.T) {
	client, _, cleanup := setupTestGRPCServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 1. Without observations: should return ASSURANCE_STATE_UNKNOWN (Invariant I-02)
	respUnknown, err := client.EvaluateSubject(ctx, &servicesv1.EvaluateSubjectRequest{
		Subject: &commonv1.SubjectRef{
			Scheme: "k8s",
			Id:     "default/pod-secure",
		},
		Controls: []*controlv1.ControlRef{
			{Namespace: "nist-sp-800-53", Id: "AC-6"},
			{Namespace: "nist-sp-800-53", Id: "SC-28"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(respUnknown.Evaluations) != 2 {
		t.Fatalf("expected 2 evaluations, got %d", len(respUnknown.Evaluations))
	}
	if respUnknown.SummaryState != commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN {
		t.Fatalf("expected UNKNOWN summary state without evidence, got %v", respUnknown.SummaryState)
	}

	// 2. Submit observation for subject
	_, err = client.SubmitObservation(ctx, &servicesv1.SubmitObservationRequest{
		Observation: &evidencev1.Observation{
			Id:   "obs-01",
			Type: "admission",
			Subject: &commonv1.SubjectRef{
				Scheme: "k8s",
				Id:     "default/pod-secure",
			},
			Evidence: []*evidencev1.EvidenceRef{
				{Uri: "evidence://cel/admission", Digest: assurance.ComputeStringDigest("cel-evidence-01"), MediaType: "application/json"},
			},
			ObservedAt: timestamppb.Now(),
		},
	})
	if err != nil {
		t.Fatalf("unexpected error submitting observation: %v", err)
	}

	// 3. Now evaluate subject: should be ASSURED with evidence root
	respAssured, err := client.EvaluateSubject(ctx, &servicesv1.EvaluateSubjectRequest{
		Subject: &commonv1.SubjectRef{
			Scheme: "k8s",
			Id:     "default/pod-secure",
		},
		Controls: []*controlv1.ControlRef{
			{Namespace: "nist-sp-800-53", Id: "AC-6"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if respAssured.SummaryState != commonv1.AssuranceState_ASSURANCE_STATE_ASSURED {
		t.Fatalf("expected ASSURED summary state with evidence, got %v", respAssured.SummaryState)
	}
	if respAssured.Evaluations[0].EvidenceRoot == "" {
		t.Fatal("expected non-empty EvidenceRoot with verified evidence")
	}

	// 4. Nil subject
	_, err = client.EvaluateSubject(ctx, &servicesv1.EvaluateSubjectRequest{})
	if err == nil {
		t.Fatal("expected error for nil subject, got nil")
	}
}

func TestExplainClaim(t *testing.T) {
	client, _, cleanup := setupTestGRPCServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 1. Without observations: Explain returns UNKNOWN state
	respUnknown, err := client.ExplainClaim(ctx, &servicesv1.ExplainClaimRequest{
		Subject: &commonv1.SubjectRef{
			Scheme: "k8s",
			Id:     "payments/payments-api",
		},
		Control: &controlv1.ControlRef{
			Namespace: "nist-sp-800-53",
			Id:        "AC-6",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if respUnknown.CanonicalControl != "ckodex:least-privilege" {
		t.Fatalf("unexpected canonical control: %s", respUnknown.CanonicalControl)
	}
	if respUnknown.AssuranceState != commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN {
		t.Fatalf("expected UNKNOWN state without evidence, got %v", respUnknown.AssuranceState)
	}

	// 2. Submit observation
	_, err = client.SubmitObservation(ctx, &servicesv1.SubmitObservationRequest{
		Observation: &evidencev1.Observation{
			Id:   "obs-explain-01",
			Type: "admission",
			Subject: &commonv1.SubjectRef{
				Scheme: "k8s",
				Id:     "payments/payments-api",
			},
			Evidence: []*evidencev1.EvidenceRef{
				{Uri: "evidence://cel/admission", Digest: assurance.ComputeStringDigest("cel-evidence-01"), MediaType: "application/json"},
			},
			ObservedAt: timestamppb.Now(),
		},
	})
	if err != nil {
		t.Fatalf("unexpected error submitting observation: %v", err)
	}

	// 3. Explain with evidence: returns ASSURED state
	respAssured, err := client.ExplainClaim(ctx, &servicesv1.ExplainClaimRequest{
		Subject: &commonv1.SubjectRef{
			Scheme: "k8s",
			Id:     "payments/payments-api",
		},
		Control: &controlv1.ControlRef{
			Namespace: "nist-sp-800-53",
			Id:        "AC-6",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if respAssured.AssuranceState != commonv1.AssuranceState_ASSURANCE_STATE_ASSURED {
		t.Fatalf("expected ASSURED state with evidence, got %v", respAssured.AssuranceState)
	}
	if respAssured.RenderedText == "" {
		t.Fatal("expected non-empty rendered explanation text")
	}

	// 4. Nil request arguments
	_, err = client.ExplainClaim(ctx, &servicesv1.ExplainClaimRequest{})
	if err == nil {
		t.Fatal("expected error for nil args, got nil")
	}
}

func TestGetAssuranceState(t *testing.T) {
	client, _, cleanup := setupTestGRPCServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 1. Without observations: should return ASSURANCE_STATE_UNKNOWN (Invariant I-02)
	respUnknown, err := client.GetAssuranceState(ctx, &servicesv1.GetAssuranceStateRequest{
		Subject: &commonv1.SubjectRef{
			Scheme: "k8s",
			Id:     "payments/payments-api",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if respUnknown.State != commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN {
		t.Fatalf("expected state UNKNOWN without observations, got %v", respUnknown.State)
	}

	// 2. Submit observation
	_, err = client.SubmitObservation(ctx, &servicesv1.SubmitObservationRequest{
		Observation: &evidencev1.Observation{
			Id:   "obs-state-01",
			Type: "admission",
			Subject: &commonv1.SubjectRef{
				Scheme: "k8s",
				Id:     "payments/payments-api",
			},
			Evidence: []*evidencev1.EvidenceRef{
				{Uri: "evidence://cel/admission", Digest: assurance.ComputeStringDigest("payment-evidence-01"), MediaType: "application/json"},
			},
			ObservedAt: timestamppb.Now(),
		},
	})
	if err != nil {
		t.Fatalf("unexpected error submitting observation: %v", err)
	}

	// 3. With observations: returns ASSURED state and real evidence root
	respAssured, err := client.GetAssuranceState(ctx, &servicesv1.GetAssuranceStateRequest{
		Subject: &commonv1.SubjectRef{
			Scheme: "k8s",
			Id:     "payments/payments-api",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if respAssured.State != commonv1.AssuranceState_ASSURANCE_STATE_ASSURED {
		t.Fatalf("expected state ASSURED with observations, got %v", respAssured.State)
	}
	if respAssured.EvidenceRoot == "" {
		t.Fatal("expected non-empty EvidenceRoot with observations")
	}

	// 4. Nil subject
	_, err = client.GetAssuranceState(ctx, &servicesv1.GetAssuranceStateRequest{})
	if err == nil {
		t.Fatal("expected error for nil subject, got nil")
	}
}

func TestSubmitReceipt(t *testing.T) {
	client, receiptMgr, cleanup := setupTestGRPCServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sub := assurance.SubjectRef{Scheme: "k8s", ID: "payments/api"}
	ctrl := assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
	epoch := assurance.AssuranceEpoch{
		SubjectDigest:        assurance.ComputeStringDigest(sub.URI()),
		ImplementationDigest: assurance.ComputeStringDigest("kubernetes:workload"),
		PolicyDigest:         assurance.ComputeStringDigest("policy:nist-ac6"),
		AuthorityDigest:      assurance.ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
		EnvironmentDigest:    assurance.ComputeStringDigest("cluster:local"),
	}
	evs := []assurance.EvidenceRef{
		{Digest: assurance.ComputeStringDigest("evidence-content-1")},
	}
	now := time.Now().UTC()

	// Issue a genuine receipt signed by receiptMgr
	coreReceipt, err := receiptMgr.IssueReceipt(sub, ctrl, assurance.AssuranceStateAssured, epoch, evs, now)
	if err != nil {
		t.Fatalf("failed to issue receipt: %v", err)
	}

	// 1. Submit genuine receipt
	protoReceipt := &receiptv1.ControlReceipt{
		Subject: &commonv1.SubjectRef{
			Scheme: sub.Scheme,
			Id:     sub.ID,
		},
		Control: &controlv1.ControlRef{
			Namespace: ctrl.Namespace,
			Id:        ctrl.ID,
		},
		State: commonv1.AssuranceState_ASSURANCE_STATE_ASSURED,
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

	resp, err := client.SubmitReceipt(ctx, &servicesv1.SubmitReceiptRequest{
		Receipt: protoReceipt,
	})
	if err != nil {
		t.Fatalf("unexpected error submitting receipt: %v", err)
	}
	if !resp.Verified {
		t.Fatalf("expected receipt to be verified: %s", resp.Message)
	}

	// 2. Submit tampered receipt
	tamperedReceipt := proto.Clone(protoReceipt).(*receiptv1.ControlReceipt)
	tamperedReceipt.EvidenceRoot = assurance.ComputeStringDigest("tampered-root")

	respTampered, err := client.SubmitReceipt(ctx, &servicesv1.SubmitReceiptRequest{
		Receipt: tamperedReceipt,
	})
	if err != nil {
		t.Fatalf("unexpected error on tampered receipt: %v", err)
	}
	if respTampered.Verified {
		t.Fatal("expected tampered receipt verification to fail, but it succeeded")
	}

	// 3. Nil receipt
	_, err = client.SubmitReceipt(ctx, &servicesv1.SubmitReceiptRequest{})
	if err == nil {
		t.Fatal("expected error for nil receipt, got nil")
	}
}

func TestAssuranceFreshnessAndViolations(t *testing.T) {
	client, _, cleanup := setupTestGRPCServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 1. Stale observation (> 15m old) -> ASSURANCE_STATE_STALE (F-09, F-11)
	staleSub := &commonv1.SubjectRef{Scheme: "k8s", Id: "payments/stale-service"}
	_, err := client.SubmitObservation(ctx, &servicesv1.SubmitObservationRequest{
		Observation: &evidencev1.Observation{
			Id:      "obs-stale-01",
			Type:    "admission",
			Subject: staleSub,
			Evidence: []*evidencev1.EvidenceRef{
				{Uri: "evidence://cel/stale", Digest: assurance.ComputeStringDigest("stale-01"), MediaType: "application/json"},
			},
			ObservedAt: timestamppb.New(time.Now().UTC().Add(-20 * time.Minute)),
		},
	})
	if err != nil {
		t.Fatalf("failed to submit stale observation: %v", err)
	}

	stStale, err := client.GetAssuranceState(ctx, &servicesv1.GetAssuranceStateRequest{Subject: staleSub})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stStale.State != commonv1.AssuranceState_ASSURANCE_STATE_STALE {
		t.Fatalf("expected ASSURANCE_STATE_STALE for >15m observation, got %v", stStale.State)
	}

	expStale, err := client.ExplainClaim(ctx, &servicesv1.ExplainClaimRequest{
		Subject: staleSub,
		Control: &controlv1.ControlRef{Namespace: "nist-sp-800-53", Id: "AC-6"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expStale.AssuranceState != commonv1.AssuranceState_ASSURANCE_STATE_STALE {
		t.Fatalf("expected ExplainClaim ASSURANCE_STATE_STALE for >15m observation, got %v", expStale.AssuranceState)
	}

	// 2. Future timestamp observation -> rejected as invalid timestamp -> ASSURANCE_STATE_UNKNOWN (F-09)
	futureSub := &commonv1.SubjectRef{Scheme: "k8s", Id: "payments/future-service"}
	_, err = client.SubmitObservation(ctx, &servicesv1.SubmitObservationRequest{
		Observation: &evidencev1.Observation{
			Id:      "obs-future-01",
			Type:    "admission",
			Subject: futureSub,
			Evidence: []*evidencev1.EvidenceRef{
				{Uri: "evidence://cel/future", Digest: assurance.ComputeStringDigest("future-01"), MediaType: "application/json"},
			},
			ObservedAt: timestamppb.New(time.Now().UTC().Add(10 * time.Minute)),
		},
	})
	if err != nil {
		t.Fatalf("failed to submit future observation: %v", err)
	}

	stFuture, err := client.GetAssuranceState(ctx, &servicesv1.GetAssuranceStateRequest{Subject: futureSub})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stFuture.State != commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN {
		t.Fatalf("expected ASSURANCE_STATE_UNKNOWN for future timestamp observation, got %v", stFuture.State)
	}

	// 3. Violation observation -> ASSURANCE_STATE_FAILED (F-09)
	violSub := &commonv1.SubjectRef{Scheme: "k8s", Id: "payments/violating-service"}
	_, err = client.SubmitObservation(ctx, &servicesv1.SubmitObservationRequest{
		Observation: &evidencev1.Observation{
			Id:      "obs-viol-01",
			Type:    "violation",
			Subject: violSub,
			Evidence: []*evidencev1.EvidenceRef{
				{Uri: "evidence://ebpf/violation", Digest: assurance.ComputeStringDigest("viol-01"), MediaType: "application/json"},
			},
			ObservedAt: timestamppb.Now(),
		},
	})
	if err != nil {
		t.Fatalf("failed to submit violation observation: %v", err)
	}

	stViol, err := client.GetAssuranceState(ctx, &servicesv1.GetAssuranceStateRequest{Subject: violSub})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stViol.State != commonv1.AssuranceState_ASSURANCE_STATE_FAILED {
		t.Fatalf("expected ASSURANCE_STATE_FAILED for violation observation, got %v", stViol.State)
	}

	expViol, err := client.ExplainClaim(ctx, &servicesv1.ExplainClaimRequest{
		Subject: violSub,
		Control: &controlv1.ControlRef{Namespace: "nist-sp-800-53", Id: "AC-6"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expViol.AssuranceState != commonv1.AssuranceState_ASSURANCE_STATE_FAILED {
		t.Fatalf("expected ExplainClaim ASSURANCE_STATE_FAILED for violation observation, got %v", expViol.AssuranceState)
	}
}

func TestMalformedNilSubMessagesDoNotPanic(t *testing.T) {
	client, _, cleanup := setupTestGRPCServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 1. SubmitReceipt with partially nil sub-messages MUST return InvalidArgument, never panic
	for _, tc := range []*receiptv1.ControlReceipt{
		{},
		{Subject: &commonv1.SubjectRef{Scheme: "k8s", Id: "ns/app"}},
		{
			Subject: &commonv1.SubjectRef{Scheme: "k8s", Id: "ns/app"},
			Control: &controlv1.ControlRef{Namespace: "nist", Id: "AC-6"},
		},
		{
			Subject:   &commonv1.SubjectRef{Scheme: "k8s", Id: "ns/app"},
			Control:   &controlv1.ControlRef{Namespace: "nist", Id: "AC-6"},
			Evaluator: &commonv1.AuthorityRef{Scheme: "spiffe", Subject: "eval"},
		},
	} {
		if _, err := client.SubmitReceipt(ctx, &servicesv1.SubmitReceiptRequest{Receipt: tc}); err == nil {
			t.Fatal("expected InvalidArgument error on incomplete ControlReceipt")
		}
	}

	// 2. SubmitObservation with nil Evidence element and EvaluateSubject with nil Control element
	if _, err := client.SubmitObservation(ctx, &servicesv1.SubmitObservationRequest{
		Observation: &evidencev1.Observation{
			Id:         "obs-nil-elem",
			Type:       "admission",
			Subject:    &commonv1.SubjectRef{Scheme: "k8s", Id: "ns/app"},
			Evidence:   []*evidencev1.EvidenceRef{nil, {Uri: "evidence://1", Digest: "sha256:1234"}},
			ObservedAt: timestamppb.Now(),
		},
	}); err != nil {
		t.Fatalf("expected SubmitObservation with nil evidence element to survive cleanly, got: %v", err)
	}

	if _, err := client.EvaluateSubject(ctx, &servicesv1.EvaluateSubjectRequest{
		Subject:  &commonv1.SubjectRef{Scheme: "k8s", Id: "ns/app"},
		Controls: []*controlv1.ControlRef{nil, {Namespace: "nist", Id: "AC-6"}},
	}); err != nil {
		t.Fatalf("expected EvaluateSubject with nil control element to survive cleanly, got: %v", err)
	}
}
