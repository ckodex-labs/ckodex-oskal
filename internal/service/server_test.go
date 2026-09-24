package service

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ckodex-labs/oskal/core/assurance"
	"github.com/ckodex-labs/oskal/internal/receipts"
	commonv1 "github.com/ckodex-labs/oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/oskal/proto/assurance/control/v1"
	evidencev1 "github.com/ckodex-labs/oskal/proto/assurance/evidence/v1"
	receiptv1 "github.com/ckodex-labs/oskal/proto/assurance/receipt/v1"
	servicesv1 "github.com/ckodex-labs/oskal/proto/assurance/services/v1"
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

	// 1. Valid request
	resp, err := client.EvaluateSubject(ctx, &servicesv1.EvaluateSubjectRequest{
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
	if len(resp.Evaluations) != 2 {
		t.Fatalf("expected 2 evaluations, got %d", len(resp.Evaluations))
	}
	if resp.SummaryState != commonv1.AssuranceState_ASSURANCE_STATE_ASSURED {
		t.Fatalf("expected ASSURED summary state, got %v", resp.SummaryState)
	}

	// 2. Nil subject
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

	resp, err := client.ExplainClaim(ctx, &servicesv1.ExplainClaimRequest{
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
	if resp.CanonicalControl != "ckodex:least-privilege" {
		t.Fatalf("unexpected canonical control: %s", resp.CanonicalControl)
	}
	if resp.RenderedText == "" {
		t.Fatal("expected non-empty rendered explanation text")
	}

	// Nil request arguments
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

	resp, err := client.GetAssuranceState(ctx, &servicesv1.GetAssuranceStateRequest{
		Subject: &commonv1.SubjectRef{
			Scheme: "k8s",
			Id:     "payments/payments-api",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.State != commonv1.AssuranceState_ASSURANCE_STATE_ASSURED {
		t.Fatalf("expected state ASSURED, got %v", resp.State)
	}

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
		SubjectDigest:        "sha256:sub",
		ImplementationDigest: "sha256:imp",
		PolicyDigest:         "sha256:pol",
		AuthorityDigest:      "sha256:auth",
		EnvironmentDigest:    "sha256:env",
	}
	evs := []assurance.EvidenceRef{
		{Digest: "sha256:ev1"},
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
	tamperedReceipt := &receiptv1.ControlReceipt{}
	*tamperedReceipt = *protoReceipt
	tamperedReceipt.EvidenceRoot = "sha256:tampered"

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
