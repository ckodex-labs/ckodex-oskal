package service_test

import (
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/ckodex-labs/ckodex-oskal/internal/service"
	commonv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/control/v1"
	receiptv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/receipt/v1"
	servicesv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/services/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestActualTLSReceiptRejectsContradictoryEvaluatorDomain(t *testing.T) {
	authority := assurance.AuthorityRef{Scheme: "spiffe", Subject: "receipt.test/ns/observer/sa/signer", TrustDomain: "receipt.test"}
	manager, err := receipts.NewReceiptManager(authority)
	must(t, err)
	signed, err := manager.SignReceipt(t.Context(), assurance.ControlReceipt{Subject: assurance.SubjectRef{Scheme: "file", ID: "declared-material"}, Control: assurance.ControlRef{Namespace: "example", ID: "record"}, State: assurance.AssuranceStateUnknown, EvaluatedAt: time.Now().UTC()})
	must(t, err)
	client, _ := serveTLS(t, service.NewServer(manager))
	wire := &receiptv1.ControlReceipt{Subject: &commonv1.SubjectRef{Scheme: signed.Subject.Scheme, Id: signed.Subject.ID}, Control: &controlv1.ControlRef{Namespace: signed.Control.Namespace, Id: signed.Control.ID}, State: commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN, Epoch: &commonv1.AssuranceEpoch{}, EvidenceRoot: signed.EvidenceRoot, Evaluator: &commonv1.AuthorityRef{Scheme: authority.Scheme, Subject: authority.Subject, TrustDomain: authority.TrustDomain}, EvaluatedAt: timestamppb.New(signed.EvaluatedAt), Signature: signed.Signature}
	accepted, err := client.SubmitReceipt(t.Context(), &servicesv1.SubmitReceiptRequest{Receipt: wire})
	must(t, err)
	if !accepted.Verified {
		t.Fatal(accepted.Message)
	}
	changed := proto.Clone(wire).(*receiptv1.ControlReceipt)
	changed.Evaluator.TrustDomain = "contradictory.test"
	rejected, err := client.SubmitReceipt(t.Context(), &servicesv1.SubmitReceiptRequest{Receipt: changed})
	if err == nil && rejected.Verified {
		t.Fatal("actual TLS service verified a TrustDomain-only mutation")
	}
	if err != nil && status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unexpected rejection: %v", err)
	}
	accepted, err = client.SubmitReceipt(t.Context(), &servicesv1.SubmitReceiptRequest{Receipt: wire})
	must(t, err)
	if !accepted.Verified {
		t.Fatal("unchanged receipt no longer verifies")
	}
	state, err := client.GetAssuranceState(t.Context(), &servicesv1.GetAssuranceStateRequest{Subject: wire.Subject})
	must(t, err)
	if state.State != commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN {
		t.Fatal("historical receipt acquired current standing")
	}
}
