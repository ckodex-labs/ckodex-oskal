package oskal_test

import (
	"context"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/pkg/oskal"
)

func TestTutorialInProcessSDKIntegration(t *testing.T) {
	ctx := context.Background()

	evaluatorAuth := oskal.AuthorityRef{
		Scheme:  "spiffe",
		Subject: "ckodex.internal/ns/system/sa/test-runner",
	}
	receiptMgr, err := oskal.NewReceiptManager(evaluatorAuth)
	if err != nil {
		t.Fatalf("failed to create receipt manager: %v", err)
	}

	client := oskal.NewInProcessClient(oskal.WithReceiptManager(receiptMgr))
	defer func() { _ = client.Close() }()

	subject := oskal.SubjectRef{
		Scheme: "k8s",
		ID:     "production/Deployment/auth-gateway",
	}

	obs, err := oskal.NewObservation("obs-001", "kubernetes.admission", subject).
		WithProducer(evaluatorAuth).
		WithEvidenceRef("k8s://admission/review", oskal.ComputeStringDigest("admission-payload-001"), "application/json").
		Build()
	if err != nil {
		t.Fatalf("failed to build observation: %v", err)
	}

	if _, err := client.SubmitObservation(ctx, obs); err != nil {
		t.Fatalf("evidence ingestion failed: %v", err)
	}

	state, err := client.GetAssuranceState(ctx, subject)
	if err != nil {
		t.Fatalf("failed to query assurance state: %v", err)
	}

	if state.State != oskal.StateAssured {
		t.Fatalf("expected state ASSURED, got %v", state.State)
	}

	epoch := oskal.AssuranceEpoch{
		SubjectDigest:        oskal.ComputeStringDigest(subject.URI()),
		ImplementationDigest: oskal.ComputeStringDigest("kubernetes:workload-specification"),
		PolicyDigest:         oskal.ComputeStringDigest("policy:nist-ac6"),
		AuthorityDigest:      oskal.ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
		EnvironmentDigest:    oskal.ComputeStringDigest("cluster:local"),
	}

	ctrl := oskal.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
	receipt, err := receiptMgr.IssueReceipt(
		subject,
		ctrl,
		oskal.StateAssured,
		epoch,
		[]assurance.EvidenceRef{
			{URI: "k8s://admission/review", Digest: oskal.ComputeStringDigest("admission-payload-001"), MediaType: "application/json"},
		},
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("failed to issue receipt: %v", err)
	}

	if !receiptMgr.VerifyReceipt(receipt) {
		t.Fatalf("receipt verification failed")
	}
}
