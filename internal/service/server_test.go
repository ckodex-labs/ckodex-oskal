package service_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/ckodex-labs/ckodex-oskal/internal/service"
	"github.com/ckodex-labs/ckodex-oskal/pkg/oskal"
	commonv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/common/v1"
	controlv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/control/v1"
	evidencev1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/evidence/v1"
	receiptv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/receipt/v1"
	servicesv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/services/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Actual loopback TCP, TLS 1.3 and client-certificate verification. Certificate
// identity is this isolated test authority, never a claimed SPIFFE SVID.
func serveTLS(t *testing.T, server *service.Server) (servicesv1.AssuranceServiceClient, oskal.Client) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	must(t, err)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	parsed, err := x509.ParseCertificate(der)
	must(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool})))
	servicesv1.RegisterAssuranceServiceServer(grpcServer, server)
	go func() {
		if err := grpcServer.Serve(listener); err != nil && err != grpc.ErrServerStopped {
			t.Error(err)
		}
	}()
	t.Cleanup(func() { grpcServer.Stop(); _ = listener.Close() })
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}, ServerName: "127.0.0.1"}
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(config)))
	must(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	sdk, err := oskal.NewClient(t.Context(), listener.Addr().String(), oskal.WithDialOptions(grpc.WithTransportCredentials(credentials.NewTLS(config.Clone()))))
	must(t, err)
	t.Cleanup(func() { _ = sdk.Close() })
	// The same endpoint rejects a TLS peer lacking its client certificate.
	denied, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "127.0.0.1"})))
	must(t, err)
	deniedCtx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	_, err = servicesv1.NewAssuranceServiceClient(denied).GetAssuranceState(deniedCtx, &servicesv1.GetAssuranceStateRequest{Subject: &commonv1.SubjectRef{Scheme: "k8s", Id: "ns/Pod/test"}})
	cancel()
	_ = denied.Close()
	if err == nil {
		t.Fatal("client without certificate accepted")
	}
	return servicesv1.NewAssuranceServiceClient(conn), sdk
}

func TestUnconfiguredServiceNeverPromotesMetadata(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	archive, err := storage.NewFilesystemEvidenceRepository(t.TempDir())
	must(t, err)
	signer, err := receipts.NewReceiptManager(assurance.AuthorityRef{Scheme: "local", Subject: "test-receipt-authority"})
	must(t, err)
	server := service.NewServer(signer, archive)
	client, sdk := serveTLS(t, server)
	subject := &commonv1.SubjectRef{Scheme: "k8s", Id: "ns/Pod/observed", Attributes: map[string]string{"uid": "reported-only"}}
	control := &controlv1.ControlRef{Namespace: "nist-sp-800-53", Id: "SC-28", Version: "v5"}
	for _, kind := range []string{"admission", "violation", "opa.decision.allow"} {
		response, err := client.SubmitObservation(ctx, &servicesv1.SubmitObservationRequest{Observation: &evidencev1.Observation{Id: kind, Subject: subject, Type: kind, ObservedAt: timestamppb.Now(), Observer: &commonv1.AuthorityRef{Scheme: "spiffe", Subject: "unverified.example/collector"}, Evidence: []*evidencev1.EvidenceRef{{Uri: "opaque://spiffe/cilium/sigstore/claims", Digest: assurance.ComputeStringDigest("opaque-reference"), MediaType: "application/json"}}}})
		must(t, err)
		if !response.Accepted || !strings.Contains(response.Message, "unverified") {
			t.Fatal("submission misstates authority")
		}
	}
	archived, err := archive.ListAll(ctx)
	must(t, err)
	if len(archived) != 0 {
		t.Fatal("reference metadata was converted into evidence")
	}
	response, err := client.EvaluateSubject(ctx, &servicesv1.EvaluateSubjectRequest{Subject: subject, Controls: []*controlv1.ControlRef{control}})
	must(t, err)
	e := response.Evaluations[0]
	if response.SummaryState != commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN || e.Epoch != nil || e.EvaluatedAt != nil || e.ValidUntil != nil || e.EvidenceRoot != "" || len(e.Trace) == 0 {
		t.Fatalf("fabricated evaluation: %v", response)
	}
	explained, err := client.ExplainClaim(ctx, &servicesv1.ExplainClaimRequest{Subject: subject, Control: control})
	must(t, err)
	if explained.CanonicalControl != "nist-sp-800-53:SC-28@v5" {
		t.Fatalf("control changed: %s", explained.CanonicalControl)
	}
	if len(explained.AtomicRequirements) != 0 || len(explained.Implementations) != 0 || len(explained.Evidence) != 0 || explained.Applicability != "unknown" || strings.Contains(explained.RenderedText, "[PASS]") {
		t.Fatalf("fabricated explanation: %v", explained)
	}
	sdkState, err := sdk.GetAssuranceState(ctx, assurance.SubjectRef{Scheme: subject.Scheme, ID: subject.Id, Attributes: subject.Attributes})
	must(t, err)
	if sdkState.State != assurance.AssuranceStateUnknown || !sdkState.LastEvaluated.IsZero() || sdkState.Epoch != nil || sdkState.Subject.Attributes["uid"] != "reported-only" {
		t.Fatalf("SDK changed unknown metadata: %+v", sdkState)
	}
	for _, invalid := range []*evidencev1.Observation{{}, {Id: "future", Subject: subject, Type: "admission", ObservedAt: timestamppb.New(time.Now().Add(time.Hour))}, {Id: "nil-ref", Subject: subject, Type: "admission", ObservedAt: timestamppb.Now(), Evidence: []*evidencev1.EvidenceRef{nil}}} {
		_, err := client.SubmitObservation(ctx, &servicesv1.SubmitObservationRequest{Observation: invalid})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("malformed observation got %v", err)
		}
	}
	receipt, err := signer.SignReceipt(ctx, assurance.ControlReceipt{Subject: assurance.SubjectRef{Scheme: subject.Scheme, ID: subject.Id, Attributes: subject.Attributes}, Control: assurance.ControlRef{Namespace: control.Namespace, ID: control.Id, Version: control.Version}, State: assurance.AssuranceStateUnknown, EvaluatedAt: time.Now().UTC()})
	must(t, err)
	wire := &receiptv1.ControlReceipt{Subject: subject, Control: control, State: commonv1.AssuranceState_ASSURANCE_STATE_UNKNOWN, Epoch: &commonv1.AssuranceEpoch{}, Evaluator: &commonv1.AuthorityRef{Scheme: receipt.Evaluator.Scheme, Subject: receipt.Evaluator.Subject}, EvaluatedAt: timestamppb.New(receipt.EvaluatedAt), Signature: receipt.Signature}
	accepted, err := client.SubmitReceipt(ctx, &servicesv1.SubmitReceiptRequest{Receipt: wire})
	must(t, err)
	if !accepted.Verified {
		t.Fatal(accepted.Message)
	}
	tampered := proto.Clone(wire).(*receiptv1.ControlReceipt)
	tampered.EvidenceRoot = "tampered"
	rejected, err := client.SubmitReceipt(ctx, &servicesv1.SubmitReceiptRequest{Receipt: tampered})
	must(t, err)
	if rejected.Verified {
		t.Fatal("tampered receipt accepted")
	}
	_, err = service.NewServer(nil).SubmitReceipt(ctx, &servicesv1.SubmitReceiptRequest{Receipt: wire})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("nil authority fallback: %v", err)
	}
}
