//go:build integration

package tpm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	assuranceapi "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/guestarchive"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/guesttransport"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragon"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/guest"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
	telemetryv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/telemetry/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// This is a negative real dependency integration: quotes and TLS authenticate,
// but the actual Kubernetes TCP endpoint is unavailable. No API result or source
// measurement is substituted, so control standing must remain UNKNOWN.
func TestRealGuestStreamArchivesUnknownAndIndependentSilence(t *testing.T) {
	provider, verifier := realProvider(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unavailable := "http://" + closed.Addr().String()
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := assuranceapi.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kube, err := client.New(&rest.Config{Host: unavailable, Timeout: 250 * time.Millisecond}, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	authority := assurance.AuthorityRef{Scheme: "local", Subject: "real-guest-stream-recorder"}
	manager, err := receipts.NewReceiptManager(authority)
	if err != nil {
		t.Fatal(err)
	}
	public, err := hex.DecodeString(manager.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if retained := os.Getenv("OSKAL_TPM_EVIDENCE_DIR"); retained != "" {
		if err := os.MkdirAll(retained, 0700); err != nil {
			t.Fatal(err)
		}
		directory, err = os.MkdirTemp(retained, "guest-stream-archive-*")
		if err != nil {
			t.Fatal(err)
		}
	}
	archive, err := storage.NewFilesystemEvidenceRepository(directory)
	if err != nil {
		t.Fatal(err)
	}
	subject := assurance.SubjectRef{Scheme: "k8s", ID: "unavailable/Pod/declared-subject", Attributes: map[string]string{"uid": "outside-declared-uid-not-api-verified"}}
	control := assurance.ControlRef{Namespace: "test", ID: "actual-unavailable-control"}
	publisher, err := guestarchive.New(guestarchive.Config{EnrollmentID: "real-software-tpm", SourceID: "real-software-tpm", BindingNamespace: "unavailable", BindingName: "unavailable", Subject: subject, Control: control, Producer: authority, Archive: archive, Signer: manager, Resolver: binding.NewResolver(kube), Decoder: &tetragon.EventDecoder{Producer: authority, Namespace: "unavailable"}})
	if err != nil {
		t.Fatal(err)
	}
	facts := verifier.Environment()
	enrollment := guest.Enrollment{SourceInstance: "real-software-tpm", MeasurementDigest: facts.MeasurementDigest, PolicyDigest: assurance.ComputeStringDigest("negative real dependency test"), RootKind: facts.RootKind, RootLabel: facts.RootLabel, Caveats: []string{"actual software TPM; no hardware co-residence or sensor completeness proof"}, Policy: assurance.TelemetryPolicy{HeartbeatInterval: time.Second, Tolerance: time.Second, MaxSampleAge: 3 * time.Second, MaxAttestationAge: 8 * time.Second, RequiredSignals: []string{"unavailable.sensor"}}, ChallengeTTL: time.Second, ReattestInterval: 3 * time.Second}
	serverTLS, clientTLS := streamTLS(t)
	server, err := guesttransport.NewServer(guesttransport.ServerConfig{EnrollmentID: "real-software-tpm", Enrollment: enrollment, Verifier: verifier, Publisher: publisher, Receipt: guesttransport.ReceiptScope{Key: public, Authority: authority, Subject: subject, Control: control}, TLS: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, listener) }()
	defer func() {
		server.Stop()
		select {
		case err := <-served:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(6 * time.Second):
			t.Error("server did not drain durable shutdown")
		}
	}()
	connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)), grpc.WithDisableRetry())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	observer := &guesttransport.ClientBinding{}
	stream, err := telemetryv1.NewGuestTelemetryServiceClient(connection).Stream(ctx, grpc.PerRPCCredentials(observer))
	if err != nil {
		t.Fatal(err)
	}
	key, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&telemetryv1.StreamRequest{Payload: &telemetryv1.StreamRequest_Hello{Hello: &telemetryv1.Hello{EnrollmentId: "real-software-tpm", ExportPublicKey: key}}}); err != nil {
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	wire := response.GetChallenge()
	if wire == nil {
		t.Fatal("server did not issue actual challenge")
	}
	challenge := guest.Challenge{Version: wire.Version, SessionID: wire.SessionId, ID: wire.ChallengeId, Nonce: wire.Nonce, EnrollmentDigest: wire.EnrollmentDigest, IssuedAt: wire.IssuedAt.AsTime(), ExpiresAt: wire.ExpiresAt.AsTime()}
	channel, err := observer.Exporter()
	if err != nil {
		t.Fatal(err)
	}
	qualification, err := guest.Qualification(challenge, key, channel)
	if err != nil {
		t.Fatal(err)
	}
	report, err := provider.Attest(ctx, qualification)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signedrecords.NewSigner(private)
	if err != nil {
		t.Fatal(err)
	}
	proofBody, err := json.Marshal(guest.QuoteProof{Version: 1, SessionID: challenge.SessionID, ChallengeID: challenge.ID, ReportDigest: assurance.ComputeDigest(report)})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := signer.Sign(ctx, guest.QuoteProofPayloadType, proofBody)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&telemetryv1.StreamRequest{Payload: &telemetryv1.StreamRequest_Quote{Quote: &telemetryv1.QuoteResponse{ChallengeId: challenge.ID, AttestationReport: report, SignedExportKeyProof: proof}}}); err != nil {
		t.Fatal(err)
	}
	response, err = stream.Recv()
	if err != nil {
		t.Fatalf("real quote admission: %v status=%+v", err, server.Status())
	}
	if response.GetAdmission() == nil {
		t.Fatal("actual quote was not admitted")
	}
	response, err = stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	initialRaw := response.GetSignedReceipt()
	initial, err := receipts.VerifyAttestedReceipt(ctx, initialRaw, public, &authority, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if initial.EffectiveState != assurance.AssuranceStateUnknown || initial.Body.Telemetry.Attestation == nil || initial.Body.Telemetry.QuoteDigest != assurance.ComputeDigest(report) || !strings.Contains(strings.Join(initial.Body.Telemetry.Integrity.Reasons, " "), "connection refused") {
		t.Fatalf("actual unreachable API did not produce signed UNKNOWN with causal TCP failure: %+v", initial)
	}
	// Send nothing. Receipt must originate from the independent wall-clock
	// watchdog, not a client request, synthetic sample, or injected fault callback.
	response, err = stream.Recv()
	if err != nil {
		t.Fatalf("independent silence receipt: %v status=%+v", err, server.Status())
	}
	terminalRaw := response.GetSignedReceipt()
	terminal, err := receipts.VerifyAttestedReceipt(ctx, terminalRaw, public, &authority, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if terminal.EffectiveState != assurance.AssuranceStateUnknown || terminal.Body.Telemetry.Integrity.Recovery != assurance.TelemetryFreshSessionRequired || len(terminal.Body.Telemetry.Integrity.Gaps) == 0 {
		t.Fatalf("silence did not fence: %+v", terminal)
	}
	if _, err := stream.Recv(); err == nil {
		t.Fatal("fenced stream remained open")
	}
	reopened, err := storage.OpenFilesystemEvidenceRepository(directory)
	if err != nil {
		t.Fatal(err)
	}
	items, err := reopened.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundInitial, foundTerminal, foundReport := false, false, false
	for _, item := range items {
		blob, err := reopened.Get(ctx, item.Artifact)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(blob)
		closeErr := blob.Close()
		if err != nil || closeErr != nil {
			t.Fatal(err, closeErr)
		}
		foundInitial = foundInitial || bytes.Equal(raw, initialRaw)
		foundTerminal = foundTerminal || bytes.Equal(raw, terminalRaw)
		foundReport = foundReport || bytes.Equal(raw, report)
	}
	if !foundInitial || !foundTerminal || !foundReport {
		t.Fatalf("actual archive/reopen lost evidence: initial=%v terminal=%v report=%v", foundInitial, foundTerminal, foundReport)
	}
	if _, err := reopened.VerifyIntegrity(ctx); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("OSKAL_TPM_EVIDENCE_DIR") != "" {
		for name, raw := range map[string][]byte{"initial-receipt.dsse.json": initialRaw, "terminal-receipt.dsse.json": terminalRaw, "receipt-signing.pub": []byte(manager.PublicKey() + "\n")} {
			writePublicProof(t, filepath.Join(directory, name), raw)
		}
		t.Logf("retained public receipt proof: %s; pinned recorder key: %s", directory, manager.PublicKey())
	}
	t.Logf("real TLS1.3/exporter + swtpm quote + closed TCP API -> signed UNKNOWN; independent silence -> fenced UNKNOWN; reopened %d archive objects with exact original report and both receipts", len(items))
}

func writePublicProof(t *testing.T, path string, raw []byte) {
	t.Helper()
	file, err := os.CreateTemp(filepath.Dir(path), ".public-proof-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(file.Name(), path); err != nil {
		t.Fatal(err)
	}
}

func streamTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned stream integration CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, public, private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	issue := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		raw, err := x509.CreateCertificate(rand.Reader, leaf, parsed, pub, private)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{raw, der}, PrivateKey: key}
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{issue(2, x509.ExtKeyUsageServerAuth)}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: pool, Certificates: []tls.Certificate{issue(3, x509.ExtKeyUsageClientAuth)}}
}
