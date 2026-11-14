package guesttransport

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/guest"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

func TestServerRequiresRealDependencies(t *testing.T) {
	if server, err := NewServer(ServerConfig{}); err == nil || server != nil {
		t.Fatal("unconfigured server acquired authority")
	}
	if MaxFrameBytes > 2<<20 {
		t.Fatal("whole RPC bound exceeds intended signed-record capacity")
	}
}

func TestActualTCPConnectionLimitBeforeTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bounded := newConnectionListener(listener, 1)
	defer func() { _ = bounded.Close() }()
	client1, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client1.Close() }()
	server1, err := bounded.Accept()
	if err != nil {
		t.Fatal(err)
	}
	client2, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client2.Close() }()
	accepted := make(chan net.Conn, 1)
	failed := make(chan error, 1)
	go func() {
		connection, err := bounded.Accept()
		if err != nil {
			failed <- err
			return
		}
		accepted <- connection
	}()
	select {
	case connection := <-accepted:
		_ = connection.Close()
		t.Fatal("second pre-TLS connection exceeded capacity")
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := server1.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case connection := <-accepted:
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("released connection slot did not admit waiting socket")
	}
	t.Log("real TCP sockets obey the connection bound before any TLS handshake")
}

// These are cryptographic binding tests, not invented quote verification. The
// supplied outcome is explicitly UNKNOWN with no admitted attestation/backend.
func TestActualSignedReceiptPublicationBinding(t *testing.T) {
	authority := assurance.AuthorityRef{Scheme: "local", Subject: "transport-binding-test"}
	signer, err := receipts.NewReceiptManager(authority)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	scope := ReceiptScope{Key: ed25519.PublicKey(key), Authority: authority, Subject: assurance.SubjectRef{Scheme: "file", ID: "declared-binding-test"}, Control: assurance.ControlRef{Namespace: "example", ID: "transport-binding"}}
	observed := time.Now().UTC().Add(-time.Second)
	integrity := assurance.TelemetryIntegrity{State: assurance.AssuranceStateUnknown, SessionID: assurance.ComputeStringDigest("test session context"), RootKind: "SOFTWARE_TPM", RootLabel: "software TPM root — not hardware-backed", Caveats: []string{"cryptographic binding fixture; no quote was admitted"}, Reasons: []string{"no attestation"}}
	publication := guest.Publication{EnrollmentID: "test", SessionGeneration: 1, SessionID: integrity.SessionID, ObservedAt: observed, Integrity: integrity}
	create := func(at time.Time, telemetry assurance.TelemetryEvidence, subject assurance.SubjectRef) []byte {
		t.Helper()
		raw, err := signer.SignAttestedReceipt(t.Context(), assurance.ControlReceipt{Subject: subject, Control: scope.Control, State: assurance.AssuranceStateUnknown, EvaluatedAt: at}, telemetry, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	evidence := assurance.TelemetryEvidence{Integrity: integrity}
	raw := create(observed, evidence, scope.Subject)
	if _, err := verifyPublicationReceipt(t.Context(), raw, publication, scope, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*guest.Publication){"session": func(p *guest.Publication) { p.SessionID = assurance.ComputeStringDigest("different session") }, "record": func(p *guest.Publication) { p.RecordDigest = assurance.ComputeStringDigest("different record") }, "quote": func(p *guest.Publication) { p.QuoteDigest = assurance.ComputeStringDigest("different quote") }, "observed-time": func(p *guest.Publication) { p.ObservedAt = observed.Add(time.Nanosecond) }} {
		t.Run(name, func(t *testing.T) {
			changed := publication
			change(&changed)
			if _, err := verifyPublicationReceipt(t.Context(), raw, changed, scope, time.Now().UTC()); err == nil {
				t.Fatal("unrelated signed receipt acknowledged")
			}
		})
	}
	other := scope.Subject
	other.Attributes = map[string]string{"uid": "unrelated"}
	if _, err := verifyPublicationReceipt(t.Context(), create(observed, evidence, other), publication, scope, time.Now().UTC()); err == nil {
		t.Fatal("receipt subject context changed")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := verifyPublicationReceipt(canceled, raw, publication, scope, time.Now().UTC()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
