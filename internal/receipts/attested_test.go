package receipts

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
)

// These fixtures are signed assessment claims for protocol/conformance tests.
// They are not TPM quotes or evidence that a runtime source was verified.
func attestedFixture(t *testing.T) (*ReceiptManager, assurance.ControlReceipt, assurance.TelemetryEvidence, time.Time) {
	t.Helper()
	m, err := NewReceiptManager(assurance.AuthorityRef{Scheme: "local", Subject: "attested-artifact-test"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	d := assurance.ComputeStringDigest("protocol conformance fixture")
	a := assurance.TelemetryAttestation{SessionID: d, SourceInstance: "fixture-source", MeasurementDigest: d, ExportKeyDigest: d, ChannelDigest: d, RootKind: "SOFTWARE_TPM", RootLabel: "software TPM root \u2014 not hardware-backed", Caveats: []string{"Fixture claim only; quote, source and policy were not verified by this test."}, StartedAt: now.Add(-time.Minute), VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	telemetry := assurance.TelemetryEvidence{Attestation: &a, Integrity: assurance.TelemetryIntegrity{State: assurance.AssuranceStateVerified, RootKind: a.RootKind, RootLabel: a.RootLabel, Caveats: append([]string(nil), a.Caveats...), SessionID: d, WindowStart: now.Add(-2 * time.Second), WindowEnd: now.Add(-time.Second), ValidUntil: a.ExpiresAt}, RecordDigest: d, QuoteDigest: d}
	r := assurance.ControlReceipt{Subject: assurance.SubjectRef{Scheme: "k8s", ID: "fixture/Pod/subject", Attributes: map[string]string{"uid": "enrolled-fixture-uid"}}, Control: assurance.ControlRef{Namespace: "ckodex", ID: "fixture-only"}, State: assurance.AssuranceStateVerified, Epoch: assurance.AssuranceEpoch{SubjectDigest: d, ImplementationDigest: d, PolicyDigest: d, AuthorityDigest: d, EnvironmentDigest: d}, EvidenceRoot: d, Evaluator: m.evaluator, EvaluatedAt: now}
	return m, r, telemetry, now
}

func pinnedAttestedKey(t *testing.T, m *ReceiptManager) ed25519.PublicKey {
	t.Helper()
	key, err := hex.DecodeString(m.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.PublicKey(key)
}

func TestAttestedReceiptFullBodySignatureAndHistoricalExpiry(t *testing.T) {
	m, receipt, telemetry, now := attestedFixture(t)
	raw, err := m.SignAttestedReceipt(t.Context(), receipt, telemetry)
	if err != nil {
		t.Fatal(err)
	}
	key := pinnedAttestedKey(t, m)
	result, err := VerifyAttestedReceipt(t.Context(), raw, key, &m.evaluator, now)
	if err != nil || result.SignatureStatus != "VERIFIED" || result.EffectiveState != assurance.AssuranceStateVerified || result.Body.Receipt.Signature != "" || !strings.Contains(result.Scope, "not independently reverified") {
		t.Fatalf("full-body verification: %+v %v", result, err)
	}
	later, err := VerifyAttestedReceipt(t.Context(), raw, key, nil, telemetry.Integrity.ValidUntil)
	if err != nil || later.SignedState != assurance.AssuranceStateVerified || later.Body.Receipt.State != assurance.AssuranceStateVerified || later.EffectiveState != assurance.AssuranceStateUnknown {
		t.Fatalf("expiry rewrote history or became a malformed artifact: %+v %v", later, err)
	}
	for name, mutate := range map[string]func(*AttestedControlReceipt){
		"root":        func(b *AttestedControlReceipt) { b.Telemetry.Integrity.RootKind = "HARDWARE_TPM" },
		"caveat":      func(b *AttestedControlReceipt) { b.Telemetry.Integrity.Caveats[0] = "hardware assurance" },
		"subject UID": func(b *AttestedControlReceipt) { b.Receipt.Subject.Attributes["uid"] = "other-pod" },
		"loss": func(b *AttestedControlReceipt) {
			b.Telemetry.Integrity.Loss = []assurance.TelemetryLoss{{Signal: "actual-signal", Delta: 1}}
		},
		"gap": func(b *AttestedControlReceipt) {
			b.Telemetry.Integrity.Gaps = []assurance.TelemetryGap{{Kind: "SEQUENCE", First: 2, Last: 9}}
		},
		"quote digest": func(b *AttestedControlReceipt) {
			b.Telemetry.QuoteDigest = assurance.ComputeStringDigest("other quote")
		},
	} {
		t.Run(name, func(t *testing.T) {
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(raw, &envelope); err != nil {
				t.Fatal(err)
			}
			var encoded string
			if err := json.Unmarshal(envelope["payload"], &encoded); err != nil {
				t.Fatal(err)
			}
			payload, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			var body AttestedControlReceipt
			if err := json.Unmarshal(payload, &body); err != nil {
				t.Fatal(err)
			}
			mutate(&body)
			payload, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			envelope["payload"], err = json.Marshal(base64.StdEncoding.EncodeToString(payload))
			if err != nil {
				t.Fatal(err)
			}
			tampered, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyAttestedReceipt(t.Context(), tampered, key, nil, now); err == nil {
				t.Fatal("full-body mutation survived the original real signature")
			}
		})
	}
}

func TestAttestedUnknownPreservesLossAndGapAndRejectsUpgrades(t *testing.T) {
	m, receipt, telemetry, now := attestedFixture(t)
	receipt.State, receipt.EvidenceRoot = assurance.AssuranceStateUnknown, ""
	telemetry.Integrity.State = assurance.AssuranceStateUnknown
	telemetry.Integrity.Loss = []assurance.TelemetryLoss{{Signal: "tetragon_observer_ringbuf_events_lost_total", Delta: 7}}
	telemetry.Integrity.Gaps = []assurance.TelemetryGap{{Kind: "HEARTBEAT", First: 10, Last: 14}}
	telemetry.Integrity.Reasons = []string{"observed loss and missing heartbeat slots"}
	telemetry.Integrity.Recovery = assurance.TelemetryFreshSessionRequired
	raw, err := m.SignAttestedReceipt(t.Context(), receipt, telemetry)
	if err != nil {
		t.Fatal(err)
	}
	result, err := VerifyAttestedReceipt(t.Context(), raw, pinnedAttestedKey(t, m), nil, now)
	if err != nil || result.EffectiveState != assurance.AssuranceStateUnknown || result.Body.Telemetry.Integrity.Loss[0].Delta != 7 || result.Body.Telemetry.Integrity.Gaps[0].Last != 14 {
		t.Fatalf("UNKNOWN facts lost: %+v %v", result, err)
	}
	// The application's startup can be UNKNOWN without inventing an attestation.
	telemetry.Attestation = nil
	telemetry.Integrity.SessionID = ""
	telemetry.RecordDigest, telemetry.QuoteDigest = "", ""
	if _, err := m.SignAttestedReceipt(t.Context(), receipt, telemetry); err != nil {
		t.Fatal(err)
	}
	receipt.State = assurance.AssuranceStateVerified
	if _, err := m.SignAttestedReceipt(t.Context(), receipt, telemetry); err == nil {
		t.Fatal("UNKNOWN integrity acquired positive standing")
	}
	receipt.State = assurance.AssuranceStateUnknown
	legacy, err := m.SignReceipt(t.Context(), receipt)
	if err != nil {
		t.Fatal(err)
	}
	legacyJSON, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAttestedReceipt(t.Context(), legacyJSON, pinnedAttestedKey(t, m), nil, now); err == nil {
		t.Fatal("legacy tuple signature was upgraded to v2 semantics")
	}
	if _, err := m.SignAttestedReceipt(t.Context(), legacy, telemetry); err == nil {
		t.Fatal("legacy signature embedded into a new attested body")
	}
}

func TestValidDSSESignatureCannotBypassReceiptSemantics(t *testing.T) {
	m, receipt, telemetry, now := attestedFixture(t)
	signer, err := signedrecords.NewSigner(m.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*AttestedControlReceipt){
		"missing attestation": func(b *AttestedControlReceipt) { b.Telemetry.Attestation = nil },
		"missing evidence":    func(b *AttestedControlReceipt) { b.Receipt.EvidenceRoot = "" },
		"empty evidence set":  func(b *AttestedControlReceipt) { b.Receipt.EvidenceRoot = assurance.ComputeDigest(nil) },
		"loss": func(b *AttestedControlReceipt) {
			b.Telemetry.Integrity.Loss = []assurance.TelemetryLoss{{Signal: "signal", Delta: 1}}
		},
		"future window":         func(b *AttestedControlReceipt) { b.Telemetry.Integrity.WindowEnd = now.Add(time.Second) },
		"expired at assessment": func(b *AttestedControlReceipt) { b.Telemetry.Integrity.ValidUntil = now },
		"legacy version":        func(b *AttestedControlReceipt) { b.Version = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			body := AttestedControlReceipt{Version: 2, Receipt: receipt, Telemetry: telemetry}
			mutate(&body)
			payload, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := signer.Sign(t.Context(), AttestedReceiptPayloadType, payload)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyAttestedReceipt(t.Context(), raw, pinnedAttestedKey(t, m), nil, now); err == nil {
				t.Fatal("real signature bypassed positive-state invariant")
			}
		})
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := m.SignAttestedReceipt(t.Context(), receipt, telemetry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAttestedReceipt(t.Context(), raw, public, nil, now); err == nil {
		t.Fatal("untrusted key accepted")
	}
	other := assurance.AuthorityRef{Scheme: "local", Subject: "other-authority"}
	if _, err := VerifyAttestedReceipt(t.Context(), raw, pinnedAttestedKey(t, m), &other, now); err == nil {
		t.Fatal("different expected identity claim accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := VerifyAttestedReceipt(ctx, raw, pinnedAttestedKey(t, m), nil, now); err == nil {
		t.Fatal("canceled verification continued")
	}
}
