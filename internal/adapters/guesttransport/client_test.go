package guesttransport

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/guest"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
)

func TestClientRequiresActualPorts(t *testing.T) {
	if client, err := NewClient(ClientConfig{}); err == nil || client != nil {
		t.Fatal("client accepted absent attestation and sampling dependencies")
	}
}

// This exercises the real DSSE encoder and elapsed-slot framing only. The
// declared schedule is not a quote or an assertion of verified telemetry.
func TestSignedHeartbeatPreservesMissedSlotsAndSampleTime(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signedrecords.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(-time.Second)
	run := clientSession{owner: &Client{signer: signer, config: ClientConfig{Enrollment: guest.Enrollment{SourceInstance: "framing-conformance", Policy: assurance.TelemetryPolicy{HeartbeatInterval: time.Second}}}}, session: assurance.ComputeStringDigest("framing-conformance"), standing: &assurance.TelemetryAttestation{StartedAt: start}}
	sample := guest.Sample{SourceInstance: "framing-conformance", SampledAt: start.Add(5 * time.Millisecond), Counters: []assurance.TelemetryLossCounter{{ID: "unavailable-counter", Status: assurance.TelemetrySignalUnknown, Reason: "framing test has no runtime collector"}}}
	first, err := run.heartbeat(t.Context(), sample, start.Add(10*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	sample.SampledAt = start.Add(3100 * time.Millisecond)
	second, err := run.heartbeat(t.Context(), sample, start.Add(3200*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := signedrecords.Verify(t.Context(), second.GetSignedHeartbeat(), guest.HeartbeatPayloadType, public, guest.MaxRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	var record guest.Record
	if err := signedrecords.DecodeJSON(payload, &record, guest.MaxRecordBytes); err != nil {
		t.Fatal(err)
	}
	if record.Sequence != 2 || record.Slot != 3 || record.PreviousDigest != assurance.ComputeDigest(first.GetSignedHeartbeat()) || !record.SampledAt.Equal(sample.SampledAt) || record.Counters[0].Status != assurance.TelemetrySignalUnknown {
		t.Fatalf("missed tick or actual UNKNOWN sample was rewritten: %+v", record)
	}
	if len(run.records[0].record.Counters) != 0 || len(run.records[1].record.Observations) != 0 {
		t.Fatal("receipt pending metadata retained raw observation batches")
	}
	t.Log("actual DSSE signature verifies sequence 2, elapsed slot 3, exact previous digest and original UNKNOWN sample")
}

func TestSampleBoundsBeforeEncoding(t *testing.T) {
	if err := sampleBounds(guest.Sample{Observations: []guest.Observation{{Payload: make([]byte, (32<<10)+1)}}}); err == nil {
		t.Fatal("oversized observation accepted")
	}
	if err := sampleBounds(guest.Sample{Observations: make([]guest.Observation, guest.MaxEventsPerRecord+1)}); err == nil {
		t.Fatal("oversized batch accepted")
	}
}

func TestClientStatusExpiresHistoricalPositive(t *testing.T) {
	client := Client{status: ClientStatus{State: assurance.AssuranceStateVerified, ValidUntil: time.Now().Add(-time.Millisecond), SignedReceipt: []byte("opaque historical bytes, not used to create standing")}}
	status := client.Status()
	if status.State != assurance.AssuranceStateUnknown {
		t.Fatal("expired local status remained positive")
	}
	status.SignedReceipt[0] = 'X'
	if client.status.SignedReceipt[0] == 'X' {
		t.Fatal("status exposed mutable receipt storage")
	}
}
