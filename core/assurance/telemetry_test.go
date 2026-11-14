package assurance

import (
	"encoding/json"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

// These are pure transition vectors over authenticated facts. Cryptographic,
// TPM, TLS, and native sensor proof belong to the real adapter/integration tests.
func telemetryVector() (TelemetryPolicy, TelemetryAttestation, TelemetryHeartbeat, TelemetryHeartbeat) {
	start := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	p := TelemetryPolicy{HeartbeatInterval: time.Second, Tolerance: 100 * time.Millisecond, MaxSampleAge: 2 * time.Second, MaxAttestationAge: time.Minute, RequiredSignals: []string{"bpf.missed", "observer.lost"}}
	a := TelemetryAttestation{SessionID: ComputeStringDigest("session"), SourceInstance: "pod-uid/boot-id/map-generation", MeasurementDigest: ComputeStringDigest("measurement"), ExportKeyDigest: ComputeStringDigest("key"), ChannelDigest: ComputeStringDigest("channel"), RootKind: "SOFTWARE_TPM", RootLabel: "software TPM root \u2014 not hardware-backed", Caveats: []string{"trusted host supervisor; no hardware isolation tested"}, StartedAt: start, VerifiedAt: start, ExpiresAt: start.Add(time.Minute)}
	h := TelemetryHeartbeat{SessionID: a.SessionID, SourceInstance: a.SourceInstance, Sequence: 1, Slot: 0, SampledAt: start, ReceivedAt: start, Digest: ComputeStringDigest("first authenticated record"), Counters: []TelemetryLossCounter{{ID: "bpf.missed", Status: TelemetrySignalObserved}, {ID: "observer.lost", Status: TelemetrySignalObserved}}}
	next := h
	next.Counters = slices.Clone(h.Counters)
	next.Sequence, next.Slot = 2, 1
	next.SampledAt, next.ReceivedAt = start.Add(time.Second), start.Add(time.Second)
	next.PreviousDigest, next.Digest = h.Digest, ComputeStringDigest("second authenticated record")
	return p, a, h, next
}

func TestTelemetryIntegrityTransitions(t *testing.T) {
	tests := []struct {
		name string
		edit func(*TelemetryPolicy, *TelemetryAttestation, *TelemetryHeartbeat, *TelemetryHeartbeat, *time.Time)
		want AssuranceState
		text string
	}{
		{name: "complete zero loss", want: AssuranceStateVerified},
		{name: "overlapping losses remain separate", edit: func(_ *TelemetryPolicy, _ *TelemetryAttestation, _, n *TelemetryHeartbeat, _ *time.Time) {
			n.Counters[0].Value = 2
			n.Counters[1].Value = 2
		}, want: AssuranceStateUnknown, text: "loss or throttling"},
		{name: "failed read is not zero", edit: func(_ *TelemetryPolicy, _ *TelemetryAttestation, _, n *TelemetryHeartbeat, _ *time.Time) {
			n.Counters[0].Status = TelemetrySignalUnknown
			n.Counters[0].Reason = "map lookup denied"
		}, want: AssuranceStateUnknown, text: "signal is UNKNOWN"},
		{name: "missing family", edit: func(_ *TelemetryPolicy, _ *TelemetryAttestation, _, n *TelemetryHeartbeat, _ *time.Time) {
			n.Counters = n.Counters[1:]
		}, want: AssuranceStateUnknown, text: "signal is UNKNOWN"},
		{name: "counter reset", edit: func(_ *TelemetryPolicy, _ *TelemetryAttestation, h, _ *TelemetryHeartbeat, _ *time.Time) {
			h.Counters[0].Value = 1
		}, want: AssuranceStateUnknown, text: "counter reset"},
		{name: "known historical count is not new loss", edit: func(_ *TelemetryPolicy, _ *TelemetryAttestation, h, n *TelemetryHeartbeat, _ *time.Time) {
			h.Counters[0].Value = 5
			n.Counters[0].Value = 5
		}, want: AssuranceStateVerified},
		{name: "sequence gap", edit: func(_ *TelemetryPolicy, _ *TelemetryAttestation, _, n *TelemetryHeartbeat, _ *time.Time) {
			n.Sequence = 4
		}, want: AssuranceStateUnknown, text: "sequence is discontinuous"},
		{name: "sequence replay", edit: func(_ *TelemetryPolicy, _ *TelemetryAttestation, _, n *TelemetryHeartbeat, _ *time.Time) {
			n.Sequence = 1
		}, want: AssuranceStateUnknown, text: "sequence is discontinuous"},
		{name: "sequence overflow", edit: func(_ *TelemetryPolicy, _ *TelemetryAttestation, h, n *TelemetryHeartbeat, _ *time.Time) {
			h.Sequence = math.MaxUint64
			n.Sequence = 1
		}, want: AssuranceStateUnknown, text: "sequence is discontinuous"},
		{name: "skipped scheduled heartbeat", edit: func(p *TelemetryPolicy, _ *TelemetryAttestation, _, n *TelemetryHeartbeat, now *time.Time) {
			n.Slot = 3
			n.SampledAt = n.SampledAt.Add(2 * p.HeartbeatInterval)
			n.ReceivedAt = n.SampledAt
			*now = n.ReceivedAt
		}, want: AssuranceStateUnknown, text: "slots are discontinuous"},
		{name: "same TLS session different producer", edit: func(_ *TelemetryPolicy, _ *TelemetryAttestation, _, n *TelemetryHeartbeat, _ *time.Time) {
			n.SourceInstance = "replacement"
		}, want: AssuranceStateUnknown, text: "source or session changed"},
		{name: "different verifier session", edit: func(_ *TelemetryPolicy, _ *TelemetryAttestation, _, n *TelemetryHeartbeat, _ *time.Time) {
			n.SessionID = ComputeStringDigest("old session")
		}, want: AssuranceStateUnknown, text: "source or session changed"},
		{name: "chain mismatch", edit: func(_ *TelemetryPolicy, _ *TelemetryAttestation, _, n *TelemetryHeartbeat, _ *time.Time) {
			n.PreviousDigest = ComputeStringDigest("other record")
		}, want: AssuranceStateUnknown, text: "record chain"},
		{name: "silence exact deadline", edit: func(p *TelemetryPolicy, _ *TelemetryAttestation, _, n *TelemetryHeartbeat, now *time.Time) {
			*now = n.SampledAt.Add(p.HeartbeatInterval + p.Tolerance)
		}, want: AssuranceStateUnknown, text: "deadline missed"},
		{name: "late just within tolerance", edit: func(p *TelemetryPolicy, _ *TelemetryAttestation, _, n *TelemetryHeartbeat, now *time.Time) {
			n.ReceivedAt = n.ReceivedAt.Add(p.Tolerance - time.Nanosecond)
			*now = n.ReceivedAt
		}, want: AssuranceStateVerified},
		{name: "late beyond tolerance", edit: func(p *TelemetryPolicy, _ *TelemetryAttestation, _, n *TelemetryHeartbeat, now *time.Time) {
			n.ReceivedAt = n.ReceivedAt.Add(p.Tolerance + time.Nanosecond)
			*now = n.ReceivedAt
		}, want: AssuranceStateUnknown, text: "scheduled tolerance"},
		{name: "sender cannot future date liveness", edit: func(p *TelemetryPolicy, _ *TelemetryAttestation, _, n *TelemetryHeartbeat, _ *time.Time) {
			n.SampledAt = n.SampledAt.Add(p.HeartbeatInterval)
		}, want: AssuranceStateUnknown, text: "scheduled tolerance"},
		{name: "attestation expiration", edit: func(_ *TelemetryPolicy, a *TelemetryAttestation, _, n *TelemetryHeartbeat, _ *time.Time) {
			a.ExpiresAt = n.ReceivedAt
		}, want: AssuranceStateUnknown, text: "attestation expired"},
		{name: "periodic attestation required", edit: func(p *TelemetryPolicy, a *TelemetryAttestation, h, n *TelemetryHeartbeat, now *time.Time) {
			h.Slot = 59
			h.SampledAt = a.StartedAt.Add(59 * time.Second)
			h.ReceivedAt = h.SampledAt
			n.Slot = 60
			n.SampledAt = a.StartedAt.Add(60 * time.Second)
			n.ReceivedAt = n.SampledAt
			a.ExpiresAt = a.ExpiresAt.Add(time.Hour)
			*now = n.ReceivedAt
			p.MaxSampleAge = 2 * time.Second
		}, want: AssuranceStateUnknown, text: "attestation expired"},
		{name: "far future slot bounded", edit: func(_ *TelemetryPolicy, _ *TelemetryAttestation, _, n *TelemetryHeartbeat, _ *time.Time) {
			n.Slot = math.MaxUint64
		}, want: AssuranceStateUnknown, text: "bounded session"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, a, h, n := telemetryVector()
			now := n.ReceivedAt
			if test.edit != nil {
				test.edit(&p, &a, &h, &n, &now)
			}
			result, err := EvaluateTelemetryWindow(p, a, &h, n, now)
			if err != nil || result.State != test.want || (test.text != "" && !strings.Contains(strings.Join(result.Reasons, ";"), test.text)) {
				t.Fatalf("result=%+v error=%v, want state=%s reason=%q", result, err, test.want, test.text)
			}
			if result.RootLabel != a.RootLabel || len(result.Caveats) != len(a.Caveats) {
				t.Fatal("root and caveats did not travel with result")
			}
			if len(result.Loss) > 0 && (len(result.Loss) != 2 || result.Loss[0].Delta != 2 || result.Loss[1].Delta != 2) {
				t.Fatal("overlapping family counts were aggregated or lost")
			}
		})
	}
}

func TestTelemetryBaselineGapAndRecovery(t *testing.T) {
	p, a, h, n := telemetryVector()
	baseline, err := EvaluateTelemetryWindow(p, a, nil, h, h.ReceivedAt)
	if err != nil || baseline.State != AssuranceStateUnknown {
		t.Fatalf("a baseline passed: %+v %v", baseline, err)
	}
	n.Sequence = 5
	gap, err := EvaluateTelemetryWindow(p, a, &h, n, n.ReceivedAt)
	if err != nil || !slices.Equal(gap.Gaps, []TelemetryGap{{Kind: "SEQUENCE", First: 2, Last: 4}}) {
		t.Fatalf("missing exact sequence range: %+v %v", gap, err)
	}
	raw, err := json.Marshal(gap)
	if err != nil || !strings.Contains(string(raw), `"first":2,"last":4`) || !strings.Contains(string(raw), "not hardware-backed") {
		t.Fatalf("artifact lost its gaps or root: %s %v", raw, err)
	}
	// A fresh session must establish its own baseline before becoming eligible.
	a.SessionID = ComputeStringDigest("fresh session")
	h.SessionID, n.SessionID, n.Sequence = a.SessionID, a.SessionID, 2
	r, err := EvaluateTelemetryWindow(p, a, &h, n, n.ReceivedAt)
	if err != nil || r.State != AssuranceStateVerified || gap.State != AssuranceStateUnknown {
		t.Fatalf("new complete session did not recover, or old gap was rewritten: %+v %v", r, err)
	}
}

func TestTelemetryRejectsInvalidContracts(t *testing.T) {
	tests := []struct {
		name string
		edit func(*TelemetryPolicy, *TelemetryAttestation, *TelemetryHeartbeat)
	}{
		{"no required loss signal", func(p *TelemetryPolicy, _ *TelemetryAttestation, _ *TelemetryHeartbeat) { p.RequiredSignals = nil }},
		{"duplicate required loss signal", func(p *TelemetryPolicy, _ *TelemetryAttestation, _ *TelemetryHeartbeat) {
			p.RequiredSignals = []string{"loss", "loss"}
		}},
		{"unbounded tolerance", func(p *TelemetryPolicy, _ *TelemetryAttestation, _ *TelemetryHeartbeat) {
			p.Tolerance = 2 * p.HeartbeatInterval
		}},
		{"unlabeled software TPM", func(_ *TelemetryPolicy, a *TelemetryAttestation, _ *TelemetryHeartbeat) {
			a.RootLabel = "hardware protected"
		}},
		{"no software caveat", func(_ *TelemetryPolicy, a *TelemetryAttestation, _ *TelemetryHeartbeat) { a.Caveats = nil }},
		{"empty channel identity", func(_ *TelemetryPolicy, a *TelemetryAttestation, _ *TelemetryHeartbeat) { a.ChannelDigest = "" }},
		{"missing signal status", func(_ *TelemetryPolicy, _ *TelemetryAttestation, h *TelemetryHeartbeat) { h.Counters[0].Status = "" }},
		{"duplicate signal", func(_ *TelemetryPolicy, _ *TelemetryAttestation, h *TelemetryHeartbeat) {
			h.Counters[1] = h.Counters[0]
		}},
		{"unknown without cause", func(_ *TelemetryPolicy, _ *TelemetryAttestation, h *TelemetryHeartbeat) {
			h.Counters[0].Status = TelemetrySignalUnknown
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, a, h, _ := telemetryVector()
			test.edit(&p, &a, &h)
			if result, err := EvaluateTelemetryWindow(p, a, nil, h, h.ReceivedAt); err == nil || result.State != AssuranceStateUnknown {
				t.Fatalf("invalid contract admitted: %+v %v", result, err)
			}
		})
	}
}
