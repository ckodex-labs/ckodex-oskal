package tetragonsampler

import (
	"slices"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragonhealth"
)

// Pure transition conformance, not a TPM or TLS admission test. The context
// explicitly declares its lack of attestation; only counter/window semantics
// are under test here.
func windowContext(start time.Time, source string, signals []string) (assurance.TelemetryPolicy, assurance.TelemetryAttestation) {
	digest := assurance.ComputeStringDigest("unattested normalization transition context")
	return assurance.TelemetryPolicy{HeartbeatInterval: time.Second, Tolerance: 500 * time.Millisecond, MaxSampleAge: 3 * time.Second, MaxAttestationAge: 10 * time.Second, RequiredSignals: signals}, assurance.TelemetryAttestation{SessionID: digest, SourceInstance: source, MeasurementDigest: digest, ExportKeyDigest: digest, ChannelDigest: digest, RootKind: "UNATTESTED_NATIVE_TEST_CONTEXT", RootLabel: "domain transition input only; no authenticated channel, quote or control standing", Caveats: []string{"only the pure window function is exercised; no admission authority is established"}, StartedAt: start, VerifiedAt: start, ExpiresAt: start.Add(10 * time.Second)}
}

func TestHistoricalCountVersusWindowLoss(t *testing.T) {
	start := time.Now().UTC()
	id := "metrics.tetragon_event_cache_fetch_failures_total"
	policy, attestation := windowContext(start, "pure-transition", []string{id})
	before := assurance.TelemetryHeartbeat{SessionID: attestation.SessionID, SourceInstance: attestation.SourceInstance, Sequence: 1, SampledAt: start, ReceivedAt: start, Digest: assurance.ComputeStringDigest("first schema record"), Counters: []assurance.TelemetryLossCounter{measured(id, 8649)}}
	baseline, err := assurance.EvaluateTelemetryWindow(policy, attestation, nil, before, start)
	if err != nil || baseline.State != assurance.AssuranceStateUnknown {
		t.Fatalf("initial baseline: %+v %v", baseline, err)
	}
	after := before
	after.Sequence = 2
	after.Slot = 1
	after.PreviousDigest = before.Digest
	after.Digest = assurance.ComputeStringDigest("second schema record")
	after.SampledAt = start.Add(time.Second)
	after.ReceivedAt = after.SampledAt
	unchanged, err := assurance.EvaluateTelemetryWindow(policy, attestation, &before, after, after.ReceivedAt)
	if err != nil || unchanged.State != assurance.AssuranceStateVerified {
		t.Fatalf("unchanged historical total was misclassified as new loss: %+v %v", unchanged, err)
	}
	after.Counters = []assurance.TelemetryLossCounter{measured(id, 8650)}
	increased, err := assurance.EvaluateTelemetryWindow(policy, attestation, &before, after, after.ReceivedAt)
	if err != nil || increased.State != assurance.AssuranceStateUnknown || len(increased.Loss) != 1 || increased.Loss[0].Delta != 1 {
		t.Fatalf("actual window increment escaped UNKNOWN: %+v %v", increased, err)
	}
}

func TestRawSeriesResetCannotHideBehindRisingSum(t *testing.T) {
	sample := tetragonhealth.MetricsSample{Families: []tetragonhealth.Family{{Name: "tetragon_event_cache_fetch_failures_total", Kind: tetragonhealth.Counter, Availability: tetragonhealth.Observed, Series: []tetragonhealth.Series{{Labels: []tetragonhealth.Label{{Name: "entry_type", Value: "process_info"}, {Name: "event_type", Value: "PROCESS_EXEC"}}, Value: 5}, {Labels: []tetragonhealth.Label{{Name: "entry_type", Value: "pod_info"}, {Name: "event_type", Value: "PROCESS_EXEC"}}, Value: 5}}}}}
	before, err := metricSeries(sample)
	if err != nil {
		t.Fatal(err)
	}
	sample.Families[0].Series[0].Value = 4
	sample.Families[0].Series[1].Value = 9
	after, err := metricSeries(sample)
	if err != nil {
		t.Fatal(err)
	}
	if err := compareSeries(before, after); err == nil {
		t.Fatal("sum increased10->13 while one raw counter reset5->4")
	}
	sample.Families[0].Series[0].Value = 6
	after, err = metricSeries(sample)
	if err != nil || compareSeries(before, after) != nil {
		t.Fatal("valid per-series increments rejected", err)
	}
	slices.Reverse(sample.Families[0].Series[0].Labels)
	reordered, err := metricSeries(sample)
	if err != nil || compareSeries(after, reordered) != nil {
		t.Fatal("label order changed canonical identity", err)
	}
	sample.Families[0].Series[0].Labels[0].Value = "PROCESS_EXIT"
	replacement, err := metricSeries(sample)
	if err != nil {
		t.Fatal(err)
	}
	if err := compareSeries(after, replacement); err == nil {
		t.Fatal("same-size label manifest replacement accepted")
	}
	sample.Families[0].Series = sample.Families[0].Series[:1]
	removed, err := metricSeries(sample)
	if err != nil {
		t.Fatal(err)
	}
	if err := compareSeries(after, removed); err == nil {
		t.Fatal("series disappearance accepted")
	}
}
