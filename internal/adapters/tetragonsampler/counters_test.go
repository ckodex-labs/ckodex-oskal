package tetragonsampler

import (
	"slices"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragonhealth"
)

// These deterministic normalization vectors are not evidence of runtime zeros.
func normalizationWitness() tetragonhealth.KernelWitness {
	w := tetragonhealth.KernelWitness{Availability: tetragonhealth.Observed, Throttle: tetragonhealth.ThrottleObservation{Availability: tetragonhealth.Observed}}
	for op := range 256 {
		for _, failure := range bpfErrors {
			w.Loss = append(w.Loss, tetragonhealth.KernelLoss{Opcode: uint8(op), Error: failure})
		}
	}
	for _, name := range mapNames {
		w.Maps = append(w.Maps, tetragonhealth.MapObservation{MapEnrollment: tetragonhealth.MapEnrollment{Name: name, MaxEntries: 10}, Stats: &tetragonhealth.MapStats{}})
	}
	return w
}
func TestNormalizationPreservesUnknownAndNativeCellIdentities(t *testing.T) {
	w := normalizationWitness()
	metric := tetragonhealth.MetricsSample{Families: []tetragonhealth.Family{{Name: "tetragon_cgroup_rate_total", Kind: tetragonhealth.Counter, Availability: tetragonhealth.Observed, Series: []tetragonhealth.Series{{Labels: []tetragonhealth.Label{{Name: "type", Value: "delete"}}, Value: 42}, {Labels: []tetragonhealth.Label{{Name: "type", Value: "throttle_start"}}, Value: 0}}}}}
	values, err := counters(metric, w, 0)
	if err != nil {
		t.Fatal(err)
	}
	ids := RequiredSignals()
	if len(ids) > assurance.MaxTelemetrySignals || len(values) != len(ids) {
		t.Fatal("counter profile exceeds kernel bounds")
	}
	for i, v := range values {
		if v.ID != ids[i] {
			t.Fatalf("counter identity mismatch %s", v.ID)
		}
	}
	find := func(id string) assurance.TelemetryLossCounter {
		t.Helper()
		for _, v := range values {
			if v.ID == id {
				return v
			}
		}
		t.Fatal(id)
		return assurance.TelemetryLossCounter{}
	}
	if find("native.bpf.000.unknown").Status != assurance.TelemetrySignalObserved {
		t.Fatal("actual successful witness cell was erased")
	}
	if find("metrics.tetragon_missed_prog_probes_total").Status != assurance.TelemetrySignalUnknown {
		t.Fatal("absent optional probe became zero")
	}
	if find("metrics.tetragon_cgroup_rate_total.type=throttle_start").Status != assurance.TelemetrySignalObserved {
		t.Fatal("normal deletes were misclassified as throttle loss")
	}
	w.Loss[0].Value = 1
	w.Throttle.ActiveCgroups = []uint64{123}
	w.Maps[0].Stats.Entries = 10
	values, err = counters(metric, w, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"native.throttle.active", "native.map.execve_map.capacity"} {
		if find(id).Status != assurance.TelemetrySignalUnknown {
			t.Fatalf("adverse %s became complete visibility", id)
		}
	}
	if find("native.bpf.000.unknown").Status != assurance.TelemetrySignalObserved || find("native.bpf.000.unknown").Value != 1 || find("stream.throttle.events").Value != 1 {
		t.Fatal("observed cumulative values were erased instead of compared over a window")
	}
	w.Loss = append(w.Loss[:1791], w.Loss[0])
	if _, err := counters(metric, w, 0); err == nil {
		t.Fatal("duplicate native cell accepted")
	}
	if !slices.IsSorted(ids) {
		t.Fatal("unstable required signal order")
	}
}

func TestEventRequestKeepsPodlessThrottleWithoutAggregation(t *testing.T) {
	request := eventRequest("enrolled")
	if request.AggregationOptions != nil || len(request.AllowList) != 2 || len(request.AllowList[1].Namespace) != 0 {
		t.Fatal("throttle filter or no-aggregation contract changed")
	}
}
