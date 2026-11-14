package tetragonsampler

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragonhealth"
)

var bpfErrors = []string{"unknown", "ENOENT", "E2BIG", "EBUSY", "EINVAL", "ENOSPC", "EAGAIN"}
var throttleTypes = []string{"delete_fail", "lookup_fail", "throttle_start", "throttle_stop", "update_fail"}
var mapNames = []string{"execve_map", "tg_execve_joined_info_map"}

// These are separate upstream failure families, not a sum of uniquely lost
// events. Probe and JSON-exporter applicability is deliberately not inferred.
var metricSignals = []string{
	"tetragon_observer_ringbuf_events_lost_total", "tetragon_observer_ringbuf_queue_events_lost_total", "tetragon_observer_ringbuf_errors_total",
	"tetragon_notify_overflowed_events_total", "tetragon_missed_link_probes_total", "tetragon_missed_prog_probes_total",
	"tetragon_field_filter_failed_total", "tetragon_events_missing_process_info_total", "tetragon_event_cache_fetch_failures_total", "tetragon_handler_errors_total",
	"tetragon_events_export_failed_total", "tetragon_export_ratelimit_events_dropped_total",
}

func bpfID(op int, err string) string { return fmt.Sprintf("native.bpf.%03d.%s", op, err) }

// RequiredSignals returns the conservative complete profile. A narrower policy
// requires explicit outside justification; absent probes are not declared safe.
func RequiredSignals() []string {
	ids := make([]string, 0, 1820)
	for op := range 256 {
		for _, err := range bpfErrors {
			ids = append(ids, bpfID(op, err))
		}
	}
	for _, name := range mapNames {
		for _, kind := range []string{"update", "delete", "capacity"} {
			ids = append(ids, "native.map."+name+"."+kind)
		}
	}
	for _, name := range metricSignals {
		ids = append(ids, "metrics."+name)
	}
	for _, kind := range throttleTypes {
		ids = append(ids, "metrics.tetragon_cgroup_rate_total.type="+kind)
	}
	ids = append(ids, "native.throttle.active", "stream.throttle.events")
	slices.Sort(ids)
	return ids
}

func measured(id string, value uint64) assurance.TelemetryLossCounter {
	return assurance.TelemetryLossCounter{ID: id, Value: value, Status: assurance.TelemetrySignalObserved}
}

func unknown(id, reason string) assurance.TelemetryLossCounter {
	return assurance.TelemetryLossCounter{ID: id, Status: assurance.TelemetrySignalUnknown, Reason: reason}
}

func counters(metrics tetragonhealth.MetricsSample, witness tetragonhealth.KernelWitness, throttles uint64) ([]assurance.TelemetryLossCounter, error) {
	if witness.Availability != tetragonhealth.Observed || len(witness.Loss) != 256*7 {
		return nil, fmt.Errorf("complete successful native witness is required")
	}
	out := make([]assurance.TelemetryLossCounter, 0, 1820)
	seen := make(map[string]bool, 1792)
	for _, loss := range witness.Loss {
		id := bpfID(int(loss.Opcode), loss.Error)
		if !slices.Contains(bpfErrors, loss.Error) || seen[id] {
			return nil, fmt.Errorf("native BPF cell set changed")
		}
		seen[id] = true
		out = append(out, measured(id, loss.Value))
	}
	for _, name := range mapNames {
		found := false
		for _, observed := range witness.Maps {
			if observed.Name != name {
				continue
			}
			found = true
			if observed.Stats == nil {
				return nil, fmt.Errorf("native map statistics missing")
			}
			out = append(out, measured("native.map."+name+".update", observed.Stats.UpdateErrors), measured("native.map."+name+".delete", observed.Stats.DeleteErrors))
			signal := measured("native.map."+name+".capacity", 0)
			if observed.MaxEntries == 0 || observed.Stats.Entries >= uint64(observed.MaxEntries) {
				signal = unknown(signal.ID, "actual map occupancy is full or capacity unknown; occupancy is a gauge, not a cumulative loss counter")
			}
			out = append(out, signal)
		}
		if !found {
			return nil, fmt.Errorf("native map %s missing", name)
		}
	}
	active := measured("native.throttle.active", 0)
	if witness.Throttle.Availability != tetragonhealth.Observed || len(witness.Throttle.ActiveCgroups) > 0 {
		active = unknown(active.ID, "active throttle gauge is unavailable or reports throttled cgroups; no cumulative zero inferred")
	}
	out = append(out, active, measured("stream.throttle.events", throttles))
	for _, name := range metricSignals {
		signal := unknown("metrics."+name, "metric family absent; no zero inferred")
		for _, family := range metrics.Families {
			if family.Name != name {
				continue
			}
			if family.Availability != tetragonhealth.Observed || family.Kind != tetragonhealth.Counter || len(family.Series) == 0 {
				signal.Reason = "metric family unavailable: " + family.Reason
				break
			}
			var total uint64
			for _, series := range family.Series {
				if math.MaxUint64-total < series.Value {
					return nil, fmt.Errorf("metric family total overflow")
				}
				total += series.Value
			}
			signal = measured(signal.ID, total)
			break
		}
		out = append(out, signal)
	}
	for _, kind := range throttleTypes {
		id := "metrics.tetragon_cgroup_rate_total.type=" + kind
		value := unknown(id, "required throttle transition series absent")
		for _, family := range metrics.Families {
			if family.Name != "tetragon_cgroup_rate_total" || family.Availability != tetragonhealth.Observed || family.Kind != tetragonhealth.Counter {
				continue
			}
			for _, series := range family.Series {
				if len(series.Labels) == 1 && series.Labels[0].Name == "type" && series.Labels[0].Value == kind {
					value = measured(id, series.Value)
				}
			}
		}
		out = append(out, value)
	}
	slices.SortFunc(out, func(a, b assurance.TelemetryLossCounter) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}
