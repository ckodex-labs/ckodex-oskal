package tetragonsampler

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragonhealth"
)

// metricSeries tracks each underlying series used by an aggregated failure
// signal. Ordinary event/activity totals are retained as health evidence, but
// their changing workload-label sets are not the loss-counter manifest.
func metricSeries(sample tetragonhealth.MetricsSample) (map[string]uint64, error) {
	out := make(map[string]uint64)
	for _, family := range sample.Families {
		if !slices.Contains(metricSignals, family.Name) && family.Name != "tetragon_cgroup_rate_total" {
			continue
		}
		if family.Kind != tetragonhealth.Counter {
			return nil, fmt.Errorf("loss-family kind changed: %s", family.Name)
		}
		for _, series := range family.Series {
			if len(out) >= tetragonhealth.DefaultLimits().Series {
				return nil, fmt.Errorf("raw loss-series state exceeds cardinality bound")
			}
			labels := slices.Clone(series.Labels)
			slices.SortFunc(labels, func(a, b tetragonhealth.Label) int { return strings.Compare(a.Name, b.Name) })
			for i, label := range labels {
				if i > 0 && label.Name == labels[i-1].Name {
					return nil, fmt.Errorf("duplicate raw counter label")
				}
			}
			encoded, err := json.Marshal(struct {
				Name   string                 `json:"name"`
				Labels []tetragonhealth.Label `json:"labels"`
			}{family.Name, labels})
			if err != nil {
				return nil, err
			}
			key := assurance.ComputeDigest(encoded)
			if _, found := out[key]; found {
				return nil, fmt.Errorf("duplicate raw loss-series identity")
			}
			out[key] = series.Value
		}
	}
	return out, nil
}

func compareSeries(previous, current map[string]uint64) error {
	if previous == nil {
		return nil
	}
	if len(previous) != len(current) {
		return fmt.Errorf("raw loss-series manifest changed; establish a fresh source session")
	}
	for id, before := range previous {
		after, present := current[id]
		if !present {
			return fmt.Errorf("raw loss-series disappeared or was replaced: %s", id)
		}
		if after < before {
			return fmt.Errorf("raw loss-series counter reset: %s", id)
		}
	}
	return nil
}
