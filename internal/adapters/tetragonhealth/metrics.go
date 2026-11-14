package tetragonhealth

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type familySchema struct {
	name   string
	kind   Kind
	labels string
}

// Names and upstream TYPEs are pinned to v1.8.0, not inferred from suffixes.
var schemas = []familySchema{
	{"tetragon_observer_ringbuf_events_lost_total", Counter, ""},
	{"tetragon_observer_ringbuf_queue_events_lost_total", Counter, ""},
	{"tetragon_observer_ringbuf_errors_total", Counter, ""},
	{"tetragon_observer_ringbuf_events_received_total", Counter, ""},
	{"tetragon_observer_ringbuf_queue_events_received_total", Counter, ""},
	{"tetragon_notify_overflowed_events_total", Counter, ""},
	{"tetragon_bpf_missed_events_total", Counter, "opcode,opstr,error"},
	{"tetragon_events_total", Counter, "event_type,namespace,workload,pod,binary,node_name"},
	{"tetragon_map_entries", Gauge, "map"},
	{"tetragon_map_capacity", Gauge, "map"},
	{"tetragon_map_errors_update_total", Gauge, "map"},
	{"tetragon_map_errors_delete_total", Gauge, "map"},
	{"tetragon_cgroup_rate_total", Counter, "type"},
	{"tetragon_missed_link_probes_total", Counter, "policy,attach"},
	{"tetragon_missed_prog_probes_total", Counter, "policy,attach"},
	{"tetragon_field_filter_failed_total", Counter, ""},
	{"tetragon_events_missing_process_info_total", Counter, ""},
	{"tetragon_event_cache_fetch_failures_total", Counter, "entry_type,event_type"},
	{"tetragon_handler_errors_total", Counter, "opcode,opstr,error"},
	{"tetragon_events_export_failed_total", Counter, ""},
	{"tetragon_export_ratelimit_events_dropped_total", Counter, ""},
	{"tetragon_events_exported_total", Counter, ""},
}

var decimal = regexp.MustCompile(`^[+]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]{1,3})?$`)

func digest(raw []byte) string {
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

func validateLimits(l Limits) error {
	max := DefaultLimits()
	if l.Bytes < 1 || l.Bytes > max.Bytes || l.Lines < 1 || l.Lines > max.Lines || l.LineBytes < 1 || l.LineBytes > max.LineBytes || l.Series < 1 || l.Series > max.Series || l.FamilySeries < 1 || l.FamilySeries > max.FamilySeries {
		return fmt.Errorf("metrics limits must be positive and within DefaultLimits")
	}
	return nil
}

// ParseMetrics accepts bounded Prometheus text 0.0.4. Integer scientific
// notation is parsed exactly; NaN, fractions, negatives and uint64 overflow fail.
// Parse errors invalidate the whole sample; callers must not use partial facts.
func ParseMetrics(r io.Reader, limits Limits) (MetricsSample, error) {
	var out MetricsSample
	if r == nil {
		return out, fmt.Errorf("metrics reader is required")
	}
	if err := validateLimits(limits); err != nil {
		return out, err
	}
	raw, err := io.ReadAll(io.LimitReader(r, limits.Bytes+1))
	if err != nil {
		return out, fmt.Errorf("read metrics: %w", err)
	}
	out = MetricsSample{Contract: ContractVersion, RawDigest: digest(raw), Bytes: len(raw)}
	if int64(len(raw)) > limits.Bytes {
		return out, fmt.Errorf("metrics body exceeds byte bound")
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return out, fmt.Errorf("empty or unterminated metrics body")
	}
	indices := make(map[string]int, len(schemas))
	for i, schema := range schemas {
		indices[schema.name] = i
		out.Families = append(out.Families, Family{Name: schema.name, Kind: schema.kind, Availability: Unknown, Reason: "metric family absent; zero is not established"})
	}
	types := make(map[string]Kind, len(schemas))
	seen := make(map[string]struct{})
	s := bufio.NewScanner(bytes.NewReader(raw))
	s.Buffer(make([]byte, min(limits.LineBytes, 4096)), limits.LineBytes)
	lines, samples := 0, 0
	for s.Scan() {
		lines++
		if lines > limits.Lines {
			return out, fmt.Errorf("metrics line bound exceeded")
		}
		line := s.Text()
		if strings.HasPrefix(line, "# TYPE ") {
			parts := strings.Fields(line)
			if len(parts) != 4 {
				return out, fmt.Errorf("malformed metrics TYPE at line %d", lines)
			}
			if i, ok := indices[parts[2]]; ok {
				if _, exists := types[parts[2]]; exists || Kind(parts[3]) != schemas[i].kind {
					return out, fmt.Errorf("duplicate or incompatible TYPE for %s", parts[2])
				}
				types[parts[2]] = Kind(parts[3])
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		samples++
		if samples > limits.Series {
			return out, fmt.Errorf("metrics total series bound exceeded")
		}
		end := strings.IndexAny(line, " {\t")
		if end < 1 {
			return out, fmt.Errorf("malformed metric sample at line %d", lines)
		}
		name := line[:end]
		i, ok := indices[name]
		if !ok {
			continue
		}
		if types[name] != schemas[i].kind {
			return out, fmt.Errorf("sample without matching preceding TYPE for %s", name)
		}
		series, err := parseSeries(line[len(name):], schemas[i])
		if err != nil {
			return out, fmt.Errorf("parse %s: %w", name, err)
		}
		key := name + labelKey(series.Labels)
		if _, exists := seen[key]; exists {
			return out, fmt.Errorf("duplicate series for %s", name)
		}
		seen[key] = struct{}{}
		f := &out.Families[i]
		if len(f.Series) >= limits.FamilySeries {
			return out, fmt.Errorf("family series bound exceeded for %s", name)
		}
		f.Series = append(f.Series, series)
		if len(f.Series) == 1 {
			f.Availability, f.Reason = Observed, ""
		}
		// Upstream exposes float64 values. Above 2^53, an apparently integral
		// sample cannot establish unit-accurate counter changes.
		if series.Value > 1<<53 {
			f.Availability, f.Reason = Unknown, "Prometheus value exceeds exact consecutive integer precision"
		}
	}
	if err := s.Err(); err != nil {
		return out, fmt.Errorf("scan bounded metrics lines: %w", err)
	}
	for i := range out.Families {
		sort.Slice(out.Families[i].Series, func(a, b int) bool {
			return labelKey(out.Families[i].Series[a].Labels) < labelKey(out.Families[i].Series[b].Labels)
		})
	}
	return out, nil
}

func parseSeries(rest string, schema familySchema) (Series, error) {
	var out Series
	if strings.HasPrefix(rest, "{") {
		var err error
		out.Labels, rest, err = parseLabels(rest[1:], schema.labels)
		if err != nil {
			return out, err
		}
	}
	if err := validateLabels(out.Labels, schema); err != nil {
		return out, err
	}
	if len(rest) == 0 || (rest[0] != ' ' && rest[0] != '\t') {
		return out, fmt.Errorf("sample separator missing")
	}
	fields := strings.Fields(rest)
	if len(fields) != 1 {
		return out, fmt.Errorf("exactly one untimestamped value is required")
	}
	value := fields[0]
	if len(value) > 48 || !decimal.MatchString(value) {
		return out, fmt.Errorf("value is not a bounded nonnegative decimal")
	}
	n, ok := new(big.Rat).SetString(value)
	if !ok || !n.IsInt() || !n.Num().IsUint64() {
		return out, fmt.Errorf("value is not an exact uint64")
	}
	out.Value = n.Num().Uint64()
	return out, nil
}

func validateLabels(labels []Label, schema familySchema) error {
	required := schema.labels
	if schema.name == "tetragon_events_total" {
		required = "event_type"
	}
	for _, name := range strings.Split(required, ",") {
		if name == "" {
			continue
		}
		present := false
		for _, label := range labels {
			if label.Name == name {
				present = true
			}
		}
		if !present {
			return fmt.Errorf("required label %s is absent", name)
		}
	}
	for _, label := range labels {
		if label.Name == "map" && label.Value != "execve_map" && label.Value != "tg_execve_joined_info_map" {
			return fmt.Errorf("unknown monitored map")
		}
		if schema.name == "tetragon_cgroup_rate_total" && !strings.Contains(",throttle_start,throttle_stop,lookup_fail,update_fail,delete_fail,check,process,delete,", ","+label.Value+",") {
			return fmt.Errorf("unknown cgroup rate counter type")
		}
	}
	return nil
}

func parseLabels(rest, allowed string) ([]Label, string, error) {
	var labels []Label
	seen := map[string]bool{}
	for {
		if len(rest) == 0 {
			return nil, "", fmt.Errorf("unterminated labels")
		}
		if rest[0] == '}' {
			sort.Slice(labels, func(i, j int) bool { return labels[i].Name < labels[j].Name })
			return labels, rest[1:], nil
		}
		eq := strings.IndexByte(rest, '=')
		if eq < 1 || eq > 64 {
			return nil, "", fmt.Errorf("invalid label name")
		}
		name := rest[:eq]
		if !strings.Contains(","+allowed+",", ","+name+",") || seen[name] || len(labels) >= 8 {
			return nil, "", fmt.Errorf("unknown, duplicate or excessive label")
		}
		seen[name] = true
		rest = rest[eq+1:]
		if len(rest) == 0 || rest[0] != '"' {
			return nil, "", fmt.Errorf("label value must be quoted")
		}
		end := 1
		for end < len(rest) && rest[end] != '"' {
			if rest[end] == '\\' {
				end++
				if end >= len(rest) || !strings.ContainsRune("\\\"n", rune(rest[end])) {
					return nil, "", fmt.Errorf("invalid Prometheus label escape")
				}
			}
			end++
		}
		if end >= len(rest) || end > 1024 {
			return nil, "", fmt.Errorf("unterminated or excessive label value")
		}
		value, err := strconv.Unquote(rest[:end+1])
		if err != nil {
			return nil, "", fmt.Errorf("decode label: %w", err)
		}
		labels = append(labels, Label{Name: name, Value: value})
		rest = rest[end+1:]
		if len(rest) == 0 || (rest[0] != ',' && rest[0] != '}') {
			return nil, "", fmt.Errorf("invalid label separator")
		}
		if rest[0] == ',' {
			rest = rest[1:]
			if strings.HasPrefix(rest, "}") {
				return nil, "", fmt.Errorf("trailing label comma")
			}
		}
	}
}

func labelKey(labels []Label) string {
	var b strings.Builder
	for _, label := range labels {
		b.WriteString(strconv.Quote(label.Name))
		b.WriteString(strconv.Quote(label.Value))
	}
	return b.String()
}
