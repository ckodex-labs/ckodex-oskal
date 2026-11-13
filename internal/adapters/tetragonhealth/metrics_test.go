package tetragonhealth

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// This real Prometheus registry and TCP server test exposition compatibility.
// Its instrument values are not presented as evidence of kernel sensor behavior.
func registryServer(t *testing.T) *httptest.Server {
	t.Helper()
	registry := prometheus.NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{Name: "tetragon_observer_ringbuf_events_received_total", Help: "Number of perf events Tetragon ring buffer received."})
	counter.Add(1234567)
	registry.MustRegister(counter)
	lost := prometheus.NewCounter(prometheus.CounterOpts{Name: "tetragon_observer_ringbuf_events_lost_total", Help: "Number of perf events Tetragon ring buffer lost."})
	registry.MustRegister(lost)
	entries := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "tetragon_map_entries", Help: "The total number of in-use entries per map."}, []string{"map"})
	entries.WithLabelValues("execve_map").Set(3)
	entries.WithLabelValues("tg_execve_joined_info_map").Set(0)
	registry.MustRegister(entries)
	mapErrors := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "tetragon_map_errors_update_total", Help: "The number of failed updates per map."}, []string{"map"})
	mapErrors.WithLabelValues("execve_map").Set(0)
	registry.MustRegister(mapErrors)
	events := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tetragon_events_total", Help: "The total number of Tetragon events"}, []string{"event_type", "namespace", "workload", "pod", "binary", "node_name"})
	events.WithLabelValues("PROCESS_EXEC", "demo", "worker", "pod", "/bin/with \"quote\"", "node").Inc()
	registry.MustRegister(events)
	server := httptest.NewServer(promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	t.Cleanup(server.Close)
	return server
}

func realExposition(t *testing.T) []byte {
	t.Helper()
	server := registryServer(t)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/plain; version=0.0.4")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read actual Prometheus response: %v %v", readErr, closeErr)
	}
	return raw
}

func family(t *testing.T, sample MetricsSample, name string) Family {
	t.Helper()
	for _, f := range sample.Families {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("missing fixed schema %s", name)
	return Family{}
}

func TestMetricsReaderActualPrometheusTCP(t *testing.T) {
	server := registryServer(t)
	reader := MetricsReader{Endpoint: server.URL + "/metrics", Timeout: time.Second, Limits: DefaultLimits()}
	sample, err := reader.Read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	received := family(t, sample, "tetragon_observer_ringbuf_events_received_total")
	if received.Availability != Observed || len(received.Series) != 1 || received.Series[0].Value != 1234567 || sample.RawDigest == "" || sample.CompletedAt.Before(sample.StartedAt) {
		t.Fatalf("actual exposition not preserved: %+v", sample)
	}
	loss := family(t, sample, "tetragon_observer_ringbuf_events_lost_total")
	if loss.Availability != Observed || loss.Series[0].Value != 0 {
		t.Fatalf("actual initialized counter zero missing: %+v", loss)
	}
	missed := family(t, sample, "tetragon_bpf_missed_events_total")
	if missed.Availability != Unknown || len(missed.Series) != 0 {
		t.Fatalf("sparse absent kernel family fabricated a zero: %+v", missed)
	}
	if got := family(t, sample, "tetragon_map_errors_update_total"); got.Kind != Gauge || got.Availability != Observed {
		t.Fatalf("upstream gauge type changed: %+v", got)
	}
}

func TestMetricExpositionBoundaries(t *testing.T) {
	raw := realExposition(t)
	needle := "tetragon_observer_ringbuf_events_received_total 1.234567e+06"
	if !bytes.Contains(raw, []byte(needle)) {
		t.Fatalf("test requires actual upstream scientific formatting; got %s", raw)
	}
	for _, value := range []string{"NaN", "+Inf", "-1", "0.1", "18446744073709551616", "1e999", "1/1", "0x10", "1 1700000000"} {
		t.Run(value, func(t *testing.T) {
			altered := bytes.Replace(raw, []byte(needle), []byte("tetragon_observer_ringbuf_events_received_total "+value), 1)
			if _, err := ParseMetrics(bytes.NewReader(altered), DefaultLimits()); err == nil {
				t.Fatal("invalid numeric or timestamp boundary accepted")
			}
		})
	}
	for value, expected := range map[string]uint64{"18446744073709551615": 18446744073709551615, "9007199254740993": 9007199254740993, "1.234567e+06": 1234567, "1.23e2": 123} {
		t.Run("exact-"+value, func(t *testing.T) {
			altered := bytes.Replace(raw, []byte(needle), []byte("tetragon_observer_ringbuf_events_received_total "+value), 1)
			sample, err := ParseMetrics(bytes.NewReader(altered), DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			f := family(t, sample, "tetragon_observer_ringbuf_events_received_total")
			if len(f.Series) != 1 || f.Series[0].Value != expected {
				t.Fatalf("integer lexeme was rounded: %+v", f)
			}
			if expected > 1<<53 && f.Availability != Unknown {
				t.Fatal("upstream float64 precision limit was ignored")
			}
		})
	}
	for name, altered := range map[string][]byte{
		"wrong upstream type":  bytes.Replace(raw, []byte("tetragon_map_errors_update_total gauge"), []byte("tetragon_map_errors_update_total counter"), 1),
		"duplicate sample":     append(bytes.Clone(raw), []byte(needle+"\n")...),
		"duplicate type":       append(bytes.Clone(raw), []byte("# TYPE tetragon_map_entries gauge\n")...),
		"incomplete transport": raw[:len(raw)-1],
		"unknown map":          bytes.Replace(raw, []byte("execve_map"), []byte("untracked_map"), 1),
		"missing map label":    bytes.ReplaceAll(raw, []byte("{map=\"execve_map\"}"), nil),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseMetrics(bytes.NewReader(altered), DefaultLimits()); err == nil {
				t.Fatal("invalid schema boundary accepted")
			}
		})
	}
	for _, limits := range []Limits{
		{Bytes: 32, Lines: 32768, LineBytes: 16384, Series: 16384, FamilySeries: 2048},
		{Bytes: 4194304, Lines: 1, LineBytes: 16384, Series: 16384, FamilySeries: 2048},
		{Bytes: 4194304, Lines: 32768, LineBytes: 16, Series: 16384, FamilySeries: 2048},
		{Bytes: 4194304, Lines: 32768, LineBytes: 16384, Series: 1, FamilySeries: 2048},
		{Bytes: 4194304, Lines: 32768, LineBytes: 16384, Series: 16384, FamilySeries: 1},
	} {
		if _, err := ParseMetrics(bytes.NewReader(raw), limits); err == nil {
			t.Fatalf("resource bound accepted: %+v", limits)
		}
	}
}

func TestMetricsReaderTransportBoundaries(t *testing.T) {
	for _, endpoint := range []string{"http://localhost:2112/metrics", "http://192.0.2.1:2112/metrics", "https://127.0.0.1:2112/metrics", "http://u:p@127.0.0.1:2112/metrics", "http://127.0.0.1:2112/metrics?x=y"} {
		if _, err := (MetricsReader{Endpoint: endpoint, Timeout: time.Second, Limits: DefaultLimits()}).Read(t.Context()); err == nil {
			t.Fatalf("unauthorized endpoint accepted: %s", endpoint)
		}
	}
	server := registryServer(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := (MetricsReader{Endpoint: server.URL + "/metrics", Timeout: time.Second, Limits: DefaultLimits()}).Read(ctx); err == nil {
		t.Fatal("canceled read succeeded")
	}
	if _, err := ParseMetrics(strings.NewReader(""), DefaultLimits()); err == nil {
		t.Fatal("empty metrics succeeded")
	}
}
