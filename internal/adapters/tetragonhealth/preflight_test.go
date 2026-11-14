package tetragonhealth

import (
	"testing"
	"time"
)

// These are pure configuration transition checks, not a substituted backend or
// a claim that any endpoint is reachable. Real HTTP tests exercise that boundary.
func TestMetricsReaderPreflight(t *testing.T) {
	valid := MetricsReader{Endpoint: "http://127.0.0.1:2112/metrics", Timeout: time.Second, Limits: DefaultLimits()}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"http://localhost:2112/metrics", "http://192.0.2.1:2112/metrics", "https://127.0.0.1:2112/metrics", "http://user@127.0.0.1:2112/metrics", "http://127.0.0.1:2112/metrics?x=1", "http://127.0.0.1:2112/other"} {
		r := valid
		r.Endpoint = endpoint
		if err := r.Validate(); err == nil {
			t.Errorf("preflight admitted %q", endpoint)
		}
	}
	for _, timeout := range []time.Duration{0, 5*time.Second + time.Nanosecond} {
		r := valid
		r.Timeout = timeout
		if err := r.Validate(); err == nil {
			t.Errorf("preflight admitted timeout %s", timeout)
		}
	}
	r := valid
	r.Limits.Bytes++
	if err := r.Validate(); err == nil {
		t.Fatal("preflight admitted an increased response budget")
	}
}
