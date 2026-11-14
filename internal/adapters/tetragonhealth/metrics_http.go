package tetragonhealth

import (
	"context"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

// MetricsReader is restricted to numeric loopback addresses in its own network
// namespace. Deployment must attest that namespace to the enrolled sensor.
// Local transport does not authenticate the metrics producer by itself.
type MetricsReader struct {
	Endpoint string
	Timeout  time.Duration
	Limits   Limits
}

func (r MetricsReader) Read(ctx context.Context) (out MetricsSample, err error) {
	out = MetricsSample{Contract: ContractVersion, StartedAt: time.Now().UTC()}
	defer func() { out.CompletedAt = time.Now().UTC() }()
	u, err := url.Parse(r.Endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/metrics" {
		return out, fmt.Errorf("metrics requires an exact loopback http /metrics endpoint")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.IsLoopback() || u.Port() == "" || r.Timeout <= 0 || r.Timeout > 5*time.Second {
		return out, fmt.Errorf("numeric loopback address, explicit port and timeout within five seconds required")
	}
	if err := validateLimits(r.Limits); err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: r.Timeout}).DialContext, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 16 << 10, ResponseHeaderTimeout: r.Timeout}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: r.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return out, fmt.Errorf("create metrics request: %w", err)
	}
	req.Header.Set("Accept", "text/plain; version=0.0.4")
	resp, err := client.Do(req)
	if err != nil {
		return out, fmt.Errorf("read local metrics: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close metrics response: %w", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" {
		return out, fmt.Errorf("metrics requires uncompressed HTTP 200, received %d", resp.StatusCode)
	}
	mediaType, parameters, mediaErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "text/plain" || parameters["version"] != "0.0.4" {
		return out, fmt.Errorf("metrics requires Prometheus text version 0.0.4")
	}
	parsed, err := ParseMetrics(resp.Body, r.Limits)
	parsed.StartedAt, parsed.CompletedAt = out.StartedAt, time.Now().UTC()
	return parsed, err
}
