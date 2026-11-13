package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

type acceptedConnections struct {
	mu         sync.Mutex
	live       map[net.Conn]bool
	total, max int
	accepted   chan struct{}
	closed     chan struct{}
}

func newAcceptedConnections() *acceptedConnections {
	return &acceptedConnections{live: make(map[net.Conn]bool), accepted: make(chan struct{}, MaxWebhookConnections*4), closed: make(chan struct{}, MaxWebhookConnections*4)}
}
func (c *acceptedConnections) state(connection net.Conn, state http.ConnState) {
	c.mu.Lock()
	switch state {
	case http.StateNew:
		c.live[connection] = true
		c.total++
		if len(c.live) > c.max {
			c.max = len(c.live)
		}
	case http.StateClosed, http.StateHijacked:
		delete(c.live, connection)
	}
	c.mu.Unlock()
	if state == http.StateNew {
		c.accepted <- struct{}{}
	}
	if state == http.StateClosed {
		c.closed <- struct{}{}
	}
}
func (c *acceptedConnections) counts() (int, int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total, len(c.live), c.max
}

func nativeBoundedWebhook(t *testing.T) (string, *tls.Config, *acceptedConnections, func()) {
	t.Helper()
	certificate, key, err := GenerateSelfSignedCert("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	must(t, err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("test root missing")
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	address := probe.Addr().String()
	must(t, probe.Close())
	server := NewAdmissionWebhookServer(ServerConfig{ListenAddr: address, TLSCertBytes: certificate, TLSKeyBytes: key})
	server.server.ErrorLog = log.New(io.Discard, "", 0)
	counts := newAcceptedConnections()
	server.server.ConnState = counts.state
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Start(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("native Start: %v", err)
				}
			case <-time.After(6 * time.Second):
				_ = server.server.Close()
				t.Error("native context shutdown exceeded six-second test budget")
			}
		})
	}
	t.Cleanup(stop)
	return address, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost"}, counts, stop
}
func rawNativeConnection(t *testing.T, address string) net.Conn {
	t.Helper()
	var connection net.Conn
	var err error
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		connection, err = net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			t.Cleanup(func() { _ = connection.Close() })
			return connection
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("actual native listener unavailable: %v", err)
	return nil
}
func waitAccepted(t *testing.T, counts *acceptedConnections) {
	t.Helper()
	select {
	case <-counts.accepted:
	case <-time.After(time.Second):
		t.Fatal("actual native connection was not accepted")
	}
}

func TestNativeHostingBoundsBeforeTLSAndReleasesSlots(t *testing.T) {
	address, clientTLS, counts, _ := nativeBoundedWebhook(t)
	held := make([]net.Conn, 0, MaxWebhookConnections)
	for i := 0; i < MaxWebhookConnections; i++ {
		held = append(held, rawNativeConnection(t, address))
		waitAccepted(t, counts)
	}
	total, active, maximum := counts.counts()
	if total != MaxWebhookConnections || active != MaxWebhookConnections || maximum != MaxWebhookConnections {
		t.Fatalf("actual pre-TLS occupancy total=%d active=%d max=%d", total, active, maximum)
	}
	extra := rawNativeConnection(t, address)
	blockedTLS := tls.Client(extra, clientTLS.Clone())
	probeCtx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	err := blockedTLS.HandshakeContext(probeCtx)
	cancel()
	_ = blockedTLS.Close()
	var timeout net.Error
	blocked := errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout()
	if !blocked {
		t.Fatalf("extra real TLS handshake was not held by connection capacity: %v", err)
	}
	total, _, maximum = counts.counts()
	if total != MaxWebhookConnections || maximum > MaxWebhookConnections {
		t.Fatalf("stalled TLS clients bypassed native accept bound: accepted=%d max=%d", total, maximum)
	}
	must(t, held[0].Close())
	transport := &http.Transport{TLSClientConfig: clientTLS.Clone()}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get("https://" + address + "/healthz")
	must(t, err)
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16))
	must(t, err)
	if response.StatusCode != 200 || string(body) != "ok" || response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("released slot did not permit a real verified TLS1.3 request")
	}
	_, _, maximum = counts.counts()
	if maximum > MaxWebhookConnections {
		t.Fatalf("accepted concurrency exceeded bound after release: %d", maximum)
	}
	for _, connection := range held {
		_ = connection.Close()
	}
	t.Logf("VERIFIED %d stalled real pre-TLS connections filled native capacity; extra handshake held; release permitted verified-server TLS1.3 health request; max accepted=%d", MaxWebhookConnections, maximum)
}

func TestNativeShutdownUnblocksSaturatedAcceptAndStalledRequest(t *testing.T) {
	address, clientTLS, counts, stop := nativeBoundedWebhook(t)
	// One actual TLS request stalls mid-body while the remaining native slots
	// stall before TLS. No fake handler, sink, or backend is involved.
	secure := tls.Client(rawNativeConnection(t, address), clientTLS.Clone())
	handshake, cancel := context.WithTimeout(t.Context(), time.Second)
	err := secure.HandshakeContext(handshake)
	cancel()
	must(t, err)
	t.Cleanup(func() { _ = secure.Close() })
	waitAccepted(t, counts)
	_, err = io.WriteString(secure, "POST /validate HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
	must(t, err)
	held := make([]net.Conn, 0, MaxWebhookConnections-1)
	for i := 1; i < MaxWebhookConnections; i++ {
		held = append(held, rawNativeConnection(t, address))
		waitAccepted(t, counts)
	}
	pending := rawNativeConnection(t, address)
	start := time.Now()
	stop()
	if time.Since(start) > 6*time.Second {
		t.Fatal("native shutdown exceeded bounded drain")
	}
	for _, connection := range append(held, pending) {
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		_, err := connection.Read(make([]byte, 1))
		var timeout net.Error
		if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatalf("native stopped but real blocked connection remained open: %v", err)
		}
	}
	_ = secure.SetReadDeadline(time.Now().Add(time.Second))
	_, err = io.ReadAll(io.LimitReader(secure, 16<<10))
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatal("actual stalled HTTP request was not unblocked by shutdown")
	}
	total, _, maximum := counts.counts()
	if maximum > MaxWebhookConnections {
		t.Fatalf("shutdown accepted excess connections total=%d max=%d", total, maximum)
	}
	t.Logf("VERIFIED saturated native Accept and stalled TLS/body clients unblocked by context shutdown in %s; max accepted=%d", time.Since(start), maximum)
}
