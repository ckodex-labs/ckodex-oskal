package webhook

import (
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// Go closes the real TCP connection and releases the listener token before it
// invokes StateClosed. Holding that later callback reproduces the hosted metric
// overlap without changing the listener or manufacturing a network response.
func TestConnStateNotificationsCanOverlapAfterTCPClosure(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var block, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var legacyMu sync.Mutex
	legacyLive := map[net.Conn]bool{}
	legacyMaximum := 0
	address, clientTLS, counts, _ := nativeBoundedWebhookWithStateHook(t, func(connection net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			block.Do(func() { close(entered); <-release })
		}
		legacyMu.Lock()
		switch state {
		case http.StateNew:
			legacyLive[connection] = true
			if len(legacyLive) > legacyMaximum {
				legacyMaximum = len(legacyLive)
			}
		case http.StateClosed, http.StateHijacked:
			delete(legacyLive, connection)
		}
		legacyMu.Unlock()
	})
	t.Cleanup(unblock)
	held := make([]net.Conn, 0, MaxWebhookConnections)
	for i := 0; i < MaxWebhookConnections; i++ {
		held = append(held, rawNativeConnection(t, address))
		waitAccepted(t, counts)
	}
	must(t, held[0].Close())
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("actual closed connection did not reach delayed state callback")
	}
	transport := &http.Transport{TLSClientConfig: clientTLS.Clone()}
	t.Cleanup(transport.CloseIdleConnections)
	response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get("https://" + address + "/healthz")
	must(t, err)
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	must(t, readErr)
	must(t, closeErr)
	if response.StatusCode != 200 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("real verified TLS request did not complete during delayed callback")
	}
	legacyMu.Lock()
	oldMaximum := legacyMaximum
	legacyMu.Unlock()
	if oldMaximum != MaxWebhookConnections+1 {
		t.Fatalf("controlled old notification metric did not reproduce hosted overlap: %d", oldMaximum)
	}
	total, active, maximum := counts.counts()
	if active != MaxWebhookConnections || maximum != MaxWebhookConnections {
		t.Fatalf("actual TCP observer confused delayed callback with open connection: total=%d active=%d max=%d", total, active, maximum)
	}

	unblock()
	for _, connection := range held {
		_ = connection.Close()
	}
	t.Logf("REPRODUCED delayed StateClosed notification metric=%d while real TCP max=%d; listener capacity unchanged", oldMaximum, maximum)
}
