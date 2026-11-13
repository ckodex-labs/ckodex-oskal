package main

import (
	"fmt"
	"net"
	"sync"

	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
)

func (g *sourceGroup) setCaptureTransport(id, state string) {
	g.captureHealthMu.Lock()
	defer g.captureHealthMu.Unlock()
	if g.captureHealth == nil {
		g.captureHealth = make(map[string]string)
	}
	g.captureHealth[id] = state
}

func (g *sourceGroup) captureTransport(id string) string {
	g.captureHealthMu.RLock()
	defer g.captureHealthMu.RUnlock()
	state := g.captureHealth[id]
	if state == "" {
		return "UNAVAILABLE"
	}
	return state
}

func (g *sourceGroup) captureReady() error {
	if g.captureCandidates == nil {
		return fmt.Errorf("no bound runtime or operational capture sources configured; configure a source before routing traffic")
	}
	sources := g.captureCandidates.Snapshot()
	if len(sources) == 0 {
		return fmt.Errorf("no bound runtime or operational capture sources configured; configure a source before routing traffic")
	}
	for _, source := range sources {
		if source.Lifecycle == collection.SourceSafeHold {
			return fmt.Errorf("capture source %s: SAFE_HOLD: %s", source.ID, source.Reason)
		}
		transport := g.captureTransport(source.ID)
		if transport != "LISTENING" && transport != "POLLING" {
			return fmt.Errorf("capture source %s: transport unavailable; inspect source status and configuration", source.ID)
		}
	}
	return nil
}

// Serving begins only when http.Server has completed its TLS setup and reached
// Accept. This avoids exposing readiness between net.Listen and ServeTLS failure.
type servingPolicyListener struct {
	net.Listener
	once  sync.Once
	ready func()
}

func (l *servingPolicyListener) Accept() (net.Conn, error) {
	l.once.Do(l.ready)
	return l.Listener.Accept()
}
