package guestarchive

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/internal/application/guest"
)

// This exercises actual queue cancellation, without a substituted archive,
// Kubernetes API, decoder, signer, or passing evaluation. Native publication is
// covered only by the separate real-cluster acceptance gate.
func TestExpiredQueuedPublicationCannotFenceNewerSource(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		p := &Publisher{gate: make(chan struct{}, 1), generation: 7, sessionID: "current", lastTime: started}
		p.gate <- struct{}{} // the actual serialization permit is occupied
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := p.Publish(ctx, guest.Publication{SessionGeneration: 8, SessionID: "late"})
			done <- err
		}()
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("queued expiry returned %v", err)
			}
		default:
			t.Fatal("expired publication remained blocked behind another operation")
		}
		if p.generation != 7 || p.sessionID != "current" || !p.lastTime.Equal(started) || p.hold != nil || p.fenced {
			t.Fatal("expired queued request changed the later source's state")
		}
		<-p.gate
	})
}
