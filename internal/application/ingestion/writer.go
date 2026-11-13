// Package ingestion binds observed runtime facts to authoritative subject epochs.
package ingestion

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

// MaxEventBytes bounds a single runtime fact before it enters evidence storage.
const MaxEventBytes = 4 << 20

// Writer persists runtime facts synchronously, providing backpressure to sources.
// The resolver must use the same epoch authority as the evaluating controller.
type Writer struct {
	Repository ports.EvidenceRepository
	Resolver   ports.CaptureResolver
	// MaxClockAhead permits an interruptible wait for bounded source clock skew.
	// Zero rejects all future timestamps. Timestamps are never rewritten.
	MaxClockAhead time.Duration
}

var _ ports.CapturedEventWriter = (*Writer)(nil)

// WriteCapturedEvent records an observed fact without promoting it to assurance.
// Missing metadata, resolver failure, and persistence failure produce no evidence.
func (w *Writer) WriteCapturedEvent(ctx context.Context, event ports.CapturedEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.Repository == nil || w.Resolver == nil {
		return fmt.Errorf("runtime evidence repository and capture resolver are required")
	}
	if err := event.Subject.Validate(); err != nil {
		return err
	}
	if err := event.Producer.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(event.Type) == "" || strings.TrimSpace(event.MediaType) == "" {
		return fmt.Errorf("runtime event type and media type are required")
	}
	if len(event.Payload) == 0 || len(event.Payload) > MaxEventBytes {
		return fmt.Errorf("runtime event payload must contain 1 to %d bytes", MaxEventBytes)
	}
	if err := waitForCaptureTime(ctx, event.CapturedAt, w.MaxClockAhead); err != nil {
		return err
	}
	subject, epoch, err := w.Resolver.ResolveCapture(ctx, event)
	if err != nil {
		return err
	}
	if err := subject.Validate(); err != nil {
		return err
	}
	if epoch.SubjectDigest == "" {
		return fmt.Errorf("runtime event subject epoch is missing")
	}
	digest := assurance.ComputeDigest(event.Payload)
	envelope := assurance.EvidenceEnvelope{
		Schema:          "assurance.ckodex.io/evidence/v1alpha1",
		ID:              "capture-" + strings.TrimPrefix(assurance.ComputeStringDigest(event.Producer.Canonical()+"|"+subject.URI()+"|"+event.Type+"|"+digest+"|"+epoch.CompositeDigest()), "sha256:"),
		Subject:         subject,
		ObservationType: event.Type,
		CapturedAt:      event.CapturedAt,
		Producer:        event.Producer,
		Artifact: assurance.EvidenceRef{
			URI:       "cas://sha256/" + strings.TrimPrefix(digest, "sha256:"),
			Digest:    digest,
			MediaType: event.MediaType,
		},
		IntegrityDigest: digest,
		Epoch:           epoch,
		ControlRefs:     event.ControlRefs,
	}
	_, err = w.Repository.Put(ctx, envelope, bytes.NewReader(event.Payload))
	return err
}

func waitForCaptureTime(ctx context.Context, capturedAt time.Time, maxAhead time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if capturedAt.IsZero() || maxAhead < 0 {
		return fmt.Errorf("runtime event timestamp is missing or clock allowance is invalid")
	}
	ahead := time.Until(capturedAt)
	if ahead <= 0 {
		return nil
	}
	if ahead > maxAhead {
		return fmt.Errorf("runtime event timestamp is %s ahead of collector clock, exceeding %s allowance", ahead, maxAhead)
	}
	timer := time.NewTimer(ahead)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if capturedAt.After(time.Now()) {
		return fmt.Errorf("runtime event timestamp remains in the future after clock alignment wait")
	}
	return nil
}
