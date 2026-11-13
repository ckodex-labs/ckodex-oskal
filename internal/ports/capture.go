package ports

import (
	"context"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// CapturedEvent is a fact received from a runtime source, before epoch binding.
// Payload contains the original serialized event, not a compliance assertion.
type CapturedEvent struct {
	Subject     assurance.SubjectRef
	Type        string
	CapturedAt  time.Time
	Producer    assurance.AuthorityRef
	Payload     []byte
	MediaType   string
	ControlRefs []assurance.ControlRef
}

// CapturedEventWriter durably records a captured fact or returns an error.
type CapturedEventWriter interface {
	WriteCapturedEvent(context.Context, CapturedEvent) error
}

// CaptureResolver binds a runtime subject to the current authoritative epoch.
// It must reject missing identity and stale workload identity instead of guessing.
type CaptureResolver interface {
	ResolveCapture(context.Context, CapturedEvent) (assurance.SubjectRef, assurance.AssuranceEpoch, error)
}

// CaptureResolverFunc adapts an application's authoritative epoch resolver.
type CaptureResolverFunc func(context.Context, CapturedEvent) (assurance.SubjectRef, assurance.AssuranceEpoch, error)

func (f CaptureResolverFunc) ResolveCapture(ctx context.Context, event CapturedEvent) (assurance.SubjectRef, assurance.AssuranceEpoch, error) {
	return f(ctx, event)
}
