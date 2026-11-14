package guest

import (
	"context"

	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

// ObservationDecoder maps authenticated raw observations into capture facts.
// A nil fact means an explicitly out-of-scope observation, never a passing
// control. Identity/epoch resolution and persistence are separate operations.
type ObservationDecoder interface {
	DecodeObservation(context.Context, Observation) (*ports.CapturedEvent, error)
}
