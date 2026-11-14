package tetragon

import (
	"context"
	"fmt"

	tetragonapi "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/guest"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"google.golang.org/protobuf/encoding/protojson"
)

// EventDecoder uses the same capture semantics as the live Tetragon collector.
// Its producer is the outside-configured recorder authority, not a claimed name
// supplied in the guest's observation. Attestation is verified before decoding.
type EventDecoder struct {
	Producer  assurance.AuthorityRef
	Namespace string
}

func (d *EventDecoder) DecodeObservation(ctx context.Context, observation guest.Observation) (*ports.CapturedEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d == nil || d.Namespace == "" || d.Producer.Validate() != nil {
		return nil, fmt.Errorf("decoding Tetragon requires an enrolled recorder and namespace")
	}
	if observation.MediaType != "application/vnd.tetragon.event+json" || len(observation.Payload) == 0 || len(observation.Payload) > 32<<10 {
		return nil, fmt.Errorf("observation must contain 1..32768 bytes of original Tetragon event JSON")
	}
	var event tetragonapi.GetEventsResponse
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(observation.Payload, &event); err != nil {
		return nil, fmt.Errorf("decode actual Tetragon event: %w", err)
	}
	collector := Collector{Producer: d.Producer, Namespace: d.Namespace}
	return collector.capture(&event)
}
