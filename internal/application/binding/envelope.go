package binding

import (
	"context"
	"fmt"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// BindEnvelope maps an observed fact only through the current real binding's
// exact type and producer contract. Unmapped facts remain archive-only. This
// never invents a control from a transport label or an untrusted payload field.
func (r *Resolver) BindEnvelope(ctx context.Context, envelope assurance.EvidenceEnvelope) (assurance.EvidenceEnvelope, error) {
	resolved, err := r.ContextForSubject(ctx, envelope.Subject)
	if err != nil {
		return assurance.EvidenceEnvelope{}, err
	}
	if envelope.Epoch != resolved.Epoch {
		return assurance.EvidenceEnvelope{}, fmt.Errorf("binding or workload epoch changed before evidence persistence")
	}
	envelope.ControlRefs = nil
	for _, requirement := range resolved.Contract.Requirements {
		if requirement.EvidenceType != envelope.ObservationType {
			continue
		}
		for _, producer := range requirement.AcceptedProducers {
			if producer == envelope.Producer.Canonical() {
				envelope.ControlRefs = resolved.Controls
				return envelope, nil
			}
		}
	}
	return envelope, nil
}
