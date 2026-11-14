package guesttransport

import (
	"bytes"
	"slices"

	"github.com/ckodex-labs/ckodex-oskal/internal/application/guest"
)

func copyChallenge(source *guest.Challenge) *guest.Challenge {
	if source == nil {
		return nil
	}
	copy := *source
	copy.Nonce = bytes.Clone(source.Nonce)
	return &copy
}
func clonePublication(p guest.Publication) guest.Publication {
	p.ExportPublicKey = bytes.Clone(p.ExportPublicKey)
	p.Challenge = copyChallenge(p.Challenge)
	p.AttestationReport = bytes.Clone(p.AttestationReport)
	p.SignedExportKeyProof = bytes.Clone(p.SignedExportKeyProof)
	p.SignedHeartbeat = bytes.Clone(p.SignedHeartbeat)
	p.Integrity.Caveats = slices.Clone(p.Integrity.Caveats)
	p.Integrity.Reasons = slices.Clone(p.Integrity.Reasons)
	p.Integrity.Gaps = slices.Clone(p.Integrity.Gaps)
	p.Integrity.Loss = slices.Clone(p.Integrity.Loss)
	if p.Standing != nil {
		copy := *p.Standing
		copy.Caveats = slices.Clone(copy.Caveats)
		p.Standing = &copy
	}
	if p.Accepted != nil {
		copy := *p.Accepted
		copy.Record.Counters = slices.Clone(copy.Record.Counters)
		copy.Record.Observations = slices.Clone(copy.Record.Observations)
		for i := range copy.Record.Observations {
			copy.Record.Observations[i].Payload = bytes.Clone(copy.Record.Observations[i].Payload)
		}
		copy.Record.HealthEvidence = slices.Clone(copy.Record.HealthEvidence)
		for i := range copy.Record.HealthEvidence {
			copy.Record.HealthEvidence[i].Payload = bytes.Clone(copy.Record.HealthEvidence[i].Payload)
		}
		copy.Integrity.Caveats = slices.Clone(copy.Integrity.Caveats)
		copy.Integrity.Reasons = slices.Clone(copy.Integrity.Reasons)
		copy.Integrity.Gaps = slices.Clone(copy.Integrity.Gaps)
		copy.Integrity.Loss = slices.Clone(copy.Integrity.Loss)
		p.Accepted = &copy
	}
	if p.RejectedQuote != nil {
		copy := *p.RejectedQuote
		copy.Challenge = copyChallenge(copy.Challenge)
		copy.AttestationReport = bytes.Clone(copy.AttestationReport)
		copy.SignedExportKeyProof = bytes.Clone(copy.SignedExportKeyProof)
		p.RejectedQuote = &copy
	}
	return p
}
