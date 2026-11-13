package assurance

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
)

const MaxTelemetrySignals = 2048

// TelemetryPolicy describes one source's observation contract. Signal identifiers
// include their canonical label set; different series are never added together.
type TelemetryPolicy struct {
	HeartbeatInterval time.Duration `json:"heartbeatInterval"`
	Tolerance         time.Duration `json:"tolerance"`
	MaxSampleAge      time.Duration `json:"maxSampleAge"`
	MaxAttestationAge time.Duration `json:"maxAttestationAge"`
	RequiredSignals   []string      `json:"requiredSignals"`
}

func (p TelemetryPolicy) Validate() error {
	if p.HeartbeatInterval < time.Millisecond || p.HeartbeatInterval > time.Hour || p.Tolerance < time.Millisecond || p.Tolerance > p.HeartbeatInterval {
		return fmt.Errorf("heartbeat interval must be 1ms..1h and tolerance 1ms..one interval")
	}
	if p.MaxSampleAge < p.HeartbeatInterval+p.Tolerance || p.MaxSampleAge > 24*time.Hour {
		return fmt.Errorf("sample age must cover the heartbeat deadline and be at most 24h")
	}
	if p.MaxAttestationAge < p.HeartbeatInterval+p.Tolerance || p.MaxAttestationAge > 24*time.Hour {
		return fmt.Errorf("attestation age must cover the heartbeat deadline and be at most 24h")
	}
	if len(p.RequiredSignals) == 0 || len(p.RequiredSignals) > MaxTelemetrySignals {
		return fmt.Errorf("required loss signals must number 1..%d", MaxTelemetrySignals)
	}
	for i, name := range p.RequiredSignals {
		if !telemetryIdentifier(name, 1024) || (i > 0 && name <= p.RequiredSignals[i-1]) {
			return fmt.Errorf("required loss signals must be bounded, unique, and sorted")
		}
	}
	return nil
}

// TelemetryAttestation is an application-verified standing, not a submitted quote.
// Its public fields do not authenticate themselves. Only the external verifier
// may construct the value used to admit a stream.
type TelemetryAttestation struct {
	SessionID         string    `json:"sessionID"`
	SourceInstance    string    `json:"sourceInstance"`
	MeasurementDigest string    `json:"measurementDigest"`
	ExportKeyDigest   string    `json:"exportKeyDigest"`
	ChannelDigest     string    `json:"channelDigest"`
	RootKind          string    `json:"rootKind"`
	RootLabel         string    `json:"rootLabel"`
	Caveats           []string  `json:"caveats"`
	StartedAt         time.Time `json:"startedAt"`
	VerifiedAt        time.Time `json:"verifiedAt"`
	ExpiresAt         time.Time `json:"expiresAt"`
}

// AttestedEnvironment contains facts returned by the enrolled cryptographic
// verifier. The application must compare them with its outside-owned policy.
type AttestedEnvironment struct {
	MeasurementDigest string `json:"measurementDigest"`
	RootKind          string `json:"rootKind"`
	RootLabel         string `json:"rootLabel"`
}

func (a TelemetryAttestation) Validate() error {
	if !telemetryDigest(a.SessionID) || !telemetryIdentifier(a.SourceInstance, 1024) || !telemetryDigest(a.MeasurementDigest) || !telemetryDigest(a.ExportKeyDigest) || !telemetryDigest(a.ChannelDigest) {
		return fmt.Errorf("attestation requires a session, source instance, and exact measurement/key/channel digests")
	}
	if !telemetryIdentifier(a.RootKind, 128) || !telemetryIdentifier(a.RootLabel, 1024) || len(a.Caveats) > 16 {
		return fmt.Errorf("attestation requires a bounded explicit root and caveats")
	}
	for _, caveat := range a.Caveats {
		if !telemetryIdentifier(caveat, 2048) {
			return fmt.Errorf("attestation caveats must be bounded and nonempty")
		}
	}
	if a.RootKind == "SOFTWARE_TPM" && (a.RootLabel != "software TPM root \u2014 not hardware-backed" || len(a.Caveats) == 0) {
		return fmt.Errorf("software TPM attestation must carry its exact root label and limitations")
	}
	if a.StartedAt.IsZero() || a.VerifiedAt.Before(a.StartedAt) || !a.ExpiresAt.After(a.VerifiedAt) {
		return fmt.Errorf("attestation requires an ordered session start, verification, and expiry")
	}
	return nil
}

type TelemetrySignalStatus string

const (
	TelemetrySignalObserved TelemetrySignalStatus = "OBSERVED"
	TelemetrySignalUnknown  TelemetrySignalStatus = "UNKNOWN"
)

// TelemetryLossCounter is a successful cumulative read or an explicit gap.
// Zero is meaningful only with OBSERVED; missing and failed reads stay UNKNOWN.
type TelemetryLossCounter struct {
	ID     string                `json:"id"`
	Value  uint64                `json:"value"`
	Status TelemetrySignalStatus `json:"status"`
	Reason string                `json:"reason,omitempty"`
}

// TelemetryHeartbeat contains facts authenticated by the application. Digest is
// the hash of the complete signed record, not a hash invented by the sender.
type TelemetryHeartbeat struct {
	SessionID      string                 `json:"sessionID"`
	SourceInstance string                 `json:"sourceInstance"`
	Sequence       uint64                 `json:"sequence"`
	Slot           uint64                 `json:"slot"`
	SampledAt      time.Time              `json:"sampledAt"`
	ReceivedAt     time.Time              `json:"receivedAt"`
	Digest         string                 `json:"digest"`
	PreviousDigest string                 `json:"previousDigest"`
	Counters       []TelemetryLossCounter `json:"counters"`
}

func (h TelemetryHeartbeat) Validate() error {
	if !telemetryDigest(h.SessionID) || !telemetryIdentifier(h.SourceInstance, 1024) || h.Sequence == 0 || !telemetryDigest(h.Digest) || (h.PreviousDigest != "" && !telemetryDigest(h.PreviousDigest)) {
		return fmt.Errorf("heartbeat requires bounded source/session identities, positive sequence, and record digests")
	}
	if h.SampledAt.IsZero() || h.ReceivedAt.IsZero() || len(h.Counters) > MaxTelemetrySignals {
		return fmt.Errorf("heartbeat requires timestamps and bounded loss counters")
	}
	for i, counter := range h.Counters {
		if !telemetryIdentifier(counter.ID, 1024) || (i > 0 && counter.ID <= h.Counters[i-1].ID) || len(counter.Reason) > 2048 {
			return fmt.Errorf("loss counters must be bounded, unique, and sorted")
		}
		if counter.Status != TelemetrySignalObserved && counter.Status != TelemetrySignalUnknown {
			return fmt.Errorf("loss counter must explicitly state OBSERVED or UNKNOWN")
		}
		if counter.Status == TelemetrySignalUnknown && strings.TrimSpace(counter.Reason) == "" {
			return fmt.Errorf("unknown loss counter requires a reason")
		}
	}
	return nil
}

// TelemetryGap preserves exact missing ranges without allocating one item per
// absent heartbeat. Ranges are inclusive, including the initial slot zero.
type TelemetryGap struct {
	Kind  string `json:"kind"`
	First uint64 `json:"first"`
	Last  uint64 `json:"last"`
}

type TelemetryLoss struct {
	Signal string `json:"signal"`
	Delta  uint64 `json:"delta"`
}

// TelemetryIntegrity is a window eligibility result, not a control assessment.
// VERIFIED permits normal control evaluation; UNKNOWN prohibits promotion.
type TelemetryIntegrity struct {
	State       AssuranceState  `json:"state"`
	RootKind    string          `json:"rootKind"`
	RootLabel   string          `json:"rootLabel"`
	Caveats     []string        `json:"caveats"`
	SessionID   string          `json:"sessionID"`
	WindowStart time.Time       `json:"windowStart"`
	WindowEnd   time.Time       `json:"windowEnd"`
	ValidUntil  time.Time       `json:"validUntil"`
	Loss        []TelemetryLoss `json:"loss,omitempty"`
	Gaps        []TelemetryGap  `json:"gaps,omitempty"`
	Reasons     []string        `json:"reasons,omitempty"`
	Recovery    string          `json:"recovery,omitempty"`
}

const TelemetryFreshSessionRequired = "FRESH_ATTESTED_SESSION"

// EvaluateTelemetryWindow evaluates adjacent authenticated heartbeats. It does
// not verify signatures or quotes and does not own session lifecycle. Callers
// must fence a broken sequence/chain/source until a fresh session is admitted.
// All time is supplied explicitly; evaluation has no I/O or ambient clock.
func EvaluateTelemetryWindow(p TelemetryPolicy, a TelemetryAttestation, previous *TelemetryHeartbeat, current TelemetryHeartbeat, now time.Time) (TelemetryIntegrity, error) {
	r := TelemetryIntegrity{State: AssuranceStateUnknown, RootKind: a.RootKind, RootLabel: a.RootLabel, Caveats: slices.Clone(a.Caveats), SessionID: a.SessionID}
	if err := p.Validate(); err != nil {
		return r, err
	}
	if err := a.Validate(); err != nil {
		return r, err
	}
	if err := current.Validate(); err != nil {
		return r, err
	}
	if now.IsZero() || now.Before(a.StartedAt) || now.Before(current.ReceivedAt) {
		return r, fmt.Errorf("evaluation time must follow session start and local receipt")
	}
	r.WindowEnd = current.SampledAt
	r.ValidUntil = a.ExpiresAt
	if expiry := current.SampledAt.Add(p.MaxSampleAge); expiry.Before(r.ValidUntil) {
		r.ValidUntil = expiry
	}
	if deadline := a.VerifiedAt.Add(p.MaxAttestationAge); deadline.Before(r.ValidUntil) {
		r.ValidUntil = deadline
	}
	if !now.Before(r.ValidUntil) {
		r.Reasons = append(r.Reasons, "attestation expired; obtain a fresh verifier challenge and quote")
		r.Recovery = TelemetryFreshSessionRequired
	}
	if a.VerifiedAt.After(now) {
		r.Reasons = append(r.Reasons, "attestation verification time is in the future")
		r.Recovery = TelemetryFreshSessionRequired
	}
	if current.SessionID != a.SessionID || current.SourceInstance != a.SourceInstance {
		r.Reasons = append(r.Reasons, "source or session changed; admit a fresh attested session")
		r.Recovery = TelemetryFreshSessionRequired
	}
	// This also bounds multiplication and a distant sender-supplied slot. A
	// schedule cannot run longer than 24h without a fresh session.
	maxSlot := uint64(24 * time.Hour / p.HeartbeatInterval)
	if current.Slot >= maxSlot {
		r.Reasons = append(r.Reasons, "heartbeat slot exceeds the bounded session schedule")
		r.Recovery = TelemetryFreshSessionRequired
		return r, nil
	}
	scheduled := a.StartedAt.Add(time.Duration(current.Slot) * p.HeartbeatInterval)
	deadline := scheduled.Add(p.HeartbeatInterval + p.Tolerance)
	if deadline.Before(r.ValidUntil) {
		r.ValidUntil = deadline
	}
	if !now.Before(deadline) {
		lastMissing := uint64(now.Sub(a.StartedAt.Add(p.Tolerance)) / p.HeartbeatInterval)
		r.Gaps = append(r.Gaps, TelemetryGap{Kind: "HEARTBEAT", First: current.Slot + 1, Last: lastMissing})
		r.Reasons = append(r.Reasons, "heartbeat deadline missed; restore and re-attest the sensor")
		r.Recovery = TelemetryFreshSessionRequired
	}
	// Deadline intervals are half open: arrival exactly at expiry is late.
	if current.ReceivedAt.Before(scheduled.Add(-p.Tolerance)) || !current.ReceivedAt.Before(scheduled.Add(p.Tolerance)) || current.SampledAt.Before(scheduled.Add(-p.Tolerance)) || !current.SampledAt.Before(scheduled.Add(p.Tolerance)) {
		r.Reasons = append(r.Reasons, "heartbeat or sample is outside its scheduled tolerance")
		r.Recovery = TelemetryFreshSessionRequired
	}
	if current.SampledAt.After(current.ReceivedAt.Add(p.Tolerance)) || !now.Before(current.SampledAt.Add(p.MaxSampleAge)) {
		r.Reasons = append(r.Reasons, "sample age is outside the evidence freshness contract")
		r.Recovery = TelemetryFreshSessionRequired
	}
	if previous == nil {
		if current.Sequence != 1 || current.Slot != 0 || current.PreviousDigest != "" {
			r.Reasons = append(r.Reasons, "initial heartbeat must start sequence 1, slot 0, and an empty record chain")
			r.Recovery = TelemetryFreshSessionRequired
		}
		r.Reasons = append(r.Reasons, "loss baseline only; a second complete heartbeat is required")
		return r, nil
	}
	if err := previous.Validate(); err != nil {
		return r, fmt.Errorf("previous heartbeat: %w", err)
	}
	r.WindowStart = previous.SampledAt
	if previous.Slot >= maxSlot {
		r.Reasons = append(r.Reasons, "previous heartbeat exceeds the bounded session schedule")
		r.Recovery = TelemetryFreshSessionRequired
	} else {
		priorSchedule := a.StartedAt.Add(time.Duration(previous.Slot) * p.HeartbeatInterval)
		if previous.SampledAt.Before(priorSchedule.Add(-p.Tolerance)) || !previous.SampledAt.Before(priorSchedule.Add(p.Tolerance)) || previous.ReceivedAt.Before(priorSchedule.Add(-p.Tolerance)) || !previous.ReceivedAt.Before(priorSchedule.Add(p.Tolerance)) {
			r.Reasons = append(r.Reasons, "previous heartbeat was outside its scheduled tolerance")
			r.Recovery = TelemetryFreshSessionRequired
		}
	}
	if previous.SessionID != current.SessionID || previous.SourceInstance != current.SourceInstance || !current.SampledAt.After(previous.SampledAt) || current.ReceivedAt.Before(previous.ReceivedAt) {
		r.Reasons = append(r.Reasons, "observation window changed source or moved backwards")
		r.Recovery = TelemetryFreshSessionRequired
	}
	if previous.Sequence == ^uint64(0) || current.Sequence != previous.Sequence+1 {
		if current.Sequence > previous.Sequence && current.Sequence-previous.Sequence > 1 {
			r.Gaps = append(r.Gaps, TelemetryGap{Kind: "SEQUENCE", First: previous.Sequence + 1, Last: current.Sequence - 1})
		}
		r.Reasons = append(r.Reasons, "record sequence is discontinuous; start a fresh attested session")
		r.Recovery = TelemetryFreshSessionRequired
	}
	if previous.Slot == ^uint64(0) || current.Slot != previous.Slot+1 {
		if current.Slot > previous.Slot && current.Slot-previous.Slot > 1 {
			r.Gaps = append(r.Gaps, TelemetryGap{Kind: "HEARTBEAT", First: previous.Slot + 1, Last: current.Slot - 1})
		}
		r.Reasons = append(r.Reasons, "heartbeat slots are discontinuous; start a fresh attested session")
		r.Recovery = TelemetryFreshSessionRequired
	}
	if current.PreviousDigest != previous.Digest {
		r.Reasons = append(r.Reasons, "signed record chain is discontinuous; start a fresh attested session")
		r.Recovery = TelemetryFreshSessionRequired
	}
	for _, id := range p.RequiredSignals {
		before, beforeOK := telemetryCounter(previous.Counters, id)
		after, afterOK := telemetryCounter(current.Counters, id)
		switch {
		case !beforeOK || !afterOK || before.Status != TelemetrySignalObserved || after.Status != TelemetrySignalObserved:
			r.Reasons = append(r.Reasons, "loss signal is UNKNOWN: "+id)
		case after.Value < before.Value:
			r.Reasons = append(r.Reasons, "loss counter reset: "+id)
			r.Recovery = TelemetryFreshSessionRequired
		case after.Value > before.Value:
			r.Loss = append(r.Loss, TelemetryLoss{Signal: id, Delta: after.Value - before.Value})
		}
	}
	if len(r.Loss) > 0 {
		r.Reasons = append(r.Reasons, "sensor loss or throttling invalidated this observation window")
	}
	if len(r.Reasons) == 0 {
		r.State = AssuranceStateVerified
	}
	return r, nil
}

func telemetryCounter(counters []TelemetryLossCounter, id string) (TelemetryLossCounter, bool) {
	i, ok := slices.BinarySearchFunc(counters, id, func(counter TelemetryLossCounter, target string) int { return strings.Compare(counter.ID, target) })
	if !ok {
		return TelemetryLossCounter{}, false
	}
	return counters[i], true
}

func telemetryIdentifier(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func telemetryDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}
