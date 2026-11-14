// Package guest owns admission and continuity of an attested telemetry session.
// Transport, TPM parsing, and durable evidence storage are separate adapters.
package guest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
)

const (
	HeartbeatPayloadType  = "application/vnd.oskal.guest-heartbeat.v1+json"
	QuoteProofPayloadType = "application/vnd.oskal.guest-quote-proof.v1+json"
	MaxReportBytes        = 4096
	MaxRecordBytes        = 1 << 20
	MaxEventsPerRecord    = 64
)

var ErrSessionClosed = errors.New("attested session is fenced; open a fresh session and re-attest")

// Enrollment is verifier-owned policy, loaded outside the guest. A submitted
// label, public key, or digest never creates its own enrollment authority.
type Enrollment struct {
	SourceInstance    string                    `json:"sourceInstance"`
	MeasurementDigest string                    `json:"measurementDigest"`
	PolicyDigest      string                    `json:"policyDigest"`
	RootKind          string                    `json:"rootKind"`
	RootLabel         string                    `json:"rootLabel"`
	Caveats           []string                  `json:"caveats"`
	Policy            assurance.TelemetryPolicy `json:"policy"`
	ChallengeTTL      time.Duration             `json:"challengeTTL"`
	ReattestInterval  time.Duration             `json:"reattestInterval"`
}

type Challenge struct {
	Version          uint32    `json:"version"`
	SessionID        string    `json:"sessionID"`
	ID               string    `json:"id"`
	Nonce            []byte    `json:"nonce"`
	EnrollmentDigest string    `json:"enrollmentDigest"`
	IssuedAt         time.Time `json:"issuedAt"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

type QuoteProof struct {
	Version      uint32 `json:"version"`
	SessionID    string `json:"sessionID"`
	ChallengeID  string `json:"challengeID"`
	ReportDigest string `json:"reportDigest"`
}

type Observation struct {
	MediaType string `json:"mediaType"`
	Payload   []byte `json:"payload"`
}

// Record is signed in full, including raw observations and health caveats. The
// verifier supplies ReceivedAt and Digest; the sender cannot choose either.
type Record struct {
	Version        uint32                           `json:"version"`
	SessionID      string                           `json:"sessionID"`
	SourceInstance string                           `json:"sourceInstance"`
	Sequence       uint64                           `json:"sequence"`
	Slot           uint64                           `json:"slot"`
	SampledAt      time.Time                        `json:"sampledAt"`
	PreviousDigest string                           `json:"previousDigest"`
	Counters       []assurance.TelemetryLossCounter `json:"counters"`
	Observations   []Observation                    `json:"observations"`
}

type AcceptedRecord struct {
	Record       Record
	SignedDigest string
	Integrity    assurance.TelemetryIntegrity
}

// Session is single-channel and single-export-key. Its mutex serializes
// challenge consumption, accepted records, and independent watchdog snapshots.
// It owns no goroutines, hidden retry, or unbounded queue.
type Session struct {
	mu                   sync.Mutex
	enrollment           Enrollment
	verifier             ports.AttestationVerifier
	key                  ed25519.PublicKey
	channel              [32]byte
	id                   string
	opened               time.Time
	lastTime             time.Time
	challenge            *Challenge
	verifying            bool
	verificationDeadline time.Time
	readingRecord        bool
	standing             *assurance.TelemetryAttestation
	quoteDigest          string
	previous             *assurance.TelemetryHeartbeat
	current              *assurance.TelemetryHeartbeat
	fault                string
}

func NewSession(e Enrollment, verifier ports.AttestationVerifier, key ed25519.PublicKey, channel [32]byte, now time.Time) (*Session, error) {
	if verifier == nil || len(key) != ed25519.PublicKeySize || channel == [32]byte{} || now.IsZero() {
		return nil, fmt.Errorf("enrolled verifier, Ed25519 export key, actual TLS channel binding, and time are required")
	}
	if err := e.Policy.Validate(); err != nil {
		return nil, err
	}
	if e.ChallengeTTL < time.Millisecond || e.ChallengeTTL > time.Minute || e.ReattestInterval < e.ChallengeTTL || e.ReattestInterval >= e.Policy.MaxAttestationAge {
		return nil, fmt.Errorf("challenge TTL must be 1ms..1m; re-attestation must follow its TTL and precede maximum attestation age")
	}
	if !digestBytes(e.PolicyDigest) {
		return nil, fmt.Errorf("outside-enrolled policy digest is required")
	}
	probe := assurance.TelemetryAttestation{SessionID: assurance.ComputeStringDigest("validation"), SourceInstance: e.SourceInstance, MeasurementDigest: e.MeasurementDigest, ExportKeyDigest: assurance.ComputeDigest(key), ChannelDigest: assurance.ComputeDigest(channel[:]), RootKind: e.RootKind, RootLabel: e.RootLabel, Caveats: e.Caveats, StartedAt: now, VerifiedAt: now, ExpiresAt: now.Add(e.Policy.MaxAttestationAge)}
	if err := probe.Validate(); err != nil {
		return nil, fmt.Errorf("enrollment: %w", err)
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, fmt.Errorf("create fresh verifier session: %w", err)
	}
	e.Caveats = slices.Clone(e.Caveats)
	e.Policy.RequiredSignals = slices.Clone(e.Policy.RequiredSignals)
	return &Session{enrollment: e, verifier: verifier, key: bytes.Clone(key), channel: channel, id: assurance.ComputeDigest(entropy[:]), opened: now, lastTime: now}, nil
}

// Qualification puts the literal verifier nonce inside signed TPM extraData.
// All remaining inputs are fixed-size digests; the versioned domain separates
// this use from other TPM qualifications. Each endpoint uses its OWN exporter.
func Qualification(c Challenge, key ed25519.PublicKey, channel [32]byte) ([64]byte, error) {
	var result [64]byte
	if c.Version != 1 || len(c.Nonce) != 32 || len(key) != ed25519.PublicKeySize || channel == [32]byte{} || !digestBytes(c.SessionID) || !digestBytes(c.EnrollmentDigest) || !digestBytes(c.ID) {
		return result, fmt.Errorf("challenge requires version 1, nonce, export key, channel, and exact session/policy/challenge digests")
	}
	keyHash := sha256.Sum256(key)
	hash := sha256.New()
	_, _ = hash.Write([]byte("oskal.guest.quote.v1\x00"))
	_, _ = hash.Write(keyHash[:])
	_, _ = hash.Write(channel[:])
	for _, digest := range []string{c.SessionID, c.EnrollmentDigest, c.ID} {
		decoded, err := hex.DecodeString(digest[7:])
		if err != nil {
			return result, err
		}
		_, _ = hash.Write(decoded)
	}
	copy(result[:32], c.Nonce)
	copy(result[32:], hash.Sum(nil))
	return result, nil
}

// Challenge creates one single-use verifier nonce. Replacing a pending
// challenge is forbidden; a timed-out or invalid response fences the session.
func (s *Session) Challenge(now time.Time) (Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkTime(now); err != nil {
		return Challenge{}, err
	}
	if s.challenge != nil || s.verifying {
		return Challenge{}, fmt.Errorf("a challenge is already pending; answer it before requesting another")
	}
	if s.standing != nil && now.Before(s.standing.VerifiedAt.Add(s.enrollment.ReattestInterval)) {
		return Challenge{}, fmt.Errorf("re-attestation is not due yet; follow the enrolled interval")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Challenge{}, fmt.Errorf("create verifier nonce: %w", err)
	}
	c := Challenge{Version: 1, SessionID: s.id, ID: assurance.ComputeDigest(nonce[:]), Nonce: bytes.Clone(nonce[:]), EnrollmentDigest: s.enrollment.PolicyDigest, IssuedAt: now, ExpiresAt: now.Add(s.enrollment.ChallengeTTL)}
	s.challenge = &c
	return cloneChallenge(c), nil
}

func (s *Session) AcceptQuote(ctx context.Context, challengeID string, report, proof []byte, received time.Time) (assurance.TelemetryAttestation, error) {
	if ctx == nil {
		return assurance.TelemetryAttestation{}, fmt.Errorf("quote verification requires a bounded operation context")
	}
	c, err := func() (Challenge, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.checkTime(received); err != nil {
			return Challenge{}, err
		}
		if s.challenge == nil || s.verifying {
			return Challenge{}, s.fail("no pending verifier challenge; replay refused")
		}
		challenge := *s.challenge
		s.challenge = nil // consume before verification, including malformed attempts
		if challengeID != challenge.ID || !received.Before(challenge.ExpiresAt) || received.Before(challenge.IssuedAt) {
			return Challenge{}, s.fail("challenge mismatch or expiry; obtain a new session")
		}
		if len(report) == 0 || len(report) > MaxReportBytes || len(proof) > 16384 {
			return Challenge{}, s.fail("quote report or export-key proof exceeds its bounded encoding")
		}
		if err := ctx.Err(); err != nil {
			return Challenge{}, s.fail("quote verification canceled: " + err.Error())
		}
		s.verifying, s.verificationDeadline = true, challenge.ExpiresAt
		return challenge, nil
	}()
	if err != nil {
		return assurance.TelemetryAttestation{}, err
	}
	report, proof = bytes.Clone(report), bytes.Clone(proof)
	// No external verifier or payload parser runs under the lifecycle mutex.
	// The independent watchdog can fence a stalled verification at its deadline.
	ctx, cancel := context.WithTimeout(ctx, s.enrollment.ChallengeTTL)
	defer cancel()
	environment, verificationErr := s.verifyQuote(ctx, c, report, proof)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifying, s.verificationDeadline = false, time.Time{}
	if s.fault != "" {
		return assurance.TelemetryAttestation{}, ErrSessionClosed
	}
	if verificationErr != nil {
		return assurance.TelemetryAttestation{}, s.fail(verificationErr.Error())
	}
	if err := ctx.Err(); err != nil {
		return assurance.TelemetryAttestation{}, s.fail("quote verification canceled: " + err.Error())
	}
	// A watchdog may have advanced verifier time during offline cryptography.
	// That can shorten acceptance, never extend the issued nonce's expiry.
	if s.lastTime.After(received) {
		received = s.lastTime
	}
	if err := s.checkTime(received); err != nil {
		return assurance.TelemetryAttestation{}, err
	}
	if !received.Before(c.ExpiresAt) {
		return assurance.TelemetryAttestation{}, s.fail("quote verification exceeded the verifier challenge deadline")
	}
	if environment.MeasurementDigest != s.enrollment.MeasurementDigest || environment.RootKind != s.enrollment.RootKind || environment.RootLabel != s.enrollment.RootLabel {
		return assurance.TelemetryAttestation{}, s.fail("verified environment differs from outside-enrolled measurement or root policy")
	}
	started := received
	if s.standing != nil {
		started = s.standing.StartedAt
	}
	a := assurance.TelemetryAttestation{SessionID: s.id, SourceInstance: s.enrollment.SourceInstance, MeasurementDigest: s.enrollment.MeasurementDigest, ExportKeyDigest: assurance.ComputeDigest(s.key), ChannelDigest: assurance.ComputeDigest(s.channel[:]), RootKind: s.enrollment.RootKind, RootLabel: s.enrollment.RootLabel, Caveats: slices.Clone(s.enrollment.Caveats), StartedAt: started, VerifiedAt: received, ExpiresAt: received.Add(s.enrollment.Policy.MaxAttestationAge)}
	s.standing = &a
	s.quoteDigest = assurance.ComputeDigest(report)
	a.Caveats = slices.Clone(a.Caveats)
	return a, nil
}

func (s *Session) verifyQuote(ctx context.Context, c Challenge, report, proof []byte) (assurance.AttestedEnvironment, error) {
	qualification, err := Qualification(c, s.key, s.channel)
	if err != nil {
		return assurance.AttestedEnvironment{}, err
	}
	environment, err := s.verifier.VerifyAttestation(ctx, report, qualification)
	if err != nil {
		return assurance.AttestedEnvironment{}, fmt.Errorf("attestation rejected: %w", err)
	}
	decoded, err := signedrecords.Verify(ctx, proof, QuoteProofPayloadType, s.key, 4096)
	if err != nil {
		return assurance.AttestedEnvironment{}, fmt.Errorf("export-key proof rejected: %w", err)
	}
	var p QuoteProof
	if err := signedrecords.DecodeJSON(decoded, &p, 4096); err != nil {
		return assurance.AttestedEnvironment{}, fmt.Errorf("export-key proof invalid: %w", err)
	}
	if p.Version != 1 || p.SessionID != s.id || p.ChallengeID != c.ID || p.ReportDigest != assurance.ComputeDigest(report) {
		return assurance.AttestedEnvironment{}, fmt.Errorf("export-key proof does not bind this session, challenge, and quote")
	}
	if err := ctx.Err(); err != nil {
		return assurance.AttestedEnvironment{}, fmt.Errorf("quote verification canceled: %w", err)
	}
	return environment, nil
}

func (s *Session) AcceptRecord(ctx context.Context, raw []byte, received time.Time) (AcceptedRecord, error) {
	if ctx == nil {
		return AcceptedRecord{}, fmt.Errorf("heartbeat verification requires an operation context")
	}
	if err := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.checkTime(received); err != nil {
			return err
		}
		if s.standing == nil {
			return s.fail("no verified attestation; submit a valid quote before telemetry")
		}
		if s.readingRecord {
			return s.fail("concurrent heartbeat processing violates the ordered stream; establish a fresh session")
		}
		if len(raw) == 0 || len(raw) > signedrecords.MaxEnvelopeBytes {
			return s.fail("signed heartbeat exceeds its bounded encoding")
		}
		s.readingRecord = true
		return nil
	}(); err != nil {
		return AcceptedRecord{}, err
	}
	raw = bytes.Clone(raw)
	record, verificationErr := s.decodeRecord(ctx, raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readingRecord = false
	if s.fault != "" {
		return AcceptedRecord{}, ErrSessionClosed
	}
	if verificationErr != nil {
		return AcceptedRecord{}, s.fail(verificationErr.Error())
	}
	commitTime := received
	if s.lastTime.After(commitTime) {
		commitTime = s.lastTime
	}
	if err := s.checkTime(commitTime); err != nil {
		return AcceptedRecord{}, err
	}
	h := assurance.TelemetryHeartbeat{SessionID: record.SessionID, SourceInstance: record.SourceInstance, Sequence: record.Sequence, Slot: record.Slot, SampledAt: record.SampledAt, ReceivedAt: received, Digest: assurance.ComputeDigest(raw), PreviousDigest: record.PreviousDigest, Counters: slices.Clone(record.Counters)}
	result, err := assurance.EvaluateTelemetryWindow(s.enrollment.Policy, *s.standing, s.current, h, commitTime)
	if err != nil {
		return AcceptedRecord{}, s.fail("invalid heartbeat facts: " + err.Error())
	}
	if err := ctx.Err(); err != nil {
		return AcceptedRecord{}, s.fail("heartbeat processing canceled: " + err.Error())
	}
	if h.SessionID != s.id || h.SourceInstance != s.enrollment.SourceInstance {
		return AcceptedRecord{}, s.fail("telemetry source or session changed")
	}
	if s.current == nil {
		if h.Sequence != 1 || h.Slot != 0 || h.PreviousDigest != "" {
			return AcceptedRecord{}, s.fail("initial heartbeat must begin sequence 1, slot 0, and an empty chain")
		}
	} else if s.current.Sequence == ^uint64(0) || h.Sequence != s.current.Sequence+1 || s.current.Slot == ^uint64(0) || h.Slot != s.current.Slot+1 || h.PreviousDigest != s.current.Digest {
		s.previous, s.current = s.current, &h
		return AcceptedRecord{}, s.fail("heartbeat sequence, scheduled slot, or signed chain is discontinuous")
	}
	s.previous, s.current = s.current, &h
	if result.Recovery == assurance.TelemetryFreshSessionRequired {
		return AcceptedRecord{}, s.fail("heartbeat integrity requires a fresh attested session")
	}
	return AcceptedRecord{Record: record, SignedDigest: h.Digest, Integrity: result}, nil
}

func (s *Session) decodeRecord(ctx context.Context, raw []byte) (Record, error) {
	payload, err := signedrecords.Verify(ctx, raw, HeartbeatPayloadType, s.key, MaxRecordBytes)
	if err != nil {
		return Record{}, fmt.Errorf("heartbeat signature rejected: %w", err)
	}
	var record Record
	if err := signedrecords.DecodeJSON(payload, &record, MaxRecordBytes); err != nil {
		return Record{}, fmt.Errorf("heartbeat payload invalid: %w", err)
	}
	if record.Version != 1 || len(record.Observations) > MaxEventsPerRecord {
		return Record{}, fmt.Errorf("heartbeat version or observation count is outside its bounds")
	}
	for _, observation := range record.Observations {
		if observation.MediaType != "application/vnd.tetragon.event+json" || len(observation.Payload) == 0 || len(observation.Payload) > 32<<10 {
			return Record{}, fmt.Errorf("observation requires bounded raw Tetragon JSON; split the batch before retrying in a fresh session")
		}
	}
	if err := ctx.Err(); err != nil {
		return Record{}, fmt.Errorf("heartbeat processing canceled: %w", err)
	}
	return record, nil
}

// Snapshot is the watchdog path. It uses verifier time and does not require a
// producer response. No heartbeat can extend the agreed fixed schedule.
func (s *Session) Snapshot(now time.Time) (assurance.TelemetryIntegrity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.IsZero() {
		return assurance.TelemetryIntegrity{State: assurance.AssuranceStateUnknown}, fmt.Errorf("watchdog requires verifier time; inspect its clock before recovery")
	}
	// A watchdog can capture time just before another local operation acquires
	// the mutex. Use that later verified observation rather than treating normal
	// scheduling as a clock rollback. Producer timestamps never enter this path.
	if now.Before(s.lastTime) {
		now = s.lastTime
	}
	s.lastTime = now
	r := assurance.TelemetryIntegrity{State: assurance.AssuranceStateUnknown, SessionID: s.id, RootKind: s.enrollment.RootKind, RootLabel: s.enrollment.RootLabel, Caveats: slices.Clone(s.enrollment.Caveats)}
	if s.current != nil && s.standing != nil {
		var err error
		r, err = assurance.EvaluateTelemetryWindow(s.enrollment.Policy, *s.standing, s.previous, *s.current, now)
		if err != nil {
			return r, err
		}
		if r.Recovery == assurance.TelemetryFreshSessionRequired {
			_ = s.fail("telemetry integrity requires a fresh attested session")
		}
		if s.standing.VerifiedAt.After(r.WindowEnd) {
			r.State = assurance.AssuranceStateUnknown
			r.Reasons = append(r.Reasons, "fresh attestation requires a new complete heartbeat window")
		}
	}
	if s.verifying && !now.Before(s.verificationDeadline) {
		_ = s.fail("quote verification exceeded its verifier challenge deadline")
	}
	if s.challenge != nil && !now.Before(s.challenge.ExpiresAt) {
		_ = s.fail("verifier challenge expired; obtain a fresh attested session")
	}
	if !now.Before(s.opened.Add(24 * time.Hour)) {
		_ = s.fail("maximum session lifetime expired; establish a fresh attested session")
	}
	if expiry := s.opened.Add(24 * time.Hour); r.ValidUntil.IsZero() || expiry.Before(r.ValidUntil) {
		r.ValidUntil = expiry
	}
	if s.standing != nil && !now.Before(s.standing.ExpiresAt) {
		_ = s.fail("attestation expired; establish a fresh attested session")
	}
	if s.standing != nil && s.current == nil && !now.Before(s.standing.StartedAt.Add(s.enrollment.Policy.Tolerance)) {
		_ = s.fail("initial heartbeat deadline missed; establish a fresh attested session")
		r.Gaps = append(r.Gaps, assurance.TelemetryGap{Kind: "HEARTBEAT", First: 0, Last: 0})
	}
	if s.current != nil && !now.Before(s.heartbeatDeadline()) {
		_ = s.fail("heartbeat deadline missed; establish a fresh attested session")
	}
	if s.standing == nil {
		r.Reasons = append(r.Reasons, "attestation is not verified; no telemetry is eligible")
	}
	if s.current == nil {
		r.Reasons = append(r.Reasons, "no signed heartbeat has arrived")
	}
	if s.fault != "" {
		r.State = assurance.AssuranceStateUnknown
		r.Reasons = append(r.Reasons, s.fault)
	}
	return r, nil
}

func (s *Session) Close(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if reason == "" {
		reason = "telemetry channel closed; establish a fresh attested session"
	}
	_ = s.fail(reason)
}

// Standing returns a copied historical attestation and exact verified report
// digest. Call Snapshot independently for current eligibility and gaps; a
// historical standing never bypasses liveness, expiry, or a fenced session.
func (s *Session) Standing() (*assurance.TelemetryAttestation, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.standing == nil {
		return nil, ""
	}
	a := *s.standing
	a.Caveats = slices.Clone(a.Caveats)
	return &a, s.quoteDigest
}

func (s *Session) checkTime(now time.Time) error {
	if s.fault != "" {
		return ErrSessionClosed
	}
	if now.IsZero() || now.Before(s.lastTime) || !now.Before(s.opened.Add(24*time.Hour)) {
		return s.fail("session clock or lifetime is invalid; establish a fresh session")
	}
	s.lastTime = now
	if s.verifying && !now.Before(s.verificationDeadline) {
		return s.fail("quote verification exceeded its verifier challenge deadline")
	}
	if s.challenge != nil && !now.Before(s.challenge.ExpiresAt) {
		return s.fail("verifier challenge expired; establish a fresh session")
	}
	if s.standing != nil && !now.Before(s.standing.ExpiresAt) {
		return s.fail("attestation expired; establish a fresh session")
	}
	if s.standing != nil && s.current == nil && !now.Before(s.standing.StartedAt.Add(s.enrollment.Policy.Tolerance)) {
		return s.fail("initial heartbeat deadline missed; establish a fresh session")
	}
	if s.current != nil && !now.Before(s.heartbeatDeadline()) {
		return s.fail("heartbeat deadline missed; establish a fresh session")
	}
	return nil
}

func (s *Session) heartbeatDeadline() time.Time {
	if s.current == nil || s.standing == nil {
		return time.Time{}
	}
	maximum := uint64(24 * time.Hour / s.enrollment.Policy.HeartbeatInterval)
	if s.current.Slot >= maximum {
		return s.standing.StartedAt
	}
	return s.standing.StartedAt.Add(time.Duration(s.current.Slot+1)*s.enrollment.Policy.HeartbeatInterval + s.enrollment.Policy.Tolerance)
}

func (s *Session) fail(reason string) error {
	if len(reason) > 4096 {
		reason = reason[:4096]
	}
	if s.fault == "" {
		s.fault = reason
	}
	return fmt.Errorf("%w: %s", ErrSessionClosed, reason)
}

func cloneChallenge(c Challenge) Challenge { c.Nonce = bytes.Clone(c.Nonce); return c }

func digestBytes(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	raw, err := hex.DecodeString(value[7:])
	return err == nil && hex.EncodeToString(raw) == value[7:]
}

// EncodeRecord signs this exact JSON serialization; verifiers never reconstruct
// or canonicalize signed payload bytes. The signer remains an outward adapter.
func EncodeRecord(record Record) ([]byte, error) {
	return json.Marshal(record)
}
