package guesttransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/guest"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
	telemetryv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/telemetry/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// ClientConfig supplies actual quote and collection adapters. Both ports must
// honor context cancellation. Run never reconnects or retries a stream.
type ClientConfig struct {
	Target       string
	TLS          *tls.Config
	EnrollmentID string
	Enrollment   guest.Enrollment
	Receipt      ReceiptScope
	ExportKey    ed25519.PrivateKey
	Attester     ports.AttestationProvider
	Sampler      guest.Sampler
	Limits       Limits
}

type ClientStatus struct {
	Running       bool
	State         assurance.AssuranceState
	Reason        string
	SignedReceipt []byte
	CheckedAt     time.Time
	ValidUntil    time.Time
}

type Client struct {
	config ClientConfig
	signer *signedrecords.Signer
	mu     sync.Mutex
	status ClientStatus
}

func NewClient(config ClientConfig) (*Client, error) {
	if config.Target == "" || len(config.Target) > 2048 || config.EnrollmentID == "" || len(config.EnrollmentID) > 128 || nilPort(config.Attester) || nilPort(config.Sampler) {
		return nil, fmt.Errorf("target, enrollment, actual attester and sampler are required")
	}
	if err := validateTLS(config.TLS, false); err != nil {
		return nil, err
	}
	if len(config.TLS.Certificates) == 0 && config.TLS.GetClientCertificate == nil {
		return nil, fmt.Errorf("client mutual TLS identity is required")
	}
	if err := config.Enrollment.Validate(); err != nil {
		return nil, err
	}
	if err := config.Receipt.validate(); err != nil {
		return nil, err
	}
	if config.Limits == (Limits{}) {
		config.Limits = DefaultLimits()
	}
	if err := config.Limits.validate(); err != nil {
		return nil, err
	}
	signer, err := signedrecords.NewSigner(config.ExportKey)
	if err != nil {
		return nil, err
	}
	config.ExportKey = bytes.Clone(config.ExportKey)
	config.Enrollment = cloneEnrollment(config.Enrollment)
	config.Receipt = cloneScope(config.Receipt)
	config.TLS = config.TLS.Clone()
	return &Client{config: config, signer: signer, status: ClientStatus{State: assurance.AssuranceStateUnknown, Reason: "no current attested stream"}}, nil
}
func (c *Client) Status() ClientStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := c.status
	result.SignedReceipt = bytes.Clone(result.SignedReceipt)
	if !result.ValidUntil.IsZero() && !time.Now().Before(result.ValidUntil) {
		result.State = assurance.AssuranceStateUnknown
		result.Reason = "receipt validity expired"
	}
	return result
}

type clientReceived struct {
	frame *telemetryv1.StreamResponse
	err   error
}
type clientSend struct {
	frame  *telemetryv1.StreamRequest
	queued time.Time
}
type quoteWork struct {
	challenge guest.Challenge
	binding   [32]byte
}
type quoteResult struct {
	challenge     guest.Challenge
	report, proof []byte
	err           error
}
type sampleResult struct {
	sample guest.Sample
	err    error
}
type submittedRecord struct {
	digest       string
	sent         time.Time
	record       guest.Record
	acknowledged bool
}
type clientSession struct {
	owner          *Client
	binding        [32]byte
	session        string
	challenge      *guest.Challenge
	quote          *quoteResult
	admission      *telemetryv1.Admission
	standing       *assurance.TelemetryAttestation
	quoteDigest    string
	records        []submittedRecord
	sequence       uint64
	previous       string
	sampling       bool
	sampleDeadline time.Time
}

// Run owns one connection and one stream. Failure always clears current local
// standing, even when a historical signed receipt remains available to inspect.
func (c *Client) Run(parent context.Context) (result error) {
	if parent == nil {
		return fmt.Errorf("client context is required")
	}
	c.mu.Lock()
	if c.status.Running {
		c.mu.Unlock()
		return fmt.Errorf("client stream or adapter workers are still active")
	}
	c.status = ClientStatus{Running: true, State: assurance.AssuranceStateUnknown, Reason: "opening attested stream"}
	c.mu.Unlock()
	ctx, cancel := context.WithCancel(parent)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		drained := make(chan struct{})
		go func() { workers.Wait(); close(drained) }()
		select {
		case <-drained:
			c.mu.Lock()
			c.status.Running = false
			c.mu.Unlock()
		case <-time.After(c.config.Limits.ShutdownTimeout):
			result = errors.Join(result, fmt.Errorf("client adapter shutdown deadline exceeded; client remains fenced"))
		}
		c.mu.Lock()
		c.status.State = assurance.AssuranceStateUnknown
		c.status.Reason = "stream ended; fresh attestation is required"
		c.mu.Unlock()
	}()
	connection, err := grpc.NewClient(c.config.Target, grpc.WithTransportCredentials(credentials.NewTLS(c.config.TLS)), grpc.WithDisableRetry(), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxFrameBytes), grpc.MaxCallSendMsgSize(MaxFrameBytes)))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, connection.Close()) }()
	observer := &ClientBinding{}
	// A deadline cancels the whole stream only if opening exceeds its budget.
	opened := make(chan struct{})
	workers.Go(func() {
		timer := time.NewTimer(c.config.Limits.HelloTimeout)
		defer timer.Stop()
		select {
		case <-opened:
		case <-ctx.Done():
		case <-timer.C:
			cancel()
		}
	})
	stream, err := telemetryv1.NewGuestTelemetryServiceClient(connection).Stream(ctx, grpc.PerRPCCredentials(observer))
	close(opened)
	if err != nil {
		return err
	}
	binding, err := observer.Exporter()
	if err != nil {
		return err
	}
	received := make(chan clientReceived, 1)
	outgoing := make(chan clientSend, 2)
	sent := make(chan error, 3)
	quoteRequests := make(chan quoteWork, 1)
	quotes := make(chan quoteResult, 1)
	sampleRequests := make(chan struct{}, 1)
	samples := make(chan sampleResult, 1)
	workers.Go(func() {
		for {
			frame, receiveErr := stream.Recv()
			select {
			case received <- clientReceived{frame, receiveErr}:
			case <-ctx.Done():
				return
			}
			if receiveErr != nil {
				return
			}
		}
	})
	workers.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case next := <-outgoing:
				if time.Since(next.queued) >= c.config.Limits.SendTimeout {
					select {
					case sent <- context.DeadlineExceeded:
					case <-ctx.Done():
					}
					return
				}
				sendErr := stream.Send(next.frame)
				select {
				case sent <- sendErr:
				case <-ctx.Done():
					return
				}
				if sendErr != nil {
					return
				}
			}
		}
	})
	workers.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case work := <-quoteRequests:
				proof := c.makeQuote(ctx, work)
				select {
				case quotes <- proof:
				case <-ctx.Done():
					return
				}
			}
		}
	})
	workers.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sampleRequests:
				sampleCtx, stop := context.WithTimeout(ctx, c.config.Limits.VerifyTimeout)
				sample, err := c.config.Sampler.Sample(sampleCtx)
				if err == nil {
					err = sampleCtx.Err()
				}
				stop()
				select {
				case samples <- sampleResult{sample, err}:
				case <-ctx.Done():
					return
				}
			}
		}
	})
	run := &clientSession{owner: c, binding: binding}
	pendingSends := []time.Time{}
	enqueue := func(frame *telemetryv1.StreamRequest) error {
		now := time.Now()
		select {
		case outgoing <- clientSend{frame, now}:
			pendingSends = append(pendingSends, now.Add(c.config.Limits.SendTimeout))
			return nil
		default:
			return fmt.Errorf("producer send queue saturated")
		}
	}
	if err := enqueue(&telemetryv1.StreamRequest{Payload: &telemetryv1.StreamRequest_Hello{Hello: &telemetryv1.Hello{EnrollmentId: c.config.EnrollmentID, ExportPublicKey: bytes.Clone(c.config.ExportKey.Public().(ed25519.PublicKey))}}}); err != nil {
		return err
	}
	initialDeadline := time.Now().Add(c.config.Limits.HelloTimeout)
	ticker := time.NewTicker(min(100*time.Millisecond, c.config.Enrollment.Policy.HeartbeatInterval/4))
	defer ticker.Stop()
	requestSample := func() {
		if !run.sampling {
			run.sampling = true
			run.sampleDeadline = time.Now().Add(c.config.Limits.VerifyTimeout)
			sampleRequests <- struct{}{}
		}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-sent:
			if err != nil {
				return err
			}
			if len(pendingSends) > 0 {
				pendingSends = pendingSends[1:]
			}
		case now := <-ticker.C:
			if run.sampling && !now.Before(run.sampleDeadline) {
				return fmt.Errorf("sample operation deadline exceeded")
			}
			for _, pending := range run.records {
				if !pending.acknowledged && !now.Before(pending.sent.Add(c.config.Limits.PublishTimeout+c.config.Limits.SendTimeout)) {
					return fmt.Errorf("receipt acknowledgement deadline exceeded")
				}
			}
			if len(pendingSends) > 0 && !now.Before(pendingSends[0]) {
				return fmt.Errorf("producer send deadline exceeded")
			}
			if run.standing == nil {
				if !now.Before(initialDeadline) {
					return fmt.Errorf("initial attestation admission deadline exceeded")
				}
				continue
			}
			if !now.Before(run.standing.ExpiresAt) {
				return fmt.Errorf("attestation expired")
			}
			if run.challenge != nil && !now.Before(run.challenge.ExpiresAt) {
				return fmt.Errorf("re-attestation challenge expired")
			}
			if run.sequence == 0 || !now.Before(run.standing.StartedAt.Add(time.Duration(run.records[len(run.records)-1].record.Slot+1)*c.config.Enrollment.Policy.HeartbeatInterval)) {
				requestSample()
			}
		case proof := <-quotes:
			if proof.err != nil {
				return proof.err
			}
			run.quote = &proof
			if err := enqueue(&telemetryv1.StreamRequest{Payload: &telemetryv1.StreamRequest_Quote{Quote: &telemetryv1.QuoteResponse{ChallengeId: proof.challenge.ID, AttestationReport: proof.report, SignedExportKeyProof: proof.proof}}}); err != nil {
				return err
			}
		case sample := <-samples:
			run.sampling = false
			if sample.err != nil {
				return sample.err
			}
			frame, err := run.heartbeat(ctx, sample.sample, time.Now().UTC())
			if err != nil {
				return err
			}
			if err := enqueue(frame); err != nil {
				return err
			}
		case incoming := <-received:
			if incoming.err != nil {
				return incoming.err
			}
			frame := incoming.frame
			if frame == nil || len(frame.ProtoReflect().GetUnknown()) != 0 {
				return fmt.Errorf("invalid verifier frame")
			}
			switch body := frame.Payload.(type) {
			case *telemetryv1.StreamResponse_Challenge:
				challenge, err := run.parseChallenge(body.Challenge, time.Now().UTC())
				if err != nil {
					return err
				}
				run.challenge = &challenge
				select {
				case quoteRequests <- quoteWork{challenge, binding}:
				default:
					return fmt.Errorf("quote worker saturated")
				}
			case *telemetryv1.StreamResponse_Admission:
				if err := run.acceptAdmission(body.Admission); err != nil {
					return err
				}
			case *telemetryv1.StreamResponse_SignedReceipt:
				if err := run.receipt(ctx, body.SignedReceipt, time.Now().UTC()); err != nil {
					return err
				}
				if run.standing != nil && run.sequence == 0 {
					requestSample()
				}
			default:
				return fmt.Errorf("unexpected verifier frame")
			}
		}
	}
}
func (c *Client) makeQuote(ctx context.Context, work quoteWork) quoteResult {
	result := quoteResult{challenge: work.challenge}
	qualification, err := guest.Qualification(work.challenge, c.config.ExportKey.Public().(ed25519.PublicKey), work.binding)
	if err != nil {
		result.err = err
		return result
	}
	op, cancel := context.WithDeadline(ctx, minTime(work.challenge.ExpiresAt, time.Now().Add(c.config.Limits.VerifyTimeout)))
	defer cancel()
	result.report, result.err = c.config.Attester.Attest(op, qualification)
	if result.err != nil {
		return result
	}
	if err := op.Err(); err != nil {
		result.err = err
		return result
	}
	if len(result.report) == 0 || len(result.report) > guest.MaxReportBytes {
		result.err = fmt.Errorf("attester report exceeds bounds")
		return result
	}
	payload, err := json.Marshal(guest.QuoteProof{Version: 1, SessionID: work.challenge.SessionID, ChallengeID: work.challenge.ID, ReportDigest: assurance.ComputeDigest(result.report)})
	if err != nil {
		result.err = err
		return result
	}
	result.proof, result.err = c.signer.Sign(op, guest.QuoteProofPayloadType, payload)
	return result
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (r *clientSession) parseChallenge(wire *telemetryv1.Challenge, now time.Time) (guest.Challenge, error) {
	if wire == nil || len(wire.ProtoReflect().GetUnknown()) != 0 || wire.IssuedAt == nil || wire.ExpiresAt == nil || wire.IssuedAt.CheckValid() != nil || wire.ExpiresAt.CheckValid() != nil {
		return guest.Challenge{}, fmt.Errorf("invalid challenge framing")
	}
	c := guest.Challenge{Version: wire.Version, SessionID: wire.SessionId, ID: wire.ChallengeId, Nonce: bytes.Clone(wire.Nonce), EnrollmentDigest: wire.EnrollmentDigest, IssuedAt: wire.IssuedAt.AsTime(), ExpiresAt: wire.ExpiresAt.AsTime()}
	if r.challenge != nil || c.EnrollmentDigest != r.owner.config.Enrollment.PolicyDigest || c.IssuedAt.After(now) || !now.Before(c.ExpiresAt) || !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > r.owner.config.Enrollment.ChallengeTTL || r.session != "" && r.session != c.SessionID {
		return c, fmt.Errorf("challenge does not match current session, enrolled policy or time")
	}
	if _, err := guest.Qualification(c, r.owner.config.ExportKey.Public().(ed25519.PublicKey), r.binding); err != nil {
		return c, err
	}
	r.session = c.SessionID
	return c, nil
}
func (r *clientSession) acceptAdmission(a *telemetryv1.Admission) error {
	e := r.owner.config.Enrollment
	if a == nil || r.quote == nil || r.challenge == nil || r.admission != nil || len(a.ProtoReflect().GetUnknown()) != 0 || a.HeartbeatStart == nil || a.AttestationExpiresAt == nil || a.HeartbeatStart.CheckValid() != nil || a.AttestationExpiresAt.CheckValid() != nil || a.SessionId != r.session || a.RootKind != e.RootKind || a.RootLabel != e.RootLabel || !slices.Equal(a.Caveats, e.Caveats) {
		return fmt.Errorf("admission does not match outstanding quote and enrollment")
	}
	r.admission = a
	return nil
}
func (r *clientSession) heartbeat(ctx context.Context, sample guest.Sample, now time.Time) (*telemetryv1.StreamRequest, error) {
	if r.standing == nil || sample.SourceInstance != r.owner.config.Enrollment.SourceInstance || sample.SampledAt.IsZero() || sample.SampledAt.After(now) {
		return nil, fmt.Errorf("actual sample must match admitted source and observation time")
	}
	if now.Before(r.standing.StartedAt) {
		return nil, fmt.Errorf("heartbeat schedule has not started")
	}
	pending := 0
	for _, record := range r.records {
		if !record.acknowledged {
			pending++
		}
	}
	if pending >= 16 {
		return nil, fmt.Errorf("unacknowledged heartbeat capacity reached")
	}
	if err := sampleBounds(sample); err != nil {
		return nil, err
	}
	slot := uint64(now.Sub(r.standing.StartedAt) / r.owner.config.Enrollment.Policy.HeartbeatInterval)
	record := guest.Record{Version: 1, SessionID: r.session, SourceInstance: sample.SourceInstance, Sequence: r.sequence + 1, Slot: slot, SampledAt: sample.SampledAt, PreviousDigest: r.previous, Counters: sample.Counters, Observations: sample.Observations}
	payload, err := guest.EncodeRecord(record)
	if err != nil {
		return nil, err
	}
	raw, err := r.owner.signer.Sign(ctx, guest.HeartbeatPayloadType, payload)
	if err != nil {
		return nil, err
	}
	digest := assurance.ComputeDigest(raw)
	record.Observations = nil
	record.Counters = nil
	r.records = append(r.records, submittedRecord{digest: digest, sent: now, record: record})
	if len(r.records) > 32 {
		r.records = slices.Clone(r.records[len(r.records)-32:])
	}
	r.sequence++
	r.previous = digest
	return &telemetryv1.StreamRequest{Payload: &telemetryv1.StreamRequest_SignedHeartbeat{SignedHeartbeat: raw}}, nil
}

func (r *clientSession) receipt(ctx context.Context, raw []byte, now time.Time) error {
	scope := r.owner.config.Receipt
	verified, err := receipts.VerifyAttestedReceipt(ctx, raw, scope.Key, &scope.Authority, now)
	if err != nil {
		return err
	}
	body := verified.Body
	t := body.Telemetry
	a := t.Attestation
	e := r.owner.config.Enrollment
	if body.Receipt.Evaluator != scope.Authority || body.Receipt.Subject.URI() != scope.Subject.URI() || !maps.Equal(body.Receipt.Subject.Attributes, scope.Subject.Attributes) || body.Receipt.Control != scope.Control || body.Receipt.Epoch != scope.Epoch || body.Receipt.EvaluatedAt.After(now) {
		return fmt.Errorf("receipt assessment scope differs from enrollment")
	}
	if t.Integrity.SessionID != r.session || t.Integrity.RootKind != e.RootKind || t.Integrity.RootLabel != e.RootLabel || !slices.Equal(t.Integrity.Caveats, e.Caveats) {
		return fmt.Errorf("receipt integrity session/root differs from enrollment")
	}
	if a == nil {
		return fmt.Errorf("receipt has no admitted attestation")
	}
	if a.SessionID != r.session || a.SourceInstance != e.SourceInstance || a.MeasurementDigest != e.MeasurementDigest || a.ExportKeyDigest != assurance.ComputeDigest(r.owner.config.ExportKey.Public().(ed25519.PublicKey)) || a.ChannelDigest != assurance.ComputeDigest(r.binding[:]) || a.RootKind != e.RootKind || a.RootLabel != e.RootLabel || !slices.Equal(a.Caveats, e.Caveats) {
		return fmt.Errorf("receipt attestation is unrelated to actual client channel/key/enrollment")
	}
	if !a.ExpiresAt.Equal(a.VerifiedAt.Add(e.Policy.MaxAttestationAge)) {
		return fmt.Errorf("receipt attestation expiry differs from enrolled policy")
	}
	admission := r.admission != nil
	if admission {
		if r.quote == nil || t.QuoteDigest != assurance.ComputeDigest(r.quote.report) || !a.StartedAt.Equal(r.admission.HeartbeatStart.AsTime()) || !a.ExpiresAt.Equal(r.admission.AttestationExpiresAt.AsTime()) || a.VerifiedAt.Before(r.quote.challenge.IssuedAt) || a.VerifiedAt.After(now) || body.Receipt.EvaluatedAt.Before(r.quote.challenge.IssuedAt) {
			return fmt.Errorf("receipt does not acknowledge outstanding quote")
		}
		if r.standing != nil && !a.StartedAt.Equal(r.standing.StartedAt) {
			return fmt.Errorf("re-attestation changed heartbeat schedule")
		}
	} else if !sameStanding(a, r.standing) || t.QuoteDigest != r.quoteDigest {
		return fmt.Errorf("receipt replay or unacknowledged quote")
	}
	if t.RecordDigest != "" {
		found := false
		for i := range r.records {
			p := &r.records[i]
			if p.digest != t.RecordDigest {
				continue
			}
			found = true
			if body.Receipt.EvaluatedAt.Before(p.sent) || !t.Integrity.WindowEnd.Equal(p.record.SampledAt) {
				return fmt.Errorf("receipt record window/time differs from sent heartbeat")
			}
			if p.acknowledged && !admission && t.Integrity.Recovery != assurance.TelemetryFreshSessionRequired {
				return fmt.Errorf("duplicate receipt acknowledgement")
			}
			p.acknowledged = true
			break
		}
		if !found {
			return fmt.Errorf("receipt references an unsent or evicted record")
		}
	} else if r.sequence != 0 {
		return fmt.Errorf("receipt omitted submitted record binding")
	}
	if (verified.SignedState == assurance.AssuranceStateVerified || verified.SignedState == assurance.AssuranceStateAssured) && verified.EffectiveState == assurance.AssuranceStateUnknown {
		return fmt.Errorf("receipt expired before client acknowledgement")
	}
	if admission {
		copy := *a
		copy.Caveats = slices.Clone(a.Caveats)
		r.standing = &copy
		r.quoteDigest = t.QuoteDigest
		r.admission = nil
		r.quote = nil
		r.challenge = nil
	}
	r.owner.mu.Lock()
	r.owner.status.State = verified.EffectiveState
	r.owner.status.SignedReceipt = bytes.Clone(raw)
	r.owner.status.CheckedAt = now
	r.owner.status.ValidUntil = body.ValidUntil
	r.owner.status.Reason = "verified receipt for current stream"
	r.owner.mu.Unlock()
	if t.Integrity.Recovery == assurance.TelemetryFreshSessionRequired {
		return guest.ErrSessionClosed
	}
	return nil
}

// Check allocations before JSON expands binary observation payloads into base64.
func sampleBounds(s guest.Sample) error {
	if len(s.Counters) > assurance.MaxTelemetrySignals || len(s.Observations) > guest.MaxEventsPerRecord {
		return fmt.Errorf("sample batch exceeds count limits")
	}
	total := 0
	for _, counter := range s.Counters {
		if len(counter.ID) > 1024 || len(counter.Reason) > 4096 || len(counter.Status) > 64 {
			return fmt.Errorf("counter identifier exceeds limit")
		}
		total += len(counter.ID) + len(counter.Reason) + 256
	}
	for _, event := range s.Observations {
		if len(event.MediaType) > 256 || len(event.Payload) > 32<<10 {
			return fmt.Errorf("observation exceeds limit")
		}
		total += len(event.MediaType) + ((len(event.Payload)+2)/3)*4 + 256
	}
	if total > guest.MaxRecordBytes-8192 {
		return fmt.Errorf("sample batch exceeds signed payload capacity")
	}
	return nil
}
