package guesttransport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/guest"
	telemetryv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/telemetry/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type ServerStatus struct {
	Mode            string
	Reason          string
	Active          bool
	LastPublication time.Time
	Integrity       assurance.AssuranceState
	Standing        assurance.AssuranceState
}
type Server struct {
	telemetryv1.UnimplementedGuestTelemetryServiceServer
	config     ServerConfig
	rpc        *grpc.Server
	streams    chan struct{}
	workers    chan struct{}
	generation atomic.Uint64
	mu         sync.Mutex
	state      ServerStatus
	handlers   sync.WaitGroup
	stopping   bool
}

func NewServer(config ServerConfig) (*Server, error) {
	if nilPort(config.Publisher) || nilPort(config.Verifier) {
		return nil, fmt.Errorf("real durable publisher and attestation verifier are required")
	}
	if config.EnrollmentID == "" || len(config.EnrollmentID) > 128 || strings.TrimSpace(config.EnrollmentID) != config.EnrollmentID {
		return nil, fmt.Errorf("one exact outside enrollment ID is required")
	}
	if err := config.Enrollment.Policy.Validate(); err != nil {
		return nil, err
	}
	if err := config.Receipt.validate(); err != nil {
		return nil, err
	}
	if err := validateTLS(config.TLS, true); err != nil {
		return nil, err
	}
	if config.Limits == (Limits{}) {
		config.Limits = DefaultLimits()
	}
	if err := config.Limits.validate(); err != nil {
		return nil, err
	}
	config.Enrollment = cloneEnrollment(config.Enrollment)
	config.Receipt = cloneScope(config.Receipt)
	config.TLS = config.TLS.Clone()
	server := &Server{config: config, streams: make(chan struct{}, config.Limits.MaxStreams), workers: make(chan struct{}, config.Limits.MaxStreams*2), state: ServerStatus{Mode: "AWAITING_ATTESTATION", Integrity: assurance.AssuranceStateUnknown, Standing: assurance.AssuranceStateUnknown}}
	server.rpc = grpc.NewServer(grpc.Creds(credentials.NewTLS(config.TLS)), grpc.MaxRecvMsgSize(MaxFrameBytes), grpc.MaxSendMsgSize(MaxFrameBytes), grpc.MaxConcurrentStreams(1), grpc.ConnectionTimeout(config.Limits.HelloTimeout), grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: 30 * time.Second, Time: 30 * time.Second, Timeout: 5 * time.Second}))
	telemetryv1.RegisterGuestTelemetryServiceServer(server.rpc, server)
	return server, nil
}
func (s *Server) Status() ServerStatus { s.mu.Lock(); defer s.mu.Unlock(); return s.state }
func (s *Server) hold(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Mode = "SAFE_HOLD"
	s.state.Integrity = assurance.AssuranceStateUnknown
	s.state.Standing = assurance.AssuranceStateUnknown
	s.state.Reason = boundedReason(err.Error())
}
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if ctx == nil || listener == nil {
		return fmt.Errorf("server context and raw TCP listener are required")
	}
	limited := newConnectionListener(listener, s.config.Limits.MaxConnections)
	defer func() { _ = limited.Close() }()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
			return
		case <-ctx.Done():
		}
		s.Stop()
	}()
	serveErr := s.rpc.Serve(limited)
	s.Stop()
	drained := make(chan struct{})
	go func() { s.handlers.Wait(); close(drained) }()
	timer := time.NewTimer(s.config.Limits.ShutdownTimeout)
	defer timer.Stop()
	select {
	case <-drained:
		if errors.Is(serveErr, grpc.ErrServerStopped) {
			return nil
		}
		return serveErr
	case <-timer.C:
		err := fmt.Errorf("guest stream shutdown deadline exceeded; UNKNOWN publication may be incomplete")
		s.hold(err)
		return errors.Join(serveErr, err)
	}
}
func (s *Server) Stop() { s.mu.Lock(); s.stopping = true; s.mu.Unlock(); s.rpc.Stop() }

func (s *Server) nextGeneration() (uint64, error) {
	for {
		current := s.generation.Load()
		if current == math.MaxUint64 {
			return 0, fmt.Errorf("session generation exhausted; replace publisher and server")
		}
		if s.generation.CompareAndSwap(current, current+1) {
			return current + 1, nil
		}
	}
}
func boundedReason(reason string) string {
	if len(reason) > 2048 {
		return reason[:2048]
	}
	return reason
}

type receivedFrame struct {
	frame *telemetryv1.StreamRequest
	err   error
}
type outgoingFrame struct {
	id    uint64
	frame *telemetryv1.StreamResponse
}
type sentFrame struct {
	id  uint64
	err error
}
type terminalOutcome struct {
	receipt []byte
	err     error
}

func (s *Server) Stream(stream telemetryv1.GuestTelemetryService_StreamServer) error {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return status.Error(codes.Unavailable, "server is stopping")
	}
	s.handlers.Add(1)
	s.mu.Unlock()
	defer s.handlers.Done()
	select {
	case s.streams <- struct{}{}:
		defer func() { <-s.streams }()
	default:
		return status.Error(codes.ResourceExhausted, "global stream capacity reached")
	}
	for acquired := 0; acquired < 2; acquired++ {
		select {
		case s.workers <- struct{}{}:
		default:
			for range acquired {
				<-s.workers
			}
			return status.Error(codes.ResourceExhausted, "prior stream I/O is still draining")
		}
	}
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	input := make(chan receivedFrame, 1)
	output := make(chan outgoingFrame, 2)
	sent := make(chan sentFrame, 3)
	go func() {
		defer func() { <-s.workers; close(input) }()
		for {
			if ctx.Err() != nil {
				return
			}
			frame, err := stream.Recv()
			select {
			case input <- receivedFrame{frame, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { <-s.workers }()
		for {
			select {
			case <-ctx.Done():
				return
			case next := <-output:
				err := stream.Send(next.frame)
				select {
				case sent <- sentFrame{next.id, err}:
				case <-ctx.Done():
					return
				}
				if err != nil {
					return
				}
			}
		}
	}()
	binding, err := ServerChannelBinding(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	timer := time.NewTimer(s.config.Limits.HelloTimeout)
	defer timer.Stop()
	var first receivedFrame
	select {
	case first = <-input:
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return status.Error(codes.DeadlineExceeded, "hello deadline exceeded")
	}
	if first.err != nil {
		return first.err
	}
	hello := first.frame.GetHello()
	if hello == nil || len(first.frame.ProtoReflect().GetUnknown()) != 0 || len(hello.ProtoReflect().GetUnknown()) != 0 || hello.EnrollmentId != s.config.EnrollmentID || len(hello.ExportPublicKey) != 32 {
		return status.Error(codes.InvalidArgument, "first frame must identify the exact enrollment and export public key")
	}
	s.mu.Lock()
	if s.state.Mode == "SAFE_HOLD" || s.state.Active {
		s.mu.Unlock()
		return status.Error(codes.FailedPrecondition, "source is active or quarantined; wait for fencing before a fresh session")
	}
	s.state.Active = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.state.Active = false; s.mu.Unlock() }()
	session, err := guest.NewSession(s.config.Enrollment, s.config.Verifier, hello.ExportPublicKey, binding, time.Now().UTC())
	if err != nil {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	generation, err := s.nextGeneration()
	if err != nil {
		s.hold(err)
		return status.Error(codes.ResourceExhausted, err.Error())
	}
	operations, stopOperations := context.WithCancel(ctx)
	defer stopOperations()
	run := &serverSession{owner: s, session: session, generation: generation, key: bytes.Clone(hello.ExportPublicKey), operations: operations, cancelOperations: stopOperations, transport: stream.Context(), terminal: make(chan terminalOutcome, 1)}
	challenge, err := session.Challenge(time.Now().UTC())
	if err != nil {
		return err
	}
	run.pending = &challenge
	outgoingID := uint64(0)
	pendingSends := map[uint64]time.Time{}
	enqueue := func(frame *telemetryv1.StreamResponse) error {
		outgoingID++
		item := outgoingFrame{id: outgoingID, frame: frame}
		select {
		case output <- item:
			pendingSends[item.id] = time.Now().Add(s.config.Limits.SendTimeout)
			return nil
		default:
			return fmt.Errorf("outbound frame queue saturated")
		}
	}
	if err := enqueue(challengeFrame(challenge)); err != nil {
		return err
	}
	watchDone := make(chan struct{})
	defer close(watchDone)
	go run.watch(watchDone)
	tick := time.NewTicker(min(100*time.Millisecond, s.config.Enrollment.Policy.Tolerance/4))
	defer tick.Stop()
	finish := func(outcome terminalOutcome) error {
		if len(outcome.receipt) > 0 && stream.Context().Err() == nil {
			id := outgoingID + 1
			if err := enqueue(&telemetryv1.StreamResponse{Payload: &telemetryv1.StreamResponse_SignedReceipt{SignedReceipt: outcome.receipt}}); err == nil {
				flush := time.NewTimer(s.config.Limits.SendTimeout)
				defer flush.Stop()
				for {
					select {
					case result := <-sent:
						if result.id == id {
							return outcome.err
						}
						if result.err != nil {
							return errors.Join(outcome.err, result.err)
						}
					case <-flush.C:
						return outcome.err
					case <-stream.Context().Done():
						return outcome.err
					}
				}
			}
		}
		return outcome.err
	}
	for {
		if operations.Err() != nil {
			run.fail("session operation context ended", operations.Err())
			return finish(<-run.terminal)
		}
		select {
		case outcome := <-run.terminal:
			return finish(outcome)
		case <-stream.Context().Done():
			run.fail("telemetry channel disconnected", stream.Context().Err())
		case result := <-sent:
			delete(pendingSends, result.id)
			if result.err != nil {
				run.fail("sending verifier response failed", result.err)
			}
		case now := <-tick.C:
			for _, deadline := range pendingSends {
				if !now.Before(deadline) {
					run.fail("verifier send deadline exceeded", context.DeadlineExceeded)
					break
				}
			}
			if operations.Err() != nil {
				continue
			}
			standing, _ := session.Standing()
			if standing != nil && run.pending == nil && !time.Now().Before(standing.VerifiedAt.Add(s.config.Enrollment.ReattestInterval)) {
				next, err := session.Challenge(time.Now().UTC())
				if err != nil {
					run.fail("re-attestation challenge failed", err)
					continue
				}
				run.pending = &next
				if err := enqueue(challengeFrame(next)); err != nil {
					run.fail("re-attestation delivery backpressure", err)
				}
			}
		case incoming, ok := <-input:
			if !ok || incoming.err != nil {
				cause := incoming.err
				if cause == nil {
					cause = io.EOF
				}
				run.fail("telemetry stream ended", cause)
				continue
			}
			if operations.Err() != nil {
				continue
			}
			frame := incoming.frame
			if frame == nil || len(frame.ProtoReflect().GetUnknown()) != 0 {
				run.fail("invalid stream framing", status.Error(codes.InvalidArgument, "unknown stream fields"))
				continue
			}
			if quote := frame.GetQuote(); quote != nil {
				if err := run.quote(quote); err != nil {
					run.fail("quote admission failed", err)
					continue
				}
				standing, _ := session.Standing()
				receipt, err := run.publish(nil, "quote admitted")
				if err != nil {
					run.fail("admission publication failed", err)
					continue
				}
				if err := enqueue(admissionFrame(standing)); err != nil {
					run.fail("admission delivery backpressure", err)
					continue
				}
				if err := enqueue(&telemetryv1.StreamResponse{Payload: &telemetryv1.StreamResponse_SignedReceipt{SignedReceipt: receipt}}); err != nil {
					run.fail("receipt delivery backpressure", err)
				}
			} else if raw := frame.GetSignedHeartbeat(); len(raw) > 0 {
				run.material.Lock()
				run.heartbeat = bytes.Clone(raw)
				run.recordDigest = assurance.ComputeDigest(raw)
				run.material.Unlock()
				op, stop := context.WithTimeout(operations, s.config.Limits.VerifyTimeout)
				accepted, err := session.AcceptRecord(op, raw, time.Now().UTC())
				stop()
				if err != nil {
					run.fail("heartbeat admission failed", err)
					continue
				}
				receipt, err := run.publish(&accepted, "heartbeat accepted")
				if err != nil {
					run.fail("heartbeat publication failed", err)
					continue
				}
				if err := enqueue(&telemetryv1.StreamResponse{Payload: &telemetryv1.StreamResponse_SignedReceipt{SignedReceipt: receipt}}); err != nil {
					run.fail("receipt delivery backpressure", err)
				}
			} else {
				run.fail("unexpected stream frame", status.Error(codes.InvalidArgument, "expected quote or signed heartbeat"))
			}
		}
	}
}

func challengeFrame(c guest.Challenge) *telemetryv1.StreamResponse {
	return &telemetryv1.StreamResponse{Payload: &telemetryv1.StreamResponse_Challenge{Challenge: &telemetryv1.Challenge{Version: c.Version, SessionId: c.SessionID, ChallengeId: c.ID, Nonce: bytes.Clone(c.Nonce), EnrollmentDigest: c.EnrollmentDigest, IssuedAt: timestamppb.New(c.IssuedAt), ExpiresAt: timestamppb.New(c.ExpiresAt)}}}
}
func admissionFrame(a *assurance.TelemetryAttestation) *telemetryv1.StreamResponse {
	return &telemetryv1.StreamResponse{Payload: &telemetryv1.StreamResponse_Admission{Admission: &telemetryv1.Admission{SessionId: a.SessionID, HeartbeatStart: timestamppb.New(a.StartedAt), AttestationExpiresAt: timestamppb.New(a.ExpiresAt), RootKind: a.RootKind, RootLabel: a.RootLabel, Caveats: slices.Clone(a.Caveats)}}}
}

type serverSession struct {
	owner                    *Server
	session                  *guest.Session
	generation               uint64
	key                      []byte
	operations               context.Context
	cancelOperations         context.CancelFunc
	transport                context.Context
	terminal                 chan terminalOutcome
	once                     sync.Once
	material                 sync.Mutex
	pending                  *guest.Challenge // stream handler owns pending
	admittedChallenge        *guest.Challenge
	report, proof, heartbeat []byte
	recordDigest             string
	rejected                 *guest.QuoteAttempt
}

func (r *serverSession) quote(q *telemetryv1.QuoteResponse) error {
	r.material.Lock()
	r.rejected = &guest.QuoteAttempt{ChallengeID: q.ChallengeId, AttestationReport: bytes.Clone(q.AttestationReport), SignedExportKeyProof: bytes.Clone(q.SignedExportKeyProof)}
	if r.pending != nil {
		copy := *r.pending
		copy.Nonce = bytes.Clone(copy.Nonce)
		r.rejected.Challenge = &copy
	}
	r.material.Unlock()
	if len(q.ProtoReflect().GetUnknown()) != 0 || len(q.AttestationReport) == 0 || len(q.AttestationReport) > guest.MaxReportBytes || len(q.SignedExportKeyProof) == 0 || len(q.SignedExportKeyProof) > maxQuoteProofBytes {
		return fmt.Errorf("quote frame exceeds admission bounds")
	}
	op, cancel := context.WithTimeout(r.operations, r.owner.config.Limits.VerifyTimeout)
	defer cancel()
	if _, err := r.session.AcceptQuote(op, q.ChallengeId, q.AttestationReport, q.SignedExportKeyProof, time.Now().UTC()); err != nil {
		return err
	}
	r.material.Lock()
	r.report = bytes.Clone(q.AttestationReport)
	r.proof = bytes.Clone(q.SignedExportKeyProof)
	r.admittedChallenge = r.pending
	r.rejected = nil
	r.material.Unlock()
	r.pending = nil
	return nil
}
func (r *serverSession) publication(accepted *guest.AcceptedRecord, reason string) (guest.Publication, error) {
	now := time.Now().UTC()
	integrity, err := r.session.Snapshot(now)
	if err != nil {
		return guest.Publication{}, err
	}
	standing, quoteDigest := r.session.Standing()
	r.material.Lock()
	defer r.material.Unlock()
	return guest.Publication{EnrollmentID: r.owner.config.EnrollmentID, SessionGeneration: r.generation, SessionID: integrity.SessionID, ObservedAt: now, ExportPublicKey: bytes.Clone(r.key), Challenge: r.admittedChallenge, AttestationReport: bytes.Clone(r.report), SignedExportKeyProof: bytes.Clone(r.proof), SignedHeartbeat: bytes.Clone(r.heartbeat), RecordDigest: r.recordDigest, Accepted: accepted, Integrity: integrity, Standing: standing, QuoteDigest: quoteDigest, Reason: boundedReason(reason), RejectedQuote: r.rejected}, nil
}
func (r *serverSession) publish(accepted *guest.AcceptedRecord, reason string) ([]byte, error) {
	publication, err := r.publication(accepted, reason)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(r.operations, r.owner.config.Limits.PublishTimeout)
	defer cancel()
	receipt, err := r.owner.publish(ctx, publication)
	if err != nil && r.operations.Err() == nil {
		r.owner.hold(err)
	}
	return receipt, err
}
func (s *Server) publish(ctx context.Context, p guest.Publication) (receipt []byte, err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("publisher panicked; durable outcome is unknown")
		}
	}()
	receipt, err = s.config.Publisher.Publish(ctx, clonePublication(p))
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	verified, err := verifyPublicationReceipt(ctx, receipt, p, s.config.Receipt, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.state.LastPublication = p.ObservedAt
	if s.state.Mode != "SAFE_HOLD" {
		s.state.Mode = "RUNNING"
		if p.Integrity.Recovery == assurance.TelemetryFreshSessionRequired {
			s.state.Mode = "FENCED"
		}
		s.state.Integrity = verified.Body.Telemetry.Integrity.State
		s.state.Standing = verified.EffectiveState
		s.state.Reason = p.Reason
	}
	s.mu.Unlock()
	return receipt, nil
}
func (r *serverSession) fail(reason string, cause error) {
	r.once.Do(func() {
		r.cancelOperations()
		r.session.Close(reason)
		p, err := r.publication(nil, reason)
		var receipt []byte
		if err == nil {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.transport), r.owner.config.Limits.PublishTimeout)
			receipt, err = r.owner.publish(ctx, p)
			cancel()
		}
		if err != nil {
			r.owner.hold(fmt.Errorf("UNKNOWN publication failed: %w", err))
		}
		r.terminal <- terminalOutcome{receipt: receipt, err: errors.Join(cause, err)}
	})
}
func (r *serverSession) watch(done <-chan struct{}) {
	interval := min(250*time.Millisecond, r.owner.config.Enrollment.Policy.Tolerance/4, r.owner.config.Enrollment.ChallengeTTL/4)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-r.operations.Done():
			return
		case <-ticker.C:
			integrity, err := r.session.Snapshot(time.Now().UTC())
			if err != nil {
				r.fail("independent watchdog failed", err)
				return
			}
			if integrity.Recovery == assurance.TelemetryFreshSessionRequired {
				r.fail("independent watchdog fenced telemetry", guest.ErrSessionClosed)
				return
			}
		}
	}
}
