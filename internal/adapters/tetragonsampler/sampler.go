package tetragonsampler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	api "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragonhealth"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/guest"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const HealthPayloadType = "application/vnd.oskal.tetragon-health.v1+json"
const MaxBatchBytes = 256 << 10
const MaxHealthBytes = 512 << 10
const MaxEventBytes = 32 << 10

// Config is owned by the outside launcher. Connection must dial the enrolled
// local Unix endpoint without retry or a substituted/custom remote dialer.
// SocketOwnerUID/GID are outside-owned DAC expectations, not peer identity.
type Config struct {
	Connection                     *grpc.ClientConn
	Metrics                        tetragonhealth.MetricsReader
	Native                         tetragonhealth.Enrollment
	GrantPath                      string
	GrantKey                       ed25519.PublicKey
	SourceInstance                 string
	Namespace                      string
	ReadTimeout                    time.Duration
	SocketOwnerUID, SocketOwnerGID uint32
}

// HealthEvidence preserves original family/label/kind semantics, including
// non-loss totals and occupancy gauges. SignedReadGrant contains the exact DSSE
// envelope whose hash appears in Kernel.GrantDigest.
type HealthEvidence struct {
	Contract             string                       `json:"contract"`
	SourceInstance       string                       `json:"sourceInstance"`
	APIVersion           string                       `json:"apiVersion"`
	NativeEnrollment     tetragonhealth.Enrollment    `json:"nativeEnrollment"`
	SignedReadGrant      []byte                       `json:"signedReadGrant"`
	Metrics              tetragonhealth.MetricsSample `json:"metrics"`
	Kernel               tetragonhealth.KernelWitness `json:"kernel"`
	StreamThrottleEvents uint64                       `json:"streamThrottleEvents"`
	Caveats              []string                     `json:"caveats"`
}

type Sampler struct {
	config     Config
	socket     string
	gate       chan struct{}
	mu         sync.Mutex
	phase      string
	cancel     context.CancelFunc
	done       chan struct{}
	fault      error
	version    string
	events     []guest.Observation
	eventBytes int
	throttles  uint64
	previous   map[string]uint64
}

var _ guest.Sampler = (*Sampler)(nil)

func New(c Config) (*Sampler, error) {
	if c.Connection == nil || c.SourceInstance == "" || len(c.SourceInstance) > 1024 || strings.TrimSpace(c.SourceInstance) != c.SourceInstance || c.Namespace == "" || len(c.Namespace) > 253 || len(c.GrantKey) != ed25519.PublicKeySize || !filepath.IsAbs(c.GrantPath) || filepath.Clean(c.GrantPath) != c.GrantPath || c.ReadTimeout < time.Millisecond || c.ReadTimeout > 5*time.Second {
		return nil, fmt.Errorf("explicit connection, source, namespace, signed grant pin/path and bounded read timeout are required")
	}
	if err := c.Native.Validate(); err != nil {
		return nil, err
	}
	if err := c.Metrics.Validate(); err != nil {
		return nil, err
	}
	socket := strings.TrimPrefix(c.Connection.Target(), "unix://")
	if socket == c.Connection.Target() || !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
		return nil, fmt.Errorf("sampler requires an explicit local Unix gRPC target")
	}
	c.GrantKey = bytes.Clone(c.GrantKey)
	c.Native.Maps = slices.Clone(c.Native.Maps)
	return &Sampler{config: c, socket: socket, gate: make(chan struct{}, 1), done: make(chan struct{}), previous: make(map[string]uint64), phase: "NEW"}, nil
}

func (s *Sampler) RequiredSignals() []string { return RequiredSignals() }

func (s *Sampler) authorize(ctx context.Context) (tetragonhealth.RoleGrant, []byte, error) {
	grant, raw, err := readGrant(ctx, s.config.GrantPath, s.config.GrantKey, s.config.Native.Digest, time.Now().UTC())
	if err != nil {
		return grant, nil, err
	}
	credentials, err := tetragonhealth.CurrentCredentials()
	if err != nil {
		return grant, nil, err
	}
	if credentials != grant.Credentials {
		return grant, nil, fmt.Errorf("actual native credentials differ from outside-signed read grant")
	}
	if err := checkSocket(s.socket, s.config.SocketOwnerUID, s.config.SocketOwnerGID); err != nil {
		return grant, nil, err
	}
	return grant, raw, nil
}

// Start owns exactly one receive goroutine and never reconnects. The caller
// retains ownership of the supplied connection. Close must precede its closure.
func (s *Sampler) Start(parent context.Context) error {
	if parent == nil {
		return fmt.Errorf("sampler lifetime context required")
	}
	s.mu.Lock()
	if s.phase != "NEW" {
		s.mu.Unlock()
		return fmt.Errorf("sampler lifecycle cannot restart")
	}
	s.phase = "STARTING"
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.mu.Unlock()
	failed := func(err error) error { s.fail(err); close(s.done); return err }
	op, stop := context.WithTimeout(ctx, s.config.ReadTimeout)
	defer stop()
	grant, _, err := s.authorize(op)
	if err != nil {
		return failed(err)
	}
	streamContext, grantCancel := context.WithDeadline(ctx, grant.ValidUntil)
	s.mu.Lock()
	s.cancel = func() { grantCancel(); cancel() }
	s.mu.Unlock()
	versionContext, versionCancel := context.WithDeadline(op, grant.ValidUntil)
	defer versionCancel()
	sensor := api.NewFineGuidanceSensorsClient(s.config.Connection)
	version, err := sensor.GetVersion(versionContext, &api.GetVersionRequest{}, grpc.MaxCallRecvMsgSize(4096), grpc.WaitForReady(false))
	if err != nil {
		return failed(fmt.Errorf("read actual Tetragon API version: %w", err))
	}
	if version == nil || version.Version != "1.8.0" && version.Version != "v1.8.0" {
		return failed(fmt.Errorf("unsupported Tetragon API version %q", version.GetVersion()))
	}
	s.mu.Lock()
	s.version = version.Version
	s.mu.Unlock()
	stream, err := sensor.GetEvents(streamContext, eventRequest(s.config.Namespace), grpc.MaxCallRecvMsgSize(MaxEventBytes), grpc.WaitForReady(false))
	if err != nil {
		return failed(err)
	}
	s.mu.Lock()
	s.phase = "RUNNING"
	s.mu.Unlock()
	go func() {
		defer close(s.done)
		for {
			event, err := stream.Recv()
			if err != nil {
				s.fail(fmt.Errorf("tetragon event stream ended: %w", err))
				return
			}
			if event == nil || proto.Size(event) > MaxEventBytes {
				s.fail(fmt.Errorf("tetragon event exceeds message bound"))
				return
			}
			raw, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(event)
			if err != nil {
				s.fail(err)
				return
			}
			if len(raw) > MaxEventBytes {
				s.fail(fmt.Errorf("tetragon event JSON exceeds byte bound"))
				return
			}
			s.mu.Lock()
			if s.fault != nil {
				s.mu.Unlock()
				return
			}
			if len(s.events) >= guest.MaxEventsPerRecord || s.eventBytes+len(raw) > MaxBatchBytes {
				s.mu.Unlock()
				s.fail(fmt.Errorf("actual Tetragon outbox overflow; visibility is fenced"))
				return
			}
			if event.GetProcessThrottle() != nil {
				if s.throttles == math.MaxUint64 {
					s.mu.Unlock()
					s.fail(fmt.Errorf("stream throttle count exhausted"))
					return
				}
				s.throttles++
			}
			s.events = append(s.events, guest.Observation{MediaType: "application/vnd.tetragon.event+json", Payload: raw})
			s.eventBytes += len(raw)
			s.mu.Unlock()
		}
	}()
	return nil
}

func eventRequest(namespace string) *api.GetEventsRequest {
	// Upstream v1.8 filters.MatchOne ORs allow-list entries. Fields within an
	// entry are ANDed. The second entry preserves podless node throttle events.
	return &api.GetEventsRequest{AllowList: []*api.Filter{{Namespace: []string{namespace}}, {EventSet: []api.EventType{api.EventType_PROCESS_THROTTLE}}}}
}
func (s *Sampler) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fault == nil {
		s.phase = "FENCED"
		s.fault = err
	}
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Sampler) Sample(parent context.Context) (guest.Sample, error) {
	if parent == nil {
		return guest.Sample{}, fmt.Errorf("sample context required")
	}
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	case <-parent.Done():
		return guest.Sample{}, parent.Err()
	}
	s.mu.Lock()
	phase, fault := s.phase, s.fault
	s.mu.Unlock()
	if phase != "RUNNING" || fault != nil {
		return guest.Sample{}, fmt.Errorf("sampler is not active: %w", errors.Join(fault, context.Canceled))
	}
	ctx, cancel := context.WithTimeout(parent, s.config.ReadTimeout)
	defer cancel()
	grant, rawGrant, err := s.authorize(ctx)
	if err != nil {
		s.fail(err)
		return guest.Sample{}, err
	}
	metrics, err := s.config.Metrics.Read(ctx)
	if err != nil {
		s.fail(err)
		return guest.Sample{}, err
	}
	witness, err := tetragonhealth.ReadWitness(ctx, s.config.Native, grant)
	if err != nil {
		s.fail(err)
		return guest.Sample{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fault != nil {
		return guest.Sample{}, s.fault
	}
	if err := ctx.Err(); err != nil {
		return guest.Sample{}, err
	}
	values, err := counters(metrics, witness, s.throttles)
	if err != nil {
		return guest.Sample{}, err
	}
	for _, value := range values {
		if before, ok := s.previous[value.ID]; ok && value.Value < before {
			s.fault = fmt.Errorf("actual cumulative signal reset: %s", value.ID)
			s.cancel()
			return guest.Sample{}, s.fault
		}
	}
	health := HealthEvidence{Contract: tetragonhealth.ContractVersion, SourceInstance: s.config.SourceInstance, APIVersion: s.version, NativeEnrollment: s.config.Native, SignedReadGrant: rawGrant, Metrics: metrics, Kernel: witness, StreamThrottleEvents: s.throttles, Caveats: []string{"local Unix DAC and loopback metrics do not independently authenticate sensor binary or prove guest co-residence", "per-family/cell signals overlap; they are not a unique lost-event total", "absent probe/export families remain UNKNOWN; this sampler does not establish their non-applicability"}}
	payload, err := json.Marshal(health)
	if err != nil {
		return guest.Sample{}, err
	}
	if len(payload) > MaxHealthBytes {
		s.fault = fmt.Errorf("complete health evidence exceeds signed record bound")
		s.cancel()
		return guest.Sample{}, s.fault
	}
	for _, value := range values {
		if value.Status == assurance.TelemetrySignalObserved || value.Value > 0 {
			s.previous[value.ID] = value.Value
		}
	}
	result := guest.Sample{SourceInstance: s.config.SourceInstance, SampledAt: time.Now().UTC(), Counters: values, Observations: s.events, HealthEvidence: []guest.Observation{{MediaType: HealthPayloadType, Payload: payload}}}
	s.events = nil
	s.eventBytes = 0
	return result, nil
}

func (s *Sampler) Close(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("close context required")
	}
	s.mu.Lock()
	if s.phase == "NEW" {
		s.mu.Unlock()
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
