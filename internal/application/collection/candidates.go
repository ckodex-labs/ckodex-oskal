// Package collection separates live candidate eligibility from durable archives.
package collection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

const (
	MaxSources             = 16
	MaxCandidatesPerSource = 4096
	MaxCandidatesPerQuery  = 4096
	MaxPayloadBytes        = 4 << 20
	MaxEnvelopeBytes       = 64 << 10
)

type SourceLifecycle string

const (
	SourceStarting    SourceLifecycle = "STARTING"
	SourceRunning     SourceLifecycle = "RUNNING"
	SourceUnavailable SourceLifecycle = "UNAVAILABLE"
	SourceSafeHold    SourceLifecycle = "SAFE_HOLD"
)

var (
	ErrSessionClosed = errors.New("source session is unavailable or superseded")
	ErrSaturated     = errors.New("source candidate bound reached; SAFE_HOLD requires a new session")
	ErrSourceBusy    = errors.New("source already has an observation being persisted")
)

type SourceConfig struct {
	ID       string
	Producer assurance.AuthorityRef
	Signer   ports.EvidenceSigner
}
type SourceStatus struct {
	ID         string          `json:"id"`
	Producer   string          `json:"producer"`
	Lifecycle  SourceLifecycle `json:"lifecycle"`
	Generation uint64          `json:"generation"`
	Eligible   int             `json:"eligible"`
	Reason     string          `json:"reason"`
}
type candidate struct {
	ref     assurance.EvidenceRef
	subject string
	digest  string
}
type source struct {
	config  SourceConfig
	status  SourceStatus
	entries map[string]candidate
	writing bool
}

// Candidates owns bounded, process-local eligibility. Reopening an archive never
// restores eligibility. It must be repopulated by a new live source session.
type Candidates struct {
	mu       sync.RWMutex
	archive  ports.EvidenceRepository
	sources  map[string]*source
	limit    int
	revision uint64
}

var _ ports.EvidenceRepository = (*Candidates)(nil)

func NewCandidates(archive ports.EvidenceRepository, configs []SourceConfig, maxPerSource int) (*Candidates, error) {
	if archive == nil || len(configs) > MaxSources || maxPerSource <= 0 || maxPerSource > MaxCandidatesPerSource {
		return nil, fmt.Errorf("archive, 0..%d sources and 1..%d candidates per source are required", MaxSources, MaxCandidatesPerSource)
	}
	c := &Candidates{archive: archive, sources: make(map[string]*source), limit: maxPerSource}
	for _, config := range configs {
		uri, err := url.Parse(config.Producer.Canonical())
		if config.ID == "" || len(config.ID) > 128 || config.Signer == nil || config.Producer.Validate() != nil || err != nil || uri.Scheme == "" || uri.Host == "" || uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" || strings.ContainsAny(config.Producer.Canonical(), "*|\r\n") {
			return nil, fmt.Errorf("source %q requires an exact producer URI and signer", config.ID)
		}
		if _, exists := c.sources[config.ID]; exists {
			return nil, fmt.Errorf("duplicate source %q", config.ID)
		}
		c.sources[config.ID] = &source{config: config, status: SourceStatus{ID: config.ID, Producer: config.Producer.Canonical(), Lifecycle: SourceUnavailable, Reason: "no active source session"}, entries: make(map[string]candidate)}
	}
	return c, nil
}

// Session fences every writer to the generation in which it was created.
type Session struct {
	owner      *Candidates
	id         string
	generation uint64
}

func (c *Candidates) BeginSession(id string) (*Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.sources[id]
	if !ok {
		return nil, fmt.Errorf("source %q is not configured", id)
	}
	s.status.Generation++
	s.status.Lifecycle = SourceStarting
	s.status.Reason = "awaiting a signed durable observation"
	s.status.Eligible = 0
	s.entries = make(map[string]candidate)
	s.writing = false
	c.revision++
	return &Session{owner: c, id: id, generation: s.status.Generation}, nil
}
func (s *Session) Repository() ports.EvidenceRepository { return &sessionRepository{session: s} }
func (s *Session) End(reason string) error {
	c := s.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	current := c.sources[s.id]
	if current.status.Generation != s.generation {
		return ErrSessionClosed
	}
	if current.status.Lifecycle == SourceSafeHold {
		return nil
	}
	if len(reason) > 1024 {
		reason = reason[:1024]
	}
	c.invalidate(current, SourceUnavailable, reason)
	return nil
}
func (c *Candidates) invalidate(s *source, lifecycle SourceLifecycle, reason string) {
	s.status.Lifecycle = lifecycle
	s.status.Reason = reason
	s.status.Eligible = 0
	s.entries = make(map[string]candidate)
	s.writing = false
	c.revision++
}
func (c *Candidates) Revision() uint64 { c.mu.RLock(); defer c.mu.RUnlock(); return c.revision }
func (c *Candidates) Snapshot() []SourceStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]SourceStatus, 0, len(c.sources))
	for _, s := range c.sources {
		out = append(out, s.status)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Put is intentionally denied on the evaluation view. Only session-bound
// repositories may sign and admit new live observations.
func (c *Candidates) Put(context.Context, assurance.EvidenceEnvelope, io.Reader) (assurance.EvidenceRef, error) {
	return assurance.EvidenceRef{}, errors.New("live evidence requires a source session repository")
}
func (c *Candidates) Get(ctx context.Context, ref assurance.EvidenceRef) (io.ReadCloser, error) {
	return c.archive.Get(ctx, ref)
}
func (c *Candidates) Verify(ctx context.Context, ref assurance.EvidenceRef) (bool, error) {
	return c.archive.Verify(ctx, ref)
}
func (c *Candidates) ListBySubject(ctx context.Context, subject assurance.SubjectRef) ([]assurance.EvidenceEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := subject.Validate(); err != nil {
		return nil, err
	}
	c.mu.RLock()
	revision := c.revision
	refs := make([]assurance.EvidenceRef, 0)
	for _, s := range c.sources {
		if s.status.Lifecycle != SourceRunning {
			continue
		}
		for _, entry := range s.entries {
			if entry.subject == subject.URI() {
				if len(refs) >= MaxCandidatesPerQuery {
					c.mu.RUnlock()
					return nil, fmt.Errorf("eligible subject exceeds %d-candidate query bound", MaxCandidatesPerQuery)
				}
				refs = append(refs, entry.ref)
			}
		}
	}
	c.mu.RUnlock()
	sort.Slice(refs, func(i, j int) bool { return refs[i].Digest < refs[j].Digest })
	envelopes := make([]assurance.EvidenceEnvelope, 0, len(refs))
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		reader, err := c.archive.Get(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("read eligible envelope: %w", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, MaxEnvelopeBytes+1))
		closeErr := reader.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return nil, err
		}
		if len(data) > MaxEnvelopeBytes || assurance.ComputeDigest(data) != ref.Digest {
			return nil, fmt.Errorf("eligible envelope integrity or size mismatch")
		}
		var envelope assurance.EvidenceEnvelope
		if err := json.Unmarshal(data, &envelope); err != nil {
			return nil, fmt.Errorf("decode eligible envelope: %w", err)
		}
		envelopes = append(envelopes, envelope)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.Revision() != revision {
		return nil, nil
	}
	return envelopes, nil
}

type sessionRepository struct{ session *Session }

func (r *sessionRepository) Get(ctx context.Context, ref assurance.EvidenceRef) (io.ReadCloser, error) {
	return r.session.owner.Get(ctx, ref)
}
func (r *sessionRepository) Verify(ctx context.Context, ref assurance.EvidenceRef) (bool, error) {
	return r.session.owner.Verify(ctx, ref)
}
func (r *sessionRepository) ListBySubject(ctx context.Context, subject assurance.SubjectRef) ([]assurance.EvidenceEnvelope, error) {
	return r.session.owner.ListBySubject(ctx, subject)
}
func (r *sessionRepository) Put(ctx context.Context, envelope assurance.EvidenceEnvelope, payload io.Reader) (assurance.EvidenceRef, error) {
	c := r.session.owner
	c.mu.Lock()
	s := c.sources[r.session.id]
	if s.status.Generation != r.session.generation || (s.status.Lifecycle != SourceStarting && s.status.Lifecycle != SourceRunning) {
		c.mu.Unlock()
		return assurance.EvidenceRef{}, ErrSessionClosed
	}
	if s.writing {
		c.invalidate(s, SourceSafeHold, "concurrent source writes exceeded the synchronous ingestion contract")
		c.mu.Unlock()
		return assurance.EvidenceRef{}, ErrSourceBusy
	}
	if _, exists := s.entries[envelope.ID]; !exists && len(s.entries) >= c.limit {
		config := s.config
		c.invalidate(s, SourceSafeHold, "candidate capacity exhausted; observations preserved in archive")
		c.mu.Unlock()
		ref, _, err := c.persist(ctx, config, envelope, payload)
		return ref, errors.Join(ErrSaturated, err)
	}
	s.writing = true
	config := s.config
	c.mu.Unlock()
	ref, signed, err := c.persist(ctx, config, envelope, payload)
	c.mu.Lock()
	defer c.mu.Unlock()
	s = c.sources[r.session.id]
	if s.status.Generation != r.session.generation || (s.status.Lifecycle != SourceStarting && s.status.Lifecycle != SourceRunning) {
		return ref, errors.Join(ErrSessionClosed, err)
	}
	s.writing = false
	if err != nil {
		c.invalidate(s, SourceUnavailable, "observation signing or persistence failed")
		return ref, err
	}
	if previous, exists := s.entries[signed.ID]; exists && previous.digest != signed.SigningDigest() {
		c.invalidate(s, SourceSafeHold, "observation identity conflicts with archived content")
		return ref, fmt.Errorf("conflicting observation identity %q; both versions retained in archive", signed.ID)
	}
	wasStarting := s.status.Lifecycle == SourceStarting
	s.entries[signed.ID] = candidate{ref: ref, subject: signed.Subject.URI(), digest: signed.SigningDigest()}
	s.status.Lifecycle = SourceRunning
	s.status.Reason = "signed observation durably persisted"
	s.status.Eligible = len(s.entries)
	if wasStarting {
		c.revision++
	}
	return ref, nil
}
func (c *Candidates) persist(ctx context.Context, config SourceConfig, envelope assurance.EvidenceEnvelope, payload io.Reader) (assurance.EvidenceRef, assurance.EvidenceEnvelope, error) {
	fail := func(err error) (assurance.EvidenceRef, assurance.EvidenceEnvelope, error) {
		return assurance.EvidenceRef{}, assurance.EvidenceEnvelope{}, err
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if envelope.Producer != config.Producer || envelope.ID == "" || len(envelope.ID) > 256 || envelope.Subject.Validate() != nil || envelope.CapturedAt.IsZero() || envelope.CapturedAt.After(time.Now()) || envelope.SignatureRef != "" || payload == nil {
		return fail(errors.New("source observation lacks its exact producer, identity, timestamp or unsigned payload"))
	}
	data, err := io.ReadAll(io.LimitReader(payload, MaxPayloadBytes+1))
	if err != nil {
		return fail(err)
	}
	digest := assurance.ComputeDigest(data)
	if len(data) == 0 || len(data) > MaxPayloadBytes || envelope.Artifact.Digest != digest || envelope.IntegrityDigest != digest || envelope.Artifact.URI != "cas://sha256/"+strings.TrimPrefix(digest, "sha256:") {
		return fail(errors.New("source observation payload integrity or bounds mismatch"))
	}
	signed, err := config.Signer.SignEvidence(ctx, envelope)
	if err != nil {
		return fail(err)
	}
	if signed.SignatureRef == "" || signed.SigningDigest() != envelope.SigningDigest() {
		return fail(errors.New("signer changed evidence bindings or omitted the signature"))
	}
	encoded, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return fail(err)
	}
	if len(encoded) > MaxEnvelopeBytes {
		return fail(errors.New("source envelope exceeds metadata bound"))
	}
	ref, err := c.archive.Put(ctx, signed, bytes.NewReader(data))
	if err != nil {
		return fail(err)
	}
	if ref.Digest != assurance.ComputeDigest(encoded) || ref.URI != "cas://sha256/"+strings.TrimPrefix(ref.Digest, "sha256:") {
		return fail(errors.New("archive returned an inconsistent envelope identity"))
	}
	if err := ctx.Err(); err != nil {
		return ref, signed, err
	}
	return ref, signed, nil
}
