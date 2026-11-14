// Package guestarchive publishes actual control evaluations with their attested
// telemetry context. Historical archive objects never restore live eligibility.
package guestarchive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/evaluation"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/guest"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/ingestion"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/ckodex-labs/ckodex-oskal/internal/verifier"
)

type Config struct {
	EnrollmentID     string
	SourceID         string
	BindingNamespace string
	BindingName      string
	Subject          assurance.SubjectRef
	Control          assurance.ControlRef
	Producer         assurance.AuthorityRef
	Archive          ports.EvidenceRepository
	Signer           *receipts.ReceiptManager
	Resolver         *binding.Resolver
	Decoder          guest.ObservationDecoder
}

// Publisher belongs to one verifier server and one enrolled source. It must not
// be shared across independent generation allocators. Restart creates an empty
// live registry even when the durable archive contains old positive receipts.
type Publisher struct {
	gate               chan struct{}
	config             Config
	candidates         *collection.Candidates
	evaluator          *evaluation.Evaluator
	generation         uint64
	sessionID          string
	lastTime           time.Time
	source             *collection.Session
	fenced             bool
	hold               error
	lastAcceptedDigest string
}

var _ guest.Publisher = (*Publisher)(nil)

func New(c Config) (*Publisher, error) {
	if c.Archive == nil || c.Signer == nil || c.Resolver == nil || c.Decoder == nil || c.EnrollmentID == "" || c.SourceID == "" || c.BindingNamespace == "" || c.BindingName == "" {
		return nil, fmt.Errorf("guest publisher requires an explicit enrollment, source, binding, archive, signer, resolver, and decoder")
	}
	if err := c.Subject.Validate(); err != nil {
		return nil, err
	}
	if err := c.Control.Validate(); err != nil {
		return nil, err
	}
	if err := c.Producer.Validate(); err != nil {
		return nil, err
	}
	if c.Producer != c.Signer.SigningAuthority() {
		return nil, fmt.Errorf("recorder authority must match its explicitly configured receipt signer")
	}
	if c.Subject.Scheme != "k8s" || c.Subject.Attributes["uid"] == "" {
		return nil, fmt.Errorf("guest publisher requires an outside-enrolled Kubernetes subject UID")
	}
	public, err := hex.DecodeString(c.Signer.PublicKey())
	if err != nil || len(public) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("guest publisher requires an actual Ed25519 recorder key")
	}
	candidates, err := collection.NewCandidates(c.Archive, []collection.SourceConfig{{ID: c.SourceID, Producer: c.Producer, Signer: c.Signer}}, 4096)
	if err != nil {
		return nil, err
	}
	verification := verifier.NewDefaultEvidenceVerifier()
	verification.RegisterPublicKey(c.Producer.Canonical(), public)
	evaluator, err := evaluation.NewEvaluator(candidates, verification)
	if err != nil {
		return nil, err
	}
	c.Subject.Attributes = maps.Clone(c.Subject.Attributes)
	return &Publisher{config: c, candidates: candidates, evaluator: evaluator, gate: make(chan struct{}, 1)}, nil
}

// Publish runs through the real resolver, signed live-candidate repository, and
// evaluator. Integrity alone never produces a positive control assessment.
func (p *Publisher) Publish(ctx context.Context, publication guest.Publication) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("publication requires a deadline-bound operation context")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 10*time.Second {
		return nil, fmt.Errorf("guest publication requires a context deadline within ten seconds")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p == nil || p.gate == nil {
		return nil, fmt.Errorf("guest publisher must be constructed before use")
	}
	select {
	case p.gate <- struct{}{}:
		defer func() { <-p.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.hold != nil {
		return nil, fmt.Errorf("guest publisher is in SAFE_HOLD; preserve its archive and restart only after diagnosis: %w", p.hold)
	}
	if err := p.admitPublication(publication); err != nil {
		return nil, err
	}
	telemetry := assurance.TelemetryEvidence{Attestation: publication.Standing, Integrity: publication.Integrity, RecordDigest: publication.RecordDigest, QuoteDigest: publication.QuoteDigest}
	if err := telemetry.ValidateAt(publication.ObservedAt); err != nil {
		return nil, p.safeHold("invalid verifier publication context", err)
	}
	if publication.Integrity.Recovery == assurance.TelemetryFreshSessionRequired {
		p.fenced = true
	}
	if p.fenced && publication.Integrity.State == assurance.AssuranceStateVerified {
		return nil, p.safeHold("fenced source attempted positive publication", guest.ErrSessionClosed)
	}
	resolved, resolveErr := p.config.Resolver.ContextForBinding(ctx, p.config.BindingNamespace, p.config.BindingName)
	if resolveErr == nil && (resolved.Subject.URI() != p.config.Subject.URI() || resolved.Subject.Attributes["uid"] != p.config.Subject.Attributes["uid"] || !slices.Contains(resolved.Controls, p.config.Control)) {
		resolveErr = fmt.Errorf("current binding changed subject UID, control, or scope; re-enroll the actual source")
	}
	if resolveErr != nil {
		telemetry.Integrity.State = assurance.AssuranceStateUnknown
		telemetry.Integrity.Reasons = append(telemetry.Integrity.Reasons, "live binding could not be established: "+resolveErr.Error())
	}
	positiveWindow := resolveErr == nil && telemetry.Integrity.State == assurance.AssuranceStateVerified && !p.fenced
	if !positiveWindow {
		if err := p.endSource("telemetry window is UNKNOWN; no live candidates are eligible"); err != nil {
			return nil, p.safeHold("invalidate source before UNKNOWN publication", err)
		}
	}
	if err := p.archiveWire(ctx, publication, resolved.Epoch); err != nil {
		return nil, p.safeHold("persist original verifier input", err)
	}
	evaluatedAt := time.Now().UTC()
	result := assurance.ClaimEvaluation{Subject: p.config.Subject, Control: p.config.Control, State: assurance.AssuranceStateUnknown, Epoch: resolved.Epoch, EvaluatedAt: evaluatedAt, ValidUntil: evaluatedAt, Telemetry: &telemetry}
	if positiveWindow {
		if err := p.ingest(ctx, publication); err != nil {
			telemetry.Integrity.State = assurance.AssuranceStateUnknown
			telemetry.Integrity.Reasons = append(telemetry.Integrity.Reasons, "authenticated observations could not enter live evidence: "+err.Error())
			if endErr := p.endSource("runtime capture failed"); endErr != nil {
				return nil, p.safeHold("invalidate failed runtime capture", errors.Join(err, endErr))
			}
		} else {
			claim := assurance.Claim{ID: p.config.SourceID + "/" + p.config.Control.Canonical(), Subject: resolved.Subject, Control: p.config.Control, TargetState: assurance.AssuranceStateAssured}
			evaluated, err := p.evaluator.Evaluate(ctx, claim, resolved.Contract, resolved.Epoch)
			if err != nil {
				return nil, p.safeHold("evaluate actual authenticated evidence", err)
			}
			result = evaluated
			result.Telemetry = &telemetry
			result.State = evaluation.ApplyPolicies(result, resolved.Policies, result.EvaluatedAt)
			if result.ValidUntil.After(telemetry.Integrity.ValidUntil) {
				result.ValidUntil = telemetry.Integrity.ValidUntil
			}
		}
	}
	// Resolution is repeated after ingestion/evaluation. A changed authority or
	// workload epoch cannot receive a receipt for the earlier configuration.
	if resolveErr == nil {
		latest, err := p.config.Resolver.ContextForBinding(ctx, p.config.BindingNamespace, p.config.BindingName)
		if err != nil || latest.Epoch != resolved.Epoch || latest.BindingUID != resolved.BindingUID {
			result.State, result.EvidenceRoot = assurance.AssuranceStateUnknown, ""
			result.ValidUntil = result.EvaluatedAt
			telemetry.Integrity.State = assurance.AssuranceStateUnknown
			telemetry.Integrity.Reasons = append(telemetry.Integrity.Reasons, "binding changed or became unreadable during publication")
			if endErr := p.endSource("binding changed during publication"); endErr != nil {
				return nil, p.safeHold("invalidate drifted source", endErr)
			}
		}
	}
	// Preserve the evaluator's actual timestamp. The transport bounds it between
	// the observed publication and acknowledgment times; it also verifies expiry.
	if result.State != assurance.AssuranceStateVerified && result.State != assurance.AssuranceStateAssured {
		result.EvidenceRoot = ""
	}
	receipt := assurance.ControlReceipt{Subject: result.Subject, Control: result.Control, State: result.State, Epoch: result.Epoch, EvidenceRoot: result.EvidenceRoot, EvaluatedAt: result.EvaluatedAt}
	raw, err := p.config.Signer.SignAttestedReceipt(ctx, receipt, telemetry, result.ValidUntil)
	if err != nil {
		return nil, p.safeHold("sign complete attested control receipt", err)
	}
	if _, err := p.put(ctx, raw, "attested.control.receipt", receipts.AttestedReceiptPayloadType, receipt.EvaluatedAt, receipt.Epoch); err != nil {
		return nil, p.safeHold("persist signed control receipt before acknowledgment", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, p.safeHold("publication deadline elapsed before acknowledgment", err)
	}
	return raw, nil
}

func (p *Publisher) admitPublication(v guest.Publication) error {
	if v.EnrollmentID != p.config.EnrollmentID || v.SessionGeneration == 0 || !validDigest(v.SessionID) || v.Integrity.SessionID != v.SessionID || v.ObservedAt.IsZero() || len(v.ExportPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("publication lacks its enrolled source, positive generation, exact session, verifier time, or export key")
	}
	if v.SessionGeneration < p.generation || (v.SessionGeneration == p.generation && p.sessionID != "" && p.sessionID != v.SessionID) {
		return fmt.Errorf("publication belongs to a superseded source generation; preserve it as history and open a fresh stream")
	}
	if !p.lastTime.IsZero() && v.ObservedAt.Before(p.lastTime) {
		return fmt.Errorf("stale publication cannot supersede a later source outcome")
	}
	if v.RecordDigest != "" && !validDigest(v.RecordDigest) {
		return fmt.Errorf("publication record digest is invalid")
	}
	if v.Standing != nil && v.Standing.ExportKeyDigest != assurance.ComputeDigest(v.ExportPublicKey) {
		return fmt.Errorf("publication export key differs from its admitted attestation")
	}
	if len(v.SignedHeartbeat) > 0 && assurance.ComputeDigest(v.SignedHeartbeat) != v.RecordDigest {
		return fmt.Errorf("publication does not bind its exact signed heartbeat")
	}
	if v.Accepted != nil && (v.Accepted.SignedDigest != v.RecordDigest || v.Accepted.Record.SessionID != v.SessionID) {
		return fmt.Errorf("accepted record differs from publication session or digest")
	}
	if v.SessionGeneration > p.generation {
		if err := p.endSource("new verifier stream generation"); err != nil {
			return p.safeHold("fence old generation", err)
		}
		p.generation, p.sessionID, p.fenced = v.SessionGeneration, v.SessionID, false
	}
	p.lastTime = v.ObservedAt
	return nil
}

func (p *Publisher) ingest(ctx context.Context, v guest.Publication) error {
	if v.Accepted == nil {
		if p.source != nil && p.lastAcceptedDigest == v.RecordDigest && v.RecordDigest != "" {
			return nil
		}
		return fmt.Errorf("a positive window requires an actually accepted signed heartbeat")
	}
	if p.source == nil {
		source, err := p.candidates.BeginSession(p.config.SourceID)
		if err != nil {
			return err
		}
		p.source = source
	}
	writer := ingestion.Writer{Repository: &boundRepository{EvidenceRepository: p.source.Repository(), resolver: p.config.Resolver}, Resolver: p.config.Resolver}
	for _, observation := range v.Accepted.Record.Observations {
		captured, err := p.config.Decoder.DecodeObservation(ctx, observation)
		if err != nil {
			return err
		}
		if captured == nil {
			continue
		}
		if captured.Producer != p.config.Producer {
			return fmt.Errorf("decoded fact attempted to change its enrolled recorder authority")
		}
		if err := writer.WriteCapturedEvent(ctx, *captured); err != nil {
			return err
		}
	}
	p.lastAcceptedDigest = v.RecordDigest
	return nil
}

func (p *Publisher) archiveWire(ctx context.Context, v guest.Publication, epoch assurance.AssuranceEpoch) error {
	if v.Challenge != nil {
		raw, err := json.Marshal(v.Challenge)
		if err != nil {
			return err
		}
		if len(raw) > 4096 {
			return fmt.Errorf("issued verifier challenge exceeds its archival bound")
		}
		if _, err := p.put(ctx, raw, "guest.verifier.challenge", "application/vnd.oskal.guest-challenge.v1+json", v.ObservedAt, epoch); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		raw         []byte
		kind, media string
		maximum     int
	}{
		{v.AttestationReport, "guest.attestation.report", "application/vnd.oskal.tpm-report.v1+json", guest.MaxReportBytes},
		{v.SignedExportKeyProof, "guest.export-key.proof", guest.QuoteProofPayloadType, 16384},
		{v.SignedHeartbeat, "guest.signed.heartbeat", guest.HeartbeatPayloadType, (guest.MaxRecordBytes+2)/3*4 + 4096},
	} {
		if len(item.raw) == 0 {
			continue
		}
		if len(item.raw) > item.maximum {
			return fmt.Errorf("%s exceeds its wire bound", item.kind)
		}
		if _, err := p.put(ctx, item.raw, item.kind, item.media, v.ObservedAt, epoch); err != nil {
			return err
		}
	}
	return nil
}

func (p *Publisher) put(ctx context.Context, raw []byte, kind, media string, observed time.Time, epoch assurance.AssuranceEpoch) (assurance.EvidenceRef, error) {
	digest := assurance.ComputeDigest(raw)
	envelope := assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/evidence/v1alpha1", ID: "guest-" + strings.TrimPrefix(digest, "sha256:") + "-" + kind, Subject: p.config.Subject, ObservationType: kind, CapturedAt: observed, Producer: p.config.Producer, Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(digest, "sha256:"), Digest: digest, MediaType: media}, IntegrityDigest: digest, Epoch: epoch}
	signed, err := p.config.Signer.SignEvidence(ctx, envelope)
	if err != nil {
		return assurance.EvidenceRef{}, err
	}
	return p.config.Archive.Put(ctx, signed, bytes.NewReader(raw))
}

func (p *Publisher) endSource(reason string) error {
	if p.source == nil {
		return nil
	}
	err := p.source.End(reason)
	if err == nil {
		p.source = nil
		p.lastAcceptedDigest = ""
	}
	return err
}

func (p *Publisher) safeHold(operation string, cause error) error {
	err := fmt.Errorf("%s: %w", operation, cause)
	if p.source != nil {
		if holdErr := p.source.SafeHold(err.Error()); holdErr != nil {
			err = errors.Join(err, fmt.Errorf("retract live candidate eligibility: %w", holdErr))
		}
	}
	if p.hold == nil {
		p.hold = err
	}
	return err
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

type boundRepository struct {
	ports.EvidenceRepository
	resolver *binding.Resolver
}

func (r *boundRepository) Put(ctx context.Context, envelope assurance.EvidenceEnvelope, payload io.Reader) (assurance.EvidenceRef, error) {
	bound, err := r.resolver.BindEnvelope(ctx, envelope)
	if err != nil {
		return assurance.EvidenceRef{}, err
	}
	return r.EvidenceRepository.Put(ctx, bound, payload)
}
