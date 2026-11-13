// Package evaluation verifies evidence bytes and authority before contract evaluation.
package evaluation

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

const (
	MaxCandidates    = 4096
	MaxArtifactBytes = 4 << 20
	MaxRequirements  = 128
)

type Evaluator struct {
	repository ports.EvidenceRepository
	verifier   ports.EvidenceVerifier
}

var _ ports.ClaimEvaluator = (*Evaluator)(nil)

func NewEvaluator(repository ports.EvidenceRepository, verifier ports.EvidenceVerifier) (*Evaluator, error) {
	if repository == nil || verifier == nil {
		return nil, errors.New("evidence repository and signature verifier are required")
	}
	return &Evaluator{repository: repository, verifier: verifier}, nil
}

func (e *Evaluator) Evaluate(ctx context.Context, claim assurance.Claim, contract assurance.EvidenceContract, epoch assurance.AssuranceEpoch) (assurance.ClaimEvaluation, error) {
	now := time.Now().UTC()
	result := assurance.ClaimEvaluation{ID: "eval-" + claim.ID, Control: claim.Control, Subject: claim.Subject, State: assurance.AssuranceStateUnknown, Vector: assurance.NewDefaultAssuranceVector(), Epoch: epoch, EvaluatedAt: now, ValidUntil: now}
	for _, r := range contract.Requirements {
		if r.Required {
			result.Completeness.Required++
		}
	}
	result.Completeness.Missing = result.Completeness.Required
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if e == nil || e.repository == nil || e.verifier == nil {
		return result, errors.New("evaluator dependencies are required")
	}
	if err := validateInputs(claim, contract, epoch); err != nil {
		return result, err
	}
	revision := uint64(0)
	versioned, hasRevision := e.repository.(ports.EvidenceRevisioner)
	if hasRevision {
		revision = versioned.Revision()
	}
	candidates, err := e.repository.ListBySubject(ctx, claim.Subject)
	if err != nil {
		return result, fmt.Errorf("list candidate evidence: %w", err)
	}
	if len(candidates) > MaxCandidates {
		return result, fmt.Errorf("candidate evidence exceeds %d-item evaluation bound", MaxCandidates)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].CapturedAt.Equal(candidates[j].CapturedAt) {
			return candidates[i].Digest() < candidates[j].Digest()
		}
		return candidates[i].CapturedAt.After(candidates[j].CapturedAt)
	})
	valid := make([]assurance.EvidenceEnvelope, 0, len(candidates))
	present := make(map[string]bool)
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if candidate.Subject.URI() != claim.Subject.URI() || !hasControl(candidate.ControlRefs, claim.Control) {
			continue
		}
		relevant := false
		for _, requirement := range contract.Requirements {
			if candidate.ObservationType == requirement.EvidenceType {
				present[requirement.ID] = true
				relevant = true
			}
		}
		if !relevant {
			continue
		}
		if err := validateEnvelope(candidate); err != nil {
			addTrace(&result, "candidate rejected: malformed metadata or missing signature")
			continue
		}
		verified, err := e.verifier.VerifySignature(ctx, candidate)
		if err != nil {
			return result, fmt.Errorf("verify candidate signature: %w", err)
		}
		if !verified {
			addTrace(&result, "candidate rejected: signature or producer key unverified")
			continue
		}
		intact, err := e.verifyArtifact(ctx, candidate.Artifact)
		if err != nil {
			return result, err
		}
		if !intact {
			addTrace(&result, "candidate rejected: artifact digest mismatch")
			continue
		}
		valid = append(valid, candidate)
	}
	result.Completeness.Missing = 0
	var digests []string
	adverse := false
	for _, requirement := range contract.Requirements {
		if requirement.Required && present[requirement.ID] {
			result.Completeness.Present++
		}
		var selected *assurance.EvidenceEnvelope
		stale := false
		for _, candidate := range valid {
			if candidate.ObservationType != requirement.EvidenceType || !acceptedProducer(requirement.AcceptedProducers, candidate.Producer.Canonical()) {
				continue
			}
			if candidate.Epoch != epoch || !e.verifier.VerifyEpoch(ctx, candidate, epoch) || !now.Before(candidate.CapturedAt.Add(requirement.MaxAge)) {
				stale = true
				continue
			}
			if candidate.CapturedAt.After(now) {
				continue
			}
			copy := candidate
			selected = &copy
			break
		}
		if selected == nil {
			if requirement.Required {
				if stale {
					result.Completeness.Stale++
				} else {
					result.Completeness.Missing++
				}
			}
			addTrace(&result, "requirement "+requirement.ID+": no fresh verified exact match")
			continue
		}
		if requirement.Required {
			result.Completeness.Verified++
		}
		result.Evidence = append(result.Evidence, selected.Artifact)
		digests = append(digests, selected.Artifact.Digest)
		expires := selected.CapturedAt.Add(requirement.MaxAge)
		if result.ValidUntil.Equal(now) || expires.Before(result.ValidUntil) {
			result.ValidUntil = expires
		}
		if assurance.IsAdverseObservationType(requirement.EvidenceType) {
			adverse = true
		}
		addTrace(&result, "requirement "+requirement.ID+": signature, artifact, producer, control, epoch and freshness verified")
	}
	if len(digests) > 0 {
		result.EvidenceRoot = assurance.CanonicalDigestList(digests)
	}
	if adverse && result.Completeness.Required > 0 {
		result.State = assurance.AssuranceStateFailed
		result.Vector.Conformance = assurance.ValenceNegative
	} else if result.Completeness.IsComplete() {
		result.State = assurance.AssuranceStateVerified
		result.Vector.Conformance = assurance.ValencePositive
		result.Vector.Integrity = assurance.ValencePositive
		result.Vector.Identity = assurance.ValencePositive
		result.Vector.Authority = assurance.ValencePositive
		result.Vector.Freshness = assurance.ValencePositive
		result.Vector.Completeness = assurance.ValencePositive
	} else if result.Completeness.Required > 0 && contract.OnMissingRequiredState == assurance.AssuranceStateFailed {
		result.State = assurance.AssuranceStateFailed
		addTrace(&result, "explicit missing-evidence policy requires FAILED")
	}
	if result.State == assurance.AssuranceStateUnknown {
		result.ValidUntil = now
	}
	if err := ctx.Err(); err != nil {
		result.State = assurance.AssuranceStateUnknown
		result.ValidUntil = now
		return result, err
	}
	if hasRevision && versioned.Revision() != revision {
		result.State = assurance.AssuranceStateUnknown
		result.Vector = assurance.NewDefaultAssuranceVector()
		result.Evidence = nil
		result.EvidenceRoot = ""
		result.Completeness = assurance.EvidenceCompleteness{Required: result.Completeness.Required, Missing: result.Completeness.Required}
		result.ValidUntil = now
		addTrace(&result, "source eligibility changed during evaluation; candidate snapshot invalidated")
	}
	return result, nil
}
func (e *Evaluator) verifyArtifact(ctx context.Context, ref assurance.EvidenceRef) (bool, error) {
	reader, err := e.repository.Get(ctx, ref)
	if err != nil {
		return false, fmt.Errorf("read candidate artifact: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(reader, MaxArtifactBytes+1))
	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return false, fmt.Errorf("read candidate artifact bytes: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if len(data) > MaxArtifactBytes {
		return false, fmt.Errorf("candidate artifact exceeds %d bytes", MaxArtifactBytes)
	}
	return assurance.ComputeDigest(data) == ref.Digest, nil
}
func validateInputs(claim assurance.Claim, contract assurance.EvidenceContract, epoch assurance.AssuranceEpoch) error {
	if claim.ID == "" || len(claim.ID) > 256 || len(claim.Subject.URI()) > 2048 || claim.Subject.Validate() != nil || claim.Control.Validate() != nil || strings.ContainsAny(claim.Subject.URI()+claim.Control.Canonical(), "|\r\n") {
		return errors.New("explicit valid claim subject and control are required")
	}
	if contract.ID == "" || len(contract.ID) > 256 || len(contract.Requirements) > MaxRequirements {
		return errors.New("explicit bounded evidence contract is required")
	}
	if !validEpoch(epoch) {
		return errors.New("five authoritative SHA-256 epoch digests are required")
	}
	if contract.OnMissingRequiredState != assurance.AssuranceStateUnspecified && contract.OnMissingRequiredState != assurance.AssuranceStateUnknown && contract.OnMissingRequiredState != assurance.AssuranceStateFailed {
		return errors.New("missing evidence policy may only produce UNKNOWN or FAILED")
	}
	ids := make(map[string]bool)
	for _, r := range contract.Requirements {
		if r.ID == "" || len(r.ID) > 128 || strings.TrimSpace(r.ID) != r.ID || strings.ContainsAny(r.ID, "|\r\n") || ids[r.ID] || r.EvidenceType == "" || len(r.EvidenceType) > 128 || strings.TrimSpace(r.EvidenceType) != r.EvidenceType || strings.ContainsAny(r.EvidenceType, "*|\r\n") || r.MaxAge <= 0 || len(r.AcceptedProducers) == 0 || len(r.AcceptedProducers) > 128 {
			return errors.New("requirements need unique identities, exact evidence types, bounded freshness and explicit producers")
		}
		ids[r.ID] = true
		for _, producer := range r.AcceptedProducers {
			uri, err := url.Parse(producer)
			if err != nil || uri.Scheme == "" || uri.Host == "" || uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" || strings.ContainsAny(producer, "*|\r\n") {
				return errors.New("accepted producers must be exact identity URIs")
			}
		}
	}
	return nil
}
func validateEnvelope(envelope assurance.EvidenceEnvelope) error {
	sig, err := hex.DecodeString(envelope.SignatureRef)
	if err != nil || len(sig) != ed25519.SignatureSize || envelope.Schema != "assurance.ckodex.io/evidence/v1alpha1" || envelope.ID == "" || envelope.CapturedAt.IsZero() || envelope.Subject.Validate() != nil || envelope.Producer.Validate() != nil || !validEpoch(envelope.Epoch) || !validDigest(envelope.Artifact.Digest) || envelope.Artifact.Digest != envelope.IntegrityDigest || envelope.Artifact.URI != "cas://sha256/"+strings.TrimPrefix(envelope.Artifact.Digest, "sha256:") || envelope.Artifact.MediaType == "" {
		return errors.New("invalid candidate envelope")
	}
	return nil
}
func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(value[7:])
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}
func validEpoch(epoch assurance.AssuranceEpoch) bool {
	return validDigest(epoch.SubjectDigest) && validDigest(epoch.ImplementationDigest) && validDigest(epoch.PolicyDigest) && validDigest(epoch.AuthorityDigest) && validDigest(epoch.EnvironmentDigest)
}
func hasControl(controls []assurance.ControlRef, control assurance.ControlRef) bool {
	for _, candidate := range controls {
		if candidate == control {
			return true
		}
	}
	return false
}
func acceptedProducer(producers []string, producer string) bool {
	for _, accepted := range producers {
		if accepted == producer {
			return true
		}
	}
	return false
}
func addTrace(result *assurance.ClaimEvaluation, message string) {
	if len(result.Trace) < MaxRequirements {
		result.Trace = append(result.Trace, message)
	}
}
