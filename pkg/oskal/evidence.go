package oskal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	commonv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/common/v1"
	evidencev1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/evidence/v1"
)

// EvidenceEnvelopeBuilder provides a fluent API for creating canonical EvidenceEnvelopes.
type EvidenceEnvelopeBuilder struct {
	env EvidenceEnvelope
	err error
}

// NewEvidenceEnvelope initializes a builder for EvidenceEnvelope.
func NewEvidenceEnvelope(schema, id string, subject SubjectRef, obsType string) *EvidenceEnvelopeBuilder {
	return &EvidenceEnvelopeBuilder{
		env: EvidenceEnvelope{
			Schema:          schema,
			ID:              id,
			Subject:         subject,
			ObservationType: obsType,
			CapturedAt:      time.Now().UTC(),
		},
	}
}

// WithProducer sets the producing authority (e.g. SPIFFE ID).
func (b *EvidenceEnvelopeBuilder) WithProducer(auth AuthorityRef) *EvidenceEnvelopeBuilder {
	b.env.Producer = auth
	return b
}

// WithArtifact attaches an evidence artifact reference.
func (b *EvidenceEnvelopeBuilder) WithArtifact(uri, digest, mediaType string) *EvidenceEnvelopeBuilder {
	b.env.Artifact = EvidenceRef{
		URI:       uri,
		Digest:    digest,
		MediaType: mediaType,
	}
	return b
}

// WithEpoch attaches the current evaluated AssuranceEpoch.
func (b *EvidenceEnvelopeBuilder) WithEpoch(epoch AssuranceEpoch) *EvidenceEnvelopeBuilder {
	b.env.Epoch = epoch
	return b
}

// WithControlRefs attaches relevant control references.
func (b *EvidenceEnvelopeBuilder) WithControlRefs(ctrls ...ControlRef) *EvidenceEnvelopeBuilder {
	b.env.ControlRefs = append(b.env.ControlRefs, ctrls...)
	return b
}

// WithCapturedAt sets explicit capture time.
func (b *EvidenceEnvelopeBuilder) WithCapturedAt(t time.Time) *EvidenceEnvelopeBuilder {
	b.env.CapturedAt = t
	return b
}

// WithIntegrityDigest sets a custom integrity digest, or computes one automatically if empty.
func (b *EvidenceEnvelopeBuilder) WithIntegrityDigest(digest string) *EvidenceEnvelopeBuilder {
	b.env.IntegrityDigest = digest
	return b
}

// Build finalizes and validates the EvidenceEnvelope.
func (b *EvidenceEnvelopeBuilder) Build() (EvidenceEnvelope, error) {
	if b.err != nil {
		return EvidenceEnvelope{}, b.err
	}
	if b.env.Schema == "" {
		b.env.Schema = "https://assurance.ckodex.io/schemas/evidence/v1"
	}
	if b.env.ID == "" {
		return EvidenceEnvelope{}, fmt.Errorf("evidence envelope ID is required")
	}
	if b.env.Subject.ID == "" {
		return EvidenceEnvelope{}, fmt.Errorf("evidence envelope subject ID is required")
	}
	if b.env.ObservationType == "" {
		return EvidenceEnvelope{}, fmt.Errorf("evidence envelope observation type is required")
	}

	if b.env.IntegrityDigest == "" {
		raw := fmt.Sprintf("%s|%s|%s|%s", b.env.ID, b.env.Subject.URI(), b.env.ObservationType, b.env.Artifact.Digest)
		h := sha256.Sum256([]byte(raw))
		b.env.IntegrityDigest = "sha256:" + hex.EncodeToString(h[:])
	}

	return b.env, nil
}

// ObservationBuilder provides a fluent API for building wire ProtoObservation instances.
type ObservationBuilder struct {
	obs *ProtoObservation
}

// NewObservation initializes a new ObservationBuilder.
func NewObservation(id, obsType string, subject SubjectRef) *ObservationBuilder {
	return &ObservationBuilder{
		obs: &ProtoObservation{
			Id:   id,
			Type: obsType,
			Subject: &commonv1.SubjectRef{
				Scheme: subject.Scheme,
				Id:     subject.ID,
			},
			ObservedAt: timestamppb.Now(),
		},
	}
}

// WithProducer sets the producing observer authority on the observation.
func (b *ObservationBuilder) WithProducer(auth AuthorityRef) *ObservationBuilder {
	b.obs.Observer = &commonv1.AuthorityRef{
		Scheme:  auth.Scheme,
		Subject: auth.Subject,
	}
	return b
}

// WithEvidenceRef adds an evidence reference.
func (b *ObservationBuilder) WithEvidenceRef(uri, digest, mediaType string) *ObservationBuilder {
	b.obs.Evidence = append(b.obs.Evidence, &evidencev1.EvidenceRef{
		Uri:       uri,
		Digest:    digest,
		MediaType: mediaType,
	})
	return b
}

// WithObservedAt sets explicit observation time.
func (b *ObservationBuilder) WithObservedAt(t time.Time) *ObservationBuilder {
	b.obs.ObservedAt = timestamppb.New(t)
	return b
}

// Build returns the finalized ProtoObservation.
func (b *ObservationBuilder) Build() (*ProtoObservation, error) {
	if b.obs.Id == "" {
		return nil, fmt.Errorf("observation ID cannot be empty")
	}
	if b.obs.Subject == nil || b.obs.Subject.Id == "" {
		return nil, fmt.Errorf("observation subject cannot be empty")
	}
	return b.obs, nil
}

// ComputeEvidenceRoot computes the canonical Merkle evidence root over a set of evidence digests.
func ComputeEvidenceRoot(digests []string) string {
	var refs []assurance.EvidenceRef
	for _, d := range digests {
		refs = append(refs, assurance.EvidenceRef{Digest: d})
	}
	// Delegate to pure assurance kernel
	if len(refs) == 0 {
		return "none"
	}
	raw := ""
	for _, r := range refs {
		raw += r.Digest + "|"
	}
	h := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(h[:])
}
