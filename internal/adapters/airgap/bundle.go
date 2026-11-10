package airgap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

// BundleMetadata describes an exported air-gap evidence bundle.
type BundleMetadata struct {
	BundleID       string    `json:"bundleId"`
	ExportedAt     time.Time `json:"exportedAt"`
	SubjectURI     string    `json:"subjectUri"`
	EpochComposite string    `json:"epochComposite"`
	Generator      string    `json:"generator"`
}

// AirgapBundle represents a self-contained, offline-verifiable package of assurance evidence.
type AirgapBundle struct {
	Metadata       BundleMetadata               `json:"metadata"`
	Evaluations    []assurance.ClaimEvaluation  `json:"evaluations"`
	Receipts       []assurance.ControlReceipt   `json:"receipts"`
	Envelopes      []assurance.EvidenceEnvelope `json:"envelopes"`
	Blobs          map[string]string            `json:"blobs"` // digest -> content string
	ManifestDigest string                       `json:"manifestDigest"`
}

// ComputeManifestDigest calculates a deterministic hash of the bundle contents.
func (b *AirgapBundle) ComputeManifestDigest() string {
	digests := make([]string, 0, len(b.Envelopes)+len(b.Receipts)+len(b.Evaluations))
	for _, ev := range b.Evaluations {
		digests = append(digests, "eval:"+ev.Digest())
	}
	for _, env := range b.Envelopes {
		digests = append(digests, "env:"+env.Digest())
	}
	for _, r := range b.Receipts {
		digests = append(digests, "receipt:"+r.EvidenceRoot+":"+r.Signature)
	}
	for digest, content := range b.Blobs {
		hContent := sha256.Sum256([]byte(content))
		digests = append(digests, "blob:"+digest+":"+hex.EncodeToString(hContent[:]))
	}
	sort.Strings(digests)

	raw := fmt.Sprintf("%s|%s|%s|%s|%d|%s",
		b.Metadata.BundleID,
		b.Metadata.SubjectURI,
		b.Metadata.EpochComposite,
		b.Metadata.Generator,
		b.Metadata.ExportedAt.UnixNano(),
		strings.Join(digests, "\n"),
	)
	h := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(h[:])
}

// ExportBundle serializes an offline evidence package into verifiable JSON bytes.
func ExportBundle(
	ctx context.Context,
	subject assurance.SubjectRef,
	evaluations []assurance.ClaimEvaluation,
	receipts []assurance.ControlReceipt,
	envelopes []assurance.EvidenceEnvelope,
	repo ports.EvidenceRepository,
) (*AirgapBundle, []byte, error) {
	now := time.Now().UTC()

	composite := ""
	if len(evaluations) > 0 {
		composite = evaluations[0].Epoch.CompositeDigest()
	}

	bundle := &AirgapBundle{
		Metadata: BundleMetadata{
			BundleID:       fmt.Sprintf("bundle-%d", now.UnixNano()),
			ExportedAt:     now,
			SubjectURI:     subject.URI(),
			EpochComposite: composite,
			Generator:      "oskal-airgap-packager:v1.0.0",
		},
		Evaluations: evaluations,
		Receipts:    receipts,
		Envelopes:   envelopes,
		Blobs:       make(map[string]string),
	}

	for _, env := range envelopes {
		if repo != nil && env.Artifact.Digest != "" {
			reader, err := repo.Get(ctx, env.Artifact)
			if err == nil {
				data, rErr := io.ReadAll(reader)
				_ = reader.Close()
				if rErr == nil {
					bundle.Blobs[env.Artifact.Digest] = string(data)
				}
			}
		}
	}

	bundle.ManifestDigest = bundle.ComputeManifestDigest()

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode air-gap bundle: %w", err)
	}

	return bundle, data, nil
}

// MaxBundleBytes bounds air-gap bundle import size (64 MiB) to prevent memory exhaustion.
const MaxBundleBytes = 64 << 20

// ImportBundle parses and cryptographically validates an offline evidence package before mutating targetRepo.
func ImportBundle(
	ctx context.Context,
	bundleData []byte,
	targetRepo ports.EvidenceRepository,
	receiptSigner ports.ReceiptSigner,
) (*AirgapBundle, error) {
	if len(bundleData) > MaxBundleBytes {
		return nil, fmt.Errorf("bundle size (%d bytes) exceeds maximum bound (%d bytes)", len(bundleData), MaxBundleBytes)
	}
	var bundle AirgapBundle
	if err := json.Unmarshal(bundleData, &bundle); err != nil {
		return nil, fmt.Errorf("invalid bundle JSON: %w", err)
	}

	// 1. Verify bundle manifest integrity
	expectedManifest := bundle.ComputeManifestDigest()
	if bundle.ManifestDigest != expectedManifest {
		return nil, fmt.Errorf("bundle manifest digest mismatch: got %s, expected %s", bundle.ManifestDigest, expectedManifest)
	}

	// 2. Verify every embedded CAS blob matches its content-addressed SHA-256 key (anti-forgery preflight)
	for digest, content := range bundle.Blobs {
		if !strings.HasPrefix(digest, "sha256:") {
			return nil, fmt.Errorf("bundle blob key %q is invalid: must have sha256 prefix", digest)
		}
		h := sha256.Sum256([]byte(content))
		computed := "sha256:" + hex.EncodeToString(h[:])
		if computed != digest {
			return nil, fmt.Errorf("bundle blob digest mismatch: key %s, computed %s", digest, computed)
		}
	}

	// 3. Verify all receipts if receipt signer is provided (Proof Before Mutation)
	if receiptSigner != nil {
		for i, receipt := range bundle.Receipts {
			valid, err := receiptSigner.VerifyReceipt(ctx, receipt)
			if err != nil || !valid {
				return nil, fmt.Errorf("receipt[%d] failed cryptographic verification: %w", i, err)
			}
		}
	}

	// 4. Load verified envelopes, blobs, and receipts into target repository only after full preflight succeeds
	if targetRepo != nil {
		for _, env := range bundle.Envelopes {
			var payload io.Reader
			if blobContent, ok := bundle.Blobs[env.Artifact.Digest]; ok {
				payload = bytes.NewReader([]byte(blobContent))
			}
			if _, err := targetRepo.Put(ctx, env, payload); err != nil {
				return nil, fmt.Errorf("failed to import envelope %s into target repository: %w", env.ID, err)
			}
		}
		if receiptRepo, ok := targetRepo.(ports.ReceiptRepository); ok {
			for i, receipt := range bundle.Receipts {
				if _, err := receiptRepo.PutReceipt(ctx, receipt); err != nil {
					return nil, fmt.Errorf("failed to import receipt[%d] into target repository: %w", i, err)
				}
			}
		}
	}

	return &bundle, nil
}
