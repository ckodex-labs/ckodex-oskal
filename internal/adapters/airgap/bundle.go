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
	digests := make([]string, 0, len(b.Envelopes)+len(b.Receipts))
	for _, env := range b.Envelopes {
		digests = append(digests, env.Digest())
	}
	for _, r := range b.Receipts {
		digests = append(digests, r.EvidenceRoot+":"+r.Signature)
	}
	for digest, content := range b.Blobs {
		hContent := sha256.Sum256([]byte(content))
		digests = append(digests, "blob:"+digest+":"+hex.EncodeToString(hContent[:]))
	}
	sort.Strings(digests)

	raw := fmt.Sprintf("%s|%s|%s|%s",
		b.Metadata.BundleID,
		b.Metadata.SubjectURI,
		b.Metadata.EpochComposite,
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
			Generator:      "oskal-airgap-packager:v0.2.0",
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

// ImportBundle parses and cryptographically validates an offline evidence package.
func ImportBundle(
	ctx context.Context,
	bundleData []byte,
	targetRepo ports.EvidenceRepository,
	receiptSigner ports.ReceiptSigner,
) (*AirgapBundle, error) {
	var bundle AirgapBundle
	if err := json.Unmarshal(bundleData, &bundle); err != nil {
		return nil, fmt.Errorf("invalid bundle JSON: %w", err)
	}

	// 1. Verify bundle manifest integrity
	expectedManifest := bundle.ComputeManifestDigest()
	if bundle.ManifestDigest != expectedManifest {
		return nil, fmt.Errorf("bundle manifest digest mismatch: got %s, expected %s", bundle.ManifestDigest, expectedManifest)
	}

	// 2. Verify all receipts if receipt signer is provided
	if receiptSigner != nil {
		for i, receipt := range bundle.Receipts {
			valid, err := receiptSigner.VerifyReceipt(ctx, receipt)
			if err != nil || !valid {
				return nil, fmt.Errorf("receipt[%d] failed cryptographic verification: %w", i, err)
			}
		}
	}

	// 3. Load verified envelopes and blobs into target repository
	if targetRepo != nil {
		for _, env := range bundle.Envelopes {
			blobContent := bundle.Blobs[env.Artifact.Digest]
			payload := bytes.NewReader([]byte(blobContent))
			if _, err := targetRepo.Put(ctx, env, payload); err != nil {
				return nil, fmt.Errorf("failed to import envelope %s into target repository: %w", env.ID, err)
			}
		}
	}

	return &bundle, nil
}
