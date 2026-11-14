package tpm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
	"github.com/google/go-tpm/tpm2"
)

const MaxReportBytes = 4096

var (
	_ ports.AttestationProvider = (*Provider)(nil)
	_ ports.AttestationVerifier = (*Verifier)(nil)
)

type report struct {
	Version uint32    `json:"version"`
	Quote   wireQuote `json:"quote"`
}

type wireQuote struct {
	Attestation string `json:"attestation"`
	Signature   string `json:"signature"`
	PCRValue    string `json:"pcrValue"`
	RootCode    string `json:"rootCode"`
	RootLabel   string `json:"rootLabel"`
}

// Attest obtains a real TPM quote and frames its exact signed bytes. The wire
// report contains no submitted AK or measurement policy to bootstrap trust.
func (p *Provider) Attest(ctx context.Context, qualification [QualificationSize]byte) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("attestation requires a context")
	}
	q, err := p.Quote(ctx, qualification)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(report{Version: 1, Quote: wireQuote{
		Attestation: base64.StdEncoding.EncodeToString(q.Attestation),
		Signature:   base64.StdEncoding.EncodeToString(q.Signature), PCRValue: base64.StdEncoding.EncodeToString(q.PCRValue[:]),
		RootCode: SoftwareRootCode, RootLabel: SoftwareRootLabel,
	}})
	if err != nil {
		return nil, fmt.Errorf("encode TPM report: %w", err)
	}
	if len(raw) > MaxReportBytes {
		return nil, fmt.Errorf("TPM report exceeds %d bytes", MaxReportBytes)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return raw, nil
}

// VerifyAttestation authenticates the report before returning facts derived from
// verifier-owned enrollment. Challenge consumption and expiry remain external.
func (v *Verifier) VerifyAttestation(ctx context.Context, raw []byte, qualification [QualificationSize]byte) (assurance.AttestedEnvironment, error) {
	if ctx == nil {
		return assurance.AttestedEnvironment{}, fmt.Errorf("verification requires a context")
	}
	if err := ctx.Err(); err != nil {
		return assurance.AttestedEnvironment{}, err
	}
	var r report
	if err := signedrecords.DecodeJSON(raw, &r, MaxReportBytes); err != nil {
		return assurance.AttestedEnvironment{}, fmt.Errorf("decode TPM report: %w", err)
	}
	if r.Version != 1 {
		return assurance.AttestedEnvironment{}, fmt.Errorf("TPM report requires version 1")
	}
	attestation, err := decodeField(r.Quote.Attestation, maxAttestationSize)
	if err != nil {
		return assurance.AttestedEnvironment{}, fmt.Errorf("report attestation: %w", err)
	}
	signature, err := decodeField(r.Quote.Signature, maxSignatureSize)
	if err != nil {
		return assurance.AttestedEnvironment{}, fmt.Errorf("report signature: %w", err)
	}
	pcr, err := decodeField(r.Quote.PCRValue, 32)
	if err != nil || len(pcr) != 32 {
		return assurance.AttestedEnvironment{}, fmt.Errorf("report requires an exact SHA-256 PCR value")
	}
	q := Quote{Attestation: attestation, Signature: signature,
		PCRValue: [32]byte(pcr), RootCode: r.Quote.RootCode, RootLabel: r.Quote.RootLabel}
	if _, err := v.Verify(q, qualification); err != nil {
		return assurance.AttestedEnvironment{}, err
	}
	if err := ctx.Err(); err != nil {
		return assurance.AttestedEnvironment{}, err
	}
	return v.Environment(), nil
}

// Environment describes the immutable, externally enrolled measurement policy.
// It is configuration, not proof of a new quote. VerifyAttestation returns these
// facts only after cryptographically verifying a report against that policy.
// The descriptor binds the canonical TPM bank/index selection and exact value;
// it is not the hash of the sensor executable or a claim about measured boot.
func (v *Verifier) Environment() assurance.AttestedEnvironment {
	if v == nil || v.key == nil {
		return assurance.AttestedEnvironment{}
	}
	descriptor := append([]byte("oskal.tpm.measurement.v1\x00"), tpm2.Marshal(selection(v.pcrIndex))...)
	descriptor = append(descriptor, v.expectedPCR[:]...)
	return assurance.AttestedEnvironment{
		MeasurementDigest: assurance.ComputeDigest(descriptor),
		RootKind:          SoftwareRootCode,
		RootLabel:         SoftwareRootLabel,
	}
}

func decodeField(encoded string, maximum int) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, fmt.Errorf("base64 field exceeds its bounds")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) > maximum || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return nil, fmt.Errorf("base64 field is not a bounded canonical encoding")
	}
	return decoded, nil
}
