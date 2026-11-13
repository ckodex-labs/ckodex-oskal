// Package tpm provides bounded TPM 2.0 quote acquisition and offline verification.
// Enrollment, measurement authority, challenge freshness, and replay consumption
// belong to the caller. A valid quote alone does not establish those properties.
package tpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

const (
	SoftwareRootCode = "SOFTWARE_TPM"
	// SoftwareRootLabel must accompany software-root evidence and demonstrations.
	SoftwareRootLabel  = "software TPM root \u2014 not hardware-backed"
	QualificationSize  = 64
	maxAttestationSize = 512
	maxSignatureSize   = 80
	maxPublicSize      = 256
)

// Enrollment is trusted verifier configuration, never supplied by a quote sender.
// AKPublic is a TPMT_PUBLIC, without a TPM2B size prefix. The names are raw names.
// This initial adapter accepts one SHA-256 PCR and an ECDSA P-256/SHA-256 AK.
type Enrollment struct {
	AKPublic        []byte
	AKName          []byte
	AKQualifiedName []byte
	PCRIndex        uint32
	ExpectedPCR     [sha256.Size]byte
}

// Quote retains the exact TPM-signed bytes. PCRValue is unsigned input which
// verification binds to the signed digest and the configured measurement policy.
type Quote struct {
	Attestation []byte
	Signature   []byte
	PCRValue    [sha256.Size]byte
	RootCode    string
	RootLabel   string
}

// VerifiedQuote reports cryptographically verified facts, not source admission.
type VerifiedQuote struct {
	AttestationDigest [sha256.Size]byte
	PCRValue          [sha256.Size]byte
	Clock             uint64
	ResetCount        uint32
	RestartCount      uint32
	Safe              bool
	RootCode          string
	RootLabel         string
}

type Verifier struct {
	key           *ecdsa.PublicKey
	qualifiedName []byte
	pcrIndex      uint32
	expectedPCR   [sha256.Size]byte
}

func NewVerifier(e Enrollment) (*Verifier, error) {
	if e.PCRIndex > 23 || len(e.AKPublic) == 0 || len(e.AKPublic) > maxPublicSize {
		return nil, fmt.Errorf("invalid enrolled PCR index or AK public size")
	}
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](e.AKPublic)
	if err != nil {
		return nil, fmt.Errorf("decode enrolled AK: %w", err)
	}
	if !bytes.Equal(tpm2.Marshal(*pub), e.AKPublic) {
		return nil, fmt.Errorf("enrolled AK is not an exact canonical TPMT_PUBLIC")
	}
	attrs := pub.ObjectAttributes
	if pub.Type != tpm2.TPMAlgECC || pub.NameAlg != tpm2.TPMAlgSHA256 ||
		!attrs.Restricted || !attrs.SignEncrypt || attrs.Decrypt ||
		!attrs.FixedTPM || !attrs.FixedParent || !attrs.SensitiveDataOrigin {
		return nil, fmt.Errorf("enrolled AK must be a restricted TPM-origin signing key")
	}
	params, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, fmt.Errorf("enrolled AK ECC parameters: %w", err)
	}
	if params.CurveID != tpm2.TPMECCNistP256 || params.Scheme.Scheme != tpm2.TPMAlgECDSA {
		return nil, fmt.Errorf("enrolled AK must use ECDSA P-256")
	}
	scheme, err := params.Scheme.Details.ECDSA()
	if err != nil || scheme.HashAlg != tpm2.TPMAlgSHA256 {
		return nil, fmt.Errorf("enrolled AK must use SHA-256")
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return nil, fmt.Errorf("derive enrolled AK name: %w", err)
	}
	if !bytes.Equal(name.Buffer, e.AKName) || !validName(e.AKQualifiedName) {
		return nil, fmt.Errorf("enrolled AK name or qualified name is invalid")
	}
	key, err := tpm2.Pub(*pub)
	if err != nil {
		return nil, fmt.Errorf("convert enrolled AK: %w", err)
	}
	pk, ok := key.(*ecdsa.PublicKey)
	if !ok || pk.Curve != elliptic.P256() {
		return nil, fmt.Errorf("enrolled AK is not a valid P-256 point")
	}
	if _, err := pk.ECDH(); err != nil {
		return nil, fmt.Errorf("validate enrolled AK point: %w", err)
	}
	return &Verifier{key: pk, qualifiedName: bytes.Clone(e.AKQualifiedName), pcrIndex: e.PCRIndex, expectedPCR: e.ExpectedPCR}, nil
}

// Verify checks exact qualification supplied from trusted challenge/channel state.
// It deliberately does not consume challenges or decide replay, TTL, or liveness.
func (v *Verifier) Verify(q Quote, expected [QualificationSize]byte) (VerifiedQuote, error) {
	if v == nil || v.key == nil {
		return VerifiedQuote{}, fmt.Errorf("verifier requires trusted enrollment")
	}
	if q.RootLabel != SoftwareRootLabel || q.RootCode != SoftwareRootCode {
		return VerifiedQuote{}, fmt.Errorf("software TPM root label is required")
	}
	if len(q.Attestation) == 0 || len(q.Attestation) > maxAttestationSize || len(q.Signature) == 0 || len(q.Signature) > maxSignatureSize {
		return VerifiedQuote{}, fmt.Errorf("quote encoding exceeds bounds")
	}
	att, err := tpm2.Unmarshal[tpm2.TPMSAttest](q.Attestation)
	if err != nil {
		return VerifiedQuote{}, fmt.Errorf("decode attestation: %w", err)
	}
	if !bytes.Equal(tpm2.Marshal(*att), q.Attestation) || att.Magic != tpm2.TPMGeneratedValue || att.Type != tpm2.TPMSTAttestQuote {
		return VerifiedQuote{}, fmt.Errorf("attestation is not an exact TPM quote encoding")
	}
	if !bytes.Equal(att.QualifiedSigner.Buffer, v.qualifiedName) || !bytes.Equal(att.ExtraData.Buffer, expected[:]) {
		return VerifiedQuote{}, fmt.Errorf("quote signer or qualification mismatch")
	}
	quoted, err := att.Attested.Quote()
	if err != nil {
		return VerifiedQuote{}, fmt.Errorf("decode quoted PCR information: %w", err)
	}
	if !matchingSelection(quoted.PCRSelect, v.pcrIndex) || q.PCRValue != v.expectedPCR {
		return VerifiedQuote{}, fmt.Errorf("quote PCR selection or measurement mismatch")
	}
	pcrDigest := sha256.Sum256(q.PCRValue[:])
	if !bytes.Equal(quoted.PCRDigest.Buffer, pcrDigest[:]) {
		return VerifiedQuote{}, fmt.Errorf("quoted PCR digest mismatch")
	}
	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](q.Signature)
	if err != nil {
		return VerifiedQuote{}, fmt.Errorf("decode quote signature: %w", err)
	}
	if !bytes.Equal(tpm2.Marshal(*sig), q.Signature) || sig.SigAlg != tpm2.TPMAlgECDSA {
		return VerifiedQuote{}, fmt.Errorf("quote signature encoding or algorithm mismatch")
	}
	ecc, err := sig.Signature.ECDSA()
	if err != nil {
		return VerifiedQuote{}, fmt.Errorf("quote ECDSA signature: %w", err)
	}
	if ecc.Hash != tpm2.TPMAlgSHA256 || !p256ScalarSize(ecc.SignatureR.Buffer) || !p256ScalarSize(ecc.SignatureS.Buffer) {
		return VerifiedQuote{}, fmt.Errorf("quote signature hash or scalar size mismatch")
	}
	digest := sha256.Sum256(q.Attestation)
	if !ecdsa.Verify(v.key, digest[:], new(big.Int).SetBytes(ecc.SignatureR.Buffer), new(big.Int).SetBytes(ecc.SignatureS.Buffer)) {
		return VerifiedQuote{}, fmt.Errorf("invalid quote signature")
	}
	return VerifiedQuote{AttestationDigest: digest, PCRValue: q.PCRValue, Clock: att.ClockInfo.Clock,
		ResetCount: att.ClockInfo.ResetCount, RestartCount: att.ClockInfo.RestartCount,
		Safe: att.ClockInfo.Safe, RootCode: SoftwareRootCode, RootLabel: SoftwareRootLabel}, nil
}

func validName(name []byte) bool {
	return len(name) == 34 && binary.BigEndian.Uint16(name[:2]) == uint16(tpm2.TPMAlgSHA256)
}

func selection(index uint32) tpm2.TPMLPCRSelection {
	bits := make([]byte, 3)
	bits[index/8] = 1 << (index % 8)
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: bits}}}
}

func matchingSelection(s tpm2.TPMLPCRSelection, index uint32) bool {
	return bytes.Equal(tpm2.Marshal(s), tpm2.Marshal(selection(index)))
}

func p256ScalarSize(scalar []byte) bool { return len(scalar) > 0 && len(scalar) <= 32 }
