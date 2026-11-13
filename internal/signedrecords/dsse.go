// Package signedrecords applies a bounded, single-signature Ed25519 admission
// profile to standard DSSE. Trust comes only from the caller's pinned public key.
package signedrecords

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

const (
	MaxPayloadBytes     = 1 << 20
	MaxPayloadTypeBytes = 256
	MaxKeyIDBytes       = 256
	MaxEnvelopeBytes    = ((MaxPayloadBytes+2)/3)*4 + 4096
)

var (
	ErrInvalid   = errors.New("invalid signed record")
	ErrLimit     = errors.New("signed record limit exceeded")
	ErrSignature = errors.New("signed record signature rejected")
)

type Signer struct{ signer *dsse.EnvelopeSigner }

// NewSigner owns a copy of a complete, internally consistent Ed25519 private
// key. It neither creates a key nor infers identity from key material.
func NewSigner(key ed25519.PrivateKey) (*Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: Ed25519 private key must contain 64 bytes", ErrInvalid)
	}
	owned := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(owned[ed25519.SeedSize:], key[ed25519.SeedSize:]) {
		return nil, fmt.Errorf("%w: Ed25519 private key is inconsistent", ErrInvalid)
	}
	signer, err := dsse.NewEnvelopeSigner(&edSigner{key: owned})
	if err != nil {
		return nil, err
	}
	return &Signer{signer: signer}, nil
}

// Sign authenticates the exact payload bytes and case-sensitive payload type.
// Payload schema, freshness and authorization belong to the caller.
func (s *Signer) Sign(ctx context.Context, payloadType string, payload []byte) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.signer == nil {
		return nil, fmt.Errorf("%w: signer is not configured", ErrInvalid)
	}
	if err := validType(payloadType); err != nil {
		return nil, err
	}
	if len(payload) > MaxPayloadBytes {
		return nil, fmt.Errorf("%w: payload exceeds one MiB", ErrLimit)
	}
	snapshot := bytes.Clone(payload)
	envelope, err := s.signer.SignPayload(ctx, payloadType, snapshot)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if len(raw) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: encoded envelope", ErrLimit)
	}
	return raw, nil
}

// Verify parses once and returns the exact bytes authenticated by the DSSE
// library. keyid is an untrusted hint and is ignored; no submitted key can become
// an authority. This profile rejects unknown fields and additional signatures.
func Verify(ctx context.Context, raw []byte, expectedType string, pinned ed25519.PublicKey, maxPayloadBytes int) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := validType(expectedType); err != nil {
		return nil, err
	}
	if len(pinned) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: pinned Ed25519 public key must contain 32 bytes", ErrInvalid)
	}
	if maxPayloadBytes <= 0 || maxPayloadBytes > MaxPayloadBytes {
		return nil, fmt.Errorf("%w: invalid payload byte budget", ErrLimit)
	}
	if len(raw) > base64.StdEncoding.EncodedLen(maxPayloadBytes)+4096 {
		return nil, fmt.Errorf("%w: encoded envelope", ErrLimit)
	}
	snapshot := bytes.Clone(raw)
	key := bytes.Clone(pinned)
	parsed, err := parseJSON(snapshot, MaxEnvelopeBytes)
	if err != nil {
		return nil, err
	}
	envelope, err := parseEnvelope(parsed)
	if err != nil {
		return nil, err
	}
	if err := validType(envelope.PayloadType); err != nil {
		return nil, err
	}
	if envelope.PayloadType != expectedType {
		return nil, fmt.Errorf("%w: unexpected payload type", ErrInvalid)
	}
	if _, err := strictBase64(envelope.Payload, maxPayloadBytes); err != nil {
		return nil, err
	}
	signature, err := strictBase64(envelope.Signatures[0].Sig, ed25519.SignatureSize)
	if err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: Ed25519 signature must contain 64 bytes", ErrInvalid)
	}
	envelope.Signatures[0].KeyID = ""
	verifier, err := dsse.NewEnvelopeVerifier(&edVerifier{key: key})
	if err != nil {
		return nil, err
	}
	_, payload, err := verifier.VerifyAndDecode(ctx, envelope)
	if canceled := contextError(ctx); canceled != nil {
		return nil, canceled
	}
	if err != nil {
		return nil, ErrSignature
	}
	return payload, nil
}

func parseEnvelope(value any) (*dsse.Envelope, error) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != 3 {
		return nil, fmt.Errorf("%w: DSSE envelope requires exactly payloadType, payload and signatures", ErrInvalid)
	}
	payloadType, typeOK := object["payloadType"].(string)
	payload, payloadOK := object["payload"].(string)
	signatures, signaturesOK := object["signatures"].([]any)
	if !typeOK || !payloadOK || !signaturesOK || len(signatures) != 1 {
		return nil, fmt.Errorf("%w: DSSE requires string payload/type and one signature", ErrInvalid)
	}
	signature, ok := signatures[0].(map[string]any)
	if !ok || len(signature) < 1 || len(signature) > 2 {
		return nil, fmt.Errorf("%w: invalid signature object", ErrInvalid)
	}
	sig, ok := signature["sig"].(string)
	if !ok {
		return nil, fmt.Errorf("%w: signature must be a string", ErrInvalid)
	}
	keyID := ""
	for name, value := range signature {
		switch name {
		case "sig":
		case "keyid":
			var valid bool
			keyID, valid = value.(string)
			if !valid || len(keyID) > MaxKeyIDBytes {
				return nil, fmt.Errorf("%w: invalid or oversized keyid", ErrInvalid)
			}
		default:
			return nil, fmt.Errorf("%w: unknown signature field", ErrInvalid)
		}
	}
	return &dsse.Envelope{PayloadType: payloadType, Payload: payload, Signatures: []dsse.Signature{{KeyID: keyID, Sig: sig}}}, nil
}

func strictBase64(encoded string, maxBytes int) ([]byte, error) {
	if len(encoded) > base64.StdEncoding.EncodedLen(maxBytes) {
		return nil, fmt.Errorf("%w: base64 field", ErrLimit)
	}
	if strings.ContainsAny(encoded, "\r\n") || len(encoded)%4 != 0 {
		return nil, fmt.Errorf("%w: noncanonical base64 encoding", ErrInvalid)
	}
	decodedSize := base64.StdEncoding.DecodedLen(len(encoded))
	if strings.HasSuffix(encoded, "==") {
		decodedSize -= 2
	} else if strings.HasSuffix(encoded, "=") {
		decodedSize--
	}
	if decodedSize > maxBytes {
		return nil, fmt.Errorf("%w: decoded payload", ErrLimit)
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding.Strict(), base64.URLEncoding.Strict()} {
		decoded, err := encoding.DecodeString(encoded)
		if err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("%w: invalid base64 encoding", ErrInvalid)
}
func validType(value string) error {
	if len(value) == 0 || len(value) > MaxPayloadTypeBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%w: payload type must be explicit, valid UTF-8 and at most 256 bytes", ErrInvalid)
	}
	return nil
}
func contextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrInvalid)
	}
	return ctx.Err()
}

type edSigner struct{ key ed25519.PrivateKey }

var _ dsse.Signer = (*edSigner)(nil)

func (s *edSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	signature := ed25519.Sign(s.key, data)
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return signature, nil
}
func (s *edSigner) KeyID() (string, error) { return "", nil }

type edVerifier struct{ key ed25519.PublicKey }

var _ dsse.Verifier = (*edVerifier)(nil)

func (v *edVerifier) Verify(ctx context.Context, data, signature []byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !ed25519.Verify(v.key, data, signature) {
		return ErrSignature
	}
	return contextError(ctx)
}
func (v *edVerifier) KeyID() (string, error)   { return "", nil }
func (v *edVerifier) Public() crypto.PublicKey { return ed25519.PublicKey(bytes.Clone(v.key)) }
