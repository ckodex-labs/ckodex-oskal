package signedrecords_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
)

const recordType = "application/vnd.ckodex.test-record.v1+json"

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, key
}
func signed(t *testing.T, body []byte) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pub, key := keys(t)
	signer, err := signedrecords.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signer.Sign(t.Context(), recordType, body)
	if err != nil {
		t.Fatal(err)
	}
	return raw, pub
}
func envelope(t *testing.T, raw []byte) dsse.Envelope {
	t.Helper()
	var value dsse.Envelope
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func encoded(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDSSEStandardInteroperabilityAndExactPayload(t *testing.T) {
	pub, key := keys(t)
	external, err := signerverifier.NewED25519SignerVerifierFromSSLibKey(&signerverifier.SSLibKey{KeyType: "ed25519", Scheme: "ed25519", KeyID: "outside-hint", KeyVal: signerverifier.KeyVal{Public: hex.EncodeToString(pub), Private: hex.EncodeToString(key)}})
	if err != nil {
		t.Fatal(err)
	}
	outsideSigner, err := dsse.NewEnvelopeSigner(external)
	if err != nil {
		t.Fatal(err)
	}
	outsideVerifier, err := dsse.NewEnvelopeVerifier(external)
	if err != nil {
		t.Fatal(err)
	}
	own, err := signedrecords.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{[]byte(" {\n \"count\" : 1 }\n"), {0, 255, 251, 254, 0}, nil} {
		produced, err := outsideSigner.SignPayload(t.Context(), recordType, body)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := signedrecords.Verify(t.Context(), encoded(t, produced), recordType, pub, 1024)
		if err != nil || !bytes.Equal(verified, body) {
			t.Fatalf("external DSSE rejected or bytes changed: %v", err)
		}
		raw, err := own.Sign(t.Context(), recordType, body)
		if err != nil {
			t.Fatal(err)
		}
		ownEnvelope := envelope(t, raw)
		_, decoded, err := outsideVerifier.VerifyAndDecode(t.Context(), &ownEnvelope)
		if err != nil || !bytes.Equal(decoded, body) {
			t.Fatalf("standard verifier rejected adapter: %v", err)
		}
		signature, err := base64.StdEncoding.DecodeString(ownEnvelope.Signatures[0].Sig)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(pub, dsse.PAE(recordType, body), signature) {
			t.Fatal("raw Ed25519 DSSE verification failed")
		}
	}
	if got := dsse.PAE("http://example.com/HelloWorld", []byte("hello world")); string(got) != "DSSEv1 29 http://example.com/HelloWorld 11 hello world" {
		t.Fatal("library PAE differs from pinned protocol vector")
	}
	t.Log("actual Ed25519 and upstream DSSE signer/verifier interoperate in both directions; exact JSON whitespace/binary/empty payload preserved")
}

func TestDSSEBase64VariantsAndUntrustedKeyHint(t *testing.T) {
	body := []byte{251, 255, 254, 255}
	raw, pub := signed(t, body)
	value := envelope(t, raw)
	sig, err := base64.StdEncoding.DecodeString(value.Signatures[0].Sig)
	if err != nil {
		t.Fatal(err)
	}
	value.Payload = base64.URLEncoding.EncodeToString(body)
	value.Signatures[0].Sig = base64.URLEncoding.EncodeToString(sig)
	value.Signatures[0].KeyID = "untrusted://not-the-pinned-key"
	decoded, err := signedrecords.Verify(t.Context(), encoded(t, value), recordType, pub, 1024)
	if err != nil || !bytes.Equal(decoded, body) {
		t.Fatalf("URL-safe encoding or ignored key hint rejected: %v", err)
	}
	wrong, _ := keys(t)
	if result, err := signedrecords.Verify(t.Context(), encoded(t, value), recordType, wrong, 1024); err == nil || result != nil {
		t.Fatal("untrusted keyid replaced pinned key")
	}
	withoutKeyID := map[string]any{"payloadType": value.PayloadType, "payload": value.Payload, "signatures": []any{map[string]any{"sig": value.Signatures[0].Sig}}}
	if _, err := signedrecords.Verify(t.Context(), encoded(t, withoutKeyID), recordType, pub, 1024); err != nil {
		t.Fatal(err)
	}
}

func TestDSSERejectsTamperingAndMalformedEnvelopes(t *testing.T) {
	raw, pub := signed(t, []byte("x"))
	original := envelope(t, raw)
	changes := map[string]func(*dsse.Envelope){
		"payload": func(e *dsse.Envelope) { e.Payload = base64.StdEncoding.EncodeToString([]byte("y")) },
		"signature": func(e *dsse.Envelope) {
			signature, _ := base64.StdEncoding.DecodeString(e.Signatures[0].Sig)
			signature[0] ^= 1
			e.Signatures[0].Sig = base64.StdEncoding.EncodeToString(signature)
		},
		"type":                func(e *dsse.Envelope) { e.PayloadType += ".changed" },
		"invalid-base64":      func(e *dsse.Envelope) { e.Payload = "%%%%" },
		"nonzero-pad-bits":    func(e *dsse.Envelope) { e.Payload = "eB==" },
		"unpadded-base64":     func(e *dsse.Envelope) { e.Payload = "eA" },
		"base64-newline":      func(e *dsse.Envelope) { e.Payload = "eA==\n" },
		"short-signature":     func(e *dsse.Envelope) { e.Signatures[0].Sig = base64.StdEncoding.EncodeToString([]byte("short")) },
		"oversized-keyid":     func(e *dsse.Envelope) { e.Signatures[0].KeyID = strings.Repeat("x", signedrecords.MaxKeyIDBytes+1) },
		"multiple-signatures": func(e *dsse.Envelope) { e.Signatures = append(e.Signatures, e.Signatures[0]) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			value := envelope(t, raw)
			change(&value)
			if payload, err := signedrecords.Verify(t.Context(), encoded(t, value), value.PayloadType, pub, 1024); err == nil || payload != nil {
				t.Fatal("malformed/tampered envelope accepted")
			}
		})
	}
	var base map[string]any
	if err := json.Unmarshal(raw, &base); err != nil {
		t.Fatal(err)
	}
	bad := map[string][]byte{
		"duplicate-payload":          []byte(`{"payload":"eA==",` + string(raw[1:])),
		"escaped-duplicate":          []byte(`{"\u0070ayload":"eA==",` + string(raw[1:])),
		"duplicate-signature-member": []byte(strings.Replace(string(raw), `"sig":`, `"sig":"eA==","sig":`, 1)),
		"unknown-root":               encoded(t, map[string]any{"payloadType": recordType, "payload": "eA==", "signatures": original.Signatures, "publicKey": hex.EncodeToString(pub)}),
		"case-alias":                 encoded(t, map[string]any{"PayloadType": recordType, "payload": "eA==", "signatures": original.Signatures}),
		"unknown-signature":          encoded(t, map[string]any{"payloadType": recordType, "payload": "eA==", "signatures": []any{map[string]any{"sig": original.Signatures[0].Sig, "algorithm": "Ed25519"}}}),
		"null-payload":               encoded(t, map[string]any{"payloadType": recordType, "payload": nil, "signatures": original.Signatures}),
		"null-signatures":            encoded(t, map[string]any{"payloadType": recordType, "payload": "eA==", "signatures": nil}),
		"null-signature":             encoded(t, map[string]any{"payloadType": recordType, "payload": "eA==", "signatures": []any{nil}}),
		"missing-signature":          encoded(t, map[string]any{"payloadType": recordType, "payload": "eA==", "signatures": []any{}}),
		"trailing-document":          append(bytes.Clone(raw), []byte(` {}`)...),
		"invalid-unicode":            []byte(strings.Replace(string(raw), `"keyid":""`, `"keyid":"\ud800"`, 1)),
		"invalid-utf8":               append(bytes.Clone(raw), 0xff),
	}
	for name, input := range bad {
		t.Run(name, func(t *testing.T) {
			if payload, err := signedrecords.Verify(t.Context(), input, recordType, pub, 1024); err == nil || payload != nil {
				t.Fatal("invalid envelope encoding accepted")
			}
		})
	}
	if _, err := signedrecords.Verify(t.Context(), raw, recordType+".wrong", pub, 1024); err == nil {
		t.Fatal("unexpected application payload type accepted")
	}
}

func TestDSSEBoundsCancellationAndOwnedKey(t *testing.T) {
	pub, key := keys(t)
	signer, err := signedrecords.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	key[0] ^= 1
	key[32] ^= 1
	raw, err := signer.Sign(t.Context(), recordType, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signedrecords.Verify(t.Context(), raw, recordType, pub, 3); err != nil {
		t.Fatal("caller mutation changed owned private key")
	}
	if result, err := signedrecords.Verify(t.Context(), raw, recordType, pub, 2); !errors.Is(err, signedrecords.ErrLimit) || result != nil {
		t.Fatalf("decoded payload budget bypassed: %v", err)
	}
	for _, length := range []int{0, 1, 32, 63, 65} {
		if _, err := signedrecords.NewSigner(make([]byte, length)); err == nil {
			t.Fatal("invalid private-key size accepted")
		}
	}
	if _, err := signedrecords.NewSigner(key); err == nil {
		t.Fatal("inconsistent private/public halves accepted")
	}
	for _, limit := range []int{-1, 0, signedrecords.MaxPayloadBytes + 1} {
		if _, err := signedrecords.Verify(t.Context(), raw, recordType, pub, limit); err == nil {
			t.Fatal("invalid byte budget accepted")
		}
	}
	for _, pinned := range []ed25519.PublicKey{nil, make([]byte, 31), make([]byte, 33)} {
		if _, err := signedrecords.Verify(t.Context(), raw, recordType, pinned, 1024); err == nil {
			t.Fatal("invalid pinned key accepted")
		}
	}
	if _, err := signer.Sign(t.Context(), recordType, make([]byte, signedrecords.MaxPayloadBytes+1)); !errors.Is(err, signedrecords.ErrLimit) {
		t.Fatal("oversized payload accepted")
	}
	if _, err := signedrecords.Verify(t.Context(), make([]byte, signedrecords.MaxEnvelopeBytes+1), recordType, pub, 1024); !errors.Is(err, signedrecords.ErrLimit) {
		t.Fatal("oversized envelope accepted")
	}
	for _, kind := range []string{"", strings.Repeat("x", signedrecords.MaxPayloadTypeBytes+1), "type\n", string([]byte{0xff}), "type\x01"} {
		if _, err := signer.Sign(t.Context(), kind, []byte("x")); err == nil {
			t.Fatal("invalid type accepted")
		}
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stop()
	for _, ctx := range []context.Context{canceled, expired} {
		if _, err := signer.Sign(ctx, recordType, nil); !errors.Is(err, ctx.Err()) {
			t.Fatalf("canceled signing: %v", err)
		}
		if _, err := signedrecords.Verify(ctx, raw, recordType, pub, 1024); !errors.Is(err, ctx.Err()) {
			t.Fatalf("canceled verification: %v", err)
		}
	}
	if _, err := (*signedrecords.Signer)(nil).Sign(t.Context(), recordType, nil); err == nil {
		t.Fatal("nil signer accepted")
	}
}

func TestSignerConcurrentUse(t *testing.T) {
	pub, key := keys(t)
	signer, err := signedrecords.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			body := []byte{byte(i), 255}
			raw, err := signer.Sign(t.Context(), recordType, body)
			if err != nil {
				t.Error(err)
				return
			}
			decoded, err := signedrecords.Verify(t.Context(), raw, recordType, pub, 1024)
			if err != nil || !bytes.Equal(decoded, body) {
				t.Errorf("concurrent verification: %v", err)
			}
		}()
	}
	workers.Wait()
}
