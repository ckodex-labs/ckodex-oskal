# Signed record adapter

This package applies a restricted application admission profile to standard DSSE
signatures. It changes no existing receipt or evidence format.

```go
signer, err := signedrecords.NewSigner(privateKey)
envelope, err := signer.Sign(ctx, payloadType, exactPayloadBytes)
payload, err := signedrecords.Verify(ctx, envelope, payloadType, pinnedPublicKey, maxPayloadBytes)
err = signedrecords.DecodeJSON(payload, &record, maxPayloadBytes)
```

Callers supply the key from trusted custody and an exact, case-sensitive expected
payload type. Submitted `keyid` is bounded but ignored; it supplies no identity or
trust. The only suite is one Ed25519 signature. The private key is copied and its
public half must match its seed. Neither keys nor authorities are generated.

The adapter uses go-securesystemslib's DSSE signer, verifier and PAE. It returns
`VerifyAndDecode`'s authenticated payload directly, without reparsing an envelope
or canonicalizing payload bytes. JSON whitespace, arbitrary binary payloads and
empty payloads remain unchanged. Caller code owns schema validation, freshness,
identity, delegation, replay protection and any assurance transition.

## Bounds and parsing

- Payload: at most 1 MiB; verification additionally applies the caller's positive
  payload budget. Payload type: 1..256 UTF-8 bytes without surrounding whitespace
  or control characters. Unauthenticated key hints: at most 256 bytes.
- Envelope: at most padded-base64 payload size plus 4 KiB. Keys and Ed25519
  signatures have their standard fixed sizes.
- Both standard and URL-safe RFC4648 base64 are accepted. Padding must be valid;
  whitespace, invalid characters and nonzero padding bits are rejected.
- Exact envelope fields and one signature are required. Duplicate members,
  unknown fields, case aliases, trailing JSON, invalid UTF-8 and unpaired Unicode
  surrogates are rejected. Cancellation is checked before and after crypto work.
- `DecodeJSON(raw, dst, maxBytes)` limits depth to 32 and keys/values to 65,536.
  It validates exact struct-field names and decodes into a fresh value, assigning
  the destination only after success. Dynamic numbers retain `json.Number`.
  Fixed arrays reject short/long lists and null instead of padding/truncating.

The typed decoder supports structs, slices, string-key maps, explicit JSON names
for embedded structures, and scalar JSON-unmarshalers such as `time.Time`.
Anonymous field promotion and custom container decoders are refused. Interfaces,
string-key maps and `json.RawMessage` intentionally permit schema-owned content;
required fields, nullable values and domain invariants still need caller validation.
Inputs and key material are snapshotted within their bounds. This is a per-call
bound; the caller owns concurrency and trusted destination-schema selection.

DSSE's general envelope recommendation permits unknown extensions. This adapter
intentionally rejects them as an application admission rule, as well as rejecting
additional signatures. Its generated envelopes and signature computation interoperate
with the standard implementation; it is not a permissive general DSSE consumer.

## Pinned primary sources

- [DSSE protocol v1.0.2, commit 4409013](https://github.com/secure-systems-lab/dsse/blob/440901313676fedd0e31f16125c302b0df81e006/protocol.md)
  defines type/payload authentication and unauthenticated key hints.
- [DSSE envelope at the same commit](https://github.com/secure-systems-lab/dsse/blob/440901313676fedd0e31f16125c302b0df81e006/envelope.md)
  defines the JSON representation and extension behavior.
- [go-securesystemslib v0.11.1 DSSE source, commit 662f0f7](https://github.com/secure-systems-lab/go-securesystemslib/tree/662f0f738ddc65cf9543c3e90114bd6d95a7e361/dsse)
  supplies the signer/verifier interfaces, PAE and VerifyAndDecode implementation.

These exact protocol and implementation versions were inspected before use.
The library was already a pinned indirect dependency; go.mod/go.sum are unchanged.

## Verification

`go test -race ./internal/signedrecords -count=1 -v` passes with real generated
Ed25519 keys. Tests cover interoperability in both directions with the upstream
signer/verifier, the published PAE example, exact payload bytes, both base64 alphabets,
ignored key hints, tampering, wrong keys, malformed/ambiguous JSON, bounded input,
Unicode, cancellation, concurrent signing and fixed-array meaning.
`golangci-lint run ./internal/signedrecords/...` reports zero issues.

No TPM, physical hardware, workload identity or deployment claim follows from this
unit's cryptographic checks. No filesystem publication API is provided.
