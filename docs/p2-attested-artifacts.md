# Full-body attested control receipts

The v2 receipt is a separate DSSE protocol with payload type
`application/vnd.oskal.attested-control-receipt.v2+json`. Its complete JSON body
contains `version: 2`, an unsigned `receipt` and `telemetry`. A real Ed25519 DSSE
signature covers all payload bytes, including subject attributes, enrolled-root
labels, caveats, sessions, measurement/key/channel digests, record/quote digests,
loss counters, inclusive missing ranges, reasons and recovery instructions.

The embedded `ControlReceipt.Signature` must be empty. Existing legacy receipt
canonical bytes and verification retain their original tuple semantics; neither
wrapping a legacy signature nor appending unsigned fields upgrades its meaning.
The legacy `ClaimEvaluation.Digest` also retains its existing meaning and is not
a digest of newly attached telemetry context.

## Construction and verification

`ReceiptManager.SignAttestedReceipt(ctx, receipt, telemetry)` requires the actual
evaluation time, enforces this manager's explicitly configured evaluator claim,
validates body coherence, and signs its complete encoding. It does not obtain or
verify a TPM quote, authenticate a source, resolve an enrollment policy, or verify
the underlying evidence artifacts. The application must perform those operations
before constructing positive assessment inputs.

`VerifyAttestedReceipt(ctx, raw, pinnedKey, expectedAuthority, now)` verifies the
full DSSE signature using only the pinned Ed25519 key and strictly decodes the v2
body. Missing/unknown/duplicate fields, wrong payload types and legacy receipt
files are not alternate verification paths. An optional expected authority
constrains the signed evaluator URI claim; a supplied nonempty trust-domain field
also constrains that metadata. This check does not independently authenticate
ownership of the key by that identity.

`TelemetryEvidence.ValidateAt` validates historical integrity coherence, and
`ValidateForEvaluation` prevents a positive control claim from bypassing UNKNOWN
visibility. VERIFIED or ASSURED control standing requires VERIFIED integrity,
an actual nonempty evidence-root digest, all five receipt epoch digests, complete
attestation fields and record/quote digests, and matching root/session/caveats.
The window must satisfy
`windowStart < windowEnd <= evaluatedAt < validUntil <= attestation.expiresAt`;
it cannot precede the session start or end before attestation verification.
Loss, missing ranges, unresolved reasons or recovery obligations prohibit
VERIFIED integrity. Arrays, strings, attributes and encoded records are bounded.

Startup UNKNOWN can omit an attestation or artifact digest that does not yet
exist. It must still carry the outside-enrolled root label, its caveats and
specific reasons. No quote, zero-loss interval or evidence artifact is fabricated
to fill those gaps. UNKNOWN may retain an expired or unordered observation window
as adverse diagnostic facts. Loss deltas remain per signal and are never added
into an invented unique lost-event total.

Historical signatures are immutable. If a previously valid positive receipt has
expired at `now`, verification preserves its `signedState` and signed body while
reporting `effectiveState: UNKNOWN`. Expiry is an incomplete assessment result,
not an invalid cryptographic signature. A contradictory positive body that was
already expired at its own evaluation time is rejected as an invalid artifact.

The software TPM root always retains the exact label
`software TPM root \u2014 not hardware-backed` (rendering the escape as an em dash).
Validating its text does not establish hardware, TEE, host-root resistance,
protected telemetry keys, or independent measurement authority.

## Explicit CLI

The command constructor is `newGuestReceiptVerifyCommand()`. Its production
registration under `assurance receipt` is intentionally owned by root integration:

```text
oskal assurance receipt verify-attested \
  --receipt-file /absolute/path/receipt.dsse.json \
  --public-key <64-hex-character-pinned-Ed25519-key> \
  --json
```

`--expected-authority <exact-URI-claim>` is optional. The public key flag accepts
hexadecimal key bytes, not a key path or a key discovered beside the receipt.
Every local flag/trust input is validated before receipt-file I/O. Standalone
verification bypasses ambient application configuration and rejects explicitly
supplied inherited backend/config flags. Unknown flags include correction
guidance. Input must be a regular file containing at most 2 MiB; the DSSE profile
additionally bounds its decoded payload to one MiB.

Results go to stdout; operational assessment status and errors go to stderr.
JSON separates `signatureStatus`, `signedState` and `effectiveState`, retains the
full authenticated body and includes the explicit verification scope:
quote, enrollment policy, source identity, TLS binding, telemetry-record
signatures and evidence artifacts were **not independently reverified**.

| Exit | Meaning |
| --- | --- |
| 0 | Valid full-body signature and structurally coherent, currently positive supplied assessment |
| 2 | Valid signature with UNKNOWN/incomplete assessment, including current expiry |
| 3 | Valid signature with a signed FAILED assessment |
| 1 | Invocation, file, signature, decoding, authority-scope or body-invariant failure |

An exit of 0 does not independently establish live source standing or repeat
the application's cryptographic/policy admission process.

## OSCAL projection

`ClaimEvaluation.Telemetry` is optional. When supplied, Assessment Results,
Component Definition and SSP projections validate its coherence with that exact
evaluation before producing bytes. Each corresponding observation or implemented
requirement retains the complete JSON telemetry context and explicit
integrity/root-kind/root-label properties in the existing CKODEX namespace.
UNKNOWN loss, gaps and caveats survive strict NIST OSCAL 1.2.3 validation.

Assessment Plan and POA&M APIs receive no claim evaluations or telemetry inputs.
They remain unchanged and cannot claim to preserve facts never supplied to them.
The projector does not invent document relationships, implementation narratives,
system boundaries or attestation facts. Schema acceptance is shape validation;
the supplied context's signature, source and provenance are not reverified.

## Verification evidence and limits

Tests generate actual Ed25519 keys and DSSE signatures. They reject mutations of
root labels, caveats, subject UID, losses, gap ranges and quote digests under the
original signature, and reject incoherent positive bodies even when a real DSSE
signature exists. Legacy downgrade/upgrade attempts fail. These are protocol
conformance fixtures, not fabricated TPM or runtime verification claims.

Compiled subprocess tests execute the actual Cobra command with test-only root
registration. They demonstrate exits 0/2/3/1, current-expiry UNKNOWN, separate
stdout JSON/stderr status, pre-I/O flag rejection and oversized-file refusal.
Production root registration and end-to-end runtime generation remain integration
gates outside this isolated change. OSCAL tests recover and compare the complete
UNKNOWN telemetry context after strict schema validation of all three applicable
document types. No VM, guest, sensor, key enrollment or production system is
created or promoted by these tests.
