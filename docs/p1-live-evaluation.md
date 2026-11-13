# Phase 1 live evidence evaluation

The `evaluation` application package verifies candidate evidence before producing
a contract result. It requires an explicit repository and evidence verifier.
Missing verifier, contract identity, exact producer authorization, positive
freshness bounds or any of the five authoritative SHA-256 epoch dimensions returns
an error and an UNKNOWN result. It never derives an epoch from a subject URI.

Every relevant candidate must have the exact subject, control (including version)
and observation type. Its Ed25519 signature is verified against the configured
producer key. The evaluator retrieves the actual artifact bytes through the
repository, enforces a 4 MiB bound and hashes those bytes. The artifact URI,
artifact digest and integrity digest must agree. Repository and verifier errors
propagate; they never fall back to another evidence source.

Required evidence counts distinguish presence, verification, stale evidence and
missing evidence. Invalid or absent candidates produce UNKNOWN unless an explicit
missing-evidence policy requires FAILED. No missing policy can request VERIFIED.
A contract with no required evidence stays UNKNOWN. Fresh verified evidence for
an explicitly listed adverse observation type produces FAILED, even when positive
requirements are complete. Unconfigured observation types do not acquire meaning
through suffix matching. VERIFIED proves the configured evidence contract; it is
not hardware or sensor attestation and does not populate runtime trust as positive.

`ValidUntil` cannot exceed the original selected evidence's capture time plus its
contract freshness limit. Original timestamps, subject identities and epochs are
never rewritten to make observations admissible. Evaluation traces contain bounded
verification outcomes rather than payloads or private reasoning.

## Source eligibility and archive retention

`collection.NewCandidates(archive, sources, maxPerSource)` configures exact source
IDs, producer identities and signers. A source has one of these lifecycle values:

| Lifecycle | Eligible evidence |
| --- | --- |
| UNAVAILABLE | None |
| STARTING | None until a signed observation is durably persisted |
| RUNNING | Only observations admitted during the current source session |
| SAFE_HOLD | None; saturation, conflicting identities or parallel writers require a new session |

`BeginSession(id)` returns a generation-bound session. Pass its `Repository()` to
`ingestion.Writer`. The repository reads the bounded payload, verifies its digest,
checks the configured producer, signs the existing canonical envelope digest, and
persists envelope and payload before publishing the observation as eligible.
`ReceiptManager.SignEvidence` uses its existing Ed25519 key and requires the exact
explicitly configured authority; the receipt constructor's legacy fallback actor
is not accepted for evidence signing. The private key is not exposed. Existing
`PublicKey()` supplies the hex public key for `DefaultEvidenceVerifier`.

`Session.End(reason)` removes eligibility immediately and retains the archive.
Writers from an ended or superseded session cannot publish late observations,
even when their durable write completes afterward. A source-session availability
revision also invalidates evaluations racing a session transition. Ordinary
additions within a RUNNING session do not invalidate an already captured candidate
snapshot; evaluations describe the facts available at their evaluation boundary.

A zero-source registry is an intentional empty evaluation view: it exposes no
archive candidates and has an empty status snapshot. It still requires a real
archive and positive candidate bound. This permits explicitly configured read-only
operation without synthetic sources; deployment readiness remains the caller's
responsibility.

Source count is bounded to 16; candidate count is explicitly configured from 1 to
4096 per source. Queries reject more than 4096 matching candidates before decoding
envelopes. Envelope metadata is bounded to 64 KiB, payloads to 4 MiB and evaluation
requirements to 128. Saturation returns `ErrSaturated`, preserves the overflow
observation in the archive when storage succeeds, and removes all eligibility for
that source. There is no eviction that silently preserves a positive result.

The tracker does not restore eligibility from disk after restart. Reopening CAS
preserves historical signed observations, but every source must begin a new
session and supply new observations. A connected stream alone proves nothing.
No heartbeat, silence threshold, packet-loss guarantee, TPM/TEE assertion or
Phase 2 attested telemetry capability is implemented or inferred here.

## Validation and integration boundary

The new tests use filesystem CAS, persisted Ed25519 keys and actual signing and
verification. No mock repository or verifier is used. They cover:

- signature and signed-field tampering; wrong subject, control, type and producer;
- wrong epoch, stale/future captures and explicit missing-evidence policy;
- missing artifact read errors and corrupted disk bytes rejected on recovery;
- unavailable sources, new sessions and tracker restart never restoring positive eligibility from archives;
- saturation preserving observations while entering SAFE_HOLD;
- real `io.Pipe` writes finishing after End, session replacement or a conflicting concurrent writer, retaining archived bytes without making them eligible;
- explicitly configured adverse evidence dominating complete positive requirements.

Focused uncached race tests and lint pass. `go build ./...` passes. At the base
revision `112c353`, the broader race suite still contains an unchanged controller
harness expecting Ready=True from an empty evaluator, and full lint reports the
existing deprecated API scheme builder. Controller/CLI wiring and those existing
integration checks remain part of the parent change. This unit does not claim a
live SDK-to-controller end-to-end demonstration; that requires the authenticated
source runners, authoritative binding resolver and re-evaluation loop.
