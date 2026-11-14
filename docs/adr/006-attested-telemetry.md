# ADR-006: Evidence from an isolated runtime

**Status:** In development

OSKAL must stop trusting a telemetry window when its source, continuity, or freshness cannot be established.

The existing live collector authenticates a transport peer and binds observations to current Kubernetes identities and policy epochs. It does not establish an attested environment, signed heartbeat continuity, or complete sensor loss accounting. An authenticated event is not proof that other events were not lost. Existing receipt signatures cover a fixed evaluation tuple, not arbitrary supplemental JSON fields. These paths must not silently acquire a stronger assurance claim.

## Authority and execution path

An operator enrolls an attestation public key, expected measurement, source identity, export policy, and permitted root outside the guest. The verifier issues a random, single-use session nonce. A TPM quote must sign that nonce together with the session, enrollment-policy digest, export-public-key hash, and the verifier's own TLS channel binding. Submitted key material and an echoed nonce do not establish enrollment or freshness.

The transport adapter owns TLS and framing. The attestation adapter verifies the actual quote, enrolled key, selection, and measurement. The application owns challenge consumption, deadlines, re-attestation, capacity, and source generation. The pure assurance domain owns the deterministic continuity and window transitions. Signing, persistence, and OSCAL projection remain outward adapters.

The initial TPM suite is ECDSA P-256/SHA-256 with one enrolled SHA-256 PCR. The demo uses a real swtpm instance and must label its artifacts and output `software TPM root -- not hardware-backed` (the human display uses an em dash). Software TPM state and quote authority belong to an explicitly trusted supervisor outside the guest. Allowing a guest unrestricted TPM control would let it reset or rewrite the demo's measurement state. A quote signs bytes; it does not by itself prove export-key non-extractability, physical co-residence, current process memory, or protection against the host administrator. No hardware or malicious-host assurance is claimed by this demo.

## Signed observations and time

Every signed record is bound to its session, source generation, monotonic sequence, scheduled heartbeat slot, previous record digest, sample time, and raw observation digests. The verifier derives its own next heartbeat deadline from the agreed schedule; a sender-supplied timestamp cannot extend liveness. Skipped slots, sequence gaps, counter resets, source replacement, invalid signatures, channel changes, and expired quotes remove eligibility. Restarting the verifier invalidates prior sessions. Recovery requires a fresh enrollment-consistent quote and a newly established complete observation window.

Heartbeats and evidence use the standardized DSSE envelope with Ed25519 and an outside-pinned public key. DSSE signs the exact payload bytes and payload type. Structured payload validation rejects duplicate fields, unknown fields, excess nesting, oversized input, and trailing documents. Health and attestation caveats must be inside the signed payload, including UNKNOWN results; an unsigned receipt attribute is insufficient. Legacy receipts retain their documented signature scope and cannot satisfy a policy requiring the new attested context.

## Sensor loss and bounded failure

Tetragon v1.8.0 has separate observer-ring, userspace-queue, listener, BPF, map, and throttling signals. Counts overlap and must not be presented as a unique lost-event total. Any positive relevant loss delta invalidates that window. A missing counter is UNKNOWN unless an independent successful read proves the relevant zero. In particular, Tetragon omits BPF missed-event series both for zero and for failed map reads. A node-local, read-only BPF witness validates the exact pinned-map ABI, source identity, map identity, and effective credentials at each sensitive read. Its signed result carries successful zeros or explicit read failures. A metrics endpoint alone cannot establish that witness.

All input, messages, samples, counters, sessions, challenges, goroutines, retries, and durable artifacts have explicit limits. Saturation or persistence failure causes visible UNKNOWN/SAFE_HOLD, never discarded evidence with a passing result. The verifier owns liveness independently of the producer. No load-balanced metrics scrape may splice different daemon instances into one stream.

## Verification obligations

Pure transition vectors cover startup, healthy continuity, loss, counter reset, missing signals, sequence and slot gaps, silence, expiry, replacement, recovery, and clock boundaries. Real TPM tests cover valid quotes, wrong and replayed session nonces, different export keys and channels, changed PCRs, malformed encodings, and expiration in application policy. Actual TLS connections establish channel-binding behavior. Real Tetragon in a fresh owned Kind cluster must demonstrate measured loss from a bounded flood and silence from stopping the source. Native BPF reads, kernel privilege behavior, and flood results cannot be inferred from compilation or portable parser tests.

Phase 2 is not accepted until the one-command demo, signed receipts, published verification command, CI, and independent review demonstrate these paths. Hardware TPMs, TEEs, physical isolation, and performance remain unverified until separately measured.
