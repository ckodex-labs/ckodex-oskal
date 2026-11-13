# Phase 2 software TPM quote adapter

The wire root code is `SOFTWARE_TPM`. The human label is the exact value of
`tpm.SoftwareRootLabel`: `software TPM root \u2014 not hardware-backed`, with the
Unicode escape rendered as an em dash. Neither a successful quote nor this
adapter establishes hardware-backed assurance.

## Change dossier

The Phase 1 path admits source observations and produces existing evidence and
receipts. This change adds a standalone cryptographic adapter, without changing
that path, the semantic kernel, ports, controllers, or receipt encoding.

The new path is externally provisioned AK and PCR policy, bounded TPM command
transport, actual `TPM2_Quote`, and offline verification against trusted enrollment
and expected qualification. The application must supply challenge, channel,
session, identity, epoch, expiry, and replay policy. Only that application may
convert verified quote facts into source eligibility.

Consequential mutations are confined to explicit integration-test provisioning:
reset demo PCR 16, measure the running test executable, extend that digest, and
create an authorization-protected restricted signing AK. The test harness is the
measurement authority for this experiment; this is not an independent guest
measurement broker, measured boot, IMA validation, or memory-integrity proof.
Production adapter code does not provision keys, reset PCRs, or enroll itself.

## API and ownership

`NewProvider(ProviderConfig)` accepts a pre-existing AK handle, raw SHA-256 AK
name, nonempty authorization, PCR index, positive timeout no greater than 30
seconds, and either an absolute Unix socket or a literal loopback TCP endpoint.
The host must own the TPM state, authorization, and command/control endpoints.
Never expose those endpoints to an untrusted guest: they permit operations beyond
quoting. A guest-facing constrained broker is outside this change.

`Provider.Quote(ctx, [64]byte)` first checks the handle's current AK name, reads
the selected SHA-256 PCR, and executes `TPM2_Quote`. It returns exact raw
`TPMS_ATTEST` bytes, the marshaled `TPMT_SIGNATURE`, the PCR value, and the explicit
software-root classification. The quote does not include a `TPM2B` size prefix.

`NewVerifier(Enrollment)` requires trusted configuration: canonical `TPMT_PUBLIC`
bytes, AK name and qualified name, the exact single-PCR selection, and its expected
SHA-256 value. Only restricted, fixed-TPM, fixed-parent, TPM-origin ECDSA P-256
signing keys using SHA-256 are accepted. Public names are never trusted merely
because they accompany a quote.

`Verifier.Verify(Quote, [64]byte)` verifies exact canonical encodings, bounds,
generated magic, quote type, qualified signer, qualification, bank/index selection,
measurement policy, PCR composite digest, ECDSA algorithm/hash, and the signature
over the original attestation bytes. It reports cryptographically verified facts,
including TPM clock/reset information. TPM clock is not verifier wall-clock time.

The caller constructs the 64-byte qualification from its own challenge and actual
TLS channel. The intended application contract is a literal verifier nonce in the
first 32 bytes followed by a domain-separated SHA-256 binding of export-key hash,
TLS exporter, session identity, and enrollment-policy identity. RFC 9266 channel
binding uses `EXPORTER-Channel-Binding`, empty context, and 32 output bytes. Never
accept a sender-supplied exporter as authoritative.

This low-level verifier is intentionally stateless: it will verify the same valid
quote again when given the same expected qualification. Atomic challenge
consumption, expiry, monotonic sessions, telemetry signatures, revocation, and
periodic reattestation must be enforced by the application. Invalid input must not
be promoted into positive source evidence; the intended application mapping is
UNKNOWN with the specific rejection retained.

## Failure and recovery bounds

One provider serializes its whole read/quote operation using a context-aware gate.
Waiting for that gate consumes the operation's timeout. Each real socket command
has a deadline, bounded 4 KiB framing, and cancellation closes its own connection.
There are no retries or timeout worker goroutines. The application bounds total
providers and incoming request concurrency. A timeout or external PCR mutation
does not fall back to an unsigned observation or a different root.

PCR read and quote are separate TPM commands. A concurrent external extension can
make the returned PCR value inconsistent with the signed digest; verification
rejects the pair. Recovery means a fresh application challenge and a fresh quote
under current enrollment. Restarted/cleared/reprovisioned TPM identity requires
explicit enrollment handling. No automatic trust promotion or state deletion is
implemented here.

## Pinned implementation inputs

- Go module `github.com/google/go-tpm` v0.9.8, upstream commit
  `6a7f64318ba9e8e7a0f8c5710b07ca47bf911f4c`.
- swtpm v0.10.2, commit `32b5a0575991a73398de9749d63cafd847008af2`, archive
  SHA-256 `f61cf6f1e9bbcb4cefb30b70cafaf1c4df54c6961e65cfa63830e8ad0e220134`.
- libtpms v0.10.2, commit `03ff2481e133540be3b3ffe3daa1483d2a73d967`, archive
  SHA-256 `edac03680f8a4a1c5c1d609a10e3f41e1a129e38ff5158f0c8deaedc719fb127`.
- Official Debian `bookworm-20261104-slim` multi-platform index
  `sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc`.

The runtime Dockerfile checks both source archive digests before compiling. Debian
build dependencies are obtained from its configured repositories, so their exact
versions are build-time observations; this is not a fully hermetic build. No
software emulator is linked into the Go process.

Primary references: [Quote API](https://github.com/google/go-tpm/blob/v0.9.8/tpm2/tpm2.go#L869),
[attestation fields](https://github.com/google/go-tpm/blob/v0.9.8/tpm2/structures.go#L1313),
[swtpm release](https://github.com/stefanberger/swtpm/releases/tag/v0.10.2),
[libtpms release](https://github.com/stefanberger/libtpms/releases/tag/v0.10.2),
[official Debian image](https://hub.docker.com/_/debian),
[RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html#section-2).

## Repeat the real integration test

Use an explicitly authorized Docker context. The following names and volume must
belong to this test only; it resets PCR 16 and temporarily pauses its TPM process.
Nothing installs onto the host. Build and runtime resource limits are explicit.
Keep the state volume and logs for diagnosis; do not reuse production TPM state.

```sh
docker context show
docker build --memory=2g --cpu-quota=200000 \
  -t oskal-p2-tpm-runtime:0.10.2 \
  -f tests/runtime/tpm/Dockerfile tests/runtime/tpm
docker run -d --name oskal-p2-tpm-runtime \
  --cpus 0.5 --memory 128m --pids-limit 64 --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --volume oskal-p2-tpm-state:/state -p 127.0.0.1::2321 \
  oskal-p2-tpm-runtime:0.10.2
docker port oskal-p2-tpm-runtime 2321
# Set this to the actual printed loopback address, never a guessed port.
export OSKAL_SWTPM_ADDRESS=127.0.0.1:PORT
export OSKAL_SWTPM_CONTAINER=oskal-p2-tpm-runtime
export OSKAL_TPM_EVIDENCE_DIR=/absolute/private/evidence/directory
go test -tags=integration -race -count=1 -v ./internal/adapters/tpm
golangci-lint run --build-tags=integration ./internal/adapters/tpm/...
go build ./...
docker logs oskal-p2-tpm-runtime
docker stop --time 5 oskal-p2-tpm-runtime
```

The integration build tag intentionally requires a real endpoint and named test
container; missing infrastructure fails the test. There are no mocks, stubs,
canned quotes, embedded simulators, or fallback returns. Evidence files are
created with mode 0600 and contain public enrollment, qualification, quote, and
verification results, never the AK authorization. `ak.pem`, `quote.sig` (ASN.1
ECDSA), and `quote.attest` support an independent OpenSSL signature check:

```sh
openssl dgst -sha256 -verify ak.pem -signature quote.sig quote.attest
```

## Observed verification, 2026-11-13

On macOS arm64 with Go 1.27.4 and Docker context `colima`, the adapter communicated
over actual published loopback TCP to the separately running Linux arm64 swtpm
process. The native image ID was
`sha256:0ea3c1e396ee6e8229d0cda015cb8b130fc410b2af72bb73c36a83b5aa9e0150`
(170,657,111 bytes). This is a local image identity, not a published OCI release.

The real integration race run passed: valid quote; wrong nonce/export key;
independent real TLS 1.3 connection binding; prior quote against a new challenge;
altered/trailing/truncated/oversized encodings; substituted AK name; wrong AK
authorization; unsigned PCR-value substitution; wrong PCR selected and signed by
the real TPM; changed PCR; concurrent acquisition; cancellation; actual Docker
pause deadline and unpause recovery. Both TLS endpoints independently derived and
compared the RFC exporter. The race run took 1.616 seconds including race-runtime
overhead. Focused tagged lint and full repository lint reported zero issues;
`go build ./...` and the full repository `go test -race ./...` passed.
OpenSSL 3.0.22 in the running container independently verified the exact quote
signature and printed `Verified OK` with exit status 0.

The repository ASCII gate still reports inherited non-ASCII characters in
`docs/capability-lease-execution.md`, `docs/p1-policy-delivery-evidence.md`,
`docs/p1-runtime-evidence.md`, and `docs/p1-policy-ingestion-evidence.md`. Those files
were unchanged. All new TPM Go source, this document, and the Dockerfile are ASCII.

No hardware, TEE, guest-root resistance, host-root resistance, continuous code
integrity, protected telemetry key, full source admission, durable replay policy,
or production deployment is proven by these results.
