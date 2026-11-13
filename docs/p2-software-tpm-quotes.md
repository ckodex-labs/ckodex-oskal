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
create an authorization-protected restricted signing AK. The test harness also
uses the dedicated disposable TPM's known default lockout authorization to reset
its dictionary-attack counter before provisioning and after intentional wrong-AK
authorization tests. Dictionary-attack protection and its parameters remain
enabled and unchanged. Production code never performs this recovery. The harness is the
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
docker network create \
  --opt com.docker.network.bridge.host_binding_ipv4=127.0.0.1 \
  oskal-p2-tpm-loopback
docker run -d --name oskal-p2-tpm-runtime \
  --network oskal-p2-tpm-loopback \
  --cpus 0.5 --memory 128m --pids-limit 64 --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --volume oskal-p2-tpm-state:/state -p 127.0.0.1::2321 \
  oskal-p2-tpm-runtime:0.10.2
docker port oskal-p2-tpm-runtime 2321
docker network inspect oskal-p2-tpm-loopback
# Set this to the actual printed loopback address, never a guessed port.
export OSKAL_SWTPM_ADDRESS=127.0.0.1:PORT
export OSKAL_SWTPM_CONTAINER=oskal-p2-tpm-runtime
export OSKAL_TPM_EVIDENCE_DIR=/absolute/private/evidence/directory
go test -tags=integration -race -count=1 -v ./internal/adapters/tpm
golangci-lint run --build-tags=integration ./internal/adapters/tpm/...
go build ./...
docker logs oskal-p2-tpm-runtime
docker stop --timeout 5 oskal-p2-tpm-runtime
```

The dedicated network must contain only the trusted TPM and any explicitly
trusted test clients. Never attach a guest or an unrelated workload to it. Host
loopback publication does not protect the raw TPM port from peers on the same
Docker network, so the default shared bridge is prohibited for this harness.

This Colima Docker runtime does not retain published ports on an `--internal`
network: the real attempted configuration ran the TPM but exposed no host port.
The verified fallback is a dedicated user-defined bridge with `Internal=false`,
only the trusted TPM as a member, and host publication explicitly on loopback.
It establishes tested network separation, not host-root resistance or denied
outbound access. Docker administrators can still attach containers or alter the
network; they remain inside the trusted-host boundary.

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

### Network isolation correction

The initial run above used the default bridge. Independent review correctly
identified that host-loopback publication still left raw TPM commands reachable
by same-bridge containers. That runtime was stopped and moved onto the dedicated
`oskal-p2-tpm-loopback` network, with no default-bridge attachment. Inspection
showed `Internal=false`, host-binding default `127.0.0.1`, and exactly one member:
`oskal-p2-tpm-runtime-2` at `172.22.0.2/16`. Its actual published endpoint was
`127.0.0.1:32770`; these addresses are observations, not portable configuration.

A separate, owned `oskal-p2-tpm-isolation-probe` container on a different owned
network attempted a real TCP connection to `172.22.0.2:2321`; it timed out with
exit 124 under a two-second bound. The complete real TPM integration race suite
then passed through the published host-loopback endpoint. The original bridge
run is not used as network-isolation proof. Network metadata, the negative probe,
and the new integration output are retained with the private runtime evidence.

## Opaque report port and enrollment coherence

`Provider.Attest(ctx, qualification)` obtains a real quote and produces a version
1 JSON report bounded to 4096 bytes. Its quote fields use canonical standard
padded base64 for the original attestation, TPM signature, and exactly 32 PCR
bytes. The shared `signedrecords.DecodeJSON` rejects duplicate/unknown/case-aliased
fields, malformed Unicode, excess nesting, and trailing documents. The report
does not supply an AK or policy that could establish its own trust.

`Verifier.VerifyAttestation(ctx, report, qualification)` implements the application
port and returns `assurance.AttestedEnvironment` only after real cryptographic
verification and the final cancellation check. Every error returns zero facts.
`Verifier.Environment()` describes the trusted configuration for operator
enrollment; calling it alone is not verification of a quote.

The measurement descriptor is:

```text
SHA256("oskal.tpm.measurement.v1\x00"
       || Marshal(enrolled TPML_PCR_SELECTION)
       || expected SHA-256 PCR value)
```

It binds the bank, index, and expected value through the canonical TPM encoding.
It is distinct from the executable hash that was extended into the PCR. The
application compares the verified measurement descriptor, root kind, and root
label with its externally supplied enrollment before admitting the source. A
report cannot relabel this software verifier as hardware-backed.

The provider now rejects empty/incomplete quote responses before returning them.
ECDSA scalars accept 1..32-byte unsigned representations, with Go's standard
ECDSA verifier enforcing the scalar range and cryptographic validity. The TPM
wire encoding still must round-trip exactly. The current libtpms implementation
emits padded curve-order-sized values, while the TCG structure is a sized ECC
parameter rather than a fixed 32-byte field. See
[libtpms signing conversion](https://github.com/stefanberger/libtpms/blob/v0.10.2/src/tpm2/crypto/openssl/CryptEccSignature.c#L143)
and [TCG Part 2, sections 11.2.5.1 and 11.3.2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf).

### Real report and session verification

The updated real integration race run passed in 3.317 seconds on the dedicated
network. It exercised strict JSON/report errors, wrong qualification,
cancellation, and verified environment facts. A bounded real-quote search found
a leading-zero scalar after 202 quotes. Removing only that leading zero preserved
the same integer and valid signature. This demonstrates verification of an
equivalent minimal encoding; it does not claim the TPM emitted minimal encoding.
If a bounded search finds no such scalar, the test explicitly reports
`NOT_DEMONSTRATED` rather than claiming that coverage.

Real quotes and real DSSE export-key proofs then drove the application session:
wrong nonce/key/TLS channel; wrong proof key; measurement/root mismatch; challenge
expiry and replay; concurrent single-use consumption; signed-record replay;
exact missing heartbeat and sequence ranges; invalid initial timestamp; counter
reset; healthy windows across periodic reattestation; rejection of premature
reattest requests; expired-quote fencing; canceled admission. Rejected admission
left no historical standing or verified quote digest.

Session time inputs were explicit deterministic transition times. Cryptography,
TPM transport, and the independent TLS exporters were real; this test does not
replace an elapsed-time end-to-end watchdog or a live Tetragon loss measurement.
Counter values are signed transition inputs, not a completeness claim about a
running sensor. Root-mismatch rejection reports UNKNOWN; before admission,
snapshot root metadata describes requested enrollment policy, not an observed
environment. Only a successfully verified standing contains admitted facts.

A retained-state rerun exposed a real `TPM_RC_LOCKOUT` after repeated intentional
bad-password vectors. That failure log was preserved. Explicit test-owned
dictionary-attack recovery made reruns reproducible without resetting TPM state
or disabling protection. The upstream legacy command reader rejects `(n, EOF)`
even when `n` contains the entire response, while the modern transport bridge
returns that pair. A test-only reader adapter preserves the actual framed bytes
and defers EOF until the next read; no response or TPM behavior is synthesized.
