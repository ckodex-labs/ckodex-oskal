# Outside-guest software TPM quote broker

This adapter proves a bounded software path: an enrolled mTLS caller proves
possession of the separately registered export key; the outside broker checks
an outside-owned ELF file before and after obtaining a real software TPM quote.
The existing downstream verifier checks the quote against its independent AK
and PCR enrollment and its exact expected 64-byte qualification.

Every successful broker response carries:

- `software TPM root — not hardware-backed`
- `Outside-owned ELF file measurement only; does not prove runtime memory integrity, key non-extractability, co-residence, or resistance to guest or host root.`

The client checks both fields. Its opaque TPM report retains the software-root
label expected by the existing verifier. Consumers must retain the limitations
when presenting or exporting assurance results. An actual quote and a matching
file do not establish that the file is the code currently executing in a guest.
A Kind demo does not prove resistance to guest root or host root.

## Authority and execution

`quoteissuer.Config` is outside-owned registration, never request-supplied:

- `Provider`: the host's existing `tpm.Provider`, including private AK auth.
- `Inspector`: mandatory real measurement implementation.
- `AllowedClientCertificateDigest`: SHA-256 of the enrolled mTLS leaf DER.
- `ExportPublicKey`: the enrolled Ed25519 export key.
- `TLS`: server certificate and client CA pool; client certificate verification
  and TLS 1.3 are enforced. Dynamic server TLS configuration is rejected.
- `ProofTTL`: positive, at most one minute; `Capacity`: 1–1024 outstanding nonces.

`NewServer(config)` followed by `Serve(ctx, listener)` exposes only
`assurance.attestation.v1.QuoteIssuer/{Challenge,Issue}`. The protocol carries no
raw TPM command, AK handle, AK authorization, TPM address, or submitted enrollment.
Network policy must prevent the guest from reaching the raw TPM/control socket;
the API alone is not network isolation.

The authenticated caller obtains a random 32-byte challenge. It signs a bounded
DSSE Ed25519 payload containing that nonce, its exact issued timestamp, the
64-byte qualification, and the SHA-256 export key digest. The server verifies
against its registered key, consumes the nonce once, checks freshness and the
outside file, obtains the real TPM report, checks the file and freshness again,
and only then returns the report. Failed attempts after nonce consumption need
a new challenge. Neither failed measurement nor a failed TPM command falls back
to a successful report.

Qualification remains opaque here. The downstream application owns the literal
verifier nonce plus its digest binding to export key, actual telemetry TLS
channel, session, policy and challenge. The broker connection is a separate TLS
connection; it must not replace that telemetry channel binding. The downstream
verifier must independently pin the same enrolled export key.

`NewClient(ClientConfig{Address, TLS, ExportPrivateKey})` implements
`ports.AttestationProvider`. Its TLS configuration requires explicit server name,
root CA pool and client certificate. `Close` closes its gRPC connection. The
client owns no AK credential and has no raw TPM interface.

## File measurement

`NewPinnedFileInspector(absoluteELFPath, expectedSHA256)` opens a read-only
file descriptor, validates ELF framing, and verifies the expected digest. Every
`Verify` checks the retained descriptor, pathname identity, regular-file bounds,
group/world write permissions and digest before returning. Replacement with
identical bytes is rejected because the outside-owned object identity changed.
Content alteration during a paused TPM quote is rejected by the second check.

Files are limited to 128 MiB; hashing checks cancellation between 64 KiB reads.
The launcher must place the file and its ancestors outside guest write authority.
This mechanism does not observe process memory, establish co-residence, or detect
an alteration that is restored between observations. It is deliberately a file
measurement adapter, with an interface for stronger independently measured roots.

## Fresh disposable provisioning

`softwareroot.Initialize(ctx, Config{Network, Address, FreshStateDirectory,
ExecutablePath, ConfirmFreshSoftwareTPM: true})` returns `*Root` containing the
actual `Enrollment`, `ProviderConfig`, and SHA-256 `Measurement` of the ELF.
The caller explicitly owns a newly created disposable software TPM and its state.
The address must be literal loopback TCP or an absolute Unix socket. The helper
cannot prove that a supplied endpoint and state directory belong together; that
custody is an explicit launcher obligation, not protocol-derived evidence.

Initialization requires a private nonsymlink state directory and creates an
exclusive consumed marker. It requires zero SHA-256 PCR16, creates a restricted
P-256/SHA-256 AK with cryptographically random authorization, extends the actual
ELF digest into PCR16, and verifies an actual quote against the resulting trusted
enrollment before returning. It does not reset PCR16, clear a TPM, change lockout
policy, or touch hardware TPM devices. A failed partial initialization retains
the marker and needs new disposable state. Reusing the marker or a nonzero PCR16
is refused. The returned AK authorization remains private to the broker.

`Root.Close(ctx)` flushes only the created transient AK. It does not delete state
or remove the marker. The owner shuts down its disposable TPM separately.

## Bounds, failure and recovery

The server admits at most 16 TCP connections, eight active RPCs, eight concurrent
streams per connection, 8192-byte RPC messages and 4096-byte TPM reports. TLS
handshake and individual RPCs have five-second bounds. Idle connections expire
after one minute and connection age targets five minutes (with gRPC jitter) plus five seconds
of grace. The underlying TPM provider retains its own serialized command budget.
Nonce storage is bounded and expired entries are reclaimed on challenge creation.
Cancellation stops the server and closes its listener/connections.

Wrong client certificate or proof key, wrong/consumed/expired nonce, changed
measurement and unavailable TPM all deny issuance. There is no success cache.
After a file is restored, a new challenge and new real quote can succeed. After
broker restart, old nonces are unknown. After TPM restart, the transient AK must
be reprovisioned from new disposable state and independently enrolled; it must
not silently replace an existing verifier enrollment.

## Demonstrated evidence

The `integration` test requires a dedicated fresh swtpm endpoint and a real ELF:

```text
OSKAL_BROKER_SWTPM_ADDRESS=127.0.0.1:<observed-port>
OSKAL_BROKER_SWTPM_CONTAINER=oskal-p2-broker-<owned-container>
OSKAL_BROKER_ELF=/absolute/path/to/outside-owned.elf
go test -race -tags=integration -count=1 -v ./internal/adapters/quoteissuer
```

The test measures a copy of the supplied real ELF. It uses real CA-signed mTLS,
DSSE signing, swtpm provisioning, quote generation and verification. It rejects
wrong caller/key, unknown nonce, replay, expiry, oversized RPCs, full challenge
capacity, cancellation, post-success mutation and same-bytes file replacement.
It pauses the actual dedicated TPM, alters the measured file while the quote is
blocked, resumes the TPM, and requires the specific post-quote measurement denial.
It then verifies recovery after file restoration. No provider or inspector mock
substitutes for these paths. Tests also refuse reused state and nonzero PCR16.

Local component evidence does not prove a deployed network policy, guest memory
integrity, hardware-backed attestation, or guest/host root resistance.
