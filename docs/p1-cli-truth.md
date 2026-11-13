# Phase 1 CLI and transport truth

The CLI distinguishes untrusted local material, explicitly verified historical
artifacts, authoritative current Kubernetes binding context, and authorized
execution. These paths make different claims.

## Local material and projections

`record manifest` stores exact input bytes with the declared namespaced subject.
It reports `RECORDED_UNTRUSTED`, `authority: UNKNOWN`, and
`admission: NOT_ASSESSED`. It does not manufacture a producer identity, admission
observation, control mapping, runtime epoch, or signed receipt. The former
file-only `record admission` path fails with migration guidance.

Local CLI, MCP, and UTCP analysis share an UNKNOWN-only material evaluator. A
file's presence or digest does not establish an authored contract, current
binding, trusted producer, or assurance. Its coherence remains UNKNOWN even when
material is present. Read operations open an existing CAS
without creating directories. Storage errors propagate.

All five OSCAL CLI projections accept `--projection-context` containing actual
authored document relationships and metadata. Assessment plans require an
actual contract, SSPs require system context, and POA&Ms require actual supplied
findings. UNKNOWN does not invent a failed control or remediation finding.
Pinned NIST 1.2.3 JSON schemas validate generated documents structurally; this is
not a claim of security compliance or runtime implementation.

## Explicit verification

`identity --workload-api unix:///... --spiffe-id spiffe://...` reads the process's
fresh SPIRE Workload API identity and chain. An unavailable backend or unexpected
identity returns UNKNOWN with exit 2. This does not establish another workload's
identity.

`verify bundle` hashes an actual artifact and requires an explicitly supplied
trusted-root file and SHA-256 pin, exact certificate issuer, and exact SAN.
Successful verification covers historical bundle cryptography, CT, and Rekor
proof. It does not establish current root freshness or runtime artifact
continuity. Signature, signer, pin, or artifact mismatch returns exit 3.

`assurance evaluate` requires an explicit kubeconfig, namespace, ControlBinding,
trusted producer key file, authority snapshot digest, and evidence directory.
It resolves the actual workload and contract configuration from the API and
checks exact stored bytes, producer signatures, control scope, freshness, and
epoch. Missing or stale evidence returns UNKNOWN/2; evaluated failure returns
FAILED/3. It does not establish live observer availability or overall admission.
The same explicit options can supply evaluations for OSCAL projection.

## Effects and caller identity

Local CLI and MCP effects require an actual durable Kubernetes CapabilityLease.
The caller comes from a fresh Kubernetes SelfSubjectReview or the explicitly
configured process's fresh SPIRE identity. Request arguments cannot replace it.

HTTP effects require SPIFFE TLS 1.3 mutual authentication with exact own and peer
IDs. The HTTP adapter supplies transport-owned TLS state to fresh peer
verification; headers and arguments do not supply identity. Admission then binds
that peer to the Kubernetes lease's principal, scope, capability, expiry, and
turn/hash state. Execution reservation precedes the effect; durable completion
and an execution receipt follow it. Replay is denied. Plaintext HTTP is limited
to loopback and fixed read-only analysis without an execution broker.

Accepted HTTP connections are bounded before TLS/Workload API processing. HTTP
body/header limits and server deadlines apply; shutdown drains in-flight work
within five seconds. Backend outage fails closed, without last-good identity or
archive trust fallback.

## Observed verification (2026-11-13)

- Actual CLI subprocess verified the committed real release Sigstore bundle and
  rejected wrong signer, wrong root pin, altered artifact, and unavailable SPIRE.
- Actual subprocesses produced all five OSCAL documents from authored metadata;
  each passed the pinned NIST 1.2.3 schema. Missing required metadata failed.
- Real isolated Kind API: a signed Deployment read verified against its actual
  ControlBinding. Changing that binding made the old epoch UNKNOWN/2. The exact
  same archive remained UNKNOWN through ordinary offline UTCP analysis.
- Real SelfSubjectReview identified `kubernetes-admin` for a CLI diagnostic lease;
  the broker reserved and durably completed one turn. A claimed principal could
  not authorize a lease held by a different principal.
- Real SPIRE 1.16.0 agent and CLI subprocess HTTP server: the peer
  `spiffe://phase1.oskal.test/cli` completed one `run_doctor` lease turn and received
  a receipt. Spoofed principal and replay returned HTTP 400; permitted execution
  returned HTTP 200; plaintext was denied. Test namespace:
  `oskal-cli-mtls-1794562130406059344`.
- Focused package tests and linter passed. Full `go test -race ./...` passed all
  packages except the older controller harness assertion expecting Ready=True
  for UNKNOWN evidence; that assertion is corrected on the parent integration
  branch. This branch alone is therefore PARTIALLY VERIFIED until integration.

Live tests are opt-in: `OSKAL_CLI_KUBECONFIG` identifies an explicitly authorized
API; `OSKAL_SPIRE_TEST_SOCKET` and `OSKAL_SPIRE_TEST_ID` identify a real agent.
`OSKAL_CLI_TEST_BINARY` selects a previously built package binary when running
compiled integration tests in the real agent container. Test namespaces and
private evidence were retained for inspection. The two owned SPIRE containers
and their network were removed after preserving logs and stopped runtime data
in a private archive; the real Kind API evidence was retained. No production deployment,
release, signed promotion, Phase 2 attestation, or hardware claim is made.
