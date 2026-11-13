OSKAL checks Kubernetes evidence and reports UNKNOWN by default when required evidence is missing.

[![CI](https://github.com/ckodex-labs/ckodex-oskal/actions/workflows/ci.yml/badge.svg)](https://github.com/ckodex-labs/ckodex-oskal/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ckodex-labs/ckodex-oskal/badge)](https://scorecard.dev/viewer/?uri=github.com/ckodex-labs/ckodex-oskal)

Code-Review and Contributors scores may be low because this project has a solo maintainer; the badge reports the measured result.
Scorecard publishing runs on the default branch. Pull requests run a read-only scan; the result badge remains unverified until the publishing workflow is merged and run.

With Go matching go.mod, make, Docker, Kind and kubectl installed, run from this checkout:

```sh
make demo
```

A real fresh-cluster run produced:

```text
before: demo:api-node-ready = PASS (OSKAL control state ASSURED); Verified 1/1 requirements
after: demo:api-node-ready = UNKNOWN; Verified 0/1 requirements
Elapsed: 32.236s
```

The demo creates a Kind cluster, installs six resource definitions, reads its real
node condition through a local API proxy, and runs the OSKAL reconciler locally.
Stopping that proxy removes the current observation. The affected control becomes
UNKNOWN while its earlier evidence remains archived. PASS here means only that
the Kubernetes API reported Node Ready=True; it is not a security audit.

The controller container is not deployed by this demo. Observations are unsigned,
and there is no hardware attestation. The demo checks current source availability
explicitly; production repository ingestion does not yet implement that contract.
Clusters and artifacts are retained, and the command prints their locations.
[Exact run, prerequisites, failures and tool versions](docs/p1-demo-evidence.md).
Two earlier attempts failed because the shared Colima VM exhausted its inotify
instance limit. The successful run required an approved temporary limit increase,
which was restored afterward. A clean-machine first-run result remains unverified.

## What exists

The committed implementation has been built, vetted, linted and tested with the
Go race detector. These local checks do not prove every external integration.

| Capability | Implementation and limits |
| --- | --- |
| Evaluation | Pure Go control evaluation with required evidence, freshness, producer and epoch checks. An epoch identifies the subject and policy versions to which evidence applies. Missing evidence is UNKNOWN by default; policy can escalate it to FAILED. Expired or mismatched evidence can be STALE. |
| Kubernetes | Six custom resource definitions (CRDs) and reconciliation, plus an HTTPS admission webhook with enforcing, warning and audit modes. The demo verifies real CRD status updates. |
| Evidence storage | SHA-256 content-addressed storage (CAS): content is located by its digest. Atomic filesystem writes and offline export/import exist. Startup recovery can skip unreadable or corrupt blobs. |
| Receipts | Ed25519 signatures over evaluation receipts. The evidence root is a digest of sorted evidence digests, not a Merkle inclusion-proof tree. A signed receipt does not authenticate unsigned observations. |
| Runtime adapters | Tetragon and Cilium event normalization exists. Live event subscriptions are not wired into the controller. |
| Identity | X.509 SPIFFE identity validation exists. A live SPIRE Workload API integration is not wired. SPIFFE identifies workloads; SPIRE supplies those identities. |
| Supply chain | The adapter named Sigstore uses a custom signature payload, not cosign/Fulcio/Rekor verification. The committed baseline can accept a trusted signer without a pinned verification key. Do not use it as a production signature admission control. |
| Capability leases | Time- and turn-bounded authorization exists in the in-memory broker. Kubernetes lease status reconciliation is not connected to broker enforcement. |
| OSCAL | Five embedded NIST OSCAL 1.2.3 schemas and document projection exist. OSCAL is a machine-readable format for control and assessment information. Schema validation does not establish semantic completeness or compliance. |

## Not built or not proven

Attested in-guest telemetry, sensor heartbeats, event-loss accounting, replay
rejection, hardware-backed attestation and production sensor-liveness enforcement
are not implemented by this change. They require a separately approved Phase 2.

The diagnostics still contain assertions that should not be treated as verification:
Sigstore doctor status can reflect configuration presence, and inspect reconstructs
some execution and lineage labels without checking actual receipts. The controller
can fall back to memory if its filesystem store cannot initialize. These limits
must be addressed before relying on the system for consequential admission.

No performance, scale, hardware, production-readiness or compliance claim is made.

## Development

The following checks were run successfully against this change:

```sh
go build ./...
go vet ./...
go test -count=1 -race ./...
golangci-lint run ./...
```

See [architecture](docs/architecture/CKX-OSKAL-001.md),
[contribution guidance](CONTRIBUTING.md) and [security reporting](SECURITY.md).
The Apache 2.0 [license](LICENSE) applies.
