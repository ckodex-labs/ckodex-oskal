OSKAL checks Kubernetes security evidence and reports UNKNOWN by default when required evidence is missing.

[![CI](https://github.com/ckodex-labs/ckodex-oskal/actions/workflows/ci.yml/badge.svg)](https://github.com/ckodex-labs/ckodex-oskal/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ckodex-labs/ckodex-oskal/badge)](https://scorecard.dev/viewer/?uri=github.com/ckodex-labs/ckodex-oskal)

With Go matching go.mod, make, Docker, Kind, kubectl, Helm and Git installed:

```sh
make demo
```

A fresh-cluster run deployed the real controller and Tetragon sensor, observed a
non-root process, then stopped the sensor:

```text
Before: ASSURED, 1/1 verified, root=sha256:aa5f5d807c79e3bc25ae66e3cd640ce7dc648c1250e894039676fa8a8d99c0e0, signed receipt=rcpt-9dad178f057f509fb28cfe26a30852bcab86f48657ed8dcb891f7a497978a6ea
After: UNKNOWN, 0/1 verified, root cleared, signed receipt=rcpt-b1e82640a59083bc95dad1a9d0f8da5dcd5177c94b7a407f3d5692b0ba370d23
Source-loss transition observed in 3.014592917s.
Both receipts verified with the actual CLI and the host-pinned public key.
Demo acceptance duration: 1m26.568509s.
```

The control means that this Pod was observed executing with a nonzero effective
UID. It does not certify all process privileges or the cluster's overall security.
The collector uses mutual TLS, signs the captured evidence, and evaluates it against
an explicit contract and policy. When the source stops, earlier evidence remains
archived but loses eligibility for the current assessment. The demo verifies both
receipts against a public key created before deployment.

The quoted run used an unchanged source snapshot and the inspected official chart;
three earlier image-identity checks failed and were corrected before this fresh run
succeeded. [Exact command, output, failures and scope](docs/p1-deployed-demo-evidence.md).
The cluster and protected artifacts are retained for inspection; cleanup is printed.
Local signing keys are not hardware-backed, and no TEE assurance is claimed.

## Implemented and verified

A control is a named requirement. An EvidenceContract declares which observations,
producers and freshness windows it needs. A ControlBinding connects that contract
to a real workload. A separate AssurancePolicy authorizes promotion from VERIFIED
to ASSURED. Missing or unverifiable evidence never becomes a pass; explicit policy
may escalate UNKNOWN to FAILED.

| Capability | Demonstrated behavior |
| --- | --- |
| Runtime capture | Real Tetragon 1.8.0 and Hubble/Cilium 1.20.4 APIs over mutual TLS, live Pod identity checks, and disk-backed evidence. Effective-UID and observed-flow facts do not imply complete least privilege or isolation. |
| Policy-engine inputs | Real Kyverno PolicyReport/OpenReports, Gatekeeper audit and masked OPA decision logs decoded and delivered to storage. Reporter pass, zero violations and truncated audit lists are not automatic compliance decisions. |
| Identity | Real SPIRE Workload API identity, exact mutual-TLS peers, stopped-agent denial and recovery. SPIFFE identifies workloads; SPIRE supplies those identities. |
| Artifact verification | Real Sigstore signatures and provenance bundles, exact issuer/signer, explicit trusted-root pin and artifact digest. Wrong identity, missing proof and tampering are rejected. Historical verification does not prove current TUF freshness or running-image lineage. |
| Evidence and receipts | SHA-256 content-addressed storage (CAS), atomic writes, immutable full-digest receipt references, and Ed25519 evaluation receipts. Corrupt recovery fails closed and preserves bytes. The aggregate root is not a Merkle inclusion-proof tree. |
| Execution authority | Kubernetes CapabilityLease reads and atomic turn reservations, authenticated caller/scope/capability checks, actual completion history and crash-safe pending state. Execution chains are unsigned and do not protect against an administrator rewriting status. |
| OSCAL export | All five embedded NIST OSCAL 1.2.3 schemas, with explicit document relationships and system facts. OSCAL is a machine-readable assessment format; schema validity is not certification. Missing mandatory facts produce errors. |
| Diagnostics and clients | Unverified material remains UNKNOWN in CLI, MCP, UTCP, service and SDK paths. Receipt verification requires an explicit key. Network clients require explicit TLS trust; archive inventory does not invent current assurance. |

The pure Go semantic kernel contains domain rules; adapters own Kubernetes, RPC,
identity and storage integration. Source sessions separate current eligibility from
immutable history. Detailed evidence and boundaries are recorded in the
[controller](docs/p1-publication-guards.md), [runtime](docs/p1-runtime-evidence.md),
[policy ingestion](docs/p1-policy-ingestion-evidence.md),
[delivery](docs/p1-policy-delivery-evidence.md),
[lease](docs/p1-capability-lease-evidence.md),
[CLI](docs/p1-cli-truth.md), and [service](docs/p1-service-evaluation.md) records.

## Known limits

- Phase 2 attested in-guest telemetry, hardware or software TPM quotes, signed
  heartbeats and complete sensor-loss accounting are not implemented. An explicit
  Hubble loss notice faults the source; that is not proof of loss-free visibility.
- Policy-engine ingestion retains native assertions, missing revisions and audit
  truncation. Capture-only records do not authorize control promotion; an authored
  mapping and sufficient proof are required.
- Bound workload resolution supports Pods and Deployments. Unsupported or ambiguous
  attribution fails closed. UID-less flows have an additional creation-time guard.
- Multi-object Kubernetes reads/publications are not transactional. Consumers must
  verify current epoch and validity deadlines before consequential actions.
- Lease revocation constrains new admissions; already-granted external effects need
  downstream fencing for guaranteed cancellation. Pending uncertain effects are
  never automatically replayed or refunded.
- The deployed runtime proof was Linux arm64 in a four-CPU, approximately 8 GiB
  Colima VM. Cross-compilation does not establish native support on other targets.
  Resource contention caused earlier control-plane delays; unrelated workloads
  were preserved. No performance or scale claim is made.
- Scorecard publishing runs on the default branch. The PR scan is read-only; the
  published result badge remains unverified until an approved merge and publishing
  run. Code-Review and Contributors may score low for a solo maintainer.

## Development

The integrated source has passed build, vet, race tests and the existing linter:

```sh
go build ./...
go vet ./...
go test -count=1 -race ./...
golangci-lint run ./...
```

Use [explicit projection inputs](docs/oscal-projection-inputs.md) for OSCAL exports,
[security reporting](SECURITY.md) for disclosures, and
[contribution guidance](CONTRIBUTING.md) for changes. The Apache 2.0
[license](LICENSE) applies.

## Verify this release

Verify the signature and provenance before running a downloaded binary.

The prepared version is **v1.0.1**. It has not been published by this work.
The release workflow builds five binary archives and one Linux container image
archive, attaches SHA-256 checksums and signing/provenance bundles, and signs the
versioned registry image by digest. Cross-compilation is not native platform testing.
The [SLSA 1.2 specification](https://slsa.dev/spec/v1.2/) uses the
`https://slsa.dev/provenance/v1` build predicate; no SLSA level is claimed.

With cosign **3.1.4**, GitHub CLI supporting `gh attestation verify`, and the assets
downloaded into one directory, use the following commands. For rehearsal artifacts,
set `OSKAL_REF=refs/heads/p1/release`; after the author publishes v1.0.1, use
`OSKAL_REF=refs/tags/v1.0.1`. Branch evidence must never substitute for the tag identity.

```sh
OSKAL_REF=refs/tags/v1.0.1
OSKAL_IDENTITY="https://github.com/ckodex-labs/ckodex-oskal/.github/workflows/release.yml@$OSKAL_REF"
cosign verify-blob --bundle checksums.sigstore.json \
  --certificate-identity "$OSKAL_IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
sha256sum --check checksums.txt
gh attestation verify oskal_1.0.1_linux_amd64.tar.gz \
  --repo ckodex-labs/ckodex-oskal --bundle provenance.sigstore.json \
  --cert-identity "$OSKAL_IDENTITY" --source-ref "$OSKAL_REF" \
  --deny-self-hosted-runners
```

Verify provenance for each archive you will use. The workflow also pins verification
to the source commit. The checksum signature covers all five binary archives and
the container archive. For registry use, the separately signed `image-reference.txt`
identifies the digest; verify that pointer and the image with the same exact tag
identity before pulling or executing it. Tag-specific verification is unexecuted
until the real tag exists. The branch rehearsal cannot prove registry publication.

Branch pushes to `p1/release` and manual workflow dispatch run the non-publishing
rehearsal. Only a stable tag push can publish a release or registry image. Rehearsal
does create real public signing/attestation records and an Actions artifact bundle.
The author must review the PRs and push the real tag. Existing release/image versions
and unexpected registry/API lookup responses stop publication. A partial publication
requires operator investigation; rerunning does not replace an existing version.
