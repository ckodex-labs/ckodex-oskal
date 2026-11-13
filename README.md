OSKAL checks Kubernetes security evidence and reports UNKNOWN by default when required evidence is missing.

With Go matching go.mod, make, Docker, Kind, kubectl, Helm and Git installed:

```sh
make demo
```

A fresh-cluster run deployed the real controller and Tetragon sensor, observed a
non-root process, then stopped the sensor:

ASSURED means the observed check passed its explicit policy.

```text
Before: ASSURED, 1/1 verified, root=sha256:ea667a485cba14fe41364fdb6ce25767958e3f7b87688fab79100d9e28613084, signed receipt=rcpt-55cd983060949917afe2b85f30ba2084819ac854df84623956306959c1c12e4a
After: UNKNOWN, 0/1 verified, root cleared, signed receipt=rcpt-f4ebf1ec7e84c14e2467740c62e3657a2a1aef05c6d00299481285abc33f5344
Source-loss transition observed in 3.014099416s.
Both receipts verified with the actual CLI and the host-pinned public key.
Demo acceptance duration: 1m30.990875542s.
```

The control means that this Pod was observed executing with a nonzero effective
UID. It does not certify all process privileges or the cluster's overall security.
The collector uses mutual TLS, signs the captured evidence, and evaluates it against
an explicit contract and policy. When the source stops, earlier evidence remains
archived but loses eligibility for the current assessment. The demo verifies both
receipts against a public key created before deployment.

The quoted run used clean source `02a9f36`, Go 1.27.4 and the default official chart
download. A preceding wrapper mistake restricted executable permissions; that
failed run and the earlier image-identity failures remain recorded.
[Exact command, output, failures and scope](docs/p1-deployed-demo-evidence.md).
The stopped cluster and protected artifacts are retained for inspection.
Local signing keys are not hardware-backed, and no TEE assurance is claimed.

[![CI](https://github.com/ckodex-labs/ckodex-oskal/actions/workflows/ci.yml/badge.svg?branch=p1/controller)](https://github.com/ckodex-labs/ckodex-oskal/actions/workflows/ci.yml)
[![Scorecard PR scan](https://github.com/ckodex-labs/ckodex-oskal/actions/workflows/scorecard.yml/badge.svg?branch=p1/controller&event=pull_request)](https://github.com/ckodex-labs/ckodex-oskal/actions/workflows/scorecard.yml)

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
| Admission capture | Actual TLS request checks and durable request captures. Configured storage failures deny admission in enforcing, audit and warn modes. Captures establish neither workload creation nor runtime privilege. |
| Identity | Real SPIRE Workload API identity, exact mutual-TLS peers, stopped-agent denial and recovery. SPIFFE identifies workloads; SPIRE supplies those identities. |
| Artifact verification | Real Sigstore signatures and provenance bundles, exact issuer/signer, explicit trusted-root pin and artifact digest. Wrong identity, missing proof and tampering are rejected. Historical verification does not prove current TUF freshness or running-image lineage. |
| Evidence and receipts | SHA-256 content-addressed storage (CAS), atomic writes, immutable full-digest receipt references, and Ed25519 evaluation receipts. Corrupt recovery fails closed and preserves bytes. The aggregate root is not a Merkle inclusion-proof tree. |
| Archive bounds | Explicit byte/object budgets, bounded restore and metadata, and SAFE_HOLD on exhausted capacity. Historical bytes remain intact; reviewed operator limits allow reopening. |
| Execution authority | Kubernetes CapabilityLease reads and atomic turn reservations, authenticated caller/scope/capability checks, actual completion history and crash-safe pending state. Execution chains are unsigned and do not protect against an administrator rewriting status. |
| OSCAL export | All five embedded NIST OSCAL 1.2.3 schemas, with explicit document relationships and system facts. OSCAL is a machine-readable assessment format; schema validity is not certification. Missing mandatory facts produce errors. |
| Diagnostics and clients | Unverified material remains UNKNOWN in CLI, MCP, UTCP, service and SDK paths. Receipt verification requires an explicit key. Network clients require explicit TLS trust; archive inventory does not invent current assurance. |

The pure Go semantic kernel contains domain rules; adapters own Kubernetes, RPC,
identity and storage integration. Source sessions separate current eligibility from
immutable history. Detailed evidence and boundaries are recorded in the
[controller](docs/p1-publication-guards.md), [runtime](docs/p1-runtime-evidence.md),
[policy ingestion](docs/p1-policy-ingestion-evidence.md),
[delivery](docs/p1-policy-delivery-evidence.md),
[controller capture](docs/p1-policy-controller.md),
[admission](docs/p1-admission-capture.md),
[archive limits](docs/p1-archive-configuration.md),
[lease](docs/p1-capability-lease-evidence.md),
[CLI](docs/p1-cli-truth.md), and [service](docs/p1-service-evaluation.md) records.

## Known limits

- Phase 2 attested in-guest telemetry, hardware or software TPM quotes, signed
  heartbeats and complete sensor-loss accounting are not implemented. An explicit
  Hubble loss notice faults the source; that is not proof of loss-free visibility.
- Policy-engine ingestion retains native assertions, missing revisions and audit
  truncation. Capture-only records do not authorize control promotion; an authored
  mapping and sufficient proof are required.
- Receipt signatures cover the canonical assessment tuple. Supplemental subject
  attributes require the trusted full-JSON reference; signature validity alone
  does not establish current assurance. The demo checks both.
  [Verification scope](docs/p1-receipt-verification-scope.md).
- Model/AI forensics is not implemented. Subject descriptor helpers generate no
  forensics evidence or model-safety finding.
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
  badge above shows its actual workflow status. The
  [published score](https://scorecard.dev/viewer/?uri=github.com/ckodex-labs/ckodex-oskal)
  awaits an approved merge and publishing run. Code-Review and Contributors may
  score low for a solo maintainer.

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
