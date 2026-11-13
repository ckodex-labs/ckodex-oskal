# Sigstore adapter

`NewBundleVerifier` uses sigstore-go v1.4.0 with required exact issuer and signer
identity and caller-supplied trusted root JSON. Each verification requires a
SHA-256 artifact digest, certificate transparency, artifact transparency and a
trusted observer timestamp. Missing policy, missing roots and unverifiable
bundles fail closed. No unpinned signer or custom Ed25519 metadata fallback exists.

The caller must acquire roots through authenticated TUF updates or explicitly
pinned offline custody. The adapter does not fetch roots and does not treat roots
inside an input bundle as authoritative. Offline verification establishes signed
historical evidence, not current TUF freshness. Root changes require a new verifier.

`VerifyBundle` accepts at most 4 MiB of bundle JSON and returns private verified
facts. It performs no network I/O. Cancellation is checked before and after the
bounded-input synchronous cryptographic verification; the underlying library
cannot interrupt an individual cryptographic operation.

`VerifiedBundle.Receipt` serializes artifact, bundle and root digests, exact
verified identity, predicate type and verification time for durable storage.
`Evidence` references the bundle and hashes that receipt. The caller must retain
both receipt and bundle and supply the authenticated verifier's producer identity.
A detached signature produces signature evidence only. A verified SLSA v1
statement produces provenance evidence, but does not imply a SLSA assurance level,
validate an arbitrary SBOM, or prove the running workload uses the signed artifact.
`VerifyArtifactContinuity` compares separately established running, admitted and
signed digests; the caller is responsible for authenticating those observations.

Primary version and API references:

- https://github.com/sigstore/sigstore-go/releases/tag/v1.4.0
- https://github.com/sigstore/sigstore-go/blob/v1.4.0/pkg/verify/signed_entity.go
- https://github.com/sigstore/sigstore-go/blob/v1.4.0/pkg/verify/certificate_identity.go

Tests use real published GitHub Actions release bundles; see `testdata/README.md`
for source identity and root custody. Positive and negative verification runs are
offline. They do not prove live root refresh, OCI registry discovery or a running
Kubernetes workload's artifact lineage.
