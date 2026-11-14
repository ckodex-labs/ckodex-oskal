# Local Dagger attestation verification

`Dagger.Attest` is a local byte-consistency check using an ephemeral key generated
inside each uncached signing execution.
It does not authenticate a source revision, builder identity, release identity,
trusted timestamp or SLSA level. The GitHub OIDC release flow in
`.github/workflows/release.yml` is a separate contract and is unchanged.

## Failure and correction

[CI run 43534260835, job 132259298565](https://github.com/ckodex-labs/ckodex-oskal/actions/runs/43534260835/job/132259298565)
reached the old cosign 2.4.1 blob-signing step after build/vet/race/lint passed.
That command used the default public Rekor upload behavior. The reported
duplicate-signature path then attempted a log-entry fetch and received HTTP 404.
This establishes an unwanted online dependency in a local-only gate; it does
not establish that all Rekor services or the separate release flow are broken.

The module now uses upstream [cosign v3.1.4](https://github.com/sigstore/cosign/releases/tag/v3.1.4)
from its [documented OCI namespace](https://github.com/sigstore/cosign/blob/v3.1.4/README.md#dockerfile),
pinned to the immutable multi-platform index:

```text
ghcr.io/sigstore/cosign/cosign:v3.1.4@sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d
```

The index resolved through the public registry includes Linux AMD64 child
`sha256:dfc0619d0ccc361d2632001060e65051cf41ece7280aa68b85877a447e9f935b`
and Linux ARM64 child
`sha256:ed349ce82b95c8f86d3769f81651abe3ce0c2542e2d132149e2ebc3f56b6814b`.
This records the selected image identity; it is not an independent verification
of its publisher's signing identity.

## Signing and verification contract

Cosign 3.1.4 defaults to a TUF-provided signing configuration and current
Sigstore bundles. The previous `--output-signature` and `--output-attestation`
outputs are deprecated and ignored in its default bundle mode.

The local gate runs `cosign signing-config create --out
offline-signing-config.json` without default-service flags. Its actual output
contains no Fulcio, Rekor, OIDC or timestamp service URLs. Both signing commands
use that file, an explicitly generated local private key,
`--oidc-disable-ambient-providers`, and `--bundle`. Upstream's
[configuration loader](https://github.com/sigstore/cosign/blob/v3.1.4/cmd/cosign/cli/signcommon/common.go)
does not load TUF trust material for a local key and a configuration with no
services.

The key and tampered copies live in one execution's temporary mount. Only the
public key and public evidence outputs are exported. `TUF_ROOT` points inside
that temporary mount, and the script requires that no TUF cache was created.
HTTP(S) proxy settings point to unreachable loopback port 9, with no bypass list.
No host/global TUF configuration is changed.

For each actual binary, the gate verifies both the blob signature and the
attestation using the generated public key. `verify-blob-attestation` explicitly
retains `--check-claims=true`, checking the binary's digest against its signed
in-toto subject. Appending bytes must fail both verifiers, and the gate fails if
either altered binary is accepted. Each cosign signing/verification command has
a 30-second timeout. The module retains lazy Dagger execution so independent scan
work is not unnecessarily serialized behind signing. The caller owns its complete
execution deadline; the existing hosted SSDLC job is bounded to 30 minutes.

Both local verifiers use `--insecure-ignore-tlog` because this profile deliberately
creates no transparency record. Cosign's warning is expected: public transparency
and auditability are absent. Signature verification and attestation subject-digest
verification remain enforced; `--no-verify` is not used. This setting does not
apply to the release workflow or establish any externally trusted identity.

## Public output files

| File | Meaning |
| --- | --- |
| `cosign.pub` | Fresh local consistency key, not an identity anchor |
| `offline-signing-config.json` | Explicit configuration with no remote signing services |
| `oskal.sigstore.json`, `oskal-controller.sigstore.json` | Current-format blob signature bundles |
| `oskal.intoto.sigstore.json`, `oskal-controller.intoto.sigstore.json` | Current-format attestation bundles |
| `provenance.json` | Locally asserted build predicate, without an assurance-level claim |
| `local-verification.txt` | Successful signature/subject checks and altered-binary rejection |

Consumers of older local output filenames must use these bundle files with
cosign 3.1.4. Release artifact names and verification are unchanged.

## Observed verification and limits

On 2026-11-13, Dagger CLI/engine 0.21.11 on Linux ARM64 built both repository
binaries and executed the real final-source Attest gate. It completed in 1m24s and
exported its public outputs with exit status 0. Four valid checks printed
`Verified OK`. Altered binaries failed blob signature verification and attestation
subject-digest verification. The exact current script was also run in an owned,
resource-bounded Docker container using `--network none`; its result is recorded
alongside the local evidence below.
That container ran as UID/GID 65532, with a read-only root filesystem, all
capabilities dropped, 2 CPUs, 512 MiB memory and 64 PIDs. It exited 0 with four
valid cryptographic checks and four expected altered-binary rejections. Its
actual cosign reported version 3.1.4 and source commit
`0e48502cf5ef34e2e60bbd3617aa19945712f705` on Linux ARM64. The exported binaries
matched the Dagger-attested hashes before this independent execution.

Local retained evidence is under
`/private/tmp/oskal-p2-offline-attestation-evidence/`, including the actual Dagger
log, exported public bundles, exact signing script, binary hashes and the
network-disabled execution log/metadata. These files contain no claim that
hosted CI has passed this change. A new GitHub Actions run remains required after
the root-owned PR is pushed. Image/module downloads and build dependencies still
use networking; the offline claim concerns only local signing and verification.
