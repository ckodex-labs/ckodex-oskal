# Public release verification fixtures

The checksum signature and SLSA v1 statement were produced by the real GitHub
Actions release rehearsal at:
https://github.com/ckodex-labs/ckodex-oskal/actions/runs/43364940173

Source revision: `83cb19252fb652e0fcce7887b73fd22bcc1e6f4d`.
Exact signer: `https://github.com/ckodex-labs/ckodex-oskal/.github/workflows/release.yml@refs/heads/p1/release`.
Issuer: `https://token.actions.githubusercontent.com`.
These are historical verification fixtures, not production trust policy.

`trusted_root.json` was copied from the isolated public-good Sigstore TUF cache
used for the successful cosign 3.1.4 verification on 2026-11-12. Its upstream
repository is https://tuf-repo-cdn.sigstore.dev. The production caller must supply
its own TUF-authenticated or explicitly pinned offline root; it must never trust
a root delivered alongside an untrusted bundle. Offline verification authenticates
historical signing time and transparency evidence, not current TUF freshness.

Tests verify the real bundles without network access. Negative cases alter the
artifact digest, exact issuer, exact signer, signature, certificate, transparency
entry, and inclusion evidence. No mock signing service or generated fixture
stands in for the release backend.
