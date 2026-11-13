# Explicit signing authority and model descriptor scope

## Change dossier

The signing path previously accepted an absent authority and substituted a
production-looking SPIFFE evaluator. Its evidence authority remained empty,
creating two different authority interpretations in one signing manager.
`SignReceipt` also accepted a different nonempty evaluator supplied by its caller.
The SPIRE authorization resolver installed example production trust domains and
producer grants when its policy was nil.

Repository-wide Go call inventory before this change found:

- Receipt-manager production callers already supplied explicit local or SPIFFE
  authority references. One evaluation test deliberately constructed an empty
  manager; it now expects constructor refusal.
- A storage quota test re-signed a SPIFFE fixture with an unrelated local
  signer. It now reuses the original signer instead of changing identity or
  weakening the new receipt-authority check.
- `NewSpireAuthorityResolver` was called only by its authorization and SVID
  tests. No production caller depended on implicit production grants.
- `NewShieldObserver`, `ModelForensics`, and `GenerateModelEvidence` were called
  only by `internal/adapters/shield/shield_test.go`. No production integration or
  public SDK exposed them. The pure model/agent subject helpers were also used
  only by their own descriptor tests.

The smallest coherent change removes those defaults and the unused generator,
preserves the receipt signature format and descriptor helpers, and verifies
actual key material before admitting a signer. There are no main, webhook,
CEL, infrastructure, protocol, or model-backend changes in this unit.

## Signing contract

All receipt signing constructors require `AuthorityRef.Validate()` before key
generation, directory creation, or persistent key reads. An authority reference
is a supplied claim; passing structural validation or generating a local key
does not authenticate a SPIFFE identity or establish evidence trust.

`NewReceiptManagerFromKey` requires the 64-byte Ed25519 private key format. It
derives the standard key from the seed, rejects a contradictory public half, and
keeps an owned copy so later caller mutation cannot change its signing identity.
Receipt signing fills an entirely absent evaluator from that explicitly
configured authority, and rejects a nonempty evaluator that differs in any
authority field, matching the existing evidence-signer identity comparison.
Cancelled signing is refused before a receipt is modified or signed.

Persistent private/public files contain exactly 128/64 hexadecimal characters,
respectively, with an optional final LF or CRLF. Reads are bounded before decode;
non-regular files and malformed or oversized encodings are refused. A public
file that differs from the private key is an error, as is a public file without
its private key. Those files are preserved for operator investigation instead of
being silently replaced or rotated. A missing public file may be regenerated
only from the existing validated private key. Private-key writes retain mode
0600. Existing receipt canonical bytes and signatures are unchanged.

Key-directory ownership and competing writers remain operator responsibilities.
This is not a distributed key-custody protocol or proof of crash durability.
Independent receipt verification proves a signature under the supplied public
key; it does not itself authenticate evaluator labels or verify observations.

## SPIRE policy contract

Nil and default policies grant no domains or evidence authorities. Explicit
policies are validated and copied before use. Invalid configuration denies all
rather than partially accepting its valid entries. Policies permit at most 64
trust domains, 256 exact producer grants, and 64 evidence types per producer;
producer labels and type strings have bounded sizes. A literal `*` evidence type
retains its existing meaning as an explicitly configured all-types grant.
Wildcard producer identities are refused.

`ValidateIdentity` checks label syntax and configured trust-domain scope.
`IsAuthorizedProducer` applies the configured grant to an identity that the
caller must authenticate independently through the SVID/peer verification path.
Neither method treats a caller-supplied SPIFFE string as authentication evidence.
Changing the original policy's maps or slices cannot expand the resolver's
copied authority snapshot.

## Model scope

The retired Shield generator converted a supplied `TamperProof` boolean and
`SafetyScore` into evidence and findings without a model inspector or retained
payload. Its old VERIFIED/ASSURED projection test therefore did not demonstrate
model forensics, tamper detection, model admission, or AI-BOM verification.

Only `BuildModelSubjectRef` and `BuildAgentSubjectRef` remain. They preserve
caller-supplied identity metadata and perform no collection, digest verification,
security assessment, or assurance transition. Model security and AI forensics
are not supplied by this adapter; no replacement capability is claimed.

## Verification

Tests use generated Ed25519 keys, actual temporary files and real cryptographic
verification. They cover missing authority without persistent side effects,
private/public inconsistency, oversized/malformed files, public-key orphan and
mismatch preservation, private-key ownership, exact receipt evaluator binding,
cancelled signing, reopening, and regeneration of a missing matching public file.
Authorization tests cover empty/default denial, explicit grants, wrong domains,
wrong evidence types, malformed configurations, and caller-mutation isolation.
Descriptor tests assert only subject metadata construction.

The same tests against the prior signing/policy implementations through a
temporary Go overlay reproduced their failures with real keys and files. No
private key bytes were printed. The baseline reproduction log is retained at
`/private/tmp/oskal-explicit-authority-baseline/repro.log`.

Verified locally: focused race tests, `go test -race -count=1 -p=2 ./...`,
`go build -p=2 ./...`, and full `golangci-lint run` passed. The first full race
run exposed the storage test's unrelated signer described above; the complete
suite passed after that caller retained its original signer. These checks
provide local evidence; no deployed SPIRE, model, hardware, or production claim
follows from them. Logs are retained under
`/private/tmp/oskal-explicit-authority-{focused,full-race-final,build,lint-final}.log`.
The checks used the installed Go 1.27.3 darwin/arm64 toolchain. Verification
under the final release toolchain and the final deployed assembly is separate.
