# Receipt authority verification and signature scope

Receipt verification now rejects contradictory evaluator metadata without changing
the existing receipt format, canonical bytes, digest algorithm or Ed25519 signature.

## Authority meaning

`AuthorityRef.Validate` remains pure and uses only the standard library. A SPIFFE
authority must use the lowercase scheme and have an unambiguous URI authority with a canonical lowercase domain,
without user information, port, query or fragment. A nonempty `TrustDomain` must
match that URI's host exactly. An absent domain may be derived from the URI; it
cannot name a different domain. Non-SPIFFE authorities may not declare TrustDomain.
Surrounding whitespace and control delimiters are rejected.

This validates the meaning of an authority label. It does not authenticate an SVID,
network peer or signing-key owner. SPIFFE authentication remains a separate live
adapter boundary. Inventory found no legitimate non-SPIFFE TrustDomain usage;
the non-SPIFFE occurrence was an intentional negative test. Existing SPIFFE sources
supply the domain from their verified identity. A legacy controller test fixture
contains a contradictory domain; no validation rule was weakened for that fixture.

Both internal and public SDK receipt-manager verification require the exact full
evaluator reference configured on that manager, as well as the correct signature.
A different valid evaluator using the same key is therefore refused. Omitting an
explicit configured TrustDomain is also a full-reference mismatch for this API.

`VerifyIndependentReceipt` remains available for explicit key-only verification.
It first validates evaluator semantics, then verifies the existing signature. It
has no expected evaluator configuration, so an absent domain and the same domain
derived from the signed URI may both be valid representations. Contradictory
or malformed authority metadata is rejected. Signing constructors use the same
semantic validation before generating or reading keys or creating directories.

## What the legacy signature binds

The canonical signed tuple is exactly:

1. Subject URI.
2. Canonical control reference.
3. Assurance state string.
4. Composite epoch digest.
5. Evidence root string.
6. Evaluator URI.
7. Evaluation timestamp in Unix nanoseconds.

`Subject.Attributes` is **not directly covered by this signature**. The separate
TrustDomain field is not independently encoded in it; semantic validation prevents
that redundant field from contradicting the signed evaluator URI. Verifying this
tuple does not independently validate the facts represented by the epoch/evidence
digests, source observations, current authorization or current assurance standing.

`ControlReceipt.Digest()` and the service's submitted-receipt digest identify this
canonical tuple. They are not hashes of the entire JSON object. A complete immutable
CAS reference, `rcpt-<SHA256 of stored JSON bytes>`, binds additional serialized
metadata to that reference. A reference itself needs trusted custody; an untrusted
hash or a mutable compatibility alias does not authenticate supplemental claims.

No signature-format migration is implied by these checks. In particular, a test
that changes only Subject.Attributes continues to verify the legacy signature,
while real CAS receipt references differ for the changed full JSON bytes.

## Verification evidence

Before the fix, real generated-key tests reproduced acceptance of a TrustDomain-only
mutation by independent and manager verification. The actual TLS gRPC service also
returned Verified for that mutation. Constructors accepted contradictory authorities
and created key files. These baseline runs failed the new regression assertions.

After the fix, focused tests passed for:

- Unchanged valid SPIFFE/local receipts.
- TrustDomain-only mutation rejection by independent and manager verification.
- Exact manager authority checks despite another valid evaluator using the same key.
- Invalid authority rejection before key-file creation.
- Real TCP/mutual-TLS SubmitReceipt rejection and subsequent unchanged-receipt success.
- Continued UNKNOWN current standing after historical receipt submission.
- Full JSON CAS identity changing when unsigned supplemental metadata changes.

The new cryptographic tests use real Ed25519 keys and temporary files. Transport
verification uses an actual TLS gRPC listener. No Kubernetes API, SPIRE server,
VM or infrastructure changes are needed, and no current-assurance promotion
bypass is claimed from the historical receipt issue.

Verified with Go 1.27.4: race tests for core assurance, receipts and the SDK;
focused actual-TLS service tests; focused SPIRE authority/SVID compatibility tests;
scoped builds; and scoped golangci-lint. The final merged repository's complete
checks and native runtime acceptance remain separate integration gates.
