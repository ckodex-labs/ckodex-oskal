---
title: "Receipts & Merkle Derivation Specification"
description: "Mathematical and structural specification for Ed25519 ControlReceipts and SHA-256 canonical Merkle evidence trees."
quadrant: "reference"
tier: "E5"
invariant: "Receipt after execution: non-repudiable proof of state"
---

## 1. Overview

To satisfy non-repudiation in regulated environments, OSKAL does not rely on mutable database rows. Instead, state transitions produce immutable, cryptographically signed receipts binding an `AssuranceState` to an active `AssuranceEpoch` and a canonical SHA-256 Merkle Evidence Root.

---

## 2. Canonical Merkle Tree Derivation

Given a set of `N` verified leaf evidence envelopes:

```text
E   = { e_1, e_2, ..., e_N }
h_i = SHA-256(Canonicalize(e_i))
```

### Lexicographical Sorting

To guarantee deterministic root derivation regardless of ingestion order, leaf digests are sorted lexicographically:

```text
H_0 = Sort([h_1, h_2, ..., h_N])
```

### Pairwise Compression

At each layer `k`, adjacent pairs are concatenated and hashed; if a layer has an odd number of elements, the trailing element is carried forward:

```text
H_{k+1}[j]    = SHA-256(H_k[2j] || H_k[2j+1])
H_{k+1}[last] = H_k[last]                       (when len(H_k) is odd)
```

Reduction terminates when `|H_M| = 1`. The single surviving digest is the **Canonical Merkle Evidence Root**:

```text
EvidenceRoot = H_M[0]
```

---

## 3. `ControlReceipt` Data Structure

```text
ControlReceipt = {
    subject:        SubjectRef { scheme, id },
    control:        ControlRef { namespace, id },
    state:          AssuranceState ("ASSURED" | "VERIFIED" | "STALE" | "FAILED" | "UNKNOWN"),
    epoch:          AssuranceEpoch { subjectDigest, implementationDigest, policyDigest, authorityDigest, environmentDigest },
    evidenceRoot:   "sha256:<hex>",
    evaluator:      AuthorityRef { scheme, subject },
    evaluatedAt:    RFC3339 Timestamp,
    signature:      Hex-encoded Ed25519 signature over canonical payload
}
```

---

## 4. Signing & Verification Protocol

The Ed25519 signature binds the canonical serialized receipt fields (excluding `signature`):

```text
Payload   = CanonicalSerialize(subject, control, state, epoch, evidenceRoot, evaluator, evaluatedAt)
Signature = Ed25519_Sign(PrivateKey_Signer, Payload)
```

An auditor or external verifier can independently verify the receipt offline without access to the Kubernetes API server or OSKAL cluster using `oskal assurance receipt verify --receipt-file <receipt.json> --public-key <key.pub>` or `oskal.VerifyIndependentReceipt(...)`.
