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

Given a set of $N$ verified leaf evidence envelopes:

$$E = \{e_1, e_2, \dots, e_N\}$$

Each envelope contains a canonical SHA-256 integrity digest:

$$h_i = \text{SHA-256}(\text{Canonicalize}(e_i))$$

### Lexicographical Sorting

To ensure deterministic root derivation regardless of ingestion order, the digests are sorted lexicographically:

$$H_0 = \text{Sort}([h_1, h_2, \dots, h_N])$$

### Pairwise Compression

At each layer $k$, adjacent pairs are concatenated and hashed:

$$H_{k+1}[j] = \text{SHA-256}(H_k[2j] \mathbin{\Vert} H_k[2j+1])$$

If a layer contains an odd number of elements, the final element is carried forward:

$$H_{k+1}[\text{last}] = H_k[\text{last}]$$

The process terminates when $|H_M| = 1$. The single surviving element is the **Canonical Merkle Evidence Root**:

$$\text{EvidenceRoot} = H_M[0]$$

---

## 3. `ControlReceipt` Data Structure

```text
ControlReceipt = {
    receipt_id:        String (UUID or deterministic identifier),
    control:           ControlRef { framework, control_id },
    subject:           SubjectRef { kind, namespace, name, generation },
    state:             AssuranceStateEnum,
    evidence_root:     Hex-encoded SHA-256 digest,
    issued_at:         RFC3339 Timestamp,
    expires_at:        RFC3339 Timestamp,
    signer_spiffe_id:  SPIFFE ID of issuing authority,
    public_key:        Hex-encoded Ed25519 public key,
    signature:         Hex-encoded Ed25519 signature over canonical payload
}
```

---

## 4. Signing & Verification Protocol

The signature covers the canonical wire representation of the receipt fields excluding the signature itself:

$$\text{Payload} = \text{ReceiptID} \mathbin{\Vert} \text{Control} \mathbin{\Vert} \text{Subject} \mathbin{\Vert} \text{State} \mathbin{\Vert} \text{EvidenceRoot} \mathbin{\Vert} \text{IssuedAt} \mathbin{\Vert} \text{ExpiresAt}$$

$$\text{Signature} = \text{Ed25519\_Sign}(\text{PrivateKey}_{\text{Signer}}, \text{Payload})$$

An auditor or external verifier can independently verify the receipt without access to the Kubernetes API server or OSKAL cluster using the public key and payload.
