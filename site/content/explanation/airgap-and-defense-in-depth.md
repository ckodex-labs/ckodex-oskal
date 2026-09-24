---
title: "Air-Gap Architecture & Anti-Contamination"
description: "How OSKAL maintains cryptographic assurance and complete functionality in disconnected, air-gapped, and sovereign environments."
quadrant: "explanation"
tier: "E5"
invariant: "Air-gap is a design property, not an afterthought"
---

## 1. The Air-Gap Imperative

Regulated environments (defense, financial core banking, sovereign cloud) frequently mandate completely disconnected operation. Many modern cloud-native compliance tools fail under these constraints because they rely on:
- Live external SaaS dashboards for reporting.
- Public Rekor transparency logs and public Fulcio OIDC issuers for Sigstore.
- Remote package registries and dynamic external vulnerability databases.

OSKAL is architected with **Air-Gap as a First-Class Design Property**.

---

## 2. Core Air-Gap Principles

### Self-Contained Trust Roots
- The SPIFFE trust domain is anchored in a local, air-gapped SPIRE server with a dedicated intermediate CA.
- Sigstore/Cosign verification operates with pre-distributed public keys or private in-cluster Rekor instances.

### Offline Cryptographic Receipts
- State transitions produce self-contained `ControlReceipt` records signed with Ed25519.
- Receipts carry their own public key reference and SHA-256 Merkle Evidence Root.
- Any auditor can verify the receipt offline on a disconnected laptop using standard cryptographic libraries without network calls.

### Pure Domain Purity
- The Semantic Kernel (`core/assurance/`) has zero external network calls.
- Evaluation determinism is preserved regardless of internet availability.

---

## 3. Anti-Contamination & Quarantine

If an air-gapped node detects an evidence conflict (e.g. signature verification failure or an unexpected change in model weight digests), OSKAL applies the **Containment Protocol**:
1. **Freeze**: Prevent admission or promotion of the affected workload.
2. **Preserve Evidence**: Record the exact contradictory observations in the flight recorder log.
3. **Quarantine**: Transition the workload's Vector State to $L = \text{QUARANTINED}$ and $A = \text{CONTRADICTED}$.
4. **Isolate**: Instruct Cilium to restrict egress and isolate the pod without destroying the container state needed for forensics.
