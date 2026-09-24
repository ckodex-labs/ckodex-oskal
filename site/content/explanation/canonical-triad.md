---
title: "The Canonical Triad"
description: "Architectural rationale: OSCAL interoperability above, assurance semantics in the center, Kubernetes realization below."
quadrant: "explanation"
tier: "E5"
invariant: "OSCAL interoperability above; assurance semantics in the center; Kubernetes realization below"
---

## Executive Summary

Traditional compliance tooling fails in one of three ways:
1. **Document-only**: They treat compliance as static JSON or YAML documents (OSCAL or spreadsheets) divorced from running infrastructure.
2. **Scanner aggregators**: They run periodic CLI scanners and collapse thousands of raw alert logs into a single subjective dashboard score.
3. **Cluster-locked**: They write proprietary Kubernetes CRDs that cannot interoperate with external regulatory frameworks or auditors.

OSKAL resolves this structural tension through the **Canonical Triad**:

```text
+-----------------------------------------------------------------------+
|                       OSCAL INTEROPERABILITY ABOVE                    |
|       NIST SP 800-53, FedRAMP, OSCAL 1.2.3 Assessment Results         |
+-----------------------------------------------------------------------+
                                   ^
                                   | (Projections & Metaschema Export)
                                   v
+-----------------------------------------------------------------------+
|                      ASSURANCE SEMANTICS IN CENTER                    |
|   Pure Semantic Kernel, Zero K8s Imports, Vector State S(e,t),        |
|            Section 51 Explain Graph, Cryptographic Receipts           |
+-----------------------------------------------------------------------+
                                   ^
                                   | (Hexagonal Adapters & Envelopes)
                                   v
+-----------------------------------------------------------------------+
|                    KUBERNETES REALIZATION BELOW                       |
|   ValidatingAdmissionPolicy (CEL), Cilium Network, Tetragon eBPF,     |
|             SPIFFE/SPIRE Identity, Sigstore Supply-Chain              |
+-----------------------------------------------------------------------+
```

---

## 1. OSCAL Interoperability Above

NIST Open Security Controls Assessment Language (OSCAL) is an open, machine-readable standard for security plans, control baselines, and assessment results.

However, OSCAL is a **data exchange format**, not an execution engine. Attempting to use OSCAL schemas directly inside a low-latency Kubernetes reconciliation loop introduces massive impedance mismatch:
- OSCAL structures are deeply nested and verbose.
- OSCAL schemas do not define epoch invalidation semantics or admission gating latencies.

Therefore, OSKAL places OSCAL **above**:
- OSCAL models are projected from the runtime state on demand.
- Projections are validated against the official metaschema by `ckodex-oscal-cli`.
- Auditors receive standard OSCAL Assessment Results without compromising cluster performance.

---

## 2. Assurance Semantics in the Center

The center is the **Pure Semantic Kernel** (`core/assurance/`):
- It contains **strictly zero Kubernetes imports**.
- It does not know about containers, pods, HTTP, or etcd.
- It models compliance as state transitions across the multi-dimensional vector $S(e,t)$.
- It defines what "evidence", "claim", "contract", and "epoch" mean deterministically.

Because the core is pure domain logic, it can be tested with 100% determinism, embedded into standalone Go binaries via `pkg/oskal`, and run air-gapped without external cluster dependencies.

---

## 3. Kubernetes Realization Below

The bottom layer is the concrete **Kubernetes Substrate**:
- High-performance, native enforcement points:
  - Admission gating via in-tree `ValidatingAdmissionPolicy` CEL expressions.
  - Process capability dropping observed by Tetragon eBPF sensors.
  - Zero-trust network segmentation enforced by Cilium NetworkPolicies.
  - Cryptographic identity attested by SPIFFE/SPIRE SVIDs.
  - Supply-chain provenance verified by Sigstore Cosign.

Hexagonal adapters translate these substrate-specific events into technology-neutral `EvidenceEnvelope` objects, passing them up to the Semantic Kernel for evaluation.
