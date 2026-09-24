---
title: "Auditor & CISO Persona Guide"
description: "How Security & Compliance Officers and external auditors leverage OSKAL for continuous FedRAMP/NIST assessment, non-repudiation, and audit-ready proof."
quadrant: "personas"
tier: "E5"
invariant: "Receipt after execution: non-repudiable proof of state"
---

## Executive Summary

As a Compliance Officer, CISO, or Regulatory Auditor, your primary frustration is usually the discrepancy between declared security policies on paper and what is actually running inside the production infrastructure.

OSKAL transforms compliance from an annual, painful screenshot-gathering exercise into a **continuous, machine-verifiable evidence stream**.

---

## 1. Zero Tolerance for Fake Claims (Invariant I-02)

Traditional security tools often output green checkmarks by default when a scanner fails to run or encounters a network error. 

OSKAL strictly enforces **Invariant I-02**:
- If an observation is missing or expired, the state is strictly reported as `UNKNOWN`.
- An `UNKNOWN` state cannot be exported as a passing claim in NIST OSCAL documents.
- Every claim in an exported OSCAL Assessment Results file is backed by a verifiable SHA-256 Merkle Evidence Root.

---

## 2. The Section 51 Explain Graph

When auditing a specific control (for example, NIST SP 800-53 `AC-6` Least Privilege or `SI-7` Software Integrity), you do not need to guess how an assessment score was derived.

Run:

```bash
oskal assurance explain --subject-name payment-service --control AC-6
```

The output gives you the complete **Section 51 Explain Graph**:
- Exact atomic evidence requirements.
- Contributing sensor envelopes with collection timestamps.
- Issuing producer SPIFFE IDs.
- Ed25519 digital signature of the control receipt.

---

## 3. Exporting NIST OSCAL 1.2.3 for FedRAMP Assessment

OSKAL generates standard, schema-valid NIST OSCAL 1.2.3 Assessment Results JSON documents on demand:

```bash
oskal export oscal --model assessment-results --output /tmp/audit-results.json
```

These documents can be directly fed into:
- eMASS / FedRAMP automated assessment portals.
- `ckodex-oscal-cli` for metaschema and constraint verification.
- `ckodex-xoscal` for mathematical vector state verification.
