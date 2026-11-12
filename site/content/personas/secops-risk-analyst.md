---
title: "SecOps & Risk Analyst Persona Guide"
description: "How Security Operations and Risk Analysts monitor real-time drift, manage bounded exceptions, and triage anti-conflict states."
quadrant: "personas"
tier: "E5"
invariant: "Derogation is explicit state: accepted risk does not rewrite history (I-05)"
---

## Executive Summary

As a Security Operations (SecOps) Engineer or Risk Analyst, you manage operational crises, security exceptions, and incident responses.

Traditional compliance systems force you into a false dilemma: either block a critical business deployment, or secretly disable security controls and pretend the system is passing.

OSKAL introduces **Explicit Derogations** and **Real-Time Vector State Triage**.

---

## 1. Explicit Derogation via `ControlException` (Invariant I-05)

When a business requirement forces a temporary risk acceptance (derogation):
- **Accepted risk does not rewrite history**. The underlying check continues to truthfully report `NEGATIVE` valence.
- The exception is formally recorded in a `ControlException` CRD with an explicit expiration timestamp, authorized approver SPIFFE ID, and active compensating controls.

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: ControlException
metadata:
  name: exception-legacy-db-root
  namespace: billing
spec:
  subject:
    apiVersion: apps/v1
    kind: Deployment
    namespace: billing
    name: legacy-billing-gateway
  controls:
    - "nist-sp-800-53:AC-6"
  justification:
    ticket: "SEC-4812"
    notes: "Legacy database driver requires root user until Q4 migration."
  authority:
    requiredApprovers:
      - "spiffe://ckodex.internal/ns/secops/sa/ciso-signer"
  validity:
    notBefore: "2026-09-01T00:00:00Z"
    notAfter: "2026-10-01T00:00:00Z"
  compensatingControls:
    - "Cilium network policy blocking all outbound internet egress"
    - "Tetragon runtime enforcement terminating any bash invocation"
```

Once `validity.notAfter` passes, the exception expires automatically. Permanent exceptions are rejected by the Semantic Kernel.

---

## 2. Triaging Anti-State and Containment

When a critical contradiction occurs (for example, an active container found executing a binary whose signature was revoked), OSKAL flags an **Anti-Conflict (`A > 0`)**:
- The workload state transitions to `FAILED` or `QUARANTINED`.
- Invariant dominance ensures this contradiction cannot be hidden by other passing checks.

To triage and isolate:

```bash
oskal assurance explain --subject-name compromised-pod --control SI-7
```

SecOps can then invoke the **Containment Protocol** without destroying the pod's memory state, preserving the forensic evidence needed to investigate the incident.
