---
title: "Vector State vs. The Fallacy of Boolean Compliance"
description: "Why binary pass/fail is insufficient for regulated systems, and how the multi-dimensional vector product S(e,t) preserves operational truth."
quadrant: "explanation"
tier: "E5"
invariant: "State is a vector, not a boolean"
---

## 1. The Fallacy of Boolean Compliance

Traditional compliance dashboards reduce complex, distributed runtime systems to binary booleans:

```text
Status: PASS (or FAIL)
```

This abstraction collapses distinct, vital dimensions of operational reality:
1. **Absence vs. Verification**: Is the control passing because evidence exists, or simply because no scanner has run yet?
2. **Structural Contradictions (Anti-State)**: If 99 non-critical checks pass, but a cryptographic lease has been revoked, does the system score 99%? In reality, a mandatory anti-state dominates all positive evidence.
3. **Decoherence**: What if the declared deployment digest differs from the container digest currently executing in the Linux kernel?

---

## 2. The Vector Product Formulation

In CKODEX and OSKAL, governed state is modeled as a typed product:

$$S(e,t) = \langle P, V, A, C, E, L, \tau \rangle$$

Where each dimension is evaluated independently and never averaged:

### $P$ &mdash; Presence
Distinguishes evidence existence:
- `EMPTY`: No evidence exists.
- `PRESENT`: Value or envelope is available.
- `UNKNOWN`: Evidence cannot presently be established.
- `REDACTED`: Evidence exists but is cryptographically masked.

> **Critical Rule:** `EMPTY` and `UNKNOWN` are NOT negative. Absence of evidence is never evidence of failure, but it strictly precludes `PASS` (Invariant I-02).

### $V$ &mdash; Valence
Directional effect of evidence:
- `POSITIVE`: Supports control fulfillment.
- `NEGATIVE`: Adversely affects control (legitimate failure).
- `NEUTRAL`: Informational.
- `MIXED`: Multiple conflicting observations.

### $A$ &mdash; Anti (Conflict Relation)
Represents structural opposition where an invariant is violated:
- Example: Workload running while its authorization lease has expired.
- Mandatory anti-state cannot be averaged away by positive scores.

### $C$ &mdash; Coherence
Measures alignment between representations of reality:
- `COHERENT`: Declared intent, admission records, and runtime telemetry agree.
- `DECOHERENT`: Divergence between declared image digest and executing container.

### $E$ &mdash; Evidence Status
Cryptographic assurance level:
- `CLAIMED`: Asserted without proof.
- `OBSERVED`: Raw sensor telemetry captured.
- `VERIFIED`: Integrity digest and signature validated.

### $L$ &mdash; Lifecycle & Operational Mode
- `NORMAL`, `DEGRADED`, `SAFE_HOLD`, `QUARANTINED`, `FAILED`.

### $\tau$ &mdash; Epoch & Temporal Coordinate
- Binds evaluation to a specific `AssuranceEpoch` and RFC3339 timestamp.

---

## 3. Complementary FSM and Vector State

The 7-state Lifecycle FSM answers:
> **Where is the workload in its operational lifecycle?**

The Vector State $S(e,t)$ answers:
> **What is the semantic quality and cryptographic trust of that state?**

By maintaining both, OSKAL enables precise, machine-verifiable governance without compromising technical truth.
