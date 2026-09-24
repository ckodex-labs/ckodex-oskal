# ADR-003: Assurance Epochs, Temporal Invalidation, and Semantic Drift

**Status:** Accepted  
**Date:** 2026-09-23  
**Authors:** Codex Architectural Guild  
**Classification:** CKODEX Architecture Decision Record  

---

## 1. Context

In traditional compliance auditing, an assessment is performed once (e.g. annually or upon deployment) and is treated as valid indefinitely until the next audit cycle. In Kubernetes, this model is dangerously invalid:
- Workloads are mutable: Pods restart, container images are repulled, config maps update, node kernels change.
- Policies mutate: A ValidatingAdmissionPolicy or Cilium NetworkPolicy may be modified or deleted out-of-band.
- Authorities rotate: SPIRE trust domains, signing keys, and admission certificates rotate.
- Evidence decays: Runtime process telemetry collected yesterday does not prove that a newly spawned container today is running as non-root.

Collapsing assurance into a static Boolean flag (`compliant: true`) fails to capture temporal validity and environmental shifts.

## 2. Decision

We establish the concept of the **Assurance Epoch** and the **Temporal Assurance Finite State Machine (FSM)**.

### 2.1 The Assurance Epoch

An Assurance Epoch encapsulates the cryptographic state vector of the environment in which an evaluation was made. It is computed as a composite digest over five immutable dimensions:

```text
AssuranceEpoch = {
    SubjectDigest:        Digest(Subject Spec, Generation, UID, Image Digest),
    ImplementationDigest: Digest(Admission CEL rules, DaemonSet configurations, agent binaries),
    PolicyDigest:         Digest(AssurancePolicy rules, EvidenceContract constraints),
    AuthorityDigest:      Digest(SPIRE Trust Bundle, Cosign Verification Keys, Approver Identities),
    EnvironmentDigest:    Digest(Kubernetes version, Node Kernel, OSKAL runtime version)
}
```

```text
CompositeEpochDigest = SHA256(
    SubjectDigest        || ":" ||
    ImplementationDigest || ":" ||
    PolicyDigest         || ":" ||
    AuthorityDigest      || ":" ||
    EnvironmentDigest
)
```

### 2.2 Canonical Assurance State Machine

Assurance is modeled as an 7-state finite state machine:

```text
                  evidence ingested
UNKNOWN ─────────────────────────────────────────► OBSERVED

OBSERVED ───────── verification passed ──────────► VERIFIED

VERIFIED ───────── policy + authority valid ─────► ASSURED

ASSURED ────────── epoch mismatch / timeout ─────► STALE

STALE ──────────── re-evaluation ────────────────► OBSERVED

ANY STATE ──────── confirmed violation ──────────► FAILED

ANY STATE ──────── evidence invalid/corrupted ───► UNKNOWN
```

#### State Definitions:
- `UNKNOWN`: Insufficient evidence exists to establish compliance or non-compliance. (Constitutional Invariant I-02: Absence of evidence is UNKNOWN, never PASS).
- `OBSERVED`: Raw observations have been collected from producers but cryptographic verification or policy checks are pending.
- `VERIFIED`: The evidence payload signatures, digests, and provenance have been cryptographically proven.
- `ASSURED`: All required evidence contracts are satisfied within the current epoch and verified against authoritative policy.
- `STALE`: The subject spec changed, the policy changed, the authority rotated, or the evidence reached its TTL (`maxAge`).
- `FAILED`: Active, verified evidence confirms a violation of the control requirement. Note: `FAILED != UNKNOWN`.

### 2.3 Semantic Drift Detection

Semantic drift occurs when the running reality diverges from the epoch under which assurance was granted:
- **Resource Drift:** Kubernetes Deployment generation incremented or image digest changed → SubjectDigest changes → Transition to `STALE`.
- **Policy Drift:** Admin updates admission policy or EvidenceContract freshness → PolicyDigest changes → Transition to `STALE`.
- **Implementation Drift:** Tetragon tracing policy or Cilium rule modified → ImplementationDigest changes → Transition to `STALE`.
- **Authority Drift:** SPIFFE CA rotated or Cosign key updated → AuthorityDigest changes → Transition to `STALE`.
- **Temporal Drift:** `now() > validUntil` → Transition to `STALE`.

Drift invalidates existing claims immediately and triggers deterministic re-evaluation.

## 3. Consequences

### Positive:
- Eradicates compliance amnesia: Stale or modified workloads cannot claim legacy compliance.
- Explainable transitions: Every state change is backed by an explicit trigger, timestamp, and epoch delta.
- Zero false confidence: If telemetry goes dark, state transitions to `UNKNOWN` or `STALE`, never staying green.

### Negative / Trade-offs:
- Requires continuous monitoring of Kubernetes API change streams (`Generation` changes, policy updates).
- Requires efficient caching of epoch digests to avoid redundant cryptographic recomputations.
