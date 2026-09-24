# ADR-004: Five-CRD Initial Kubernetes API Boundary

**Status:** Accepted  
**Date:** 2026-09-23  
**Authors:** Codex Architectural Guild  
**Classification:** CKODEX Architecture Decision Record  

---

## 1. Context

Kubernetes operators often suffer from API bloat by creating dozens of Custom Resource Definitions (CRDs) for internal entities (e.g. separate CRDs for every observation, claim, rule, mapping, and framework). This causes:
- Excessive API server serialization overhead;
- Cluster-wide namespace clutter;
- Complex RBAC matrices;
- Increased controller synchronization complexity.

At the same time, Kubernetes operators need native declarative mechanisms to express control bindings, contracts, policies, exceptions, and summary status.

## 2. Decision

We cap the initial OSKAL Kubernetes CRD surface at exactly **five declarative resources**:

```text
┌────────────────────────────────────────────────────────┐
│                   1. ControlBinding                    │
│  Binds canonical controls & mappings to k8s subjects   │
│  and implementation providers                          │
└───────────────────────────┬────────────────────────────┘
                            │ references
                            ▼
┌────────────────────────────────────────────────────────┐
│                  2. EvidenceContract                   │
│  Defines required evidence types, freshness (maxAge),  │
│  and accepted authorized producers                     │
└───────────────────────────┬────────────────────────────┘
                            │ evaluated by
                            ▼
┌────────────────────────────────────────────────────────┐
│                  3. AssurancePolicy                    │
│  Defines evaluation semantics, required assurance      │
│  states, violation thresholds, and admission gating    │
└───────────────────────────┬────────────────────────────┘
                            │ checked for
                            ▼
┌────────────────────────────────────────────────────────┐
│                  4. ControlException                   │
│  Time-bounded, authorized risk acceptance & exceptions │
│  with mandatory compensating controls                  │
└───────────────────────────┬────────────────────────────┘
                            │ yields
                            ▼
┌────────────────────────────────────────────────────────┐
│                  5. AssuranceState                     │
│  Projected operator status summary (state enum, epoch, │
│  evidenceRoot, conditions, control breakdown)          │
└────────────────────────────────────────────────────────┘
```

### Detailed Resource Responsibilities:

1. **`ControlBinding` (`assurance.ckodex.io/v1alpha1`):**
   - Cluster-scoped or namespaced binding between external/canonical controls (e.g. NIST SP 800-53 `AC-6` via `ckodex:container.least-privilege`), workload subject selectors (e.g. Deployments with `assurance.ckodex.io/profile: regulated`), and implementation mechanisms (CEL ValidatingAdmissionPolicy, Tetragon, Cilium).
2. **`EvidenceContract` (`assurance.ckodex.io/v1alpha1`):**
   - Declarative contract specifying what proof is mandatory. Enforces required evidence types (e.g. `kubernetes.admission`, `spiffe.workload.identity`, `workload.runtime.process`), freshness tolerances (`maxAge: 5m`), and acceptable producer identities.
3. **`AssurancePolicy` (`assurance.ckodex.io/v1alpha1`):**
   - Configures operational expectations: required state (`Assured`), whether `unknownIsViolation` is true/false, admission gating integration, and evaluation staleness thresholds.
4. **`ControlException` (`assurance.ckodex.io/v1alpha1`):**
   - Strictly bounded exception mechanism. Mandates approving SPIFFE identities, justification tickets, finite expiry (`notAfter`), and active compensating controls. Permanent or unbounded exceptions are rejected.
5. **`AssuranceState` (`assurance.ckodex.io/v1alpha1`):**
   - The operator-facing status projection for a subject. Exposes current state, epoch digests, Merkle `evidenceRoot`, evaluated timestamps, and Kubernetes status conditions (`EvidenceReady`, `EvaluationReady`, `Assured`, `Stale`, `Degraded`).

### Explicit Non-CRDs:
- `Observation`: Transient runtime facts; ingested via gRPC/API and stored in external CAS/ClickHouse. Never a CRD.
- `EvidenceEnvelope`: Stored in content-addressed storage. Never a CRD.
- `ClaimEvaluation`: Internal evaluation graph node. Never a CRD.
- `ControlReceipt`: Cryptographic artifact emitted to storage and transparency logs. Never a CRD.

## 3. Consequences

### Positive:
- Clean, minimal footprint on the Kubernetes control plane.
- Clear separation between declared configuration (`ControlBinding`, `EvidenceContract`, `AssurancePolicy`, `ControlException`) and observed status projection (`AssuranceState`).
- Avoids abusing etcd as an evidence or event database.

### Negative / Trade-offs:
- Detailed forensic queries and evidence graphs cannot be answered by `kubectl get` alone; they require the OSKAL CLI or gRPC explain API.
