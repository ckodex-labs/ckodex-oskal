# ADR-005: OSCAL Projection Rather Than OSCAL Inheritance

**Status:** Accepted  
**Date:** 2026-09-23  
**Authors:** Codex Architectural Guild  
**Classification:** CKODEX Architecture Decision Record  

---

## 1. Context

NIST OSCAL (Open Security Controls Assessment Language) is designed as a document-exchange and reporting standard. It models static structures: catalogs, profiles, component definitions, system security plans (SSPs), assessment plans (APs), assessment results (ARs), and plans of action and milestones (POA&Ms).

A common architectural trap is attempting to make OSCAL data structures the internal runtime domain model of an execution engine. This leads to:
- OSCAL XML/JSON/YAML schema constraints polluting high-speed runtime evaluation loops;
- Inability to model live temporal dynamics (such as continuous micro-epochs, stream backpressure, kernel-level telemetry, and vector states);
- Tight coupling to specific schema versions (OSCAL 1.0.0 vs 1.1.0 vs 1.2.3).

Conversely, some compliance systems ignore standard OSCAL entirely, creating proprietary report formats that cannot be ingested by enterprise governance tools.

## 2. Decision

We establish the principle: **OSCAL Projection Rather Than OSCAL Inheritance**.

```text
CKODEX Assurance Core Graph
(Claims, Observations, Evidences, Epochs, Vector State)
                   │
                   ▼ Projection Layer
        ┌─────────────────────┐
        │  XOSCAL Projector   │
        └──────────┬──────────┘
                   │
    ┌──────────────┼──────────────┐
    ▼              ▼              ▼
Component     Assessment         SSP
Definition     Results       (Snapshot)
  (OSCAL)       (OSCAL)        (OSCAL)
```

### Projection Mapping Rules:

1. **Component Definition Projection:**
   - Source: `ImplementationBinding` and `AtomicControl`.
   - Target: OSCAL `component-definition` -> `defined-component` -> `control-implementation` -> `implemented-requirement`.
   - Technical implementations (e.g. CEL rules, Tetragon sensors) project into component descriptions, properties, and parameters.

2. **Assessment Results Projection:**
   - Source: `ClaimEvaluation`, `Observation`, `EvidenceRef`, `Finding`.
   - Target: OSCAL `assessment-results` -> `result` -> `observation` + `finding`.
   - Each claim evaluation projects into a distinct OSCAL `observation` with `collected` timestamp, `observer` subject, and `relevant-evidence` links pointing to the content-addressed evidence digest in back-matter.
   - Any confirmed violation projects into an OSCAL `finding` with explicit target control, related observations, and severity.

3. **System Security Plan (SSP) Projection:**
   - Source: Kubernetes cluster topology, subject inventory, active control bindings, and responsibilities.
   - Target: OSCAL `system-security-plan` snapshot.
   - The SSP is treated strictly as an exported point-in-time projection, never as live runtime state.

4. **POA&M Projection:**
   - Source: Triaged findings and unresolved non-compliances.
   - Target: OSCAL `plan-of-action-and-milestones` -> `poam-item`.
   - Not every transient finding immediately triggers a POA&M item; only findings vetted through risk policy and marked for tracked remediation project to POA&M.

### Invariants:
- **Traceability (Constitutional Invariant I-06):** Every exported OSCAL assertion MUST be reverse-derivable from the live assurance graph.
- **No Orphan Findings:** Every OSCAL finding must reference its source claim evaluation, observation, evidence digest, and subject URI.
- **Independence:** The Assurance Core never imports OSCAL schema packages. All transformation is performed by the XOSCAL projection adapter.

## 3. Consequences

### Positive:
- The Assurance Core remains hyper-performant, typed, and decoupled from standard schema updates.
- Full, native compatibility with official NIST OSCAL v1.2.3 tooling and FedRAMP/DoD submission workflows.
- Clean separation between internal evidence storage (content-addressed CAS) and external audit representation (OSCAL back-matter references).

### Negative / Trade-offs:
- Requires maintaining projection serialization logic in the `projection/oscal` package.
- High-frequency live claims must be batched or sampled when exporting to static OSCAL documents to avoid generating gigabyte-sized assessment reports.
