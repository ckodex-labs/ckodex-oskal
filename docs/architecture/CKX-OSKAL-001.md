# CKX-OSKAL-001
## OSKAL — Kubernetes Continuous Assurance Architecture

**Status:** Implementation Candidate  
**Classification:** CKODEX Architecture / Assurance Runtime  
**Target:** `ckodex-labs`  
**Primary existing projects:**
- `ckodex-labs/ckodex-xoscal`
- `ckodex-labs/ckodex-oscal-cli`

**New capability:** OSKAL — Kubernetes Continuous Assurance Runtime  
**Canonical principle:** OSCAL interoperability above; assurance semantics in the center; Kubernetes realization below.

---

# 0. Codex Executive Instruction

Do **not** implement OSKAL as:
- another OSCAL document generator;
- an OSCAL-to-CRD converter;
- a collection of Kyverno policies;
- an OPA wrapper;
- a scanner aggregator;
- a compliance dashboard;
- a Kubernetes-only fork of XOSCAL;
- a second OSCAL data model;
- an evidence database stored in etcd.

Implement OSKAL as:
> A Kubernetes-native realization of CKODEX continuous assurance that binds canonical controls to concrete implementations, observes actual system state, evaluates evidence contracts, produces temporally bounded assurance claims, detects semantic drift, and projects defensible results through XOSCAL into standard OSCAL artifacts.

The core dependency rule is:

```text
Kubernetes
    │
    ▼
OSKAL adapters
    │
    ▼
CKODEX Assurance Core
    │
    ▼
XOSCAL projection
    │
    ▼
OSCAL
```

Never invert this dependency.

---

# 1. Why This Exists

OSCAL already gives us machine-readable representations for:
- catalogs;
- profiles;
- component definitions;
- SSPs;
- assessment plans;
- assessment results;
- POA&M;
- mappings.

NIST OSCAL v1.2.3 is the current release as of August 13, 2026. It is a security/maintenance patch and does not change the OSCAL models.
The existing XOSCAL repository already contains Protobuf representations and services around these families.

What OSCAL intentionally does **not** provide is a Kubernetes runtime that continuously proves:

```text
requirement
  ↓
control objective
  ↓
implementation
  ↓
subject
  ↓
observation
  ↓
evidence
  ↓
claim evaluation
  ↓
assurance state
```

OSKAL fills that gap.

---

# 2. Problem Statement

Traditional Kubernetes compliance often collapses:
```text
policy passed
```
into:
```text
control satisfied
```
These statements are not equivalent.

Examples:
- A Pod manifest declaring `runAsNonRoot` does not prove the process is executing as intended.
- A NetworkPolicy does not prove the expected runtime flow isolation.
- A signed OCI artifact does not prove that the running workload corresponds to that artifact.
- No scanner finding does not prove absence of a weakness.
- A benchmark mapping does not prove complete implementation of a framework control.
- A control verified yesterday is not automatically valid after the workload, policy, image, identity or node changes.

OSKAL therefore distinguishes:
```text
CONTROL
POLICY
IMPLEMENTATION
OBSERVATION
EVIDENCE
CLAIM
ASSESSMENT
ASSURANCE
```
These MUST NOT be conflated.

---

# 3. Constitutional Invariants

The implementation MUST enforce these invariants.

- **I-01 — Mapping does not establish compliance:** `Control A maps to Control B` does not mean `Control A is implemented`.
- **I-02 — Absence of evidence is UNKNOWN:** Never `no finding → PASS`. Instead: `insufficient evidence → UNKNOWN`.
- **I-03 — Evidence is contextual:** Evidence is valid only relative to `subject + implementation + policy revision + authority + epoch + time`.
- **I-04 — Every assurance claim is explainable:** Every claim MUST be reverse-traceable through `AssuranceState → ClaimEvaluation → EvidenceContract → Evidence → Observation → EvidenceProducer → Subject`.
- **I-05 — Exceptions are bounded:** Every exception requires subject scope, control scope, justification, approving authority, issue time, expiration, compensating controls where required, evidence, auditability. Permanent `ignore=true` semantics are forbidden.
- **I-06 — OSCAL export is derived:** Every exported OSCAL assertion MUST be derivable from the assurance graph. OSCAL MUST NOT become a parallel source of runtime truth.
- **I-07 — Assurance is temporal:** A valid control evaluation can become stale (`ASSURED → STALE`).
- **I-08 — Enforcement and assessment are separate:** A control can be preventive, detective, corrective, compensating, or informational. Assessment MUST NOT assume that every control is enforceable.
- **I-09 — Runtime truth outranks declared intent:** Where declared configuration and observed runtime state disagree, the discrepancy becomes evidence and potentially a finding.
- **I-10 — Authority is explicit:** Every privileged assertion SHOULD identify who or what was authorized to produce it. Prefer workload identities such as SPIFFE IDs.

---

# 4. Bounded Contexts

There SHALL be three conceptual bounded contexts:

1. **XOSCAL:** Owns standards interoperability (OSCAL parsing, generation, validation, profiles, mappings, component definitions, SSP, assessment plans/results, POA&M). XOSCAL MUST NOT require Kubernetes.
2. **CKODEX Assurance Core:** Owns domain semantics (`ControlRef`, `ControlObjective`, `AtomicControl`, `Applicability`, `Subject`, `Implementation`, `ImplementationBinding`, `EvidenceRequirement`, `EvidenceContract`, `Observation`, `Evidence`, `EvidenceRef`, `EvidenceProducer`, `Claim`, `ClaimEvaluation`, `Finding`, `Exception`, `Remediation`, `Authority`, `Epoch`, `AssuranceState`, `ControlReceipt`). The Assurance Core MUST contain zero dependencies on Kubernetes APIs.
3. **OSKAL:** Owns Kubernetes realization (Kubernetes discovery, resource subjects, control binding, admission integration, runtime evidence ingestion, scanner evidence ingestion, identity evidence, supply-chain evidence, reconciliation, drift invalidation, assurance-state projection to Kubernetes).

---

# 5. Target Architecture

```text
                 ┌──────────────────────────────┐
                 │    Regulations / Standards   │
                 │ NIST • ISO • CIS • CMMC ... │
                 └──────────────┬───────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │      OSCAL      │
                       └────────┬────────┘
                                │
                         interoperability
                                │
                                ▼
╔══════════════════════════════════════════════════════════════╗
║                         XOSCAL                               ║
║                                                             ║
║ Catalog • Profile • Mapping • Component Definition          ║
║ SSP • Assessment Plan • Assessment Results • POA&M          ║
║ Proto • gRPC • validation • import/export                   ║
╚═══════════════════════════╤══════════════════════════════════╝
                            │
                          projection
                            │
                            ▼
╔══════════════════════════════════════════════════════════════╗
║                 CKODEX ASSURANCE CORE                        ║
║                                                             ║
║ Control                                                     ║
║   ↓                                                         ║
║ AtomicControl                                               ║
║   ↓                                                         ║
║ ImplementationBinding                                       ║
║   ↓                                                         ║
║ EvidenceContract                                            ║
║   ↓                                                         ║
║ Observation → Evidence → ClaimEvaluation                    ║
║                         ↓                                   ║
║               AssuranceState / Finding                      ║
║                         ↓                                   ║
║                       Receipt                               ║
╚═══════════════════════════╤══════════════════════════════════╝
                            ▲
                            │
                          adapters
                            │
╔═══════════════════════════╧══════════════════════════════════╗
║                          OSKAL                               ║
║                                                             ║
║ Kubernetes API                                              ║
║ CEL • admission • Cilium • Tetragon • Falco                ║
║ Sigstore • SPIRE • scanners • OpenReports                  ║
╚══════════════════════════════════════════════════════════════╝
```

---

# 6. Core Assurance FSM

```text
                  evidence
UNKNOWN ─────────────────────────► OBSERVED

OBSERVED ───── verification ─────► VERIFIED

VERIFIED ─ policy + authority ───► ASSURED

ASSURED ─ epoch change ──────────► STALE

STALE ─ re-evaluation ───────────► OBSERVED

ANY ─ confirmed violation ───────► FAILED

ANY ─ evidence invalid ──────────► UNKNOWN
```

- `FAILED != UNKNOWN`: `FAILED` means sufficient evidence supports nonconformance. `UNKNOWN` means sufficient evidence for a defensible determination is unavailable.

---

# 7. Five CRD Surface

Initial release:
1. `ControlBinding`
2. `EvidenceContract`
3. `AssurancePolicy`
4. `ControlException`
5. `AssuranceState`

Evidence payloads MUST NOT be stored in Kubernetes etcd.
