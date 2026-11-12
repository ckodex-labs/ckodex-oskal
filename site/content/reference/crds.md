---
title: "Kubernetes CRD Reference"
description: "Technical schema reference for the six Custom Resource Definitions in api/assurance/v1alpha1."
quadrant: "reference"
tier: "E5"
invariant: "Do not store evidence blobs in etcd (ADR-002)"
---

## Group & Version

```text
Group:   assurance.ckodex.io
Version: v1alpha1
```

| Kind | Short Name | Purpose |
| :--- | :--- | :--- |
| `ControlBinding` | `cb` | Bind canonical controls & external frameworks to Kubernetes workloads |
| `EvidenceContract` | `ec` | Declare required evidence types, freshness bounds, and allowed producers |
| `AssurancePolicy` | `ap` | Cluster governance thresholds, admission gating, and failure policies |
| `ControlException` | `ce` | Temporally bounded derogation with compensating controls (I-05) |
| `AssuranceState` | `as` | Lightweight state & Merkle root projection (zero raw evidence in etcd) |
| `CapabilityLease` | `cl` | Bounded, revocable authority for agentic workcells and UTCP tools |

---

## 1. `ControlBinding` (`cb`)

Binds canonical security controls to workload subject selectors, implementation providers, and `EvidenceContract` references.

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: ControlBinding
metadata:
  name: <string>
  namespace: <string>
spec:
  controls:
    - canonical:
        namespace: <string>       # e.g. "nist-sp-800-53"
        id: <string>              # e.g. "AC-6"
        version: <string>         # e.g. "Rev5"
      mappings:
        - framework: <string>     # e.g. "NIST-SP-800-53"
          control: <string>       # e.g. "AC-6"
          version: <string>       # e.g. "5"
  subjects:
    apiGroups:
      - <string>
    kinds:
      - <string>                  # e.g. "Deployment", "StatefulSet"
    namespaceSelector: <metav1.LabelSelector>
    labelSelector: <metav1.LabelSelector>
  requirements:
    - id: <string>                # e.g. "binding-admission-least-privilege"
      evidenceContract: <string>  # Name of EvidenceContract
      implementations:
        - purpose: <string>       # "preventive" | "detective" | "corrective" | "compensating"
          provider: <string>      # "kubernetes-validating-admission" | "tetragon" | "cilium" | "sigstore"
          ref:
            name: <string>
            namespace: <string>
status:
  observedGeneration: <int64>
  activeSubjects: <int>
  conditions: <[]metav1.Condition>
```

---

## 2. `EvidenceContract` (`ec`)

Specifies the required evidence signals, freshness durations, and accepted producer authorities that must be satisfied for a control.

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: EvidenceContract
metadata:
  name: <string>
  namespace: <string>
spec:
  requirements:
    - id: <string>                # e.g. "req-admission-valid"
      type: <string>              # e.g. "k8s:admission:review", "sigstore:cosign:attestation"
      required: <bool>
      freshness: <duration>       # e.g. "15m0s", "24h0m0s"
      acceptedProducers:
        - <string>                # e.g. "spiffe://assurance.ckodex.io/ns/ckodex-system/sa/oskal-webhook"
  onMissingRequiredEvidence:
    state: <string>               # "Unknown" | "Failed" (Invariant I-02)
status:
  observedGeneration: <int64>
  conditions: <[]metav1.Condition>
```

---

## 3. `AssurancePolicy` (`ap`)

Defines governance thresholds, freshness constraints, failure behavior, and admission enforcement configuration.

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: AssurancePolicy
metadata:
  name: <string>
spec:
  requiredState: <string>         # e.g. "Assured"
  evidence:
    requireFresh: <bool>
  behavior:
    failOnConfirmedViolation: <bool>
    unknownIsViolation: <bool>
  freshness:
    maxEvaluationAge: <duration>
  enforcement:
    admission:
      enabled: <bool>
status:
  observedGeneration: <int64>
  conditions: <[]metav1.Condition>
```

---

## 4. `ControlException` (`ce`)

Defines a temporally bounded, authorized derogation for a specific control failure (Invariant I-05: Derogation does not erase failure).

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: ControlException
metadata:
  name: <string>
  namespace: <string>
spec:
  subject:
    apiVersion: <string>
    kind: <string>
    namespace: <string>
    name: <string>
  controls:
    - <string>
  justification:
    ticket: <string>
    notes: <string>
  authority:
    requiredApprovers:
      - <string>
  validity:
    notBefore: <timestamp>
    notAfter: <timestamp>         # Permanent exceptions are rejected (I-05)
  compensatingControls:
    - <string>
status:
  phase: <string>                 # "Active" | "Expired" | "Revoked"
  observedGeneration: <int64>
  conditions: <[]metav1.Condition>
```

---

## 5. `AssuranceState` (`as`)

Lightweight status projection resource. **Stores zero raw evidence blobs in etcd** (ADR-002).

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: AssuranceState
metadata:
  name: <string>
  namespace: <string>
spec:
  subjectRef:
    apiVersion: <string>
    kind: <string>
    namespace: <string>
    name: <string>
    uid: <string>
status:
  state: <string>                 # "Assured" | "Verified" | "Observed" | "Stale" | "Failed" | "Unknown"
  epoch:
    subject: <string>
    policy: <string>
    implementation: <string>
    authority: <string>
    environment: <string>
    composite: <string>
  evidenceRoot: <string>          # SHA-256 Merkle root of leaf envelopes
  evaluatedAt: <timestamp>
  validUntil: <timestamp>
  controls:
    - id: <string>
      state: <string>
      evidenceSummary: <string>
  conditions: <[]metav1.Condition>
```

---

## 6. `CapabilityLease` (`cl`)

Governs bounded, revocable authority for agentic workcells and UTCP tool execution (ADR-006).

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: CapabilityLease
metadata:
  name: <string>
  namespace: <string>
spec:
  principal: <string>
  scope: <string>
  allowedCapabilities:
    - <string>                    # e.g. "tool:read-evidence", "tool:validate-oscal", "tool:scaffold-policy"
  maxTurns: <int>
  ttl: <duration>
status:
  phase: <string>                 # "Active" | "Exhausted" | "Expired" | "Revoked"
  currentTurn: <int>
  lastReceiptHash: <string>
  issuedAt: <timestamp>
  expiresAt: <timestamp>
  revocationReason: <string>
  observedGeneration: <int64>
  conditions: <[]metav1.Condition>
```
