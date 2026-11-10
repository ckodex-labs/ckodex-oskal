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

---

## 1. `ControlBinding`

Binds canonical security controls to workload selectors, atomic requirements, and `EvidenceContract` references.

### Schema:

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: ControlBinding
metadata:
  name: <string>
  namespace: <string>
spec:
  selector:
    namespaces:
      - <string>
    workloadSelector:
      matchLabels: <map[string]string>
  controls:
    - canonical:
        namespace: <string>       # e.g. "ckodex"
        id: <string>              # e.g. "container.least-privilege"
      mappings:
        - framework: <string>     # e.g. "NIST-SP-800-53"
          version: <string>       # e.g. "rev5"
          controlId: <string>     # e.g. "AC-6"
  requirements:
    - id: <string>                # e.g. "non-root-execution"
      implementation: <string>    # e.g. "validating-admission-policy/disallow-root"
      evidenceContract: <string>  # Name of EvidenceContract
status:
  observedGeneration: <int64>
  conditions:
    - type: Ready
      status: "True" | "False"
      reason: "ASSURED" | "UNKNOWN" | "STALE" | "FAILED"
```

---

## 2. `EvidenceContract`

Specifies the evidence requirements, accepted producers, and freshness bounds that must be met to satisfy a control.

### Schema:

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: EvidenceContract
metadata:
  name: <string>
  namespace: <string>
spec:
  requirementId: <string>
  requiredEvidence:
    - type: <string>              # "kubernetes.admission" | "runtime.ebpf"
      producerSelector:
        spiffeTrustDomain: <string>
        allowedSubjects:
          - <string>
      maxAge: <duration>          # e.g. "15m", "1h"
      verification:
        signatureRequired: <bool>
        provenanceRequired: <bool>
  evaluation:
    engine: <string>              # "cel"
    expression: <string>
  failurePolicy:
    onMissingEvidence: "UNKNOWN" | "FAILED"
    onStaleEvidence: "STALE" | "FAILED"
    onUnverifiedSignature: "FAILED"
status:
  observedGeneration: <int64>
  conditions: <[]metav1.Condition>
```

---

## 3. `AssurancePolicy`

Defines cluster-wide governance thresholds, admission gating modes, and runtime containment rules.

### Schema:

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: AssurancePolicy
metadata:
  name: <string>
spec:
  mode: <string>                  # "enforcing" | "warn" | "audit"
  admission:
    requireVerifiedProvenance: <bool>
    requireValidControls:
      - <string>
    unknownDisposition: <string>  # "DENY" | "ADMIT_WITH_OBLIGATIONS"
  runtime:
    onInvalidation: <string>      # "ALERT_AND_QUARANTINE"
    quarantineAction: <string>    # "APPLY_ISOLATION_NETWORK_POLICY"
```

---

## 4. `ControlException`

Defines a temporally bounded, authorized derogation for a specific control failure (Invariant I-05: Derogation does not erase failure).

### Schema:

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: ControlException
metadata:
  name: <string>
  namespace: <string>
spec:
  subject:
    kind: <string>
    name: <string>
    namespace: <string>
  controls:
    - <string>
  justification:
    reason: <string>
    ticket: <string>
    compensatingControls:
      - <string>
  authority:
    requiredApprovers:
      - <string>
    signatureRef: <string>
  validity:
    notBefore: <timestamp>
    notAfter: <timestamp>         # Permanent exceptions are strictly rejected (I-05)
```

---

## 5. `AssuranceState`

The lightweight status projection resource. **Stores zero raw evidence blobs in etcd** (ADR-002).

### Schema:

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
    name: <string>
    namespace: <string>
status:
  state: <string>                 # "UNKNOWN" | "OBSERVED" | "VERIFIED" | "ASSURED" | "STALE" | "FAILED"
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
```

---

## 6. `CapabilityLease`

Governs bounded, revocable authority for agentic workcells and UTCP tool execution (ADR-006).

### Schema:

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: CapabilityLease
metadata:
  name: <string>
  namespace: <string>
spec:
  leaseId: <string>
  holderSpiffeId: <string>
  issuerSpiffeId: <string>
  allowedEffects:
    - <string>                    # "READ_K8S_STATE" | "EMIT_EVIDENCE_CAS" | "PROJECT_OSCAL"
  allowedSubjectPrefixes:
    - <string>
  maxCalls: <int32>
  notBefore: <timestamp>
  expiresAt: <timestamp>
  revoked: <bool>
status:
  state: <string>                 # "ACTIVE" | "EXPIRED" | "REVOKED" | "EXHAUSTED"
  callsConsumed: <int32>
  lastReceiptHash: <string>
```
