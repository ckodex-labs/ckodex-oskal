---
title: "Kubernetes CRD Reference"
description: "Technical schema reference for the five Custom Resource Definitions in api/assurance/v1alpha1."
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

Binds a canonical control to workload selectors and an implementation provider.

### Schema:

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: ControlBinding
metadata:
  name: <string>
  namespace: <string>
spec:
  canonicalControl: <string>      # e.g. "ckodex:container.least-privilege"
  frameworkMappings:              # Standards cross-walks
    - framework: <string>         # e.g. "NIST-SP-800-53"
      controlId: <string>         # e.g. "AC-6"
  workloadSelector:               # Target workloads
    matchLabels: <map[string]string>
  implementation:
    provider: <string>            # "kubernetes.admission.cel" | "tetragon" | "cilium"
    componentRef: <string>        # Identifier of enforcement resource
    policyDigest: <string>        # SHA-256 digest of implementation policy
  evidenceContractRef:
    name: <string>                # Name of EvidenceContract
status:
  observedGeneration: <int64>
  bindingState: <string>          # "Bound" | "Unbound" | "Error"
```

---

## 2. `EvidenceContract`

Specifies the evidence requirements that must be met to satisfy a control.

### Schema:

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: EvidenceContract
metadata:
  name: <string>
  namespace: <string>
spec:
  subjectSelector:
    matchLabels: <map[string]string>
  requiredEvidence:
    - observationType: <string>   # "kubernetes.admission" | "workload.runtime.capabilities"
      maxAge: <duration>          # e.g. "30m", "1h"
      allowedProducers:           # Authorized SPIFFE IDs
        - <string>
status:
  contractStatus: <string>        # "Active" | "Pending"
```

---

## 3. `AssurancePolicy`

Defines cluster-wide governance thresholds, staleness bounds, and admission gating behaviors.

### Schema:

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: AssurancePolicy
metadata:
  name: <string>
spec:
  defaultStalenessTolerance: <duration>  # Default: "1h"
  enforceAdmissionGating: <bool>         # Reject pods if state is UNKNOWN/FAILED
  quarantineThreshold: <int32>           # Max failed evaluations before quarantine
```

---

## 4. `ControlException`

Defines a temporally bounded, authorized derogation for a specific control failure.

### Schema:

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: ControlException
metadata:
  name: <string>
  namespace: <string>
spec:
  controlRef:
    framework: <string>
    controlId: <string>
  subject:
    kind: <string>
    name: <string>
    namespace: <string>
  justification: <string>         # Reason for derogation
  approverSPIFFEID: <string>      # Identity of authorized risk owner
  compensatingControls:           # Active secondary mitigations
    - <string>
  validFrom: <timestamp>
  expiresAt: <timestamp>          # Permanent exceptions are strictly rejected (I-05)
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
status:
  currentState: <string>          # "UNKNOWN" | "OBSERVED" | "VERIFIED" | "ASSURED" | "STALE" | "FAILED"
  activeEpoch:
    epochId: <string>
    subjectDigest: <string>
    policyDigest: <string>
  evidenceRoot: <string>          # SHA-256 Merkle root of leaf envelopes
  lastTransitionTime: <timestamp>
```
