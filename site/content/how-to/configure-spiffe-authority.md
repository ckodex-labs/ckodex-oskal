---
title: "How to Enforce SPIFFE/SPIRE Authority Validation"
description: "Configure zero-trust cryptographic workload identity validation for all evidence producers in the cluster."
quadrant: "how-to"
tier: "E5"
invariant: "Authority is explicit, never inferred (I-10)"
---

## Context

In OSKAL, **Invariant I-10** mandates that authority precedes evidence. An unauthenticated agent or compromised sidecar cannot emit valid evidence envelopes. All evidence producers must present a verifiable X.509 SVID (SPIFFE Verifiable Identity Document) issued by an authorized SPIRE agent.

---

## 1. Configure the SPIRE Agent and Trust Domain

Ensure your SPIRE installation issues SVIDs within the cluster's root trust domain:

```text
Trust Domain: ckodex.internal
Issuer:       spiffe://ckodex.internal/spire-server
```

Evidence producers must be assigned explicit SPIFFE IDs:
- Admission controller: `spiffe://ckodex.internal/ns/system/sa/oskal-cel-adapter`
- Runtime sensor: `spiffe://ckodex.internal/ns/system/sa/oskal-tetragon-adapter`
- Supply chain scanner: `spiffe://ckodex.internal/ns/system/sa/oskal-sigstore-adapter`

---

## 2. Declare Authorized Producers in EvidenceContract

In your `EvidenceContract`, specify the required observation types alongside the exact allowed producer SPIFFE IDs:

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: EvidenceContract
metadata:
  name: contract-workload-identity
  namespace: production
spec:
  subjectSelector:
    matchLabels:
      tier: secure-core
  requiredEvidence:
    - observationType: "kubernetes.admission"
      maxAge: 30m
      allowedProducers:
        - "spiffe://ckodex.internal/ns/system/sa/oskal-cel-adapter"
    - observationType: "workload.runtime.capabilities"
      maxAge: 15m
      allowedProducers:
        - "spiffe://ckodex.internal/ns/system/sa/oskal-tetragon-adapter"
```

---

## 3. Verify Producer Rejection on Spoofed Authority

If an evidence envelope is received with an unauthorized or mismatched SPIFFE ID:

```json
{
  "id": "env-spoofed-001",
  "producer_spiffe_id": "spiffe://untrusted.domain/bad-actor",
  "observation": {
    "observation_type": "kubernetes.admission"
  }
}
```

The OSKAL Spire adapter immediately rejects the envelope:

```text
[REJECTED] Ingestion denied: Producer SPIFFE ID 'spiffe://untrusted.domain/bad-actor'
is not permitted by EvidenceContract 'contract-workload-identity'.
Authority state: ANTI_CONFLICT.
```

The rejected envelope is recorded in the flight recorder log and preserved for forensic audit, ensuring zero authority contamination.
