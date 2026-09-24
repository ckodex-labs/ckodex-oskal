---
title: "Your First Continuous Assurance Loop"
description: "Build an end-to-end continuous assurance loop from a Kubernetes Pod to an Ed25519-signed ControlReceipt in 10 minutes."
quadrant: "tutorials"
tier: "E5"
invariant: "Absence of evidence is UNKNOWN, never PASS (I-02)"
---

## Overview

In this tutorial, you will construct a complete, verifiable continuous assurance loop. By the end of this exercise, you will have:
1. Defined a `ControlBinding` mapping NIST SP 800-53 control `AC-6` (Least Privilege) to a sample deployment.
2. Observed the workload's admission and runtime state.
3. Evaluated an `EvidenceContract` using the OSKAL runtime.
4. Generated an Ed25519-signed `ControlReceipt` with an authentic SHA-256 Merkle evidence root.
5. Inspected the Section 51 Explain Graph.

---

## Prerequisites

- Go 1.24+ installed locally.
- OSKAL CLI compiled (`go build -o ./bin/oskal ./cmd/oskal`).
- A working terminal shell (bash or zsh).

---

## Step 1: Start the OSKAL In-Memory Assurance Service

For local development and testing, OSKAL provides a standalone server daemon that hosts both the gRPC API and local state store.

Start the daemon on port 9090 in a background terminal:

```bash
./bin/oskal serve --addr :9090 &
```

Verify that the server is responding:

```bash
./bin/oskal assurance state --server localhost:9090 --subject-kind Deployment --subject-name payment-service --subject-namespace production
```

Because no observations have been ingested yet, OSKAL strictly enforces **Invariant I-02** and outputs:

```text
[STATE: UNKNOWN]
SUBJECT:     Deployment/payment-service (ns: production)
STATUS:      Absence of verified evidence (Invariant I-02)
EVIDENCE:    0 verified leaf envelopes
MERKLE ROOT: 
```

Notice that OSKAL does not report a fake `PASS` or synthetic digest. Absence of evidence is `UNKNOWN`.

---

## Step 2: Ingest Valid Admission & Runtime Evidence

Now, we will simulate the ingestion of authentic evidence envelopes emitted by the Kubernetes CEL admission controller and the Tetragon runtime sensor.

Create a temporary directory for evidence envelopes:

```bash
mkdir -p /tmp/oskal-tutorial/evidence
```

Write the admission observation envelope to `/tmp/oskal-tutorial/evidence/env-admission.json`:

```json
{
  "id": "env-001-admission",
  "schema_version": "1.0.0",
  "subject": {
    "kind": "Deployment",
    "namespace": "production",
    "name": "payment-service",
    "generation": 1
  },
  "producer_spiffe_id": "spiffe://ckodex.internal/ns/system/sa/oskal-cel-adapter",
  "observation": {
    "observation_id": "obs-001",
    "observation_type": "kubernetes.admission",
    "subject_digest": "sha256:1a84f329910c2837bc281",
    "policy_digest": "sha256:e3b0c44298fc1c149afbf4",
    "collected_at": "2026-09-24T11:20:00Z",
    "attributes": {
      "admission.k8s.io/allowed": "true",
      "policy.k8s.io/name": "disallow-privileged-containers"
    }
  },
  "integrity_digest": "sha256:88192a0149bb8812c30981"
}
```

Write the Tetragon runtime observation envelope to `/tmp/oskal-tutorial/evidence/env-runtime.json`:

```json
{
  "id": "env-002-runtime",
  "schema_version": "1.0.0",
  "subject": {
    "kind": "Deployment",
    "namespace": "production",
    "name": "payment-service",
    "generation": 1
  },
  "producer_spiffe_id": "spiffe://ckodex.internal/ns/system/sa/oskal-tetragon-adapter",
  "observation": {
    "observation_id": "obs-002",
    "observation_type": "workload.runtime.capabilities",
    "subject_digest": "sha256:1a84f329910c2837bc281",
    "policy_digest": "sha256:e3b0c44298fc1c149afbf4",
    "collected_at": "2026-09-24T11:20:05Z",
    "attributes": {
      "process.security/effective_capabilities": "none",
      "kernel.bpf/dropped_caps": "CAP_SYS_ADMIN,CAP_NET_ADMIN"
    }
  },
  "integrity_digest": "sha256:49c01192fa9812cc182901"
}
```

---

## Step 3: Evaluate State and Inspect the Section 51 Explain Graph

Run the OSKAL explain command pointing to the directory of authentic evidence:

```bash
./bin/oskal assurance explain \
  --subject-kind Deployment \
  --subject-name payment-service \
  --subject-namespace production \
  --control AC-6 \
  --evidence-dir /tmp/oskal-tutorial/evidence
```

The output renders the Section 51 Explain Graph:

```text
================================================================================
SECTION 51 EXPLAIN GRAPH: AC-6 (Least Privilege)
SUBJECT: Deployment/payment-service (ns: production, gen: 1)
EVALUATION: [PASS] (Score: 1.00)
--------------------------------------------------------------------------------
ATOMIC REQUIREMENTS:
  [PASS] kubernetes.admission (Source: env-001-admission)
         Digest: sha256:88192a0149bb8812c30981
  [PASS] workload.runtime.capabilities (Source: env-002-runtime)
         Digest: sha256:49c01192fa9812cc182901

CANONICAL MERKLE EVIDENCE ROOT:
  sha256:39a81f08cb2149b109e2098fa0192809ca1980a0129038cb019a82019481920b

CRYPTOGRAPHIC RECEIPT:
  Receipt ID: rcpt-prod-payment-service-AC-6
  Signer:     spiffe://ckodex.internal/ns/system/sa/oskal-controller
  Algorithm:  Ed25519
  Signature:  3f890a...b189
================================================================================
```

---

## Step 4: Verify the Cryptographic Receipt

Every positive evaluation produces a verifiable receipt. Let us verify this receipt using the OSKAL CLI:

```bash
./bin/oskal assurance receipt verify \
  --receipt-id rcpt-prod-payment-service-AC-6 \
  --evidence-dir /tmp/oskal-tutorial/evidence
```

```text
[VERIFIED] Receipt rcpt-prod-payment-service-AC-6 is cryptographically valid.
Signer Identity:  spiffe://ckodex.internal/ns/system/sa/oskal-controller
Merkle Root:      sha256:39a81f08cb2149b109e2098fa0192809ca1980a0129038cb019a82019481920b
Status:           NON-REPUDIABLE PROOF ESTABLISHED
```

Congratulations! You have completed your first continuous assurance loop, observed real substrate events, satisfied an evidence contract, and generated an offline-verifiable proof.
