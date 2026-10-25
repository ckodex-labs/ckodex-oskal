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

- Go 1.27+ installed locally.
- OSKAL CLI compiled (`go build -o ./bin/oskal ./cmd/oskal`).
- A working terminal shell (bash or zsh).

---

## Step 1: Start the OSKAL In-Memory Assurance Service

For local development and testing, OSKAL provides a standalone server daemon that hosts both the gRPC API and local state store.

Start the daemon on port 9090 in a background terminal:

```bash
./bin/oskal serve --port 9090 &
```

Verify that the server is responding:

```bash
./bin/oskal assurance state --server localhost:9090 --subject-kind Deployment --subject-name payment-service --subject-namespace production
```

Because no observations have been ingested yet, OSKAL strictly enforces **Invariant I-02** and outputs:

```text
SUBJECT:         k8s://production/Deployment/payment-service
STATE:           UNKNOWN
STATUS:          No matching evidence envelopes found (Invariant I-02)
EVIDENCE ROOT:   none
LAST EVALUATED:  2026-10-25T12:00:00Z
FRESHNESS:       unknown
MISSING SIGNALS: kubernetes.admission, runtime.ebpf, spiffe.svid
REMEDIATION:     oskal record admission --file <manifest.yaml> OR specify --server
```

Notice that OSKAL does not report a fake `PASS` or synthetic digest. Absence of evidence is `UNKNOWN`.

---

## Step 2: Ingest Valid Admission & Runtime Evidence

Now, we will simulate the ingestion of authentic evidence envelopes emitted by the Kubernetes CEL admission controller and the runtime sensor.

Create a temporary directory for evidence envelopes:

```bash
mkdir -p /tmp/oskal-tutorial/evidence
```

You can either record evidence automatically from a manifest using the OSKAL CLI:

```bash
./bin/oskal record admission --file examples/sample-workload.yaml --evidence-dir /tmp/oskal-tutorial/evidence
```

Or write the canonical admission observation envelope directly to `/tmp/oskal-tutorial/evidence/env-admission.json`:

```json
{
  "schema": "https://assurance.ckodex.io/schemas/v1",
  "id": "env-001-admission",
  "subject": {
    "scheme": "k8s",
    "id": "production/Deployment/payment-service"
  },
  "observationType": "admission",
  "capturedAt": "2026-10-25T12:00:00Z",
  "producer": {
    "scheme": "spiffe",
    "subject": "ckodex.internal/ns/system/sa/oskal-cel-adapter"
  },
  "artifact": {
    "uri": "file:///manifests/payment-service.yaml",
    "digest": "sha256:88192a0149bb8812c3098194a081bc2014918239018401928091820491820938",
    "mediaType": "application/yaml"
  },
  "integrityDigest": "sha256:88192a0149bb8812c3098194a081bc2014918239018401928091820491820938",
  "epoch": {
    "subjectDigest": "sha256:1a84f329910c2837bc2810000000000000000000000000000000000000000000",
    "implementationDigest": "sha256:f47a981240182409182409182409182409182409182409182409182409182409",
    "policyDigest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "authorityDigest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "environmentDigest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
  },
  "controlRefs": [
    {
      "namespace": "nist-sp-800-53",
      "id": "AC-6"
    }
  ]
}
```

Write the runtime observation envelope to `/tmp/oskal-tutorial/evidence/env-runtime.json`:

```json
{
  "schema": "https://assurance.ckodex.io/schemas/v1",
  "id": "env-002-runtime",
  "subject": {
    "scheme": "k8s",
    "id": "production/Deployment/payment-service"
  },
  "observationType": "runtime.capabilities",
  "capturedAt": "2026-10-25T12:00:05Z",
  "producer": {
    "scheme": "spiffe",
    "subject": "ckodex.internal/ns/system/sa/oskal-tetragon-adapter"
  },
  "artifact": {
    "uri": "k8s://production/Deployment/payment-service/caps",
    "digest": "sha256:49c01192fa9812cc182901380918204918240182903810293810928301928301",
    "mediaType": "application/json"
  },
  "integrityDigest": "sha256:49c01192fa9812cc182901380918204918240182903810293810928301928301",
  "epoch": {
    "subjectDigest": "sha256:1a84f329910c2837bc2810000000000000000000000000000000000000000000",
    "implementationDigest": "sha256:f47a981240182409182409182409182409182409182409182409182409182409",
    "policyDigest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "authorityDigest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "environmentDigest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
  },
  "controlRefs": [
    {
      "namespace": "nist-sp-800-53",
      "id": "AC-6"
    }
  ]
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
SUBJECT
k8s://production/Deployment/payment-service

CONTROL
nist-sp-800-53:AC-6

CANONICAL CONTROL
ckodex:least-privilege

APPLICABILITY
[PASS] applicable

ATOMIC REQUIREMENTS

[PASS] non-root execution
[PASS] capability restriction
[PASS] bounded ServiceAccount
[PASS] network isolation
[PASS] workload identity
[PASS] approved artifact

IMPLEMENTATIONS

non-root
  kubernetes ValidatingAdmissionPolicy
capabilities
  Kubernetes CEL
  Tetragon runtime observer
identity
  SPIFFE/SPIRE
network
  Cilium
artifact
  Sigstore

EVIDENCE

[PASS] admission decision
[PASS] signed OCI artifact
[PASS] workload identity
[PASS] network configuration
[PASS] runtime process observation
[PASS] capability observation

COMPLETENESS
6 / 6 required

FRESHNESS
current

AUTHORITY
verified

ASSURANCE
ASSURED

EVIDENCE ROOT
sha256:33b2bca7002b852ba15a9fae8d57597393caa446c467bde0afed6a7c9b327fdf
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
