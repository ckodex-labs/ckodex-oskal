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

## Step 2: Record Authentic Admission Evidence

Now generate a cryptographically digested `EvidenceEnvelope` and Ed25519-signed `ControlReceipt` directly from the included sample workload manifest (`examples/sample-workload.yaml`, which defines `Deployment/payments-api` in namespace `ckodex-assurance-test`).

Create a temporary directory for evidence envelopes:

```bash
mkdir -p /tmp/oskal-tutorial/evidence
```

Record the admission evidence envelope and control receipt with the OSKAL CLI:

```bash
./bin/oskal record admission \
  --file examples/sample-workload.yaml \
  --evidence-dir /tmp/oskal-tutorial/evidence
```

The command computes authentic SHA-256 content and epoch digests and writes:
- An `EvidenceEnvelope` JSON file (`ev-adm-payments-api-<epoch>.json`)
- A signed `ControlReceipt` JSON file (`rcpt-adm-payments-api.json` and `rcpt-AC-6.json`)

---

## Step 3: Evaluate State and Inspect the Section 51 Explain Graph

Run the OSKAL explain command pointing to the local evidence directory:

```bash
./bin/oskal assurance explain \
  --subject-kind Deployment \
  --subject-name payments-api \
  --subject-namespace ckodex-assurance-test \
  --control AC-6 \
  --evidence-dir /tmp/oskal-tutorial/evidence
```

The output renders the Section 51 Explain Graph:

```text
SUBJECT
k8s://ckodex-assurance-test/Deployment/payments-api

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
sha256:c44cd7657e107c058f1182c4f7411930236431ca9c3b610d613e3a9eed9ffb8e
```

---

## Step 4: Verify the Cryptographic Receipt

Every positive evaluation produces a verifiable receipt. Verify the generated receipt using the OSKAL CLI:

```bash
./bin/oskal assurance receipt verify \
  --receipt-file /tmp/oskal-tutorial/evidence/rcpt-adm-payments-api.json
```

```text
[VERIFIED] Receipt in /tmp/oskal-tutorial/evidence/rcpt-adm-payments-api.json is cryptographically valid.
Signer Identity:  spiffe://ckodex.internal/ns/system/sa/oskal-admission-controller
Merkle Root:      sha256:c44cd7657e107c058f1182c4f7411930236431ca9c3b610d613e3a9eed9ffb8e
Status:           NON-REPUDIABLE PROOF ESTABLISHED
```

Congratulations! You have completed your first continuous assurance loop, recorded authentic evidence from a Kubernetes workload manifest, inspected the Section 51 Explain Graph, and verified an Ed25519-signed receipt.
