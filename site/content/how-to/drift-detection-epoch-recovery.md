---
title: "How to Detect and Recover from Runtime Drift"
description: "Understand automatic epoch invalidation when Kubernetes workloads mutate, and trigger reconciliation back to ASSURED state."
quadrant: "how-to"
tier: "E5"
invariant: "Assurance is temporal: ASSURED transitions to STALE on drift (I-07)"
---

## Context

Static compliance creates a false sense of security: an auditor checks a configuration once a year, while Kubernetes pods change dozens of times a day.

In OSKAL, **Invariant I-07** enforces temporal assurance. If a workload's Kubernetes `.metadata.generation` increments, or container image digest changes, the active `AssuranceEpoch` is immediately invalidated. The state transitions from `ASSURED` to `STALE`.

---

## 1. Inspecting Active Epoch & Generating Drift

Consider a workload currently in `ASSURED` state:

```bash
oskal assurance state --subject-name payment-service
```

```text
[STATE: ASSURED]
SUBJECT:     Deployment/payment-service (generation: 1)
EPOCH:       0192a
HASH:        sha256:7b29a10f88e421cd93e4811a01c3f9104b2a8c199201f3089ef04358bbd7821c
```

Now, simulate an update to the deployment manifest (e.g. updating an environment variable or rolling an image):

```bash
kubectl set env deployment/payment-service LOG_LEVEL=debug -n production
```

The Kubernetes API server increments `.metadata.generation` from `1` to `2`.

---

## 2. Observing the Drift Invalidation

Check the assurance state immediately after the update:

```bash
oskal assurance drift --subject-name payment-service
```

Output:

```text
================================================================================
DRIFT ANALYSIS FOR Deployment/payment-service
PREVIOUS STATE: ASSURED (Epoch: 0192a, Generation: 1)
CURRENT STATE:  STALE   (Generation: 2)
--------------------------------------------------------------------------------
DRIFT REASONS:
  [DETECTED] DriftSubject: Generation changed from 1 to 2.
  [DETECTED] SubjectDigestMismatch: Container spec modified.

INSPECTION:
  Previous Merkle Evidence Root: sha256:7b29...821c
  Active Evidence Root:          INVALIDATED (STALE)
================================================================================
```

---

## 3. Reconciling Back to ASSURED

The OSKAL Kubernetes controller detects the `STALE` state and initiates reconciliation:
1. Re-triggers admission CEL evaluation for generation 2.
2. Waits for Tetragon / Cilium runtime telemetry confirming that the new pods adhere to capability restrictions.
3. Computes a new `AssuranceEpoch` (`0192b`) with updated subject and policy digests.
4. Transitions state back to `ASSURED` and issues a fresh `ControlReceipt`.
