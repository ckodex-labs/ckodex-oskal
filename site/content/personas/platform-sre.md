---
title: "Platform Engineer & SRE Persona Guide"
description: "How Platform Engineers and Site Reliability Engineers deploy, operate, and maintain OSKAL controllers, CRDs, and low-latency admission hooks."
quadrant: "personas"
tier: "E5"
invariant: "Invisible excellence: complex guarantees behind simple operator controls"
---

## Executive Summary

As a Platform Engineer or SRE, your primary constraints are **system stability, admission latency, minimal resource overhead, and failure containment**. You cannot tolerate compliance agents crashing production API servers or flooding etcd with gigabytes of raw scan logs.

OSKAL is built specifically to address these operational constraints.

---

## 1. Zero Evidence Storage in etcd (ADR-002)

A common failure mode of Kubernetes compliance operators is storing full scan reports and SBOMs directly inside Custom Resource `status` fields, leading to etcd database exhaustion and cluster outages.

OSKAL implements **ADR-002**:
- Only the lightweight `AssuranceState` CRD is persisted in Kubernetes (state enum, epoch identifier, condition booleans, and the 64-character SHA-256 `evidenceRoot`).
- Raw evidence envelopes and heavy telemetry payloads are processed in memory and retained in an external evidence store or local air-gap flight recorder.

---

## 2. Ultra-Low-Latency Admission Gating via Native CEL

Instead of deploying heavy external admission webhooks that introduce latency spikes and network failure points, OSKAL leverages Kubernetes-native `ValidatingAdmissionPolicy`:
- Admission rules run in-process inside the `kube-apiserver` using the Common Expression Language (CEL).
- Sub-millisecond evaluation latency.
- The OSKAL controller merely observes the admission events and computes integrity digests asynchronously.

---

## 3. High Availability Controller Deployment

The OSKAL controller deploys via standard Kubernetes manifests with built-in leader election:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oskal-controller
  namespace: oskal-system
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: controller
          image: ghcr.io/ckodex-labs/ckodex-oskal/oskal-controller:v0.1.0-alpha.1
          resources:
            limits:
              cpu: "500m"
              memory: "512Mi"
            requests:
              cpu: "100m"
              memory: "128Mi"
```

---

## 4. Automatic Drift Invalidation & Reconciliation

When developers roll an application or update a config map, Kubernetes increments `.metadata.generation`.

The OSKAL controller automatically:
1. Detects the generation increment without polling.
2. Invalidates the active `AssuranceEpoch` (`ASSURED -> STALE`).
3. Re-evaluates admission and runtime evidence.
4. Restores `ASSURED` status once new telemetry confirms compliance.
