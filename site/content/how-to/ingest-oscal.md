---
title: "Ingesting NIST OSCAL Artifacts"
description: "How to translate NIST OSCAL 1.2.3 Component Definitions and SSPs into active Kubernetes ControlBindings and EvidenceContracts."
quadrant: "how-to"
tier: "E5"
---

This guide demonstrates how to bidirectional ingest NIST OSCAL v1.2.3 Component Definitions and System Security Plans (SSPs) into active Kubernetes Custom Resources using the OSKAL CLI.

## Overview

Traditional compliance workflows store OSCAL as static documentation in repository silos. OSKAL activates these specifications by translating `implemented-requirements` and component definitions directly into live Kubernetes CRDs (`ControlBinding` and `EvidenceContract`).

```text
[ NIST OSCAL 1.2.3 JSON/YAML ]
              |
              v
     `oskal import oscal`
              |
              +---> ControlBinding (Subject + Controls)
              |
              +---> EvidenceContract (Requirements + Freshness)
              |
              v
     `kubectl apply -f -`
```

## Step 1: Prepare the OSCAL Document

Provide a standard NIST OSCAL v1.2.3 JSON or YAML document. For example, `oscal-component-definition.json`:

```json
{
  "component-definition": {
    "uuid": "8b9487b3-c11f-4d4e-b552-84b2c1598501",
    "metadata": {
      "title": "Payment Gateway Service Component Definition",
      "version": "1.0.0",
      "oscal-version": "1.2.3"
    },
    "components": [
      {
        "uuid": "comp-payments-api-001",
        "type": "software",
        "title": "payments-api",
        "control-implementations": [
          {
            "uuid": "ci-pci-01",
            "source": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
            "implemented-requirements": [
              {
                "uuid": "ir-ac-6",
                "control-id": "AC-6",
                "props": [
                  {"name": "evidence-type", "value": "admission"},
                  {"name": "producer", "value": "kubernetes-validating-admission"},
                  {"name": "freshness", "value": "24h"}
                ]
              }
            ]
          }
        ]
      }
    ]
  }
}
```

## Step 2: Ingest and Apply Manifests

Execute the import command targeting the workload namespace:

```bash
oskal import oscal \
  --file oscal-component-definition.json \
  --namespace production | kubectl apply -f -
```

Example terminal receipt:

```text
[PASS] Ingested OSCAL ComponentDefinition: Payment Gateway Service Component Definition (UUID: 8b9487b3-c11f-4d4e-b552-84b2c1598501)
[INFO] Generated 1 ControlBinding(s) and 1 EvidenceContract(s)
---
evidencecontract.assurance.ckodex.io/payments-api-contract configured
controlbinding.assurance.ckodex.io/payments-api-binding configured
```

## Step 3: Verify Controller Reconciliation

Inspect the instantiated resources:

```bash
kubectl get controlbindings,evidencecontracts -n production
```

Verify status conditions:

```bash
kubectl describe controlbinding payments-api-binding -n production
```
