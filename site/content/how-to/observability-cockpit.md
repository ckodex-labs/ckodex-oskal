---
title: "Deep Observability & Prometheus Metrics"
description: "How to scrape OSKAL assurance metrics, configure OpenTelemetry tracing, and import the Grafana Cockpit."
quadrant: "how-to"
tier: "E5"
---

This guide covers the setup of continuous assurance metrics collection, OpenTelemetry tracing, and the Grafana Assurance Cockpit.

## Prometheus Metrics Endpoints

The OSKAL Controller Manager exposes metrics on port `8080` at `/metrics` by default.

### Key Assurance Metrics

| Metric | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `oskal_assurance_state` | Gauge | `namespace`, `binding`, `status`, `generation` | Current vector assurance status (1=active, 0=inactive). |
| `oskal_evidence_envelopes_total` | Counter | `source`, `type`, `status` | Total evidence envelopes ingested and processed. |
| `oskal_receipts_issued_total` | Counter | `contract_id`, `status` | Cryptographic receipts signed and issued. |
| `oskal_drift_invalidations_total` | Counter | `binding`, `reason` | Invalidation events provoked by workload drift. |
| `oskal_evaluation_duration_seconds` | Histogram | `contract_id` | Evaluation latency distribution for contracts. |

## Step 1: Deploy with ServiceMonitor

When using the Prometheus Operator, enable the ServiceMonitor in the Helm chart:

```bash
helm upgrade --install oskal deploy/helm/ckodex-oskal \
  --namespace ckodex-assurance \
  --create-namespace \
  --set metrics.serviceMonitor.enabled=true
```

## Step 2: Import the Grafana Assurance Cockpit

Import the prebuilt dashboard JSON located at:

```text
deploy/dashboards/grafana-assurance-cockpit.json
```

The dashboard includes:
- Real-time Assured vs Degraded workload counter.
- Drift Invalidation event rate (1h window).
- Evidence Envelope Ingestion throughput by producer.
- P50, P95, and P99 Contract Evaluation latency curves.
- HA Controller Leader Election standing.
