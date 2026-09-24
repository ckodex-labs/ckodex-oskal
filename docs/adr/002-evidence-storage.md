# ADR-002: Evidence Storage Strategy Outside Kubernetes etcd

**Status:** Accepted  
**Date:** 2026-09-23  
**Authors:** Codex Architectural Guild  
**Classification:** CKODEX Architecture Decision Record  

---

## 1. Context

Kubernetes custom resources (`CRDs`) backed by `etcd` have hard performance, storage, and architectural constraints:
- `etcd` object limits: Default maximum request size is 1.5 MiB; recommended maximum database size is 2 to 8 GiB.
- High-frequency write churn: Streaming runtime telemetry (e.g. Tetragon process traces, Cilium network flows, vulnerability scan results, Sigstore bundles) would overwhelm etcd with write serialization, causing leader elections and cluster instability.
- Security and audit: Audit trails and evidence envelopes require immutable content-addressed storage and long-term cryptographic retention, which etcd is not designed to provide.

## 2. Decision

We mandate that **no raw evidence payloads or detailed observation traces shall ever be stored in Kubernetes etcd**.

Instead, OSKAL implements a multi-tier storage architecture separated by responsibility:

```text
┌───────────────────────────────┐
│        Kubernetes etcd        │ ◄── Current summary state only
│    (AssuranceState Status)    │     (State enum, epoch, evidenceRoot, conditions)
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│       Evidence Envelope       │ ◄── Standardized metadata envelope
│     (EvidenceRef Pointer)     │     (ID, subject, digest, URI, mediaType, signature)
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│     Content-Addressed CAS     │ ◄── Immutable evidence artifacts & raw payloads
│    (S3 / RustFS / OCI / MinIO)│     (Cryptographic verification via digest)
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│  Analytical / Telemetry Store │ ◄── High-volume temporal observations
│   (ClickHouse / LanceDB)      │     (For continuous correlation and time-series audit)
└───────────────────────────────┘
```

### Core Invariants:
1. **CRD Representation:** Kubernetes CRD status (`AssuranceState.status`) contains only:
   - Summary state (`AssuranceState` enum);
   - Effective `AssuranceEpoch`;
   - Root cryptographic hash (`evidenceRoot` Merkle digest);
   - Timestamp boundaries (`evaluatedAt`, `validUntil`);
   - Standard Kubernetes status conditions (`EvidenceReady`, `EvaluationReady`, `Assured`, `Stale`, `Degraded`).
2. **Evidence Envelope:** Evidence items are referenced via `EvidenceRef`:
   ```go
   type EvidenceRef struct {
       URI       string
       Digest    string
       MediaType string
   }
   ```
3. **Repository Abstraction:** Access to evidence payloads is mediated by an abstracted `EvidenceRepository` port:
   ```go
   type EvidenceRepository interface {
       Put(ctx context.Context, envelope EvidenceEnvelope, payload io.Reader) (EvidenceRef, error)
       Get(ctx context.Context, ref EvidenceRef) (io.ReadCloser, error)
       Verify(ctx context.Context, ref EvidenceRef) (VerificationResult, error)
   }
   ```
4. **Air-Gap Capability:** The storage backend MUST support local S3-compatible or local filesystem engines (RustFS/MinIO) for fully air-gapped clusters without external cloud dependencies.

## 3. Consequences

### Positive:
- Protects Kubernetes etcd stability and maintains sub-millisecond API responsiveness.
- Supports multi-megabyte SBOMs, SLSA provenance documents, and kernel tracing streams without cluster degradation.
- Ensures evidence immutability and verifiable content addressing.

### Negative / Trade-offs:
- Requires deploying an object storage adapter or volume for durable evidence in the cluster.
- Reconcilers fetch evidence references lazily rather than reading inline data from the Kubernetes informer cache.
