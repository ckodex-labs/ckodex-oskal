# ckodex-oskal -- Kubernetes Continuous Assurance Runtime

[![Go Report Card](https://goreportcard.com/badge/github.com/ckodex-labs/ckodex-oskal)](https://goreportcard.com/report/github.com/ckodex-labs/ckodex-oskal)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![OSCAL Version](https://img.shields.io/badge/OSCAL-v1.2.3-green.svg)](https://pages.nist.gov/OSCAL/)

**OSKAL** is the Kubernetes Continuous Assurance Runtime of the CKODEX Architecture (`CKX-OSKAL-001`).

It bridges the gap between machine-readable security specifications (OSCAL) and dynamic cloud-native runtime reality.

---

## The Core Rule

```text
Kubernetes Runtime / Substrate
      │
      ▼
OSKAL Adapters & Controllers
      │
      ▼
CKODEX Assurance Core (Pure Domain Semantics)
      │
      ▼
XOSCAL Projection (Standards Mapping & Serialization)
      │
      ▼
OSCAL v1.2.3 Specification Artifacts
```

## Architectural Signature

- **Pure Kernel:** The Assurance Core is 100% technology-neutral with zero Kubernetes dependencies.
- **Shared Validation:** Continuous assurance evaluated deterministically against explicit Evidence Contracts.
- **Vector State, Not Booleans:** Multidimensional state (`Applicability`, `Conformance`, `Integrity`, `Authority`, `Identity`, `Runtime`, `Freshness`, `Completeness`, `Coherence`).
- **Absence of Evidence is UNKNOWN:** Never `no finding -> PASS`. Insufficient evidence is always `UNKNOWN`.
- **Temporal Assurance & Epochs:** Cryptographic binding over subject, policy, implementation, authority, and environment. Any divergence triggers immediate `STALE` transition.
- **Content-Addressed CAS:** Detailed evidence traces and blobs live in content-addressed storage, never in Kubernetes `etcd`.
- **Five CRD Surface:** `ControlBinding`, `EvidenceContract`, `AssurancePolicy`, `ControlException`, and `AssuranceState`.

---

## Directory Structure

```text
ckodex-oskal/
├── api/assurance/v1alpha1/      # Five Kubernetes CRDs
├── cmd/oskal-controller/        # Controller entrypoint (leader election, probes, metrics)
├── config/                      # Kustomize / CRD / RBAC manifests
│   ├── crd/bases/
│   ├── manager/
│   └── rbac/
├── core/assurance/              # Pure Assurance Kernel (FSM, Epochs, Claims, Evidence)
├── dagger/                      # Automated CI/CD DAG pipeline
├── docs/                        # Architecture specs & ADRs
│   ├── adr/
│   └── architecture/
├── internal/
│   ├── application/reconcile/   # Reconcilers
│   └── ports/                   # Hexagonal architecture ports
├── proto/assurance/             # Canonical Protobuf definitions & generated Go code
└── tests/                       # Unit, property, and integration tests
```

---

## License

Apache-2.0
