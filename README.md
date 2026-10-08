# ckodex-oskal -- Kubernetes Continuous Assurance Runtime

[![Go Report Card](https://goreportcard.com/badge/github.com/ckodex-labs/ckodex-oskal)](https://goreportcard.com/report/github.com/ckodex-labs/ckodex-oskal)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![OSCAL Version](https://img.shields.io/badge/OSCAL-v1.2.3-green.svg)](https://pages.nist.gov/OSCAL/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](Makefile)

**OSKAL** is the Kubernetes Continuous Assurance Runtime of the CKODEX Architecture (`CKX-OSKAL-001`).

It bridges the gap between machine-readable security specifications (**NIST OSCAL v1.2.3**) and dynamic cloud-native runtime substrates. Instead of relying on static spreadsheets, paper audits, or unverified claims, OSKAL continuously evaluates cryptographic evidence against formal contracts and projects defensible proof into standard OSCAL artifacts.

---

## The Core Rule

```text
Intent & Authority
       |
       v
Kubernetes Runtime / Substrate (Workloads, Pods, Network, Kernel)
       |
       v
OSKAL Runtime Observers & Adapters (CEL, Webhook, Tetragon, Cilium, SPIRE, Sigstore)
       |
       v
CKODEX Assurance Core (Pure Domain Semantics & Vector State)
       |
       v
XOSCAL Projector (Standards Mapping & Serialization)
       |
       v
NIST OSCAL v1.2.3 Artifacts (Assessment Results, SSP, Component Definition, POAM)
```

---

## Architectural Signature

- **Pure Semantic Kernel:** `core/assurance` owns domain semantics and invariants with zero external dependencies (100% Go standard library).
- **Invariant I-02 (Absence of Evidence is UNKNOWN):** Never return optimistic passes. If evidence is missing, unverified, expired, or corrupted, the state MUST resolve to `UNKNOWN` or `STALE`, never `PASS` or `ASSURED`.
- **Vector State, Not Booleans:** State is modeled as a typed product:
  $$S(e,t) = \langle P, V, A, C, E, L, \tau \rangle$$
  where $P$ is Presence, $V$ is Valence, $A$ is Anti/Conflict, $C$ is Coherence, $E$ is Evidence Status, $L$ is Lifecycle, and $\tau$ is Epoch.
- **Hard Invariants Dominate Scores:** Critical security violations (e.g. root execution or prohibited capability) can never be averaged away by passing scores.
- **Temporal Assurance & Epochs:** Cryptographic binding over subject, policy, implementation, authority, and environment. Any divergence triggers immediate `STALE` transition.
- **Content-Addressed CAS:** Evidence blobs and forensic traces live in content-addressed storage (SHA-256 CAS), never polluting Kubernetes `etcd`.
- **Offline Air-Gap Portability:** Self-contained bundles export and import verifiable evidence packages without public network dependencies.
- **Four Truth Channels:** Differentiates between Telemetry Trace, Execution Trace, Decision Trace, and Evidence Trace.

---

## The Five Kubernetes CRDs

OSKAL extends Kubernetes with five declarative Custom Resource Definitions:

1. **`ControlBinding` (`assurance.ckodex.io/v1alpha1`):**  
   Binds security controls (e.g. NIST SP 800-53 `AC-6`, `SC-7`, `CM-8`) to target workloads and defines the required Evidence Contracts.
2. **`EvidenceContract` (`assurance.ckodex.io/v1alpha1`):**  
   Specifies required evidence types, accepted producers (SPIFFE trust domains), and freshness SLAs.
3. **`AssurancePolicy` (`assurance.ckodex.io/v1alpha1`):**  
   Defines admission gates, evaluation triggers, and strictness policies.
4. **`ControlException` (`assurance.ckodex.io/v1alpha1`):**  
   Encodes authorized, time-bounded derogations with explicit justifications and compensating controls (never permanent).
5. **`AssuranceState` (`assurance.ckodex.io/v1alpha1`):**  
   Emits the live, continuous assurance vector, evidence root, and per-control status directly into the cluster.

---

## Quickstart

### 1. Build Binaries

```bash
git clone https://github.com/ckodex-labs/ckodex-oskal.git
cd ckodex-oskal

# Build oskal CLI and oskal-controller
make build
```

The binaries are placed in `./bin/`:
- `./bin/oskal` (CLI utility)
- `./bin/oskal-controller` (Kubernetes controller manager)

### 2. Run Local Verification

```bash
# Run all unit, property, and contract tests with race detection
make test

# Run linter
make lint
```

### 3. Evaluate Workload Assurance via CLI

```bash
# Inspect continuous assurance state
./bin/oskal assurance state --help

# Explain why a claim is assured, unknown, or failing
./bin/oskal assurance explain --help

# Export live evaluations to NIST OSCAL v1.2.3 Assessment Results
./bin/oskal export assessment-results --help
```

### 4. Deploy Controller to Kubernetes

Install the Custom Resource Definitions:

```bash
kubectl apply -f config/crd/bases/
```

Run the controller manager against your active cluster:

```bash
./bin/oskal-controller
```

---

## OSCAL v1.2.3 Export

OSKAL projects live Kubernetes evaluations into official NIST OSCAL v1.2.3 JSON artifacts:

| Document | CLI Command | Output Artifact |
| -------- | ----------- | --------------- |
| Assessment Results | `oskal export assessment-results` | `assessment-results.json` |
| Component Definition | `oskal export component-definition` | `component-definition.json` |
| System Security Plan | `oskal export ssp` | `system-security-plan.json` |
| Assessment Plan | `oskal export assessment-plan` | `assessment-plan.json` |
| Plan of Action & Milestones | `oskal export poam` | `plan-of-action-and-milestones.json` |

Every projected assertion retains content-addressed back-matter references linking directly to the cryptographic evidence digest and Ed25519 evaluation receipt.

---

## Air-Gap Bundle Export & Import

For air-gapped or disconnected environments, OSKAL packages full evaluations, receipts, envelopes, and content-addressed blobs into portable, tamper-evident packages:

```go
// Export offline package
bundle, data, err := airgap.ExportBundle(ctx, subjectRef, evaluations, receipts, envelopes, casRepo)

// Import and cryptographically verify on an isolated system
importedBundle, err := airgap.ImportBundle(ctx, data, targetRepo, receiptSigner)
```

Any modification to evaluations, receipts, metadata, or blobs triggers manifest verification failure.

---

## Repository Structure

```text
ckodex-oskal/
|-- api/assurance/v1alpha1/      # Kubernetes CRD Go types & deepcopy functions
|-- cmd/
|   |-- oskal/                   # oskal CLI (eval, explain, export, serve)
|   \-- oskal-controller/        # Kubernetes Controller Manager entrypoint
|-- config/                      # Kustomize, CRD schemas, RBAC manifests
|-- core/assurance/              # Pure Semantic Kernel (100% Go stdlib only)
|-- dagger/                      # Native Dagger Go SDK CI/CD pipeline
|-- docs/                        # Architecture specs & ADRs
|   |-- adr/                     # Architectural Decision Records (ADR-001 to ADR-005)
|   \-- architecture/            # CKX-OSKAL-001 specification
|-- examples/                    # Sample workloads and OSCAL definitions
|-- internal/
|   |-- adapters/
|   |   |-- airgap/              # Offline Air-Gap bundle exporter/importer
|   |   |-- cel/                 # Common Expression Language admission engine
|   |   |-- cilium/              # Network security policy observer
|   |   |-- kubernetes/          # Workload subject discovery & control resolver
|   |   |-- openreports/         # Vulnerability scanner report adapter
|   |   |-- shield/              # AI-BOM & model integrity observer
|   |   |-- sigstore/            # OCI signature & provenance verifier
|   |   |-- spire/               # SPIFFE/SPIRE workload attestation & SVID validator
|   |   |-- storage/             # Content-addressed storage (CAS) & state repo
|   |   |-- tetragon/            # eBPF runtime process & capability observer
|   |   \-- webhook/             # Kubernetes Validating Admission Webhook
|   |-- application/
|   |   |-- explain/             # Evidence explainability engine
|   |   \-- reconcile/           # ControlBinding & AssuranceState controllers
|   |-- ports/                   # Hexagonal architecture port interfaces
|   |-- projection/oscal/        # NIST OSCAL v1.2.3 JSON projector
|   |-- receipts/                # Ed25519 receipt signing & Merkle root generator
|   |-- service/                 # gRPC AssuranceService daemon
|   \-- telemetry/               # Prometheus metrics & OpenTelemetry tracers
|-- pkg/oskal/                   # In-process public Go SDK client
|-- proto/assurance/             # Canonical gRPC & Protobuf schemas
\-- tests/
    |-- contract/                # Conformance vector test suites
    \-- integration/             # End-to-end integration test harnesses
```

---

## Verification & Hardware Validation

This repository is continuously validated on:
- **macOS** (Apple Silicon)
- **Linux Physical Host** (`Ubuntu 24.04.1 LTS`, Kernel `7.0.0-34-generic`, bare-metal Kind cluster `ckodex-dev`)

All tests execute with race detection enabled (`-race`) and maintain zero linter issues (`golangci-lint run ./...`).

---

## Community & Security

- **Contributing:** Please read [CONTRIBUTING.md](CONTRIBUTING.md) for architectural invariants and commit standards.
- **Security:** To report security vulnerabilities, see [SECURITY.md](SECURITY.md).

---

## License

Copyright (c) 2026 CKODEX Labs.  
Licensed under the Apache License, Version 2.0 (the "License"). You may obtain a copy of the License at [LICENSE](LICENSE).
