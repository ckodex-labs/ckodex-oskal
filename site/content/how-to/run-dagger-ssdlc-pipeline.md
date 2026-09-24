---
title: "How to Run the Dagger SSDLC Pipeline"
description: "Execute the reproducible, containerized Dagger SSDLC pipeline with Syft SBOM generation and Grype vulnerability scanning."
quadrant: "how-to"
tier: "E5"
invariant: "Invisible excellence: complex guarantees behind simple operator controls"
---

## Context

OSKAL ships with a containerized Secure Software Development Lifecycle (SSDLC) pipeline authored in Go using the **Dagger v0.21.9 Engine**. The pipeline guarantees reproducible linting, protobuf compatibility checks, test suite execution under race detector, Syft CycloneDX SBOM generation, Grype vulnerability scanning, and static binary compilation.

---

## 1. Inspect Available Dagger Pipeline Functions

From the root of the repository, list all exported Dagger functions:

```bash
dagger functions
```

Output:

```text
Name          Description
all           All executes the complete SSDLC pipeline (Lint, ProtoCheck, Test, Scan, Build, Evidence).
build         Build compiles both static binaries: oskal CLI and oskal-controller.
evidence      Evidence assembles an immutable SSDLC evidence bundle directory.
lint          Lint executes golangci-lint v2 and buf lint on the codebase.
proto-check   ProtoCheck validates protobuf backward-compatibility and linting.
scan          Scan generates a CycloneDX Software Bill of Materials (SBOM) using Syft.
test          Test executes the full continuous assurance test suite with race detector and coverage.
vuln-check    VulnCheck evaluates the generated SBOM with Grype for known vulnerabilities.
```

---

## 2. Execute Code Quality & Lint Checks

Run `golangci-lint` v2 and `buf lint` inside a clean container:

```bash
dagger call lint --source=.
```

The container downloads the pinned golangci-lint image and runs all configured linters against the exact `.golangci.yml` schema, exiting with code 0 if 0 issues are found.

---

## 3. Generate SBOM and Scan with Grype

Generate a CycloneDX 1.5 JSON SBOM:

```bash
dagger call scan --source=. export --path=/tmp/sbom.json
```

Evaluate the generated SBOM with Grype:

```bash
dagger call vuln-check --source=.
```

---

## 4. Run the Complete End-to-End Pipeline

Execute all stages in dependency order and compile static binaries:

```bash
dagger call all --source=.
```

The pipeline finishes by packaging an immutable SSDLC evidence bundle containing the generated SBOM, test reports, SARIF lint outputs, and signed receipts.
