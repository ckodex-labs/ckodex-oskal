# Contributing to ckodex-oskal

Thank you for your interest in contributing to **OSKAL** (Kubernetes Continuous Assurance Runtime).

## Core Architectural Invariants

Every contribution MUST adhere to the following non-negotiable principles:

1. **Pure ASCII Invariant**:
   All source code, unit tests, configuration files, documentation, and git commit messages MUST contain 100% pure ASCII characters (0x00 - 0x7F). Emojis and Unicode typographical symbols are strictly prohibited.

2. **Invariant I-02 (Absence of Evidence is UNKNOWN)**:
   Never return synthetic or optimistic passes. If evidence is missing, unverified, expired, or corrupted, the state MUST resolve to `UNKNOWN` or `STALE`, never `PASS` or `ASSURED`.

3. **Pure Semantic Kernel**:
   `core/assurance/` owns deterministic domain semantics and MUST depend only on the Go standard library. External imports (such as Kubernetes client-go, cloud SDKs, or gRPC) are strictly prohibited in the core kernel.

4. **Multi-Dimensional Vector State**:
   Truth is modeled as a typed product vector: Presence, Valence, Anti, Coherence, Evidence, Lifecycle, and Epoch. Do not collapse vector states into simplistic booleans.

5. **Evidence Everywhere**:
   Consequential state changes must be backed by cryptographically verifiable evidence envelopes stored in content-addressed storage (CAS) and signed with Ed25519 receipts.

## Development Workflow

### Prerequisites

- Go 1.24+
- `golangci-lint`
- Docker or Podman
- (Optional) `kind` for local Kubernetes testbed

### Running Checks

```bash
# Build CLI and Controller binaries
make build

# Run all tests with race detector enabled
make test

# Run linter
make lint

# Run full checks (format, lint, test, build)
make all
```

### Commit Messages

Commit messages must follow the Conventional Commits specification in imperative mood using pure ASCII:

```text
feat(core): implement temporal epoch drift detection
fix(webhook): validate non-root execution in init containers
docs(readme): add cli quickstart guide
```

### Pull Request Process

1. Fork and create a topic branch from `develop`.
2. Ensure `make all` passes cleanly without warnings.
3. Verify that your diff contains 100% pure ASCII.
4. Submit your pull request targeting the `develop` branch.
