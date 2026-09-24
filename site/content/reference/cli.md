---
title: "OSKAL CLI Reference"
description: "Comprehensive reference manual for the oskal command-line utility."
quadrant: "reference"
tier: "E5"
invariant: "Invisible excellence: complex guarantees behind simple operator controls"
---

## SYNOPSIS

```text
oskal [global flags] <command> [command flags] [arguments]
```

---

## GLOBAL FLAGS

- `--server <host:port>`: Target address of the gRPC AssuranceService daemon (default: `localhost:9090`).
- `--evidence-dir <path>`: Directory containing authentic local `EvidenceEnvelope` JSON files for offline evaluation.
- `--format <text|json>`: Output format (default: `text`). Pure ASCII only.
- `--verbose`: Enable debug logging.

---

## COMMANDS

### `oskal assurance state`

Queries the active assurance state for a specific Kubernetes subject.

#### Flags:
- `--subject-kind <kind>`: Kubernetes resource kind (e.g. `Deployment`, `Pod`, `Service`). Required.
- `--subject-name <name>`: Workload name. Required.
- `--subject-namespace <namespace>`: Kubernetes namespace (default: `default`).
- `--control <id>`: Filter state by canonical or NIST control ID.

#### Output Fields:
- `STATE`: One of `UNKNOWN`, `OBSERVED`, `VERIFIED`, `ASSURED`, `STALE`, `FAILED`.
- `STATUS`: Explanation of active state (e.g. `Absence of verified evidence`).
- `EVIDENCE`: Count of verified leaf evidence envelopes.
- `MERKLE ROOT`: Hexadecimal SHA-256 Merkle root.

---

### `oskal assurance explain`

Renders the Section 51 Explain Graph for an assurance claim.

#### Flags:
- `--subject-kind <kind>`, `--subject-name <name>`, `--subject-namespace <namespace>`. Required.
- `--control <id>`: Target control identifier. Required.

#### Behavior:
- Renders atomic requirements.
- Lists contributing evidence envelopes, producers, and integrity digests.
- Displays the Ed25519 digital signature of the issuing authority.

---

### `oskal assurance evidence`

Lists and inspects raw cryptographic evidence envelopes associated with a subject.

#### Flags:
- `--subject-kind <kind>`, `--subject-name <name>`, `--subject-namespace <namespace>`. Required.
- `--envelope-id <id>`: Display detailed contents of a single evidence envelope.

---

### `oskal assurance drift`

Analyzes differences between active runtime state, subject generation, and the baseline `AssuranceEpoch`.

#### Output:
- Detects generation increments.
- Identifies container image digest changes.
- Reports policy digest mutations.

---

### `oskal export oscal`

Projects runtime assurance state into official NIST OSCAL 1.2.3 JSON documents.

#### Flags:
- `--model <assessment-results|component-definition|assessment-plan|poam>`: Model type (default: `assessment-results`).
- `--output <path>`: Destination file path.
- `--subject-namespace <namespace>`: Namespace filter.

---

### `oskal serve`

Starts the standalone gRPC AssuranceService daemon and in-memory evaluation engine.

#### Flags:
- `--addr <host:port>`: Listening address (default: `:9090`).
- `--storage <memory|dir>`: Evidence storage driver (default: `memory`).
- `--data-dir <path>`: Directory for persisting evidence envelopes when storage is `dir`.
