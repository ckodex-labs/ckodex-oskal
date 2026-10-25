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
- `--config <path>`: Path to OSKAL configuration file (default: `.oskal.yaml`).
- `-h, --help`: Display help information for any command.

---

## COMMAND SUMMARY

| Command | Subcommands | Purpose |
| :--- | :--- | :--- |
| `oskal assurance` | `state`, `explain`, `evidence`, `drift`, `receipt verify` | Continuous assurance evaluation and explainability |
| `oskal record` | `admission` | Record evaluation evidence from workload manifests |
| `oskal export` | `assessment-results`, `component-definition`, `assessment-plan`, `ssp`, `poam` | Export to NIST OSCAL v1.2.3 JSON models |
| `oskal import` | `oskal` | Import OSCAL component definitions into Kubernetes CRDs |
| `oskal validate` | (standalone) | Validate OSCAL documents against NIST v1.2.3 schemas |
| `oskal scaffold` | `control-binding`, `evidence-contract`, `oscal-component` | Generate boilerplate compliance and policy CRDs |
| `oskal doctor` | (standalone) | Preflight diagnostics and environment verification |
| `oskal inspect` | (standalone) | Four-channel truth inspection for a subject |
| `oskal cockpit` | (standalone) | Interactive ASCII monitoring console |
| `oskal mcp` | (standalone) | Model Context Protocol (MCP) stdio JSON-RPC server |
| `oskal serve` | (standalone) | Start the gRPC AssuranceService daemon |
| `oskal webhook` | (standalone) | Run the Kubernetes Validating Admission Webhook |
| `oskal config` | `init`, `show`, `validate` | Manage `.oskal.yaml` configuration |
| `oskal prune` | (standalone) | Prune expired CAS evidence envelopes |

---

## COMMAND DETAILS

### `oskal assurance state`

Queries the active continuous assurance state for a specific Kubernetes subject.

```bash
oskal assurance state [subject-uri] [flags]
```

#### Flags:
- `--subject-kind <kind>`: Kubernetes resource kind (e.g. `Deployment`, `Pod`).
- `--subject-name <name>`: Workload name.
- `--subject-namespace <namespace>`: Kubernetes namespace (default: `default`).
- `--control <id>`: Filter state by control ID (e.g. `AC-6`).

#### Examples:
```bash
# Using positional subject URI:
oskal assurance state k8s://production/Deployment/payment-service

# Using explicit flags:
oskal assurance state --subject-kind Deployment --subject-name payment-service --subject-namespace production

# Offline against a local evidence directory:
oskal assurance state --evidence-dir ./evidence --subject-name payment-service
```

---

### `oskal assurance explain`

Renders the Section 51 Explain Graph justifying an assurance disposition.

```bash
oskal assurance explain [subject-uri] [flags]
```

#### Flags:
- `--subject-kind <kind>`, `--subject-name <name>`, `--subject-namespace <namespace>`
- `--control <id>`: Control identifier (default: `AC-6`).

#### Output Sections:
1. `SUBJECT` and `CONTROL` specifications.
2. `APPLICABILITY` determination.
3. `ATOMIC REQUIREMENTS` verification status.
4. `IMPLEMENTATIONS` and policy digests.
5. `EVIDENCE` leaf completeness (`N / M required`).
6. `ASSURANCE` disposition (`ASSURED`, `UNKNOWN`, `STALE`, `FAILED`).
7. `EVIDENCE ROOT`: Merkle tree root hash.

---

### `oskal assurance evidence`

Lists verified evidence envelopes collected for a subject.

```bash
oskal assurance evidence [subject-uri] [flags]
```

#### Flags:
- `--subject-kind <kind>`, `--subject-name <name>`, `--subject-namespace <namespace>`

---

### `oskal assurance drift`

Detects semantic drift between observed runtime state and the recorded `AssuranceEpoch`.

```bash
oskal assurance drift [subject-uri] [flags]
```

#### Output:
- Subject status (`IN_SYNC`, `DRIFT_DETECTED`).
- Recorded vs. current policy digests.
- Freshness and epoch invalidation indicators.

---

### `oskal assurance receipt verify`

Verifies an Ed25519 cryptographic `ControlReceipt` and its Merkle evidence root.

```bash
oskal assurance receipt verify [flags]
```

#### Flags:
- `--receipt-id <id>`: Receipt ID to verify against the active evidence repository.
- `--receipt-file <path>`: Path to a raw `ControlReceipt` JSON file.

#### Example:
```bash
oskal assurance receipt verify --receipt-id rcpt-prod-payment-service-AC-6
```

---

### `oskal record admission`

Evaluates a Kubernetes workload YAML manifest and generates an authentic `EvidenceEnvelope` in the target evidence directory.

```bash
oskal record admission --file <path> [flags]
```

#### Flags:
- `--file <path>`: Path to Kubernetes workload YAML manifest (required).
- `--evidence-dir <dir>`: Target directory for evidence envelopes (default: `./evidence`).

#### Example:
```bash
oskal record admission --file examples/sample-workload.yaml --evidence-dir /tmp/evidence
```

---

### `oskal export`

Projects continuous assurance state into official NIST OSCAL v1.2.3 JSON models.

#### Subcommands:
- `oskal export assessment-results [--subject <uri>]`: Export Assessment Results JSON.
- `oskal export component-definition [--component <name>]`: Export Component Definition JSON.
- `oskal export assessment-plan [--subject <uri>]`: Export Assessment Plan JSON.
- `oskal export ssp [--subject <uri>]`: Export System Security Plan JSON.
- `oskal export poam [--subject <uri>]`: Export Plan of Action and Milestones JSON.

#### Example:
```bash
oskal export assessment-results --subject k8s://production/Deployment/payments-api > ar.json
```

---

### `oskal import oscal`

Imports a NIST OSCAL v1.2.3 Component Definition or SSP and transforms it into Kubernetes `ControlBinding` and `EvidenceContract` CRD manifests.

```bash
oskal import oscal --file <path> [flags]
```

#### Flags:
- `--file <path>`: Path to OSCAL JSON document (use `-` for stdin). Required.
- `--namespace <ns>`: Target Kubernetes namespace (default: `ckodex-assurance`).
- `--output-dir <dir>`: Target directory to write CRD YAML files.

---

### `oskal validate`

Validates OSCAL documents against official NIST schemas with zero-tolerance schema conformance.

```bash
oskal validate <file-or-dir> [flags]
```

#### Flags:
- `--output <table|json|yaml>`: Format of validation report (default: `table`).
- `--strict`: Enable strict schema validation mode.

#### Example:
```bash
oskal validate examples/oscal-component-definition.json
```

---

### `oskal scaffold`

Scaffolds compliance artifacts and CRDs.

#### Subcommands:
- `oskal scaffold control-binding --control <id> --subject <uri>`: Generates a Kubernetes `ControlBinding` CRD.
- `oskal scaffold evidence-contract --control <id> --subject <uri>`: Generates an `EvidenceContract` CRD.
- `oskal scaffold oscal-component --name <name> --control <id>`: Generates a starter OSCAL Component Definition JSON.

#### Flags:
- `--output <yaml|json>`: Output format (default: `yaml`).

---

### `oskal doctor`

Runs preflight health checks and diagnostics covering the storage layer, gRPC connectivity, and schema registries (Constitution Section 36 & 37).

```bash
oskal doctor [flags]
```

#### Flags:
- `--output <table|json|yaml>`: Output format (default: `table`).

---

### `oskal inspect`

Performs deep four-channel truth reconstruction (Telemetry, Execution, Decision, Evidence) for a given subject.

```bash
oskal inspect <subject-uri> [flags]
```

#### Flags:
- `--output <table|tree|json|yaml>`: Output format (default: `table`).

---

### `oskal cockpit`

Launches a terminal-based ASCII cockpit dashboard providing real-time assurance tracking, Merkle root verification, and drift alerts.

```bash
oskal cockpit [flags]
```

#### Flags:
- `--refresh <duration>`: Polling interval (default: `2s`).
- `--subject <uri>`: Initial workload subject URI to monitor.

---

### `oskal mcp`

Runs the Model Context Protocol (MCP) JSON-RPC 2.0 daemon over standard I/O for integration with AI agent coding harnesses and IDE extensions.

```bash
oskal mcp
```

---

### `oskal serve`

Starts the gRPC AssuranceService daemon hosting continuous evaluation loops and evidence stores.

```bash
oskal serve [flags]
```

#### Flags:
- `--port <int>`: Port for gRPC service to listen on (default: `9090`).

---

### `oskal webhook`

Starts the Kubernetes Validating Admission Webhook server with in-flight cryptographic attestation.

```bash
oskal webhook [flags]
```

#### Flags:
- `--listen <addr>`: Address to bind webhook HTTPS server (default: `:8443`).
- `--mode <enforce|audit>`: Webhook enforcement mode (default: `enforce`).
- `--evidence-dir <path>`: Local CAS directory for written admission envelopes.
- `--tls-cert <path>`: Path to TLS certificate.
- `--tls-key <path>`: Path to TLS private key.
- `--self-signed`: Generate ephemeral self-signed certificates for local testing.

---

### `oskal config`

Manages the local `.oskal.yaml` configuration file.

#### Subcommands:
- `oskal config init [--force]`: Initializes a default configuration file.
- `oskal config show`: Prints the active resolved configuration.
- `oskal config validate`: Checks the configuration syntax and file paths.

---

### `oskal prune`

Enforces bounded retention on the local Content-Addressable Storage (CAS) directory by removing expired evidence envelopes.

```bash
oskal prune [flags]
```

#### Flags:
- `--older-than <duration>`: Retention age threshold (default: `720h`).
- `--dry-run`: Preview envelopes that would be deleted without deleting them.
