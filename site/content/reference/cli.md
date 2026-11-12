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

- `--server <host:port>`: Target address of the gRPC `AssuranceService` daemon (e.g. `localhost:9090`).
- `--tls-ca-file <path>`: Optional path to TLS CA certificate for gRPC client connections.
- `--evidence-dir <path>`: Path to directory containing local `EvidenceEnvelope` JSON files for offline evaluation.
- `--config <path>`: Path to OSKAL configuration file (default: `.oskal.yaml`).
- `-v, --version`: Print OSKAL CLI version.
- `-h, --help`: Display help information for any command.

---

## COMMAND SUMMARY

| Command | Subcommands | Purpose |
| :--- | :--- | :--- |
| `oskal assurance` | `state`, `explain`, `evidence`, `drift`, `receipt verify` | Continuous assurance evaluation and explainability |
| `oskal record` | `admission` | Record evaluation evidence from workload manifests |
| `oskal export` | `assessment-results`, `component-definition`, `assessment-plan`, `ssp`, `poam` | Export to NIST OSCAL v1.2.3 JSON models |
| `oskal import` | `oscal` | Import OSCAL Component Definition or SSP into Kubernetes CRDs |
| `oskal validate` | (standalone) | Validate OSCAL documents against NIST v1.2.3 schemas |
| `oskal scaffold` | `<profile>` (`nist-sp-800-53`, `pci-dss`, `soc-2`, `iso-27001`) | Generate baseline compliance and policy CRDs |
| `oskal doctor` | (standalone) | Preflight diagnostics and environment verification |
| `oskal inspect` | (standalone) | Four-channel truth inspection for a subject |
| `oskal cockpit` | (standalone) | Interactive ASCII monitoring console |
| `oskal mcp` | (standalone) | Model Context Protocol (MCP) stdio JSON-RPC 2.0 server |
| `oskal utcp` | `manual`, `validate`, `search`, `list-tools`, `call`, `serve`, `sdk-config` | Universal Tool Calling Protocol (UTCP v1.0.1) discovery and execution |
| `oskal list-tools` | (standalone) | Top-level shortcut to list all registered OSKAL UTCP tools |
| `oskal call` | (standalone) | Top-level shortcut to invoke an OSKAL UTCP tool directly |
| `oskal serve` | (standalone) | Start the gRPC `AssuranceService` daemon |
| `oskal webhook` | (standalone) | Run the Kubernetes Validating Admission Webhook |
| `oskal config` | `init`, `view` | Manage `.oskal.yaml` configuration |
| `oskal prune` | (standalone) | Prune expired CAS evidence envelopes |
| `oskal version` | (standalone) | Print OSKAL CLI version and build metadata |

---

## COMMAND DETAILS

### `oskal assurance state`

Queries the active continuous assurance state for a specific Kubernetes subject.

```bash
oskal assurance state [<subject-uri>] [flags]
```

#### Flags:
- `--subject-kind <kind>`: Kubernetes resource kind (e.g. `Deployment`, `Pod`).
- `--subject-name <name>`: Workload name.
- `--subject-namespace <namespace>`: Kubernetes namespace (default: `default`).

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
oskal assurance explain [<subject-uri>] [flags]
```

#### Flags:
- `--subject-kind <kind>`, `--subject-name <name>`, `--subject-namespace <namespace>`
- `--control <id>`: Target control to explain (default: `nist-sp-800-53:AC-6`).

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
oskal assurance evidence [<subject-uri>] [flags]
```

#### Flags:
- `--subject-kind <kind>`, `--subject-name <name>`, `--subject-namespace <namespace>`

---

### `oskal assurance drift`

Detects semantic drift between observed runtime state and the recorded `AssuranceEpoch`.

```bash
oskal assurance drift [<subject-uri>] [flags]
```

#### Flags:
- `--subject-kind <kind>`, `--subject-name <name>`, `--subject-namespace <namespace>`

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
- `--receipt-id <id>`: ID of the receipt to verify against the active evidence repository.
- `--receipt-file <path>`: Path to a raw `ControlReceipt` JSON file.
- `--public-key <hex-or-file>`: Ed25519 public key hex string or path to a `.pub` file.

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
- `--file <path>`: Path to Kubernetes workload YAML manifest.
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
- `-f, --file <path>`: Path to OSCAL JSON or YAML document (use `-` for stdin).
- `-n, --namespace <ns>`: Target Kubernetes namespace for generated CRDs (default: `default`).
- `-o, --output-dir <dir>`: Target directory to write generated CRD manifests (defaults to stdout).

---

### `oskal validate`

Validates NIST OSCAL v1.2.3 documents (JSON or YAML) with sub-millisecond embedded schema checking and exact JSON path error diagnostics.

```bash
oskal validate <file-path-or-dash> [flags]
```

#### Flags:
- `--output <table|json|yaml>`: Output format (default: `table`).
- `--schema <auto|assessment-results|component-definition|ssp|assessment-plan|poam>`: Schema override (default: `auto`).

#### Example:
```bash
oskal validate examples/oscal-component-definition.json
```

---

### `oskal scaffold`

Scaffolds compliance artifacts (`EvidenceContract`, `ControlBinding`, admission policy ConfigMap, and OSCAL Component Definition) for a baseline profile.

```bash
oskal scaffold [profile] [flags]
```

#### Supported Profiles:
- `nist-sp-800-53`
- `pci-dss`
- `soc-2`
- `iso-27001`

#### Flags:
- `--workload <name>`: Target Kubernetes workload name (default: `example-app`).
- `-n, --namespace <ns>`: Target Kubernetes namespace (default: `default`).
- `-o, --output-dir <dir>`: Directory to output scaffolded files (if omitted, prints YAML to stdout).
- `--output <yaml|json>`: Output format (default: `yaml`).

---

### `oskal doctor`

Runs deep preflight diagnostics covering Kubernetes connectivity, SPIFFE/SPIRE Workload API socket, Sigstore trust root, local CAS evidence directory, and embedded NIST OSCAL v1.2.3 schemas.

```bash
oskal doctor [flags]
```

#### Flags:
- `--output <table|json|yaml>`: Output format (default: `table`).

---

### `oskal inspect`

Reconstructs the four truth channels (Telemetry trace, Execution trace, Decision trace, Evidence trace) for a governed workload subject.

```bash
oskal inspect <subject-uri> [flags]
```

#### Flags:
- `--control <id>`: Control to inspect (default: `nist-sp-800-53:AC-6`).
- `--output <table|tree|json|yaml>`: Output format (default: `table`).

---

### `oskal cockpit`

Displays a pure-ASCII terminal cockpit dashboard of workload vector states, Merkle roots, drift alerts, and reconciliation loops.

```bash
oskal cockpit [flags]
```

#### Flags:
- `--once`: Render a single frame and exit (ideal for CI and scripts).
- `--refresh <duration>`: Dashboard refresh interval (default: `2s`).
- `--subject <uri>`: Filter dashboard to a specific workload subject.

---

### `oskal mcp`

Starts the Model Context Protocol (MCP) JSON-RPC 2.0 daemon over standard I/O, exposing 17 governed tools (8 OSKAL continuous assurance tools and 9 UTCP registry/bridge tools). See [UTCP v1.0.1 & MCP Reference](../utcp-mcp/).

```bash
oskal mcp
```

---

### `oskal utcp`

Universal Tool Calling Protocol (UTCP v1.0.1) manual export, validation, discovery, execution, HTTP serving, and multi-SDK configuration generation.

#### Subcommands:
- `oskal utcp manual [--transport <cli|http|grpc|mcp>] [--output <json|yaml>] [--base-url <url>] [--binary <path>] [--grpc-addr <host:port>]`: Export the OSKAL UTCP v1.0.1 manual.
- `oskal utcp validate <manual-file>`: Validate a UTCP manual against `utcp-specification` v1.0.1 and CKODEX invariants.
- `oskal utcp search [query] [--tag <tag>] [--limit <int>]`: Search OSKAL UTCP tools by keyword and tag.
- `oskal utcp list-tools`: List all registered OSKAL UTCP tools (also available as `oskal list-tools`).
- `oskal utcp call [<provider-name>] <tool-name> [--args <json>]`: Invoke an OSKAL UTCP tool directly (also available as `oskal call`).
- `oskal utcp serve [--addr <addr>] [--base-url <url>]`: Start native UTCP HTTP discovery (`GET /utcp`, `GET /.well-known/utcp.json`) and tool execution (`POST /tools/call`) server (default `--addr`: `:8090`).
- `oskal utcp sdk-config [--lang <all|go|rust|typescript|python|utcp-mcp>] [--base-url <url>] [--binary <path>]`: Generate UTCP provider configs and client snippets across Go, Rust, TypeScript, Python, and `utcp-mcp`.

---

### `oskal serve`

Starts the gRPC `AssuranceService` daemon hosting continuous evaluation loops and evidence stores.

```bash
oskal serve [flags]
```

#### Flags:
- `--port <int>`: Port for gRPC service to listen on (default: `9090`).
- `--tls-cert-file <path>`: Optional path to TLS server certificate PEM file.
- `--tls-key-file <path>`: Optional path to TLS server private key PEM file.

---

### `oskal webhook`

Starts the Kubernetes Validating Admission Webhook server with in-flight attestation.

```bash
oskal webhook [flags]
```

#### Flags:
- `--listen <addr>`: Address and port for webhook HTTPS server (default: `:8443`).
- `--mode <enforcing|audit|warn>`: Webhook enforcement mode (default: `enforcing`).
- `--evidence-dir <path>`: Directory to record admitted in-flight evidence envelopes.
- `--namespace <ns>`: Kubernetes Namespace for TLS SANs (default: `ckodex-system`).
- `--service-name <name>`: Kubernetes Service name for TLS SANs (default: `oskal-webhook`).
- `--self-signed`: Generate self-signed TLS certificate if files are not provided (default: `true`).
- `--tls-cert-file <path>`: Path to TLS certificate file.
- `--tls-key-file <path>`: Path to TLS private key file.

---

### `oskal config`

Manages persistent `.oskal.yaml` configuration.

#### Subcommands:
- `oskal config init [path]`: Initializes a default `.oskal.yaml` configuration file.
- `oskal config view`: Prints the active OSKAL configuration and source file path.

---

### `oskal prune`

Enforces bounded retention on the local Content-Addressable Storage (CAS) directory by removing expired evidence envelopes.

```bash
oskal prune [flags]
```

#### Flags:
- `--older-than <duration>`: Retention age threshold (default: `720h0m0s`).
- `--dry-run`: Preview envelopes that would be deleted without removing them.
