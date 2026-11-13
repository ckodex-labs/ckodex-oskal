# CKODEX OSKAL Universal Tool Calling Protocol (UTCP) Architecture

**Status:** Canonical  
**Specification:** UTCP v1.0.1 (`utcp-specification`)  
**Supported Ecosystem:**
- Organization: https://github.com/universal-tool-calling-protocol
- Specification: https://github.com/universal-tool-calling-protocol/utcp-specification
- UTCP-MCP Bridge: https://github.com/universal-tool-calling-protocol/utcp-mcp
- Go SDK: https://github.com/universal-tool-calling-protocol/go-utcp
- Rust SDK: https://github.com/universal-tool-calling-protocol/rs-utcp
- TypeScript SDK: https://github.com/universal-tool-calling-protocol/typescript-utcp
- Python SDK: https://github.com/universal-tool-calling-protocol/python-utcp

---

## 1. Architectural Rationale

In accordance with CKODEX Constitution Section 10 (*"One semantic contract, multiple native backends"*), CKODEX OSKAL supports the **Universal Tool Calling Protocol (UTCP)** as a first-class, zero-wrapper-tax agent discovery and invocation protocol alongside gRPC and MCP.

UTCP allows autonomous agents across Go (`go-utcp`), Rust (`rs-utcp`), TypeScript (`typescript-utcp`), and Python (`python-utcp`) to discover OSKAL's continuous assurance capabilities via a standardized `UTCPManual` (`utcp_version: "1.0.1"`, `manual_version: "1.0.0"`) and invoke tools directly over their native transports (`cli`, `http`, `streamable_http`, `grpc`, `sse`, `mcp`).

---

## 2. Constitutional Governance Invariants

1. **No WebSockets (`ANTI_WEBSOCKET_FORBIDDEN`):**  
   Per CKODEX Constitution Section 10 (*"Do not introduce WebSockets"*), `utcp.ValidateManual` and `utcp.Registry.RegisterToolProvider` strictly reject any UTCP manual or tool provider declaring `websocket` or `ws` in `call_template_type`, `provider_type`, or `allowed_communication_protocols`.
2. **Proof Before / Receipt After (`CapabilityLease` Gating):**  
   `KubernetesBroker.Execute` authenticates each operation, reads the actual lease, and reserves one turn using a Kubernetes resource-version compare-and-swap before invoking an effect. Completion is a distinct `ExecutionReceipt`, persisted only after the callback returns successfully. Registry mutations, external tools, and doctor probes require a broker; a nil broker denies them. Fixed local analysis remains available. See [durable lease execution](../capability-lease-execution.md) for scope, evidence, recovery and fencing limits.
3. **Absence of Evidence is `UNKNOWN` (Invariant I-02):**  
   All UTCP tools (`get_assurance_state`, `explain_claim`, `detect_drift`, `project_oscal`) query the verified Content-Addressable Storage (CAS) repository and return `UNKNOWN` when verified evidence is absent.

---

## 3. CLI & Server Operations

```bash
# 1. Export the canonical UTCP v1.0.1 manual (CLI, HTTP, gRPC, or MCP call templates)
oskal utcp manual --transport cli > examples/utcp-manual.json
oskal utcp manual --transport http --base-url http://localhost:8090

# 2. Validate any UTCP manual against utcp-specification v1.0.1 & CKODEX invariants
oskal utcp validate examples/utcp-manual.json

# 3. Search registered UTCP tools by keyword or tag
oskal utcp search drift --tag decoherence

# 4. Call a UTCP tool directly
oskal utcp call get_assurance_state --args '{"subject":"k8s://prod/payments/Deployment/payments-api"}'

# 5. Serve live UTCP discovery (GET /utcp, GET /.well-known/utcp.json) & native HTTP execution
oskal utcp serve --addr :8090 --base-url http://localhost:8090

# 6. Generate ready-to-use configs and code for go-utcp, rs-utcp, typescript-utcp, python-utcp, and utcp-mcp
oskal utcp sdk-config --lang all
```

---

## 4. `utcp-mcp` Bridge Integration (`oskal mcp`)

`oskal mcp` natively embeds all 9 `utcp-mcp` bridge tools so MCP clients can dynamically discover, search, inspect, register, deregister, and invoke UTCP manuals and tools:
- `utcp_get_manual`
- `search_tools`
- `list_tools`
- `call_tool`
- `register_manual`
- `deregister_manual`
- `register_tool_provider`
- `get_required_keys_for_tool`
- `tool_info`
