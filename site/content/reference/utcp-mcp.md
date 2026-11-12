---
title: "UTCP v1.0.1 & MCP Reference"
description: "Universal Tool Calling Protocol (UTCP v1.0.1) discovery, call templates, Model Context Protocol (MCP) bridge, and pkg/utcp SDK reference."
quadrant: "reference"
tier: "E5"
invariant: "CapabilityLease governs every agentic tool invocation (ADR-006)"
---

## 1. Protocol Architecture

OSKAL implements the Universal Tool Calling Protocol (**UTCP v1.0.1**, `utcp_version: "1.0.1"`) natively alongside the stdio Model Context Protocol (`oskal mcp`). Every tool invocation inside a workcell is bounded by a `CapabilityLease` and emits a SHA-256 `ExecutionReceipt` chained by `prevReceiptHash`.

- **Zero WebSocket policy**: `websocket` and `ws` transports are rejected (`ANTI_WEBSOCKET_FORBIDDEN`). Only `cli`, `http`, `grpc`, `mcp`, and `text` call templates are admitted.
- **Built-in manual protection**: The reserved built-in `oskal` manual cannot be overwritten by runtime registration.

---

## 2. UTCP Ecosystem Compatibility

The OSKAL UTCP adapter and `oskal utcp sdk-config` command generate drop-in provider configurations and client snippets for all six UTCP ecosystem repositories:

| Integration | Repository | Support |
| :--- | :--- | :--- |
| Specification | `utcp-specification` (`v1.0.1`) | Manual schema validation, call templates, auth/variable checks |
| MCP Bridge | `utcp-mcp` | 17 tools served over stdio JSON-RPC 2.0 via `oskal mcp` |
| Go SDK | `go-utcp` | Native HTTP, CLI, and gRPC provider configs + `pkg/utcp` client |
| Rust SDK | `rs-utcp` | Generated `UtcpClientConfig` and `HttpProvider` snippet |
| TypeScript SDK | `typescript-utcp` | Generated `UtcpClient` provider config and call snippet |
| Python SDK | `python-utcp` | Generated `UtcpClient` provider config and call snippet |

Generate configurations with:

```bash
oskal utcp sdk-config --lang all --base-url http://localhost:8090 --binary oskal
```

---

## 3. Call Transports & HTTP Endpoints

### Supported Transports

- **CLI**: `oskal utcp call <tool-name> --args '<json>'` (or `oskal call <tool-name>` / `oskal list-tools`)
- **HTTP**: `oskal utcp serve --addr :8090 --base-url http://localhost:8090`
- **gRPC**: `oskal serve --port 9090`
- **MCP (stdio)**: `oskal mcp`

### HTTP Discovery & Execution Routes (`oskal utcp serve`)

| Method & Path | Purpose |
| :--- | :--- |
| `GET /utcp` | Serve the canonical UTCP v1.0.1 manual JSON |
| `GET /.well-known/utcp.json` | Standard well-known UTCP discovery document |
| `GET /tools` | List all registered UTCP tools |
| `GET` or `POST /tools/search` | Search tools by query keyword, tags, and limit |
| `POST /tools/call` | Invoke a registered tool with JSON arguments |
| `GET /healthz` | Readiness/liveness probe returning `ok` |

---

## 4. Registered Tools & Required Capabilities

### Core OSKAL Assurance Tools (8 UTCP Tools)

| Tool Name | Required Inputs | Optional Inputs | `required_capability` |
| :--- | :--- | :--- | :--- |
| `get_assurance_state` | `subject` | - | `tool:read-evidence` |
| `explain_claim` | `subject` | `control` | `tool:read-evidence` |
| `detect_drift` | `subject` | - | `tool:read-evidence` |
| `inspect_subject` | `subject` | `control` | `tool:read-evidence` |
| `project_oscal` | `subject`, `document_type` | - | `tool:read-evidence` |
| `validate_oscal` | `content` | `schema` | `tool:validate-oscal` |
| `scaffold_compliance` | `profile` | `workload`, `namespace` | `tool:scaffold-policy` |
| `run_doctor` | - | - | `tool:query-metrics` |

### Additional `utcp-mcp` Bridge Tools (9 Tools, 17 Total on `oskal mcp`)

When running `oskal mcp`, OSKAL exposes the 8 assurance tools above plus 9 UTCP registry and bridge tools:
- `utcp_get_manual`: Emit the active UTCP v1.0.1 manual.
- `search_tools`: Search registered tools by keyword and tags.
- `list_tools`: Enumerate all registered UTCP tools.
- `call_tool`: Invoke a registered UTCP tool by name and arguments.
- `register_manual`: Register an inline UTCP manual under a provider name.
- `deregister_manual`: Remove a registered custom manual.
- `register_tool_provider`: Register an external `http`, `cli`, `grpc`, `mcp`, or `text` provider.
- `get_required_keys_for_tool`: Inspect required input keys and variables for a tool.
- `tool_info`: Retrieve full schema and call template metadata for a tool.

---

## 5. Public Go SDK (`pkg/utcp`)

```go
import "github.com/ckodex-labs/ckodex-oskal/pkg/utcp"
```

### Manual & Configuration Functions

```go
func DefaultManualOptions() ManualOptions
func BuildOSKALManual(opts ManualOptions) UTCPManual
func ValidateManual(manual UTCPManual) error
func GenerateSDKConfigs(baseURL, binaryPath string) []SDKBundle
func WithLease(ctx context.Context, leaseID, prevReceiptHash string) context.Context
```

### Client & Governed Execution

```go
func NewClient(evidenceDir string) (*Client, error)
func NewGovernedClient(evidenceDir string, broker *workcell.EffectBroker) (*Client, error)

func (c *Client) ListTools() []Tool
func (c *Client) SearchTools(query string, tags []string, limit int) []Tool
func (c *Client) GetTool(toolName string) (Tool, bool)
func (c *Client) RequiredVariablesForTool(toolName string) ([]string, error)
func (c *Client) CallTool(ctx context.Context, toolName string, args map[string]interface{}) (*ToolCallResult, error)
func (c *Client) CallToolGoverned(ctx context.Context, toolName string, args map[string]interface{}, leaseID, prevReceiptHash string) (*ToolCallResult, error)
func (c *Client) RegisterManual(name string, manual UTCPManual) error
func (c *Client) RegisterManualGoverned(ctx context.Context, name string, manual UTCPManual, leaseID, prevReceiptHash string) error
func (c *Client) DeregisterManual(ctx context.Context, name, leaseID, prevReceiptHash string) error
func (c *Client) RegisterToolProvider(ctx context.Context, cfg ProviderConfig) error
func (c *Client) DeregisterToolProvider(name string)
func (c *Client) HTTPHandler(baseURL string) http.Handler
```
