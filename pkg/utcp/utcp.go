// Package utcp provides the public Universal Tool Calling Protocol (UTCP v1.0.1)
// client, manual builder, validator, and multi-language SDK configuration generator
// for CKODEX OSKAL, compatible with:
//   - https://github.com/universal-tool-calling-protocol/utcp-specification
//   - https://github.com/universal-tool-calling-protocol/utcp-mcp
//   - https://github.com/universal-tool-calling-protocol/go-utcp
//   - https://github.com/universal-tool-calling-protocol/rs-utcp
//   - https://github.com/universal-tool-calling-protocol/typescript-utcp
//   - https://github.com/universal-tool-calling-protocol/python-utcp
package utcp

import (
	"context"
	"net/http"

	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/utcp"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/workcell"
)

const (
	// UTCPVersion is the supported Universal Tool Calling Protocol specification version.
	UTCPVersion = utcp.UTCPVersion
	// ManualVersion is the default OSKAL UTCP manual schema version.
	ManualVersion = utcp.ManualVersion
)

type (
	UTCPManual     = utcp.UTCPManual
	Info           = utcp.Info
	Tool           = utcp.Tool
	CallTemplate   = utcp.CallTemplate
	CLICommand     = utcp.CLICommand
	AuthConfig     = utcp.AuthConfig
	ProviderConfig = utcp.ProviderConfig
	ManualOptions  = utcp.ManualOptions
	ToolCallResult = utcp.ToolCallResult
	SDKBundle      = utcp.SDKBundle
)

// WithLease attaches a CapabilityLease ID and prior receipt hash to a context for governed UTCP operations.
func WithLease(ctx context.Context, leaseID, prevReceiptHash string) context.Context {
	return utcp.WithLease(ctx, leaseID, prevReceiptHash)
}

// Client is a governed Go UTCP client compatible with go-utcp.
type Client struct {
	registry *utcp.Registry
}

// NewClient initializes a new UTCP Client backed by an optional local CAS evidence directory.
func NewClient(evidenceDir string) (*Client, error) {
	reg, err := utcp.NewRegistry(evidenceDir, nil)
	if err != nil {
		return nil, err
	}
	return &Client{registry: reg}, nil
}

// NewGovernedClient initializes a UTCP Client gated by a CapabilityLease EffectBroker.
func NewGovernedClient(evidenceDir string, broker *workcell.EffectBroker) (*Client, error) {
	reg, err := utcp.NewRegistry(evidenceDir, broker)
	if err != nil {
		return nil, err
	}
	return &Client{registry: reg}, nil
}

// DefaultManualOptions returns the default UTCP manual generation options.
func DefaultManualOptions() ManualOptions {
	return utcp.DefaultManualOptions()
}

// BuildOSKALManual returns the canonical UTCP v1.0.1 manual for OSKAL.
func BuildOSKALManual(opts ManualOptions) UTCPManual {
	return utcp.BuildOSKALManual(opts)
}

// ValidateManual validates a UTCPManual against utcp-specification v1.0.1 and CKODEX invariants.
func ValidateManual(manual UTCPManual) error {
	return utcp.ValidateManual(manual)
}

// RegisterManual registers a UTCPManual in the client's registry.
func (c *Client) RegisterManual(name string, manual UTCPManual) error {
	return c.registry.RegisterManual(name, manual)
}

// RegisterManualGoverned registers a UTCPManual gated by a CapabilityLease ID and prior receipt hash.
func (c *Client) RegisterManualGoverned(ctx context.Context, name string, manual UTCPManual, leaseID, prevReceiptHash string) error {
	return c.registry.RegisterManualWithLease(ctx, name, manual, leaseID, prevReceiptHash)
}

// RegisterToolProvider registers a UTCP tool provider (http, cli, grpc, mcp, text).
func (c *Client) RegisterToolProvider(ctx context.Context, cfg ProviderConfig) error {
	return c.registry.RegisterToolProvider(ctx, cfg)
}

// DeregisterManual removes a registered UTCP manual/provider under optional CapabilityLease governance.
func (c *Client) DeregisterManual(ctx context.Context, name, leaseID, prevReceiptHash string) error {
	return c.registry.DeregisterManual(ctx, name, leaseID, prevReceiptHash)
}

// DeregisterToolProvider removes a registered UTCP tool provider.
func (c *Client) DeregisterToolProvider(name string) {
	c.registry.DeregisterToolProvider(name)
}

// GetTool looks up a registered UTCP tool by exact or namespaced name ("<manual>.<tool>").
func (c *Client) GetTool(toolName string) (Tool, bool) {
	return c.registry.GetTool(toolName)
}

// RequiredVariablesForTool returns required input/auth variables for a registered tool.
func (c *Client) RequiredVariablesForTool(toolName string) ([]string, error) {
	return c.registry.RequiredVariablesForTool(toolName)
}

// ListTools lists all registered UTCP tools.
func (c *Client) ListTools() []Tool {
	return c.registry.ListTools()
}

// SearchTools searches registered UTCP tools by keyword and tags.
func (c *Client) SearchTools(query string, tags []string, limit int) []Tool {
	return c.registry.SearchTools(query, tags, limit)
}

// CallTool invokes a registered UTCP tool directly with optional arguments.
func (c *Client) CallTool(ctx context.Context, toolName string, args map[string]interface{}) (*ToolCallResult, error) {
	return c.registry.CallTool(ctx, toolName, args, "", "")
}

// CallToolGoverned invokes a registered UTCP tool gated by a CapabilityLease ID and prior receipt hash.
func (c *Client) CallToolGoverned(ctx context.Context, toolName string, args map[string]interface{}, leaseID, prevReceiptHash string) (*ToolCallResult, error) {
	return c.registry.CallTool(ctx, toolName, args, leaseID, prevReceiptHash)
}

// HTTPHandler returns an http.Handler serving GET /utcp, GET /.well-known/utcp.json, and POST /tools/call.
func (c *Client) HTTPHandler(baseURL string) http.Handler {
	return utcp.NewHTTPServer(c.registry, baseURL).Handler()
}

// GenerateSDKConfigs generates provider configurations and code snippets for go-utcp, rs-utcp, typescript-utcp, python-utcp, and utcp-mcp.
func GenerateSDKConfigs(baseURL, binaryPath string) []SDKBundle {
	return utcp.GenerateSDKConfigs(baseURL, binaryPath)
}
