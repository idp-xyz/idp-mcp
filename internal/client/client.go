// Package client is the gateway's and the registry's MCP client toward upstream servers (2026-07-28
// modern, stateless Streamable HTTP). Every connection is re-checked against the upstream policy
// at dial time; environment proxies are never used.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"idp-mcp/internal/observability"
	"idp-mcp/internal/policy"
	"idp-mcp/internal/server"
	"idp-mcp/internal/transport"

	"go.opentelemetry.io/otel/propagation"
)

// MaxResponse bounds a buffered upstream response (discovery, catalogs).
const MaxResponse = 4 << 20

// NewHTTPClient returns an http.Client whose connections pass pol.DialControl for the host being
// dialed, follows no redirects and ignores HTTP(S)_PROXY. tlsCfg (optional) carries extra trusted
// CAs for https upstreams on private networks.
func NewHTTPClient(pol *policy.Upstream, timeout time.Duration, tlsCfg ...*tls.Config) *http.Client {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second, Control: pol.DialControl(host)}
			return d.DialContext(ctx, network, addr)
		},
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		DisableCompression:    true,
	}
	if len(tlsCfg) > 0 && tlsCfg[0] != nil {
		tr.TLSClientConfig = tlsCfg[0].Clone()
	}
	return &http.Client{Transport: tr, Timeout: 0, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// Client sends MCP requests to upstream servers.
type Client struct {
	HTTP *http.Client
	Info server.ServerInfo // clientInfo sent in _meta
}

// Meta is the _meta envelope this client sends.
func (c *Client) Meta() map[string]any {
	return map[string]any{
		server.MetaProtocolVersion:    server.ProtocolVersion,
		server.MetaClientInfo:         c.Info,
		server.MetaClientCapabilities: map[string]any{},
	}
}

// Headers returns the request headers for method, including Mcp-Name for named requests.
func Headers(method, name string) http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json, text/event-stream")
	h.Set(server.HeaderProtocolVersion, server.ProtocolVersion)
	h.Set(server.HeaderMethod, method)
	if name != "" {
		h.Set(server.HeaderName, name)
	}
	return h
}

// RPCError is a JSON-RPC error answered by the upstream.
type RPCError struct{ RPC *server.Error }

func (e *RPCError) Error() string { return e.RPC.Error() }

// Call sends one request and returns its result object.
func (c *Client) Call(ctx context.Context, endpoint, method string, params map[string]any) (json.RawMessage, error) {
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = c.Meta()
	name := ""
	if key, ok := server.NamedParam[method]; ok {
		name, _ = params[key].(string)
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = Headers(method, name)
	observability.Propagator.Inject(ctx, propagation.HeaderCarrier(req.Header))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, err := transport.ReadBounded(resp.Body, MaxResponse)
	if err != nil {
		return nil, fmt.Errorf("upstream response: %w", err)
	}
	msg, err := transport.ParseMessage(resp.Header.Get("Content-Type"), raw)
	if err != nil {
		return nil, fmt.Errorf("upstream %s HTTP %d: %w", method, resp.StatusCode, err)
	}
	var out struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   *server.Error   `json:"error"`
	}
	if err := json.Unmarshal(msg, &out); err != nil || out.JSONRPC != "2.0" || string(out.ID) != "1" {
		return nil, errors.New("malformed JSON-RPC response")
	}
	if out.Error != nil {
		return nil, &RPCError{RPC: out.Error}
	}
	if resp.StatusCode != http.StatusOK || len(out.Result) == 0 || out.Result[0] != '{' {
		return nil, fmt.Errorf("upstream %s HTTP %d without a result object", method, resp.StatusCode)
	}
	return out.Result, nil
}

// Discovery is what server/discover reports.
type Discovery struct {
	SupportedVersions []string        `json:"supportedVersions"`
	Capabilities      map[string]any  `json:"capabilities"`
	ResultType        string          `json:"resultType"`
	Meta              json.RawMessage `json:"_meta"`
}

// ServerInfo extracts the upstream's serverInfo from discovery _meta.
func (d *Discovery) ServerInfo() map[string]any {
	var meta map[string]map[string]any
	_ = json.Unmarshal(d.Meta, &meta)
	return meta[server.MetaServerInfo]
}

// Discover calls server/discover and requires a strictly modern server that offers tools.
func (c *Client) Discover(ctx context.Context, endpoint string) (*Discovery, error) {
	raw, err := c.Call(ctx, endpoint, "server/discover", nil)
	if err != nil {
		return nil, err
	}
	var d Discovery
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, errors.New("malformed discovery result")
	}
	if len(d.SupportedVersions) != 1 || d.SupportedVersions[0] != server.ProtocolVersion {
		return nil, fmt.Errorf("server is not strictly %s modern-only (supports %v)", server.ProtocolVersion, d.SupportedVersions)
	}
	if d.ResultType != "complete" && d.ResultType != "partial" {
		return nil, errors.New("discovery result has no resultType")
	}
	if _, ok := d.Capabilities["tools"]; !ok {
		return nil, errors.New("server does not offer tools")
	}
	return &d, nil
}

// List pages through a list method (tools/list, prompts/list, resources/list, ...) and returns the
// raw entries of field.
func (c *Client) List(ctx context.Context, endpoint, method, field string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	cursor := ""
	for page := 0; page < 20; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, err := c.Call(ctx, endpoint, method, params)
		if err != nil {
			return nil, err
		}
		var res map[string]json.RawMessage
		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, errors.New(method + " result is not an object")
		}
		var items []json.RawMessage
		if err := json.Unmarshal(res[field], &items); err != nil || items == nil {
			return nil, fmt.Errorf("%s result has no %s array", method, field)
		}
		all = append(all, items...)
		if len(all) > 5000 {
			return nil, fmt.Errorf("%s returned too many entries", method)
		}
		var next string
		_ = json.Unmarshal(res["nextCursor"], &next)
		if next == "" {
			return all, nil
		}
		cursor = next
	}
	return nil, fmt.Errorf("%s pagination exceeds 20 pages", method)
}

// ListTools pages through tools/list and returns the raw tool entries.
func (c *Client) ListTools(ctx context.Context, endpoint string) ([]json.RawMessage, error) {
	all, err := c.List(ctx, endpoint, "tools/list", "tools")
	if err == nil && len(all) > 500 {
		return nil, errors.New("too many tools")
	}
	return all, err
}

// ListPrompts pages through prompts/list.
func (c *Client) ListPrompts(ctx context.Context, endpoint string) ([]json.RawMessage, error) {
	return c.List(ctx, endpoint, "prompts/list", "prompts")
}

// Redact strips anything but scheme, host and path from an endpoint for logs and errors.
func Redact(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "<invalid>"
	}
	return u.Scheme + "://" + u.Host + u.Path
}
