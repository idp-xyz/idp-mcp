// Package server holds the server side of the MCP 2026-07-28 modern protocol as the gateway speaks
// it: JSON-RPC envelopes, error codes and the admission rules every request must pass before any
// authentication, authorization or routing happens.
package server

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ProtocolVersion is the only MCP revision this infrastructure speaks (ADR-0001 D12).
const ProtocolVersion = "2026-07-28"

// _meta envelope keys of a 2026-07-28 request.
const (
	MetaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	MetaClientInfo         = "io.modelcontextprotocol/clientInfo"
	MetaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	MetaServerInfo         = "io.modelcontextprotocol/serverInfo"
)

// HTTP headers of the 2026-07-28 Streamable HTTP transport.
const (
	HeaderProtocolVersion = "MCP-Protocol-Version"
	HeaderMethod          = "Mcp-Method"
	HeaderName            = "Mcp-Name"
)

// JSON-RPC and MCP error codes used by the gateway.
const (
	CodeParseError         = -32700
	CodeInvalidRequest     = -32600
	CodeMethodNotFound     = -32601
	CodeInvalidParams      = -32602
	CodeInternalError      = -32603
	CodeVersionMismatch    = -32020 // header and body name different protocol versions
	CodeUnsupportedVersion = -32022
)

// MaxRequestBody bounds a single JSON-RPC request.
const MaxRequestBody = 4 << 20

// RequestMethods are the 2026-07-28 client-to-server request methods. Requests for these must carry
// a complete _meta envelope; anything else is passed to method dispatch, which answers -32601.
// ping is not among them: 2026-07-28 removed it (SEP-2575), and removed methods answer 404/-32601.
var RequestMethods = map[string]bool{
	"server/discover": true, "tools/list": true, "tools/call": true,
	"resources/list": true, "resources/read": true, "resources/templates/list": true,
	"resources/subscribe": true, "resources/unsubscribe": true,
	"prompts/list": true, "prompts/get": true, "completion/complete": true, "logging/setLevel": true,
	"subscriptions/listen": true, "tasks/get": true, "tasks/list": true, "tasks/cancel": true, "tasks/result": true,
}

// LegacyMethods belong to the pre-2026 stateful handshake and are refused (ADR-0001 D12).
var LegacyMethods = map[string]bool{"initialize": true, "notifications/initialized": true}

// NamedParam is the params field a request repeats in the Mcp-Name header.
var NamedParam = map[string]string{"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}

// Request is a parsed JSON-RPC request. ID is kept raw so it is echoed back byte for byte.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports a request without an id.
func (r *Request) IsNotification() bool { return len(r.ID) == 0 || bytes.Equal(r.ID, []byte("null")) }

// Error is a JSON-RPC error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("jsonrpc %d: %s", e.Code, e.Message) }

// Response is a JSON-RPC response with either Result or Error.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// NullID is the id of a response to a request whose id could not be read.
var NullID = json.RawMessage("null")

// Rejection is an admission failure: the HTTP status plus the JSON-RPC error to return.
type Rejection struct {
	HTTPStatus int
	ID         json.RawMessage
	Err        *Error
}

func reject(status int, id json.RawMessage, code int, msg string, data any) *Rejection {
	if len(id) == 0 {
		id = NullID
	}
	return &Rejection{HTTPStatus: status, ID: id, Err: &Error{Code: code, Message: msg, Data: data}}
}

// validID accepts a JSON string or integer id; anything else is answered with a null id.
func validID(raw json.RawMessage) json.RawMessage {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return nil
	}
	switch x := v.(type) {
	case string:
		return raw
	case json.Number:
		if _, err := x.Int64(); err == nil {
			return raw
		}
	}
	return nil
}

// Admit parses one request body and applies the modern-only admission rules. headerVersion and
// headerMethod are the MCP-Protocol-Version and Mcp-Method header values.
func Admit(body []byte, headerVersion, headerMethod string) (*Request, *Rejection) {
	if len(body) > MaxRequestBody {
		return nil, reject(413, nil, CodeInvalidRequest, "Request body too large", nil)
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return nil, reject(400, nil, CodeInvalidRequest, "JSON-RPC batches are not supported", nil)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return nil, reject(400, nil, CodeParseError, "Parse error", nil)
	}
	var req Request
	if err := json.Unmarshal(trimmed, &req); err != nil || req.JSONRPC != "2.0" {
		return nil, reject(400, validID(raw["id"]), CodeInvalidRequest, "Invalid JSON-RPC request", nil)
	}
	id := validID(req.ID)
	if len(req.ID) > 0 && !bytes.Equal(bytes.TrimSpace(req.ID), []byte("null")) && id == nil {
		return nil, reject(400, nil, CodeInvalidRequest, "id must be a string or an integer", nil)
	}
	req.ID = id
	if headerVersion != ProtocolVersion {
		var requested any
		if headerVersion != "" {
			requested = headerVersion
		}
		return nil, reject(400, id, CodeUnsupportedVersion, "Unsupported protocol version",
			map[string]any{"supported": []string{ProtocolVersion}, "requested": requested})
	}
	if req.Method == "" {
		return nil, reject(400, id, CodeInvalidRequest, "Missing JSON-RPC method", nil)
	}
	if LegacyMethods[req.Method] {
		return nil, reject(404, id, CodeMethodNotFound, "Method not found: "+req.Method, nil)
	}
	if headerMethod != "" && headerMethod != req.Method {
		return nil, reject(400, id, CodeVersionMismatch, "Mcp-Method header does not match the body method", nil)
	}
	if req.IsNotification() || !RequestMethods[req.Method] {
		return &req, nil
	}
	params, rej := objectParams(req.Params, id)
	if rej != nil {
		return nil, rej
	}
	var meta map[string]json.RawMessage
	if m, ok := params["_meta"]; !ok || json.Unmarshal(m, &meta) != nil || meta == nil {
		return nil, reject(400, id, CodeInvalidParams, "params._meta must be an object", nil)
	}
	version, ok := meta[MetaProtocolVersion]
	if !ok {
		return nil, reject(400, id, CodeInvalidParams, "params._meta is missing the required envelope key(s): "+MetaProtocolVersion, nil)
	}
	var v string
	if json.Unmarshal(version, &v) != nil || v != ProtocolVersion {
		return nil, reject(400, id, CodeVersionMismatch, "MCP header/body protocol version mismatch", nil)
	}
	caps, ok := meta[MetaClientCapabilities]
	if !ok {
		return nil, reject(400, id, CodeInvalidParams, "params._meta is missing the required envelope key(s): "+MetaClientCapabilities, nil)
	}
	var capObj map[string]json.RawMessage
	if json.Unmarshal(caps, &capObj) != nil || capObj == nil {
		return nil, reject(400, id, CodeInvalidParams, MetaClientCapabilities+" must be an object", nil)
	}
	if key, named := NamedParam[req.Method]; named {
		// the routing header must repeat the named parameter exactly (2026-07-28 transport)
		var name string
		if json.Unmarshal(params[key], &name) != nil || name == "" {
			return nil, reject(400, id, CodeInvalidParams, "params."+key+" must be a non-empty string", nil)
		}
	}
	return &req, nil
}

func objectParams(raw json.RawMessage, id json.RawMessage) (map[string]json.RawMessage, *Rejection) {
	var params map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &params) != nil || params == nil {
		return nil, reject(400, id, CodeInvalidParams, "params must be an object", nil)
	}
	return params, nil
}

// DecodeParams decodes a request's params into v.
func (r *Request) DecodeParams(v any) error {
	if len(r.Params) == 0 {
		return &Error{Code: CodeInvalidParams, Message: "params must be an object"}
	}
	if err := json.Unmarshal(r.Params, v); err != nil {
		return &Error{Code: CodeInvalidParams, Message: "invalid params"}
	}
	return nil
}

// CheckNameHeader verifies that Mcp-Name repeats the named parameter of the request, if any.
func (r *Request) CheckNameHeader(header string) *Rejection {
	key, named := NamedParam[r.Method]
	if !named {
		return nil
	}
	var params map[string]json.RawMessage
	_ = json.Unmarshal(r.Params, &params)
	var name string
	_ = json.Unmarshal(params[key], &name)
	if header != name {
		return reject(400, r.ID, CodeVersionMismatch, "invalid MCP routing header: "+HeaderName, nil)
	}
	return nil
}
