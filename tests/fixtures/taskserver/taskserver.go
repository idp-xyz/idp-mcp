// Package taskserver is a reference MCP server (2026-07-28, stateless) implementing the
// io.modelcontextprotocol/tasks extension (SEP-2663 v2) with the fixtures the official conformance
// suite's tasks scenarios require: greet, slow_compute, failing_job, protocol_error_job,
// confirm_delete and multi_input. It exists because no SDK available here implements the extension
// server-side; the official suite is run against it directly (proving the fixture) and through the
// gateway (proving the gateway). Test double only: in-memory, never expires tasks.
package taskserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	protocolVersion = "2026-07-28"
	extensionID     = "io.modelcontextprotocol/tasks"
	ttlMs           = 600000
	pollIntervalMs  = 100
)

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type task struct {
	id       string
	status   string
	created  time.Time
	updated  time.Time
	result   map[string]any
	err      *rpcError
	inputs   map[string]map[string]any // pending inputRequests
	cancel   chan struct{}
	resume   chan struct{}
	resuming bool
}

// Server holds the tasks.
type Server struct {
	mu    sync.Mutex
	tasks map[string]*task
	n     int
}

// New returns an empty server.
func New() *Server { return &Server{tasks: map[string]*task{}} }

// Handler serves POST /mcp.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", s.serve)
	return mux
}

func iso(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func reply(w http.ResponseWriter, id json.RawMessage, result any) {
	writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func replyErr(w http.ResponseWriter, status int, id json.RawMessage, e rpcError) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	writeJSON(w, status, map[string]any{"jsonrpc": "2.0", "id": id, "error": e})
}

var tools = []map[string]any{
	{"name": "greet", "description": "Says hello.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string"}}}},
	{"name": "slow_compute", "description": "Sleeps `seconds` then answers.", "inputSchema": map[string]any{"type": "object",
		"properties": map[string]any{"seconds": map[string]any{"type": "number"}, "label": map[string]any{"type": "string"}}},
		"execution": map[string]any{"taskSupport": "optional"}},
	{"name": "failing_job", "description": "Always reports a tool execution error.", "inputSchema": map[string]any{"type": "object"},
		"execution": map[string]any{"taskSupport": "required"}},
	{"name": "protocol_error_job", "description": "Fails with a protocol-level error.", "inputSchema": map[string]any{"type": "object"},
		"execution": map[string]any{"taskSupport": "optional"}},
	{"name": "confirm_delete", "description": "Asks for confirmation through elicitation.", "inputSchema": map[string]any{"type": "object"},
		"execution": map[string]any{"taskSupport": "optional"}},
	{"name": "multi_input", "description": "Asks two questions at once.", "inputSchema": map[string]any{"type": "object"},
		"execution": map[string]any{"taskSupport": "optional"}},
}

func elicitation(message string) map[string]any {
	return map[string]any{"method": "elicitation/create", "params": map[string]any{"message": message,
		"requestedSchema": map[string]any{"type": "object", "properties": map[string]any{"confirm": map[string]any{"type": "boolean"}}}}}
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  map[string]any  `json:"params"`
	}
	if json.Unmarshal(body, &req) != nil || req.JSONRPC != "2.0" {
		replyErr(w, 400, nil, rpcError{Code: -32600, Message: "Invalid JSON-RPC request"})
		return
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != protocolVersion {
		replyErr(w, 400, req.ID, rpcError{Code: -32022, Message: "Unsupported protocol version", Data: map[string]any{"supported": []string{protocolVersion}, "requested": v}})
		return
	}
	if h := r.Header.Get("Mcp-Method"); h != "" && h != req.Method {
		replyErr(w, 400, req.ID, rpcError{Code: -32020, Message: "Mcp-Method header does not match the body method"})
		return
	}
	if req.Params == nil {
		req.Params = map[string]any{}
	}
	meta, _ := req.Params["_meta"].(map[string]any)
	caps, _ := meta["io.modelcontextprotocol/clientCapabilities"].(map[string]any)
	exts, _ := caps["extensions"].(map[string]any)
	_, hasTasks := exts[extensionID]
	missing := rpcError{Code: -32021, Message: "Missing required client capability: " + extensionID,
		Data: map[string]any{"requiredCapabilities": map[string]any{"extensions": map[string]any{extensionID: map[string]any{}}}}}
	switch req.Method {
	case "server/discover":
		reply(w, req.ID, map[string]any{"supportedVersions": []string{protocolVersion},
			"capabilities": map[string]any{"tools": map[string]any{"listChanged": false}, "extensions": map[string]any{extensionID: map[string]any{}}},
			"resultType":   "complete", "ttlMs": 0, "cacheScope": "private",
			"_meta": map[string]any{"io.modelcontextprotocol/serverInfo": map[string]any{"name": "idp-mcp-taskserver", "version": "1"}}})
	case "tools/list":
		reply(w, req.ID, map[string]any{"tools": tools, "resultType": "complete", "ttlMs": 0, "cacheScope": "private"})
	case "tools/call":
		s.call(w, r, req.ID, req.Params, hasTasks, missing)
	case "tasks/get", "tasks/cancel", "tasks/update":
		if !hasTasks {
			replyErr(w, 400, req.ID, missing)
			return
		}
		id, _ := req.Params["taskId"].(string)
		if h := r.Header.Get("Mcp-Name"); h != "" && h != id {
			replyErr(w, 400, req.ID, rpcError{Code: -32020, Message: "Mcp-Name header does not match params.taskId"})
			return
		}
		s.taskMethod(w, req.ID, req.Method, id, req.Params)
	default:
		replyErr(w, 404, req.ID, rpcError{Code: -32601, Message: "Method not found: " + req.Method})
	}
}

func text(s string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": s}}, "resultType": "complete"}
}

func (s *Server) call(w http.ResponseWriter, r *http.Request, id json.RawMessage, params map[string]any, hasTasks bool, missing rpcError) {
	name, _ := params["name"].(string)
	args, _ := params["arguments"].(map[string]any)
	if h := r.Header.Get("Mcp-Name"); h != "" && h != name {
		replyErr(w, 400, id, rpcError{Code: -32020, Message: "Mcp-Name header does not match params.name"})
		return
	}
	seconds, _ := args["seconds"].(float64)
	if seconds > 120 {
		seconds = 120
	}
	switch name {
	case "greet":
		who, _ := args["name"].(string)
		if who == "" {
			who = "world"
		}
		reply(w, id, text("Hello, "+who+"!"))
		return
	case "slow_compute", "failing_job", "protocol_error_job", "confirm_delete", "multi_input":
	default:
		replyErr(w, 200, id, rpcError{Code: -32602, Message: "Unknown tool: " + name})
		return
	}
	if !hasTasks {
		// no extension negotiated: optional tools fall through to a synchronous result, a required one is refused
		if name == "failing_job" {
			replyErr(w, 400, id, missing)
			return
		}
		if name == "slow_compute" {
			time.Sleep(time.Duration(seconds * float64(time.Second)))
		}
		reply(w, id, text("sync: "+name))
		return
	}
	t := s.create()
	reply(w, id, map[string]any{"resultType": "task", "taskId": t.id, "status": "working", "createdAt": iso(t.created),
		"lastUpdatedAt": iso(t.updated), "ttlMs": ttlMs, "pollIntervalMs": pollIntervalMs})
	go s.run(t, name, seconds)
}

func (s *Server) create() *task {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	now := time.Now()
	t := &task{id: fmt.Sprintf("task-%d", s.n), status: "working", created: now, updated: now, cancel: make(chan struct{}), resume: make(chan struct{}, 1)}
	s.tasks[t.id] = t // durable before the CreateTaskResult goes out
	return t
}

func (s *Server) settle(t *task, status string, result map[string]any, err *rpcError) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.status == "cancelled" || t.status == "completed" || t.status == "failed" {
		return
	}
	t.status, t.result, t.err, t.inputs, t.updated = status, result, err, nil, time.Now()
}

func (s *Server) run(t *task, name string, seconds float64) {
	switch name {
	case "slow_compute":
		select {
		case <-time.After(time.Duration(seconds * float64(time.Second))):
			s.settle(t, "completed", text(fmt.Sprintf("computed after %gs", seconds)), nil)
		case <-t.cancel:
		}
	case "failing_job":
		select {
		case <-time.After(time.Second):
			res := text("the job failed")
			res["isError"] = true
			s.settle(t, "completed", res, nil)
		case <-t.cancel:
		}
	case "protocol_error_job":
		select {
		case <-time.After(200 * time.Millisecond):
			s.settle(t, "failed", nil, &rpcError{Code: -32603, Message: "Internal error: the job panicked"})
		case <-t.cancel:
		}
	case "confirm_delete", "multi_input":
		s.mu.Lock()
		t.inputs = map[string]map[string]any{t.id + "-q1": elicitation("Delete the item?")}
		if name == "multi_input" {
			t.inputs[t.id+"-q2"] = elicitation("Really?")
		}
		t.status, t.updated = "input_required", time.Now()
		s.mu.Unlock()
		select {
		case <-t.resume:
			s.settle(t, "completed", text("confirmed and done"), nil)
		case <-t.cancel:
		}
	}
}

func (s *Server) taskMethod(w http.ResponseWriter, id json.RawMessage, method, taskID string, params map[string]any) {
	s.mu.Lock()
	t := s.tasks[taskID]
	if t == nil {
		s.mu.Unlock()
		replyErr(w, 200, id, rpcError{Code: -32602, Message: "Unknown task: " + taskID, Data: map[string]string{"taskId": taskID}})
		return
	}
	switch method {
	case "tasks/get":
		out := map[string]any{"resultType": "complete", "taskId": t.id, "status": t.status, "createdAt": iso(t.created),
			"lastUpdatedAt": iso(t.updated), "ttlMs": ttlMs, "pollIntervalMs": pollIntervalMs}
		if t.result != nil {
			out["result"] = t.result
		}
		if t.err != nil {
			out["error"] = t.err
		}
		if len(t.inputs) > 0 {
			out["inputRequests"] = t.inputs
		}
		s.mu.Unlock()
		reply(w, id, out)
	case "tasks/cancel":
		if t.status == "working" || t.status == "input_required" {
			t.status, t.updated, t.inputs = "cancelled", time.Now(), nil
			close(t.cancel)
		}
		s.mu.Unlock()
		reply(w, id, map[string]any{"resultType": "complete"})
	case "tasks/update":
		answers, _ := params["inputResponses"].(map[string]any)
		for k := range answers {
			delete(t.inputs, k)
		}
		t.updated = time.Now()
		if t.status == "input_required" && len(t.inputs) == 0 && !t.resuming {
			t.resuming = true
			t.status = "working"
			t.resume <- struct{}{}
		}
		s.mu.Unlock()
		reply(w, id, map[string]any{"resultType": "complete"})
	}
}

// Strings of the exposed tool names, for tests.
func ToolNames() []string {
	var out []string
	for _, t := range tools {
		out = append(out, t["name"].(string))
	}
	return out
}

var _ = strings.TrimSpace
