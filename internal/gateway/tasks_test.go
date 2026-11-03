package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"idp-mcp/adapters/identity"
	"idp-mcp/internal/federation"
	"idp-mcp/internal/invocation"
	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
)

// tasksUpstream implements the tasks extension: `echo` is sync, `slow` creates a task.
type tasksUpstream struct {
	srv    *httptest.Server
	mu     sync.Mutex
	seen   []string // "<method> <Mcp-Name>"
	sse    bool
	ttlMs  int64
	n      int
	tasks  map[string]bool
	events chan string
}

const tasksToolsJSON = `[{"name":"echo","inputSchema":{"type":"object"}},{"name":"slow","inputSchema":{"type":"object"},"execution":{"taskSupport":"optional"}}]`

func newTasksUpstream(t *testing.T) *tasksUpstream {
	u := &tasksUpstream{ttlMs: 60000, tasks: map[string]bool{}, events: make(chan string, 16)}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params map[string]any  `json:"params"`
		}
		_ = json.Unmarshal(raw, &req)
		u.mu.Lock()
		u.seen = append(u.seen, req.Method+" "+r.Header.Get(server.HeaderName))
		u.mu.Unlock()
		id := string(req.ID)
		res := func(s string) {
			msg := `{"jsonrpc":"2.0","id":` + id + `,"result":` + s + `}`
			if u.sse {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\nevent: message\ndata: "+msg+"\n\n")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, msg)
		}
		rpcErr := func(code int, m string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+id+`,"error":{"code":`+fmt.Sprint(code)+`,"message":"`+m+`"}}`)
		}
		taskID, _ := req.Params["taskId"].(string)
		switch req.Method {
		case "tools/list":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+id+`,"result":{"tools":`+tasksToolsJSON+`}}`)
		case "tools/call":
			if req.Params["name"] == "slow" {
				u.mu.Lock()
				u.n++
				tid := fmt.Sprintf("task-%d", u.n)
				u.tasks[tid] = true
				u.mu.Unlock()
				res(fmt.Sprintf(`{"resultType":"task","taskId":%q,"status":"working","createdAt":"2026-11-03T00:00:00Z","lastUpdatedAt":"2026-11-03T00:00:00Z","ttlMs":%d,"pollIntervalMs":500}`, tid, u.ttlMs))
				return
			}
			res(`{"content":[{"type":"text","text":"sync"}],"resultType":"complete"}`)
		case "tasks/get":
			u.mu.Lock()
			known := u.tasks[taskID]
			u.mu.Unlock()
			if !known {
				rpcErr(-32602, "unknown task")
				return
			}
			res(fmt.Sprintf(`{"resultType":"complete","taskId":%q,"status":"completed","createdAt":"2026-11-03T00:00:00Z","lastUpdatedAt":"2026-11-03T00:00:01Z","ttlMs":%d,"result":{"content":[{"type":"text","text":"done"}]}}`, taskID, u.ttlMs))
		case "tasks/cancel":
			u.mu.Lock()
			known := u.tasks[taskID]
			u.mu.Unlock()
			if !known {
				rpcErr(-32602, "unknown task")
				return
			}
			res(`{"resultType":"complete"}`)
		case "subscriptions/listen":
			w.Header().Set("Content-Type", "text/event-stream")
			flush := func(s string) { _, _ = io.WriteString(w, "event: message\ndata: "+s+"\n\n"); w.(http.Flusher).Flush() }
			flush(`{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"notifications":{},"_meta":{"io.modelcontextprotocol/subscriptionId":"idp-relay"}}}`)
			for {
				select {
				case ev := <-u.events:
					flush(ev)
				case <-r.Context().Done():
					return
				}
			}
		default:
			w.WriteHeader(404)
			rpcErr(-32601, "Method not found")
		}
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *tasksUpstream) count(prefix string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, s := range u.seen {
		if strings.HasPrefix(s, prefix) {
			n++
		}
	}
	return n
}

func tasksHarness(t *testing.T, u *tasksUpstream) *harness {
	var raws []json.RawMessage
	_ = json.Unmarshal([]byte(tasksToolsJSON), &raws)
	tools, err := federation.NormalizeTools(raws)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := federation.CatalogDigest(tools, nil)
	d := &release.Document{SchemaVersion: release.SchemaVersion, ReleaseID: "r1", TenantID: "t1", GatewayID: "g1",
		CreatedAt: "2026-11-02T10:00:00Z", CreatedBy: "alice", DriftAction: "block", ToolNaming: release.NamingPrefixed,
		Targets: []release.Target{{Name: "minimal", ServerID: "s1", Endpoint: u.srv.URL + "/mcp", Network: release.NetworkLoopback,
			SnapshotDigest: digest, Tools: tools, Capabilities: []string{release.CapTools, release.CapTasks}}},
		Grants: []release.Grant{{Target: "minimal", Tools: []string{"echo", "slow"}, Roles: []string{"operator"}},
			{Target: "minimal", Tools: []string{"echo"}, Roles: []string{"viewer"}}},
		Auth: release.Auth{Mode: "api-key", APIKeys: []release.APIKey{
			{ID: "k1", Subject: "svc-operator", Roles: []string{"operator"}, SHA256: identity.HashKey(operatorKey)},
			{ID: "k2", Subject: "svc-viewer", Roles: []string{"viewer"}, SHA256: identity.HashKey(viewerKey)}}}}
	env, err := release.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	g := New(Config{GatewayID: "g1", Info: server.ServerInfo{Name: "gw", Version: "t"}, DevMode: true, CallTimeout: 2 * time.Second, Recorder: rec})
	if err := g.Activate(env); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)
	return &harness{g: g, rec: rec, srv: srv}
}

func taskParams(id string) string { return `{"taskId":"` + id + `",` + metaJSON + `}` }

func TestDiscoverAdvertisesTheTasksExtensionOnlyWhenATargetOffersIt(t *testing.T) {
	h := tasksHarness(t, newTasksUpstream(t))
	caps := h.rpc(t, operatorKey, "server/discover", "", nil).body["result"].(map[string]any)["capabilities"].(map[string]any)
	if ext, _ := caps["extensions"].(map[string]any); ext == nil || ext[release.TasksExtensionID] == nil {
		t.Fatalf("extensions %v", caps)
	}
	plain := newHarness(t, "block")
	caps = plain.rpc(t, operatorKey, "server/discover", "", nil).body["result"].(map[string]any)["capabilities"].(map[string]any)
	if _, ok := caps["extensions"]; ok {
		t.Fatalf("extensions advertised without a tasks target: %v", caps)
	}
}

func TestTasksAreRoutedToTheirCreatorForTheirOwnerOnly(t *testing.T) {
	u := newTasksUpstream(t)
	h := tasksHarness(t, u)
	r := h.rpc(t, operatorKey, "tools/call", call("minimal__slow", `{}`), map[string]string{server.HeaderName: "minimal__slow"})
	res, _ := r.body["result"].(map[string]any)
	if r.status != 200 || res["resultType"] != "task" || res["taskId"] != "task-1" {
		t.Fatalf("create: %d %s", r.status, r.raw)
	}
	if h.g.tasks.Count() != 1 {
		t.Fatalf("%d bindings", h.g.tasks.Count())
	}
	// the creator reads the task through the gateway; the upstream sees Mcp-Name = taskId
	r = h.rpc(t, operatorKey, "tasks/get", taskParams("task-1"), map[string]string{server.HeaderName: "task-1"})
	if r.status != 200 || r.body["result"].(map[string]any)["status"] != "completed" || !strings.Contains(r.raw, `"text":"done"`) {
		t.Fatalf("get: %d %s", r.status, r.raw)
	}
	if u.count("tasks/get task-1") != 1 {
		t.Fatalf("upstream saw %v", u.seen)
	}
	rec := h.rec.last()
	if rec.Method != "tasks/get" || rec.Tool != "task-1" || rec.Target != "minimal" || rec.Decision != invocation.Allow || rec.Subject != "svc-operator" {
		t.Fatalf("%+v", rec)
	}
	// another caller, and an id that never existed, get the same answer and never reach the upstream
	other := h.rpc(t, viewerKey, "tasks/get", taskParams("task-1"), map[string]string{server.HeaderName: "task-1"})
	missing := h.rpc(t, viewerKey, "tasks/get", taskParams("task-9"), map[string]string{server.HeaderName: "task-9"})
	if errCode(other) != server.CodeInvalidParams || strings.Replace(other.raw, "task-1", "X", -1) != strings.Replace(missing.raw, "task-9", "X", -1) {
		t.Fatalf("other %s / missing %s", other.raw, missing.raw)
	}
	if u.count("tasks/get") != 1 {
		t.Fatalf("a foreign or unknown task reached the upstream: %v", u.seen)
	}
	if rec := h.rec.last(); rec.Decision != invocation.Deny || rec.Outcome != invocation.OutcomeDenied {
		t.Fatalf("%+v", rec)
	}
	// cancel: empty ack; removed v1 methods stay -32601; routing header must match
	r = h.rpc(t, operatorKey, "tasks/cancel", taskParams("task-1"), map[string]string{server.HeaderName: "task-1"})
	if r.status != 200 || r.body["result"].(map[string]any)["resultType"] != "complete" || u.count("tasks/cancel task-1") != 1 {
		t.Fatalf("cancel: %d %s", r.status, r.raw)
	}
	for _, m := range []string{"tasks/list", "tasks/result"} {
		if r := h.rpc(t, operatorKey, m, taskParams("task-1"), nil); r.status != 404 || errCode(r) != server.CodeMethodNotFound {
			t.Fatalf("%s: %d %s", m, r.status, r.raw)
		}
	}
	if r := h.rpc(t, operatorKey, "tasks/get", taskParams("task-1"), map[string]string{server.HeaderName: "task-2"}); r.status != 400 {
		t.Fatalf("Mcp-Name mismatch: %d", r.status)
	}
	// a sync tool creates no binding
	h.rpc(t, operatorKey, "tools/call", call("minimal__echo", `{}`), map[string]string{server.HeaderName: "minimal__echo"})
	if h.g.tasks.Count() != 1 {
		t.Fatalf("%d bindings after a sync call", h.g.tasks.Count())
	}
}

func TestTasksCreatedOverAStreamAreBound(t *testing.T) {
	u := newTasksUpstream(t)
	u.sse = true
	h := tasksHarness(t, u)
	r := h.rpc(t, operatorKey, "tools/call", call("minimal__slow", `{}`), map[string]string{server.HeaderName: "minimal__slow"})
	if r.status != 200 || r.header.Get("Content-Type") != "text/event-stream" || !strings.Contains(r.raw, `"taskId":"task-1"`) {
		t.Fatalf("%d %s", r.status, r.raw)
	}
	if h.g.tasks.Count() != 1 {
		t.Fatalf("%d bindings", h.g.tasks.Count())
	}
	u.sse = false
	if r := h.rpc(t, operatorKey, "tasks/get", taskParams("task-1"), map[string]string{server.HeaderName: "task-1"}); r.status != 200 || errCode(r) != 0 {
		t.Fatalf("get after streamed create: %s", r.raw)
	}
}

func TestExpiredTaskBindingsAreForgotten(t *testing.T) {
	u := newTasksUpstream(t)
	u.ttlMs = 1
	h := tasksHarness(t, u)
	h.rpc(t, operatorKey, "tools/call", call("minimal__slow", `{}`), map[string]string{server.HeaderName: "minimal__slow"})
	time.Sleep(30 * time.Millisecond)
	if r := h.rpc(t, operatorKey, "tasks/get", taskParams("task-1"), map[string]string{server.HeaderName: "task-1"}); errCode(r) != server.CodeInvalidParams {
		t.Fatalf("expired binding still routed: %s", r.raw)
	}
}

func TestListenRelaysTaskNotificationsToTheTaskOwner(t *testing.T) {
	u := newTasksUpstream(t)
	h := tasksHarness(t, u)
	h.rpc(t, operatorKey, "tools/call", call("minimal__slow", `{}`), map[string]string{server.HeaderName: "minimal__slow"})
	s := openListen(t, h, operatorKey, `{"taskIds":["task-1","task-99"]}`)
	honoured := s.next(t, 2*time.Second)["params"].(map[string]any)["notifications"].(map[string]any)
	if ids, _ := honoured["taskIds"].([]any); len(ids) != 1 || ids[0] != "task-1" {
		t.Fatalf("honoured %v", honoured)
	}
	deadline := time.Now().Add(2 * time.Second)
	for u.count("subscriptions/listen") == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	u.events <- `{"jsonrpc":"2.0","method":"notifications/tasks","params":{"taskId":"task-99","status":"completed"}}`
	u.events <- `{"jsonrpc":"2.0","method":"notifications/tasks","params":{"taskId":"task-1","status":"completed"}}`
	n := s.next(t, 2*time.Second)
	if n["method"] != "notifications/tasks" || n["params"].(map[string]any)["taskId"] != "task-1" || subID(n) != "sub-1" {
		t.Fatalf("%v", n)
	}
	s.quiet(t, 300*time.Millisecond)
	// not the owner: nothing honoured, no relay
	v := openListen(t, h, viewerKey, `{"taskIds":["task-1"]}`)
	if honoured := v.next(t, 2*time.Second)["params"].(map[string]any)["notifications"].(map[string]any); honoured["taskIds"] != nil {
		t.Fatalf("viewer honoured %v", honoured)
	}
}
