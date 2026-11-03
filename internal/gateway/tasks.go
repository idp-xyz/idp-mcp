package gateway

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"idp-mcp/internal/authorization"
	"idp-mcp/internal/invocation"
	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
	"idp-mcp/internal/transport"
)

// Tasks extension (SEP-2663, io.modelcontextprotocol/tasks). A task-supporting tool may answer
// tools/call with a CreateTaskResult (resultType "task", top-level taskId). Task ids are opaque and
// chosen by the upstream, so the gateway remembers which target created each task and for whom:
// tasks/get and tasks/cancel are routed to that target, and only the creating caller (same tenant
// and subject) may use the id - anyone else gets the same "unknown task" answer as for an id that
// never existed. tasks/list and tasks/result were removed in v2 and stay -32601. Bindings expire
// with the task's ttlMs (capped), so the table is bounded.

const (
	maxTaskBindings  = 100000
	maxTaskRetention = 7 * 24 * time.Hour
	defaultTaskTTL   = 24 * time.Hour // ttlMs null (unlimited) is capped to this on the gateway
)

type taskBinding struct {
	target  string
	tenant  string
	subject string
	tool    string // exposed tool name that created the task
	expires time.Time
}

type taskStore struct {
	mu      sync.Mutex
	by      map[string]taskBinding
	inserts int
}

// bindFromResult records the task of a CreateTaskResult message, if msg is one.
func (s *taskStore) bindFromResult(msg json.RawMessage, target, tool string, pr authorization.Principal) {
	var m struct {
		Result struct {
			ResultType string `json:"resultType"`
			TaskID     string `json:"taskId"`
			TTLMs      *int64 `json:"ttlMs"`
		} `json:"result"`
	}
	if json.Unmarshal(msg, &m) != nil || m.Result.ResultType != "task" || m.Result.TaskID == "" || len(m.Result.TaskID) > 256 {
		return
	}
	ttl := defaultTaskTTL
	if m.Result.TTLMs != nil && *m.Result.TTLMs > 0 {
		ttl = min(time.Duration(*m.Result.TTLMs)*time.Millisecond, maxTaskRetention)
	}
	s.bind(m.Result.TaskID, taskBinding{target: target, tenant: pr.Tenant, subject: pr.Subject, tool: tool, expires: time.Now().Add(ttl)})
}

func (s *taskStore) bind(id string, b taskBinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.by == nil {
		s.by = map[string]taskBinding{}
	}
	if s.inserts++; s.inserts%1000 == 0 || len(s.by) >= maxTaskBindings {
		now := time.Now()
		for k, v := range s.by {
			if now.After(v.expires) {
				delete(s.by, k)
			}
		}
	}
	if len(s.by) >= maxTaskBindings {
		return // full of live bindings: the task still exists upstream, the gateway just cannot route it
	}
	if old, dup := s.by[id]; dup && old.target != b.target {
		// two targets issued the same id: ambiguous, route neither (fail closed)
		s.by[id] = taskBinding{expires: b.expires}
		return
	}
	s.by[id] = b
}

// lookup returns the binding of id for the caller that created it.
func (s *taskStore) lookup(id string, pr authorization.Principal) (taskBinding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.by[id]
	if !ok || b.target == "" || time.Now().After(b.expires) || b.tenant != pr.Tenant || b.subject != pr.Subject {
		return taskBinding{}, false
	}
	return b, true
}

// Count reports live bindings (tests, status).
func (s *taskStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.by)
}

func unknownTask(id string) *server.Error {
	return &server.Error{Code: server.CodeInvalidParams, Message: "Unknown task: " + id, Data: map[string]string{"taskId": id}}
}

// taskRequest routes tasks/get and tasks/cancel to the target that created the task.
func (g *Gateway) taskRequest(w http.ResponseWriter, r *http.Request, st *state, req *server.Request, pr authorization.Principal) {
	if rej := req.CheckNameHeader(r.Header.Get(server.HeaderName)); rej != nil {
		transport.WriteRejection(w, rej)
		return
	}
	var p struct {
		TaskID string `json:"taskId"`
	}
	_ = req.DecodeParams(&p)
	done := g.recorder(r, st, pr, req, p.TaskID)
	b, ok := g.tasks.lookup(p.TaskID, pr)
	if !ok || !targetHas(st.doc, b.target, release.CapTasks) || st.router.Endpoint(b.target) == "" {
		done("", invocation.Deny, invocation.OutcomeDenied)
		transport.WriteError(w, http.StatusOK, req.ID, unknownTask(p.TaskID))
		return
	}
	// drift does not block: the task already runs upstream; its owner may still read or cancel it
	done(b.target, invocation.Allow, g.forward(w, r, st, req, st.router.Endpoint(b.target), p.TaskID, rawParams(req)))
}
