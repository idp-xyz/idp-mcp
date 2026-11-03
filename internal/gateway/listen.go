package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"idp-mcp/adapters/identity"
	"idp-mcp/internal/authorization"
	"idp-mcp/internal/client"
	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
	"idp-mcp/internal/transport"
)

// subscriptions/listen (2026-07-28, SEP-2575). The stream's first message acknowledges the filter
// the gateway honours; every notification carries _meta.subscriptionId = the listen request's id.
//
//   - toolsListChanged / promptsListChanged: the catalogs are pinned, so the client-visible lists
//     change only when a new release is activated; the gateway itself notifies then. An upstream that
//     changes its own list is drift, not a list change.
//   - resourcesListChanged / resourceSubscriptions: relayed from the resource targets the caller may
//     use (their own listen streams), re-tagged with the caller's subscription id; URIs the caller
//     cannot read are dropped from the honoured filter.
//   - A stream never outlives its credential: it ends at JWT expiry, and when a new release no longer
//     authenticates the caller.

// MetaSubscriptionID tags listen-stream notifications.
const MetaSubscriptionID = "io.modelcontextprotocol/subscriptionId"

// MaxListenStreams bounds concurrently open listen streams per gateway.
const MaxListenStreams = 1000

type subscriber struct{ changed chan struct{} }

type hub struct {
	mu   sync.Mutex
	subs map[*subscriber]bool
	done chan struct{}
	once sync.Once
}

func (h *hub) add() (*subscriber, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.subs == nil {
		h.subs = map[*subscriber]bool{}
	}
	if len(h.subs) >= MaxListenStreams {
		return nil, false
	}
	s := &subscriber{changed: make(chan struct{}, 1)}
	h.subs[s] = true
	return s, true
}

func (h *hub) remove(s *subscriber) {
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
}

func (h *hub) broadcast() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		select {
		case s.changed <- struct{}{}:
		default:
		}
	}
}

func (h *hub) closing() chan struct{} {
	h.once.Do(func() { h.done = make(chan struct{}) })
	return h.done
}

// Shutdown ends every open listen stream gracefully (with its final result).
func (g *Gateway) Shutdown() {
	ch := g.listeners.closing()
	select {
	case <-ch:
	default:
		close(ch)
	}
}

// ListenStreams reports the number of open listen streams.
func (g *Gateway) ListenStreams() int {
	g.listeners.mu.Lock()
	defer g.listeners.mu.Unlock()
	return len(g.listeners.subs)
}

type filter struct {
	Tools, Prompts, Resources bool
	Subscriptions             []string
	TaskIDs                   []string // tasks extension: notifications/tasks for these ids
}

func (f filter) honoured() map[string]any {
	out := map[string]any{}
	if f.Tools {
		out["toolsListChanged"] = true
	}
	if f.Prompts {
		out["promptsListChanged"] = true
	}
	if f.Resources {
		out["resourcesListChanged"] = true
	}
	if len(f.Subscriptions) > 0 {
		out["resourceSubscriptions"] = f.Subscriptions
	}
	if len(f.TaskIDs) > 0 {
		out["taskIds"] = f.TaskIDs
	}
	return out
}

func notification(method string, params map[string]any, subID json.RawMessage) []byte {
	if params == nil {
		params = map[string]any{}
	}
	meta, _ := params["_meta"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	meta[MetaSubscriptionID] = subID
	params["_meta"] = meta
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
	return b
}

func (g *Gateway) listen(w http.ResponseWriter, r *http.Request, st *state, req *server.Request, pr authorization.Principal) {
	var p struct {
		Notifications struct {
			ToolsListChanged      bool     `json:"toolsListChanged"`
			PromptsListChanged    bool     `json:"promptsListChanged"`
			ResourcesListChanged  bool     `json:"resourcesListChanged"`
			ResourceSubscriptions []string `json:"resourceSubscriptions"`
			TaskIDs               []string `json:"taskIds"`
		} `json:"notifications"`
	}
	if err := req.DecodeParams(&p); err != nil {
		transport.WriteError(w, http.StatusBadRequest, req.ID, err.(*server.Error))
		return
	}
	sub, ok := g.listeners.add()
	if !ok {
		transport.WriteError(w, http.StatusServiceUnavailable, req.ID, &server.Error{Code: server.CodeInternalError, Message: "Too many open listen streams"})
		return
	}
	defer g.listeners.remove(sub)
	bearer, _ := identity.Bearer(r)
	subID := req.ID

	// the filter this gateway honours for this caller
	resourceTargets := targetsWith(st.doc, release.CapResources, st.policy.ResourceTargets(pr))
	f := filter{Tools: p.Notifications.ToolsListChanged}
	f.Prompts = p.Notifications.PromptsListChanged && len(targetsWith(st.doc, release.CapPrompts, st.policy.PromptTargets(pr))) > 0
	relayTargets := map[string]*relaySpec{}
	if p.Notifications.ResourcesListChanged {
		for _, t := range targetsWith(st.doc, release.CapResourcesListChanged, resourceTargets) {
			relayTargets[t] = &relaySpec{listChanged: true}
			f.Resources = true
		}
	}
	for _, uri := range p.Notifications.ResourceSubscriptions {
		if len(f.Subscriptions) >= 100 {
			break
		}
		owner, ok := g.resourceOwner(st, pr, uri)
		if !ok || !targetHas(st.doc, owner, release.CapResourcesSubscribe) {
			continue
		}
		if relayTargets[owner] == nil {
			relayTargets[owner] = &relaySpec{}
		}
		relayTargets[owner].uris = append(relayTargets[owner].uris, uri)
		f.Subscriptions = append(f.Subscriptions, uri)
	}

	for _, id := range p.Notifications.TaskIDs {
		if len(f.TaskIDs) >= 100 {
			break
		}
		b, ok := g.tasks.lookup(id, pr)
		if !ok || !targetHas(st.doc, b.target, release.CapTasks) || st.router.Endpoint(b.target) == "" {
			continue
		}
		if relayTargets[b.target] == nil {
			relayTargets[b.target] = &relaySpec{}
		}
		relayTargets[b.target].taskIDs = append(relayTargets[b.target].taskIDs, id)
		f.TaskIDs = append(f.TaskIDs, id)
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	send := func(b []byte) bool {
		if _, err := w.Write([]byte("event: message\ndata: ")); err != nil {
			return false
		}
		if _, err := w.Write(append(b, '\n', '\n')); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send(notification("notifications/subscriptions/acknowledged", map[string]any{"notifications": f.honoured()}, subID)) {
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	frames := make(chan []byte, 64)
	for target, spec := range relayTargets {
		go g.relay(ctx, st, target, spec, subID, frames)
	}
	var expiry <-chan time.Time
	if !pr.Expires.IsZero() {
		timer := time.NewTimer(time.Until(pr.Expires))
		defer timer.Stop()
		expiry = timer.C
	}
	end := func() {
		res, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": subID,
			"result": map[string]any{"resultType": "complete", "_meta": map[string]any{MetaSubscriptionID: subID}}})
		send(res)
	}
	for {
		select {
		case <-ctx.Done():
			return // client went away
		case <-g.listeners.closing():
			end()
			return
		case <-expiry:
			end()
			return
		case <-sub.changed:
			cur := g.cur.Load()
			if cur == nil {
				end()
				return
			}
			again, err := cur.auth.Authenticate(ctx, bearer)
			if err != nil || again.Tenant != pr.Tenant || again.Subject != pr.Subject {
				end() // the new release no longer authenticates this caller
				return
			}
			if f.Tools && !send(notification("notifications/tools/list_changed", nil, subID)) {
				return
			}
			if f.Prompts && !send(notification("notifications/prompts/list_changed", nil, subID)) {
				return
			}
		case b := <-frames:
			if !send(b) {
				return
			}
		}
	}
}

func targetHas(d *release.Document, target, capability string) bool {
	for _, t := range d.Targets {
		if t.Name == target {
			return t.HasCapability(capability)
		}
	}
	return false
}

type relaySpec struct {
	listChanged bool
	uris        []string
	taskIDs     []string
}

// relay opens the target's own listen stream and forwards resource notifications for this caller.
func (g *Gateway) relay(ctx context.Context, st *state, target string, spec *relaySpec, subID json.RawMessage, out chan<- []byte) {
	upFilter := map[string]any{}
	if spec.listChanged {
		upFilter["resourcesListChanged"] = true
	}
	if len(spec.uris) > 0 {
		upFilter["resourceSubscriptions"] = spec.uris
	}
	if len(spec.taskIDs) > 0 {
		upFilter["taskIds"] = spec.taskIDs
	}
	subscribed := map[string]bool{}
	for _, u := range spec.uris {
		subscribed[u] = true
	}
	tasks := map[string]bool{}
	for _, id := range spec.taskIDs {
		tasks[id] = true
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "idp-relay", "method": "subscriptions/listen",
		"params": map[string]any{"notifications": upFilter, "_meta": st.upstream.Meta()}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, st.router.Endpoint(target), bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header = client.Headers("subscriptions/listen", "")
	req.Header.Set("Accept", "text/event-stream")
	resp, err := st.upstream.HTTP.Do(req)
	if err != nil {
		g.cfg.Log.Warn("listen relay", "target", target, "err", err)
		return
	}
	defer resp.Body.Close()
	if transport.MediaType(resp.Header.Get("Content-Type")) != "text/event-stream" {
		g.cfg.Log.Warn("listen relay: upstream did not open a stream", "target", target, "status", resp.StatusCode)
		return
	}
	rd := bufio.NewReaderSize(resp.Body, 64<<10)
	var data []string
	for {
		line, err := rd.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		case line == "" && len(data) > 0:
			var msg struct {
				Method string         `json:"method"`
				Params map[string]any `json:"params"`
			}
			raw := strings.Join(data, "\n")
			data = nil
			if json.Unmarshal([]byte(raw), &msg) != nil {
				continue
			}
			switch msg.Method {
			case "notifications/resources/list_changed":
				if !spec.listChanged {
					continue
				}
			case "notifications/resources/updated":
				if uri, _ := msg.Params["uri"].(string); !subscribed[uri] {
					continue
				}
			case "notifications/tasks", "notifications/tasks/status":
				if id, _ := msg.Params["taskId"].(string); !tasks[id] {
					continue
				}
			default:
				continue // the upstream's acknowledgment and anything not asked for
			}
			select {
			case out <- notification(msg.Method, msg.Params, subID):
			case <-ctx.Done():
				return
			}
		}
		if err != nil {
			return
		}
	}
}
