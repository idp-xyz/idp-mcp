package gateway

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"idp-mcp/internal/admission"
	"idp-mcp/internal/authorization"
	"idp-mcp/internal/invocation"
	"idp-mcp/internal/observability"
	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
	"idp-mcp/internal/transport"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Tools, prompts and resources are pinned (M3/M5): the lists are served from the release and single
// requests are routed to the target that pins the name or URI. Resource URIs are never rewritten;
// a read's owner is the one allowed target that pins the URI exactly, else the one whose pinned
// template matches. Ambiguity resolves to "not found".

// federatedCapabilities is the gateway's server/discover capability set: what at least one target
// contributes. tools/prompts list changes come from the gateway itself (on release activation, see
// listen.go); resource subscriptions and list changes are relayed from targets that offer them.
func federatedCapabilities(d *release.Document) map[string]any {
	caps := map[string]any{"tools": map[string]any{"listChanged": true}}
	var subscribe, listChanged bool
	for _, t := range d.Targets {
		if t.HasCapability(release.CapPrompts) {
			caps["prompts"] = map[string]any{"listChanged": true}
		}
		if t.HasCapability(release.CapResources) {
			subscribe = subscribe || t.HasCapability(release.CapResourcesSubscribe)
			listChanged = listChanged || t.HasCapability(release.CapResourcesListChanged)
			caps["resources"] = map[string]any{"subscribe": subscribe, "listChanged": listChanged}
		}
		if t.HasCapability(release.CapCompletions) {
			caps["completions"] = map[string]any{}
		}
		if t.HasCapability(release.CapTasks) {
			caps["extensions"] = map[string]any{release.TasksExtensionID: map[string]any{}}
		}
	}
	return caps
}

func targetsWith(d *release.Document, capability string, allowed []string) []string {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	var out []string
	for _, t := range d.Targets {
		if ok[t.Name] && t.HasCapability(capability) {
			out = append(out, t.Name)
		}
	}
	return out
}

// templateRE turns an RFC 6570 URI template into a matcher: every expression matches one or more
// characters ({+x} and {#x} may span '/', others may not).
func templateRE(tpl string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for {
		i := strings.Index(tpl, "{")
		if i < 0 {
			b.WriteString(regexp.QuoteMeta(tpl))
			break
		}
		j := strings.Index(tpl[i:], "}")
		if j < 0 {
			b.WriteString(regexp.QuoteMeta(tpl))
			break
		}
		b.WriteString(regexp.QuoteMeta(tpl[:i]))
		expr := tpl[i+1 : i+j]
		if strings.HasPrefix(expr, "+") || strings.HasPrefix(expr, "#") {
			b.WriteString(".+")
		} else {
			b.WriteString("[^/]+")
		}
		tpl = tpl[i+j+1:]
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return regexp.MustCompile(`^\b$`) // matches nothing
	}
	return re
}

func rawParams(req *server.Request) map[string]json.RawMessage {
	var params map[string]json.RawMessage
	_ = json.Unmarshal(req.Params, &params)
	if params == nil {
		params = map[string]json.RawMessage{}
	}
	return params
}

func (g *Gateway) promptsList(w http.ResponseWriter, r *http.Request, st *state, req *server.Request, pr authorization.Principal) {
	rec := g.recorder(r, st, pr, req, invocation.Whole)
	defer rec.doneList(st, pr)
	var out []server.Prompt
	for _, t := range st.doc.Targets {
		if !t.HasCapability(release.CapPrompts) {
			continue
		}
		for _, p := range t.Prompts {
			if st.policy.AllowedPrompt(pr, t.Name, p.Name) {
				if rt, ok := st.router.LookupPrompt(st.router.Expose(t.Name, p.Name)); ok {
					out = append(out, rt.Listed())
				}
			}
		}
	}
	transport.WriteResult(w, req.ID, server.PromptsListResult(out, g.cfg.Info))
}

// promptOwner resolves a client-facing prompt name to its pinned prompt, for this caller only.
func (g *Gateway) promptOwner(st *state, pr authorization.Principal, exposed string) (string, string, bool) {
	rt, ok := st.router.LookupPrompt(exposed)
	if !ok || !st.policy.AllowedPrompt(pr, rt.Target, rt.Prompt.Name) {
		return "", "", false
	}
	return rt.Target, rt.Prompt.Name, true
}

// callRecord is the audit record of one request while it is decided. A request that is refused, or answered
// in one piece, is recorded once, by done; one answered with an event stream is recorded twice, by started when
// the stream opens and by done when it ends, with its duration and the bytes relayed (ADR-0001 D49).
type callRecord struct {
	g     *Gateway
	rec   invocation.Record
	start time.Time
	span  trace.Span
	tgt   string // the target the request is routed to, once known: a stream's first record names it
}

// to sets the target the request is routed to and returns c, for the forward call.
func (c *callRecord) to(target string) *callRecord {
	c.tgt = target
	return c
}

// promptTarget is the target that pins the exposed prompt name, whoever may use it; empty if none does.
func (g *Gateway) promptTarget(st *state, exposed string) string {
	if rt, ok := st.router.LookupPrompt(exposed); ok {
		return rt.Target
	}
	return ""
}

func (g *Gateway) recorder(r *http.Request, st *state, pr authorization.Principal, req *server.Request, name string) *callRecord {
	start := time.Now()
	span := trace.SpanFromContext(r.Context())
	span.SetAttributes(attribute.String("mcp.name", name))
	return &callRecord{g: g, start: start, span: span, rec: invocation.Record{At: start.UTC(), ReleaseDigest: st.env.Digest, Subject: pr.Subject,
		Client: pr.Client, Actor: pr.Actor, AuthMethod: pr.Method, Method: req.Method, Tool: name, TraceID: observability.TraceID(r.Context())}}
}

// reason sets the record's reason; the first one set stands.
func (c *callRecord) reason(why string) {
	if c.rec.Reason == "" {
		c.rec.Reason = why
	}
}

// started records that the answer is an event stream; the call has been allowed and delivered.
func (c *callRecord) started() {
	if c == nil {
		return
	}
	s := c.rec
	s.Target, s.Decision, s.Outcome, s.LatencyMS = c.tgt, invocation.Allow, invocation.OutcomeStreamStarted, 0
	c.g.cfg.Recorder.Record(s)
}

// relayed counts bytes of an event stream passed on.
func (c *callRecord) relayed(n int) {
	if c != nil {
		c.rec.Bytes += int64(n)
	}
}

func (c *callRecord) done(target, decision, outcome string) {
	c.rec.Target, c.rec.Decision, c.rec.Outcome, c.rec.LatencyMS = target, decision, outcome, time.Since(c.start).Milliseconds()
	c.span.SetAttributes(attribute.String("idp.decision", decision), attribute.String("idp.outcome", outcome), attribute.String("idp.target", target))
	c.g.cfg.Recorder.Record(c.rec)
}

// doneList records a list request: allowed for a listed client, refused (and answered with an empty list) for
// one that is not listed, so that the audit shows who asked what the gateway does not serve them.
func (c *callRecord) doneList(st *state, pr authorization.Principal) {
	if st.policy.Listed(pr) {
		c.done("", invocation.Allow, invocation.OutcomeOK)
		return
	}
	c.reason(admission.NotListed)
	c.done("", invocation.Deny, invocation.OutcomeDenied)
}

// refusal is the reason a prompt, resource or task of target was not available to pr when the role did not
// say so: the client's, if it is the client that refuses. target is empty when nothing resolved.
func (g *Gateway) refusal(st *state, pr authorization.Principal, target string) string {
	if !st.policy.Listed(pr) {
		return admission.NotListed
	}
	if target != "" {
		return st.policy.ClientWhy(pr, target)
	}
	return ""
}

func (g *Gateway) promptsGet(w http.ResponseWriter, r *http.Request, st *state, req *server.Request, pr authorization.Principal) {
	if rej := req.CheckNameHeader(r.Header.Get(server.HeaderName)); rej != nil {
		transport.WriteRejection(w, rej)
		return
	}
	var p struct {
		Name string `json:"name"`
	}
	_ = req.DecodeParams(&p)
	rec := g.recorder(r, st, pr, req, p.Name)
	target, native, ok := g.promptOwner(st, pr, p.Name)
	if !ok {
		rec.reason(g.refusal(st, pr, g.promptTarget(st, p.Name)))
		rec.done("", invocation.Deny, invocation.OutcomeDenied)
		transport.WriteError(w, http.StatusOK, req.ID, &server.Error{Code: server.CodeInvalidParams, Message: "Unknown prompt: " + p.Name})
		return
	}
	if g.refuseBlocked(w, st, req, rec, target, "Prompt") {
		return
	}
	params := rawParams(req)
	params["name"], _ = json.Marshal(native)
	rec.done(target, invocation.Allow, g.forward(w, r, st, req, st.router.Endpoint(target), native, params, rec.to(target)))
}

func (g *Gateway) resourcesList(w http.ResponseWriter, r *http.Request, st *state, req *server.Request, pr authorization.Principal, templates bool) {
	rec := g.recorder(r, st, pr, req, invocation.Whole)
	defer rec.doneList(st, pr)
	items := []any{}
	for _, t := range st.doc.Targets {
		if !t.HasCapability(release.CapResources) || !st.policy.AllowedResources(pr, t.Name) {
			continue
		}
		if templates {
			for _, x := range t.ResourceTemplates {
				items = append(items, x)
			}
		} else {
			for _, x := range t.Resources {
				items = append(items, x)
			}
		}
	}
	field := "resources"
	if templates {
		field = "resourceTemplates"
	}
	transport.WriteResult(w, req.ID, server.Complete(map[string]any{field: items}, g.cfg.Info))
}

// resourceOwner finds the one target this caller may read uri from: an allowed target that pins the
// URI exactly, else one whose pinned template matches. Ambiguity resolves to none.
func (g *Gateway) resourceOwner(st *state, pr authorization.Principal, uri string) (string, bool) {
	var exact, byTemplate []string
	for _, t := range targetsWith(st.doc, release.CapResources, st.policy.ResourceTargets(pr)) {
		e, m := st.resources[t].owns(uri)
		switch {
		case e:
			exact = append(exact, t)
		case m:
			byTemplate = append(byTemplate, t)
		}
	}
	if len(exact) == 1 {
		return exact[0], true
	}
	if len(exact) == 0 && len(byTemplate) == 1 {
		return byTemplate[0], true
	}
	return "", false
}

func resourceNotFound(uri string) *server.Error {
	return &server.Error{Code: server.CodeInvalidParams, Message: "Resource not found", Data: map[string]string{"uri": uri}}
}

func (g *Gateway) resourcesRead(w http.ResponseWriter, r *http.Request, st *state, req *server.Request, pr authorization.Principal) {
	if rej := req.CheckNameHeader(r.Header.Get(server.HeaderName)); rej != nil {
		transport.WriteRejection(w, rej)
		return
	}
	var p struct {
		URI string `json:"uri"`
	}
	_ = req.DecodeParams(&p)
	rec := g.recorder(r, st, pr, req, p.URI)
	target, ok := g.resourceOwner(st, pr, p.URI)
	if !ok {
		rec.reason(g.refusal(st, pr, ""))
		rec.done("", invocation.Deny, invocation.OutcomeDenied)
		transport.WriteError(w, http.StatusOK, req.ID, resourceNotFound(p.URI))
		return
	}
	if g.refuseBlocked(w, st, req, rec, target, "Resource") {
		return
	}
	rec.done(target, invocation.Allow, g.forward(w, r, st, req, st.router.Endpoint(target), p.URI, rawParams(req), rec.to(target)))
}

func (g *Gateway) complete(w http.ResponseWriter, r *http.Request, st *state, req *server.Request, pr authorization.Principal) {
	var p struct {
		Ref struct {
			Type string `json:"type"`
			Name string `json:"name"`
			URI  string `json:"uri"`
		} `json:"ref"`
	}
	if err := req.DecodeParams(&p); err != nil {
		transport.WriteError(w, http.StatusBadRequest, req.ID, err.(*server.Error))
		return
	}
	params := rawParams(req)
	var target string
	var ok bool
	switch p.Ref.Type {
	case "ref/prompt":
		var native string
		rec := g.recorder(r, st, pr, req, p.Ref.Name)
		if target, native, ok = g.promptOwner(st, pr, p.Ref.Name); !ok {
			rec.reason(g.refusal(st, pr, g.promptTarget(st, p.Ref.Name)))
			rec.done("", invocation.Deny, invocation.OutcomeDenied)
			transport.WriteError(w, http.StatusOK, req.ID, &server.Error{Code: server.CodeInvalidParams, Message: "Unknown prompt: " + p.Ref.Name})
			return
		}
		var ref map[string]json.RawMessage
		_ = json.Unmarshal(params["ref"], &ref)
		ref["name"], _ = json.Marshal(native)
		params["ref"], _ = json.Marshal(ref)
		if st.isExternal(target) && g.refuseBlocked(w, st, req, rec, target, "Completion") {
			return
		}
		rec.done(target, invocation.Allow, g.forward(w, r, st, req, st.router.Endpoint(target), "", params, rec.to(target)))
	case "ref/resource":
		rec := g.recorder(r, st, pr, req, p.Ref.URI)
		if target, ok = g.resourceOwner(st, pr, p.Ref.URI); !ok {
			rec.reason(g.refusal(st, pr, ""))
			rec.done("", invocation.Deny, invocation.OutcomeDenied)
			transport.WriteError(w, http.StatusOK, req.ID, resourceNotFound(p.Ref.URI))
			return
		}
		if st.isExternal(target) && g.refuseBlocked(w, st, req, rec, target, "Completion") {
			return
		}
		rec.done(target, invocation.Allow, g.forward(w, r, st, req, st.router.Endpoint(target), "", params, rec.to(target)))
	default:
		transport.WriteError(w, http.StatusOK, req.ID, &server.Error{Code: server.CodeInvalidParams, Message: "ref.type must be ref/prompt or ref/resource"})
	}
}
