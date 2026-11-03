package gateway

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

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

func (g *Gateway) promptsList(w http.ResponseWriter, _ *http.Request, st *state, req *server.Request, pr authorization.Principal) {
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

func (g *Gateway) recorder(r *http.Request, st *state, pr authorization.Principal, req *server.Request, name string) func(target, decision, outcome string) {
	start := time.Now()
	span := trace.SpanFromContext(r.Context())
	span.SetAttributes(attribute.String("mcp.name", name))
	rec := invocation.Record{At: start.UTC(), ReleaseDigest: st.env.Digest, Subject: pr.Subject, AuthMethod: pr.Method,
		Method: req.Method, Tool: name, TraceID: observability.TraceID(r.Context())}
	return func(target, decision, outcome string) {
		rec.Target, rec.Decision, rec.Outcome, rec.LatencyMS = target, decision, outcome, time.Since(start).Milliseconds()
		span.SetAttributes(attribute.String("idp.decision", decision), attribute.String("idp.outcome", outcome), attribute.String("idp.target", target))
		g.cfg.Recorder.Record(rec)
	}
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
	done := g.recorder(r, st, pr, req, p.Name)
	target, native, ok := g.promptOwner(st, pr, p.Name)
	if !ok {
		done("", invocation.Deny, invocation.OutcomeDenied)
		transport.WriteError(w, http.StatusOK, req.ID, &server.Error{Code: server.CodeInvalidParams, Message: "Unknown prompt: " + p.Name})
		return
	}
	if st.blocked(target) {
		done(target, invocation.Allow, invocation.OutcomeNotDelivered)
		transport.WriteError(w, http.StatusServiceUnavailable, req.ID, &server.Error{Code: server.CodeInternalError,
			Message: "Prompt temporarily unavailable: the upstream catalog changed since approval"})
		return
	}
	params := rawParams(req)
	params["name"], _ = json.Marshal(native)
	done(target, invocation.Allow, g.forward(w, r, st, req, st.router.Endpoint(target), native, params))
}

func (g *Gateway) resourcesList(w http.ResponseWriter, _ *http.Request, st *state, req *server.Request, pr authorization.Principal, templates bool) {
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
	done := g.recorder(r, st, pr, req, p.URI)
	target, ok := g.resourceOwner(st, pr, p.URI)
	if !ok {
		done("", invocation.Deny, invocation.OutcomeDenied)
		transport.WriteError(w, http.StatusOK, req.ID, resourceNotFound(p.URI))
		return
	}
	if st.blocked(target) {
		done(target, invocation.Allow, invocation.OutcomeNotDelivered)
		transport.WriteError(w, http.StatusServiceUnavailable, req.ID, &server.Error{Code: server.CodeInternalError,
			Message: "Resource temporarily unavailable: the upstream catalog changed since approval"})
		return
	}
	done(target, invocation.Allow, g.forward(w, r, st, req, st.router.Endpoint(target), p.URI, rawParams(req)))
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
		done := g.recorder(r, st, pr, req, p.Ref.Name)
		if target, native, ok = g.promptOwner(st, pr, p.Ref.Name); !ok {
			done("", invocation.Deny, invocation.OutcomeDenied)
			transport.WriteError(w, http.StatusOK, req.ID, &server.Error{Code: server.CodeInvalidParams, Message: "Unknown prompt: " + p.Ref.Name})
			return
		}
		var ref map[string]json.RawMessage
		_ = json.Unmarshal(params["ref"], &ref)
		ref["name"], _ = json.Marshal(native)
		params["ref"], _ = json.Marshal(ref)
		done(target, invocation.Allow, g.forward(w, r, st, req, st.router.Endpoint(target), "", params))
	case "ref/resource":
		done := g.recorder(r, st, pr, req, p.Ref.URI)
		if target, ok = g.resourceOwner(st, pr, p.Ref.URI); !ok {
			done("", invocation.Deny, invocation.OutcomeDenied)
			transport.WriteError(w, http.StatusOK, req.ID, resourceNotFound(p.Ref.URI))
			return
		}
		done(target, invocation.Allow, g.forward(w, r, st, req, st.router.Endpoint(target), "", params))
	default:
		transport.WriteError(w, http.StatusOK, req.ID, &server.Error{Code: server.CodeInvalidParams, Message: "ref.type must be ref/prompt or ref/resource"})
	}
}
