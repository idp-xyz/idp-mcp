package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"idp-mcp/internal/authorization"
	"idp-mcp/internal/invocation"
	"idp-mcp/internal/observability"
	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
	"idp-mcp/internal/transport"
)

// Prompts are pinned like tools (M3): prompts/list is served from the release and prompts/get is
// routed to the pinned prompt's target. Resources are live: lists are fanned out to the targets the
// caller may use and merged; resource URIs are never rewritten, so a read's owner is found from the
// targets' listings (cached briefly), exact URI first, then URI templates.

const listingTTL = 30 * time.Second

// MetaUnavailable lists targets that could not be reached while assembling a merged list.
const MetaUnavailable = "io.idp-mcp/unavailableTargets"

type listing struct {
	at        time.Time
	resources map[string]bool
	templates []*regexp.Regexp
}

type listings struct {
	mu sync.Mutex
	by map[string]*listing
}

func (l *listings) get(target string) *listing {
	l.mu.Lock()
	defer l.mu.Unlock()
	if x := l.by[target]; x != nil && time.Since(x.at) < listingTTL {
		return x
	}
	return nil
}

func (l *listings) update(target string, fn func(*listing)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.by == nil {
		l.by = map[string]*listing{}
	}
	x := l.by[target]
	if x == nil || time.Since(x.at) >= listingTTL {
		x = &listing{resources: map[string]bool{}}
		l.by[target] = x
	}
	fn(x)
	x.at = time.Now()
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

func rawParams(req *server.Request) map[string]json.RawMessage {
	var params map[string]json.RawMessage
	_ = json.Unmarshal(req.Params, &params)
	if params == nil {
		params = map[string]json.RawMessage{}
	}
	return params
}

// listAll pages through a list method on one target and returns the raw entries of field.
func (g *Gateway) listAll(ctx context.Context, st *state, target, method, field string) ([]json.RawMessage, error) {
	return st.upstream.List(ctx, st.router.Endpoint(target), method, field)
}

type fanned struct {
	target string
	items  []json.RawMessage
	err    error
}

func (g *Gateway) fanOut(ctx context.Context, st *state, targets []string, method, field string) []fanned {
	out := make([]fanned, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			items, err := g.listAll(cctx, st, t, method, field)
			out[i] = fanned{target: t, items: items, err: err}
		}()
	}
	wg.Wait()
	return out
}

func decodeObject(raw json.RawMessage) map[string]any {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	_ = dec.Decode(&m)
	return m
}

func (g *Gateway) mergedResult(field string, items []any, unavailable []string) map[string]any {
	if items == nil {
		items = []any{}
	}
	res := server.Complete(map[string]any{field: items}, g.cfg.Info)
	if len(unavailable) > 0 {
		sort.Strings(unavailable)
		res["_meta"].(map[string]any)[MetaUnavailable] = unavailable
	}
	return res
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

func (g *Gateway) recorder(st *state, pr authorization.Principal, req *server.Request, name string, tc observability.TraceContext) func(target, decision, outcome string) {
	start := time.Now()
	rec := invocation.Record{At: start.UTC(), ReleaseDigest: st.env.Digest, Subject: pr.Subject, AuthMethod: pr.Method,
		Method: req.Method, Tool: name, TraceID: tc.TraceID}
	return func(target, decision, outcome string) {
		rec.Target, rec.Decision, rec.Outcome, rec.LatencyMS = target, decision, outcome, time.Since(start).Milliseconds()
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
	tc := observability.ParseOrStart(r.Header.Get("traceparent"), r.Header.Get("tracestate"))
	done := g.recorder(st, pr, req, p.Name, tc)
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
	done(target, invocation.Allow, g.forward(w, r, st, req, st.router.Endpoint(target), native, params, tc))
}

func (g *Gateway) resourcesList(w http.ResponseWriter, r *http.Request, st *state, req *server.Request, pr authorization.Principal, method, field, key string) {
	var items []any
	var unavailable []string
	for _, f := range g.fanOut(r.Context(), st, targetsWith(st.doc, release.CapResources, st.policy.ResourceTargets(pr)), method, field) {
		if f.err != nil {
			unavailable = append(unavailable, f.target)
			g.cfg.Log.Warn(method+" fan-out", "target", f.target, "err", f.err)
			continue
		}
		var keys []string
		for _, raw := range f.items {
			m := decodeObject(raw)
			if v, _ := m[key].(string); v != "" {
				keys = append(keys, v)
				items = append(items, m)
			}
		}
		st.listings.update(f.target, func(l *listing) {
			for _, k := range keys {
				if key == "uri" {
					l.resources[k] = true
				} else {
					l.templates = append(l.templates, templateRE(k))
				}
			}
		})
	}
	transport.WriteResult(w, req.ID, g.mergedResult(field, items, unavailable))
}

// resourceOwner finds the one target this caller may read uri from: the only resource target, or
// the one whose listing contains uri (exactly, else by template). Ambiguity resolves to none.
func (g *Gateway) resourceOwner(ctx context.Context, st *state, pr authorization.Principal, uri string) (string, bool) {
	candidates := targetsWith(st.doc, release.CapResources, st.policy.ResourceTargets(pr))
	switch len(candidates) {
	case 0:
		return "", false
	case 1:
		return candidates[0], true
	}
	refresh := func(t string) *listing {
		if l := st.listings.get(t); l != nil {
			return l
		}
		res := g.fanOut(ctx, st, []string{t}, "resources/list", "resources")[0]
		tpl := g.fanOut(ctx, st, []string{t}, "resources/templates/list", "resourceTemplates")[0]
		st.listings.update(t, func(l *listing) {
			for _, raw := range res.items {
				if u, _ := decodeObject(raw)["uri"].(string); u != "" {
					l.resources[u] = true
				}
			}
			for _, raw := range tpl.items {
				if u, _ := decodeObject(raw)["uriTemplate"].(string); u != "" {
					l.templates = append(l.templates, templateRE(u))
				}
			}
		})
		return st.listings.get(t)
	}
	var exact, byTemplate []string
	for _, t := range candidates {
		l := refresh(t)
		if l == nil {
			continue
		}
		if l.resources[uri] {
			exact = append(exact, t)
			continue
		}
		for _, re := range l.templates {
			if re.MatchString(uri) {
				byTemplate = append(byTemplate, t)
				break
			}
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
	tc := observability.ParseOrStart(r.Header.Get("traceparent"), r.Header.Get("tracestate"))
	done := g.recorder(st, pr, req, p.URI, tc)
	target, ok := g.resourceOwner(r.Context(), st, pr, p.URI)
	if !ok {
		done("", invocation.Deny, invocation.OutcomeDenied)
		transport.WriteError(w, http.StatusOK, req.ID, resourceNotFound(p.URI))
		return
	}
	done(target, invocation.Allow, g.forward(w, r, st, req, st.router.Endpoint(target), p.URI, rawParams(req), tc))
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
	tc := observability.ParseOrStart(r.Header.Get("traceparent"), r.Header.Get("tracestate"))
	params := rawParams(req)
	var target string
	var ok bool
	switch p.Ref.Type {
	case "ref/prompt":
		var native string
		done := g.recorder(st, pr, req, p.Ref.Name, tc)
		if target, native, ok = g.promptOwner(st, pr, p.Ref.Name); !ok {
			done("", invocation.Deny, invocation.OutcomeDenied)
			transport.WriteError(w, http.StatusOK, req.ID, &server.Error{Code: server.CodeInvalidParams, Message: "Unknown prompt: " + p.Ref.Name})
			return
		}
		var ref map[string]json.RawMessage
		_ = json.Unmarshal(params["ref"], &ref)
		ref["name"], _ = json.Marshal(native)
		params["ref"], _ = json.Marshal(ref)
		done(target, invocation.Allow, g.forward(w, r, st, req, st.router.Endpoint(target), "", params, tc))
	case "ref/resource":
		done := g.recorder(st, pr, req, p.Ref.URI, tc)
		if target, ok = g.resourceOwner(r.Context(), st, pr, p.Ref.URI); !ok {
			done("", invocation.Deny, invocation.OutcomeDenied)
			transport.WriteError(w, http.StatusOK, req.ID, resourceNotFound(p.Ref.URI))
			return
		}
		done(target, invocation.Allow, g.forward(w, r, st, req, st.router.Endpoint(target), "", params, tc))
	default:
		transport.WriteError(w, http.StatusOK, req.ID, &server.Error{Code: server.CodeInvalidParams, Message: "ref.type must be ref/prompt or ref/resource"})
	}
}
