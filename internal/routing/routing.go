// Package routing maps exposed tool names (<target>__<tool>) to the upstream target and native
// tool definition pinned in the running release.
package routing

import (
	"strings"

	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
)

// Route is where an exposed tool goes.
type Route struct {
	Exposed  string
	Target   string
	Endpoint string
	External bool        // the target is of class external (ADR-0001 D50): its tools carry the marker
	Tool     server.Tool // pinned definition, native name
}

// PromptRoute is where an exposed prompt goes.
type PromptRoute struct {
	Exposed  string
	Target   string
	Endpoint string
	Prompt   server.Prompt // pinned definition, native name
}

// Router is immutable once built; a new release builds a new router.
type Router struct {
	doc       *release.Document
	byExposed map[string]Route
	byPrompt  map[string]PromptRoute
	endpoints map[string]string
}

// New indexes a release document.
func New(d *release.Document) *Router {
	r := &Router{doc: d, byExposed: map[string]Route{}, byPrompt: map[string]PromptRoute{}, endpoints: map[string]string{}}
	for _, t := range d.Targets {
		r.endpoints[t.Name] = t.Endpoint
		for _, p := range t.Prompts {
			name := d.Expose(t.Name, p.Name)
			r.byPrompt[name] = PromptRoute{Exposed: name, Target: t.Name, Endpoint: t.Endpoint, Prompt: p}
		}
		for _, tool := range t.Tools {
			name := d.Expose(t.Name, tool.Name)
			r.byExposed[name] = Route{Exposed: name, Target: t.Name, Endpoint: t.Endpoint, External: t.External(), Tool: tool}
		}
	}
	return r
}

// Expose returns the client-facing name of a target's tool or prompt.
func (r *Router) Expose(target, name string) string { return r.doc.Expose(target, name) }

// LookupPrompt resolves an exposed prompt name to its pinned prompt.
func (r *Router) LookupPrompt(exposed string) (PromptRoute, bool) {
	pr, ok := r.byPrompt[exposed]
	return pr, ok
}

// Listed is the definition shown to clients: the pinned prompt under its exposed name.
func (pr PromptRoute) Listed() server.Prompt {
	p := pr.Prompt
	p.Name = pr.Exposed
	return p
}

// Prefixed reports whether names carry their target.
func (r *Router) Prefixed() bool { return r.doc.ToolNaming == release.NamingPrefixed }

// Lookup resolves an exposed name.
func (r *Router) Lookup(exposed string) (Route, bool) {
	rt, ok := r.byExposed[exposed]
	return rt, ok
}

// Route returns the route of a target's native tool.
func (r *Router) Route(target, tool string) (Route, bool) {
	return r.Lookup(r.doc.Expose(target, tool))
}

// Endpoint returns a target's endpoint.
func (r *Router) Endpoint(target string) string { return r.endpoints[target] }

// ourKeyPrefix is the prefix of the keys that mean something to the platform; a third party's tool may not carry one.
const ourKeyPrefix = "io.idp.telos/"

// Listed is the definition shown to clients: the pinned tool under its exposed name. The gateway's marker
// (server.MetaExternal) is set in its _meta when the target is external and removed when it is not, whatever the
// upstream put there: the marker says what the gateway knows, so no upstream can claim to be internal by leaving
// it out, and none can make an internal server look external, or the other way round, by sending it. The pinned
// definition itself is not changed.
func (rt Route) Listed() server.Tool {
	t := rt.Tool
	t.Name = rt.Exposed
	old, _ := t.Extra["_meta"].(map[string]any)
	if _, has := old[server.MetaExternal]; !has && !rt.External {
		return t // an internal tool the upstream did not mark is served exactly as pinned
	}
	meta := map[string]any{}
	for k, v := range old {
		if k == server.MetaExternal || (rt.External && strings.HasPrefix(k, ourKeyPrefix)) {
			continue // for an external tool no key of the platform survives but the gateway's own marker, set below
		}
		meta[k] = v
	}
	if rt.External {
		meta[server.MetaExternal] = true
	}
	extra := make(map[string]any, len(t.Extra)+1)
	for k, v := range t.Extra {
		extra[k] = v
	}
	if len(meta) > 0 {
		extra["_meta"] = meta
	} else {
		delete(extra, "_meta")
	}
	t.Extra = extra
	return t
}
