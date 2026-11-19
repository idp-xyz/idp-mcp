// Package authorization decides, natively and per request, whether a principal may see and call a
// tool (ADR-0001 D5). The rules come from the running release's grants (the role) and from the clients
// file (the OAuth client, D46 to D48): a tool, prompt or resource is available when both allow it.
// Every way a client can enumerate or use something goes through this package, so the client's rule
// cannot be forgotten by one path.
package authorization

import (
	"sort"
	"time"

	"idp-mcp/internal/admission"
	"idp-mcp/internal/release"
)

// Principal is an authenticated caller of the data plane.
type Principal struct {
	Subject string
	Tenant  string
	Roles   []string
	Method  string    // "api-key" or "jwt"
	KeyID   string    // api-key id, if any
	Expires time.Time // credential expiry (JWT exp); zero for API keys
	// Client is the OAuth client the token was issued to (azp); Actor the party acting for the
	// subject in a delegated token (RFC 8693 act claim: client_id, else sub). Audit only: grants are
	// decided on Subject, Tenant and Roles.
	Client string
	Actor  string
}

// ClientID is the client this principal is admitted as: the token's OAuth client; for an API key, the
// key itself ("api-key:<id>"), which an operator lists like any client. It is empty for a token that names
// no client, which is never listed.
func (pr Principal) ClientID() string {
	if pr.Method == "api-key" {
		return "api-key:" + pr.KeyID
	}
	return pr.Client
}

// Policy is the compiled grant set of one release.
type Policy struct {
	tenant    string
	allow     map[string]map[string]map[string]bool // target -> tool -> role
	prompts   map[string]map[string]map[string]bool // target -> prompt ("*" = any) -> role
	resources map[string]map[string]bool            // target -> role

	clients *admission.Clients
	expose  func(target, tool string) string
	// hostOnlyTarget lists the targets whose every tool, prompt and resource is host-only by the release
	// itself (ADR-0001 D48); see hostOnlyByRelease.
	hostOnlyTarget map[string]bool
}

// hostOnlyByRelease reports whether the release makes everything of a target host-only. No release field
// says so yet: this is where the class of an upstream will, when the gateway knows external upstreams
// (the interop decision's step X1), so that their tools are host-only without the operator listing them.
func hostOnlyByRelease(release.Target) bool { return false }

// Compile builds a policy from a release document and the clients file. A nil clients lists nobody: the
// policy then grants nothing, whatever the roles (fail closed).
func Compile(d *release.Document, clients *admission.Clients) *Policy {
	p := &Policy{tenant: d.TenantID, allow: map[string]map[string]map[string]bool{},
		prompts: map[string]map[string]map[string]bool{}, resources: map[string]map[string]bool{},
		clients: clients, expose: d.Expose, hostOnlyTarget: map[string]bool{}}
	for _, t := range d.Targets {
		p.hostOnlyTarget[t.Name] = hostOnlyByRelease(t)
	}
	for _, g := range d.Grants {
		for _, name := range g.Prompts {
			if p.prompts[g.Target] == nil {
				p.prompts[g.Target] = map[string]map[string]bool{}
			}
			if p.prompts[g.Target][name] == nil {
				p.prompts[g.Target][name] = map[string]bool{}
			}
			for _, r := range g.Roles {
				p.prompts[g.Target][name][r] = true
			}
		}
		if g.Resources {
			if p.resources[g.Target] == nil {
				p.resources[g.Target] = map[string]bool{}
			}
			for _, r := range g.Roles {
				p.resources[g.Target][r] = true
			}
		}
		if p.allow[g.Target] == nil {
			p.allow[g.Target] = map[string]map[string]bool{}
		}
		for _, tool := range g.Tools {
			if p.allow[g.Target][tool] == nil {
				p.allow[g.Target][tool] = map[string]bool{}
			}
			for _, r := range g.Roles {
				p.allow[g.Target][tool][r] = true
			}
		}
	}
	return p
}

// Decision is the outcome of Decide. Why names what refused (an admission reason, or "role" when the
// client was fine and the roles were not); Exception is the reason of the operator's host-only exception
// that was used, for the audit.
type Decision struct {
	Allowed   bool
	Why       string
	Exception string
}

// WhyRole is the reason of a refusal that the client's rule did not cause.
const WhyRole = "role"

// Decide reports whether pr may call target's native tool. A principal of another tenant is never
// allowed, whatever its roles; and not when its client may not use the tool. The client is judged first,
// so that the audit names the more actionable cause of a refusal.
func (p *Policy) Decide(pr Principal, target, tool string) Decision {
	v := p.clients.Decide(pr.ClientID(), admission.Access{Target: target, Tool: p.expose(target, tool), HostOnly: p.hostOnlyTarget[target]})
	if !v.Allowed {
		return Decision{Why: v.Why}
	}
	if pr.Tenant != p.tenant || pr.Subject == "" || !anyRole(p.allow[target][tool], pr) {
		return Decision{Why: WhyRole}
	}
	return Decision{Allowed: true, Exception: v.Exception}
}

// Allowed reports whether Decide allows the call.
func (p *Policy) Allowed(pr Principal, target, tool string) bool {
	return p.Decide(pr, target, tool).Allowed
}

// clientMay reports whether the client of pr may use the prompts and resources of target: those are
// granted by server only.
func (p *Policy) clientMay(pr Principal, target string) bool {
	return p.clients.Decide(pr.ClientID(), admission.Access{Target: target, HostOnly: p.hostOnlyTarget[target]}).Allowed
}

// ClientWhy says why the principal's client may not use target's prompts and resources, "" when it may.
func (p *Policy) ClientWhy(pr Principal, target string) string {
	return p.clients.Decide(pr.ClientID(), admission.Access{Target: target, HostOnly: p.hostOnlyTarget[target]}).Why
}

// Listed reports whether the gateway serves the principal's client at all.
func (p *Policy) Listed(pr Principal) bool { return p.clients.Listed(pr.ClientID()) }

// VisibleTools returns, sorted, the (target, tool) pairs the principal may use.
func (p *Policy) VisibleTools(pr Principal) [][2]string {
	var out [][2]string
	for target, tools := range p.allow {
		for tool := range tools {
			if p.Allowed(pr, target, tool) {
				out = append(out, [2]string{target, tool})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

func (p *Policy) caller(pr Principal) bool { return pr.Tenant == p.tenant && pr.Subject != "" }

func anyRole(roles map[string]bool, pr Principal) bool {
	for _, r := range pr.Roles {
		if roles[r] {
			return true
		}
	}
	return false
}

// AllowedPrompt reports whether pr may list and get target's prompt name.
func (p *Policy) AllowedPrompt(pr Principal, target, name string) bool {
	if !p.caller(pr) {
		return false
	}
	return p.clientMay(pr, target) && (anyRole(p.prompts[target][name], pr) || anyRole(p.prompts[target]["*"], pr))
}

// PromptTargets returns, sorted, the targets on which pr may use at least one prompt.
func (p *Policy) PromptTargets(pr Principal) []string {
	var out []string
	if !p.caller(pr) {
		return out
	}
	for target, byName := range p.prompts {
		if !p.clientMay(pr, target) {
			continue
		}
		for _, roles := range byName {
			if anyRole(roles, pr) {
				out = append(out, target)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// AllowedResources reports whether pr may list and read target's resources.
func (p *Policy) AllowedResources(pr Principal, target string) bool {
	return p.caller(pr) && p.clientMay(pr, target) && anyRole(p.resources[target], pr)
}

// ResourceTargets returns, sorted, the targets whose resources pr may use.
func (p *Policy) ResourceTargets(pr Principal) []string {
	var out []string
	for target := range p.resources {
		if p.AllowedResources(pr, target) {
			out = append(out, target)
		}
	}
	sort.Strings(out)
	return out
}
