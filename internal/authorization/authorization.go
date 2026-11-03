// Package authorization decides, natively and per request, whether a principal may see and call a
// tool (ADR-0001 D5). The rules come only from the running release's grants.
package authorization

import (
	"sort"

	"idp-mcp/internal/release"
)

// Principal is an authenticated caller of the data plane.
type Principal struct {
	Subject string
	Tenant  string
	Roles   []string
	Method  string // "api-key" or "jwt"
	KeyID   string // api-key id, if any
}

// Policy is the compiled grant set of one release.
type Policy struct {
	tenant    string
	allow     map[string]map[string]map[string]bool // target -> tool -> role
	prompts   map[string]map[string]map[string]bool // target -> prompt ("*" = any) -> role
	resources map[string]map[string]bool            // target -> role
}

// Compile builds a policy from a release document.
func Compile(d *release.Document) *Policy {
	p := &Policy{tenant: d.TenantID, allow: map[string]map[string]map[string]bool{},
		prompts: map[string]map[string]map[string]bool{}, resources: map[string]map[string]bool{}}
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

// Allowed reports whether p may call target's native tool. A principal of another tenant is never
// allowed, whatever its roles.
func (p *Policy) Allowed(pr Principal, target, tool string) bool {
	if pr.Tenant != p.tenant || pr.Subject == "" {
		return false
	}
	roles := p.allow[target][tool]
	for _, r := range pr.Roles {
		if roles[r] {
			return true
		}
	}
	return false
}

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
	return anyRole(p.prompts[target][name], pr) || anyRole(p.prompts[target]["*"], pr)
}

// PromptTargets returns, sorted, the targets on which pr may use at least one prompt.
func (p *Policy) PromptTargets(pr Principal) []string {
	var out []string
	if !p.caller(pr) {
		return out
	}
	for target, byName := range p.prompts {
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
	return p.caller(pr) && anyRole(p.resources[target], pr)
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
