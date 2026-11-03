// Package release defines the Release: the immutable, content-addressed document the registry
// service compiles from approved servers, approved grants and a gateway's auth profile, and the
// only configuration a gateway runs (ADR-0001 D2). Producer and verifier both use this package.
package release

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"idp-mcp/internal/server"
)

// SchemaVersion identifies the Release document format.
const SchemaVersion = "idp.mcp.release/v1"

// Separator joins a target name and a native tool name into the exposed tool name (ADR-0001 D7).
const Separator = "__"

var (
	targetNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)
	toolNameRE   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	sha256HexRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	roleRE       = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
)

// ValidTargetName reports whether name may be used as a target name.
func ValidTargetName(name string) bool { return targetNameRE.MatchString(name) }

// ValidToolName reports whether a native or exposed tool name is acceptable.
func ValidToolName(name string) bool { return toolNameRE.MatchString(name) }

// Document is the signed-off content of a release.
type Document struct {
	SchemaVersion string   `json:"schemaVersion"`
	ReleaseID     string   `json:"releaseId"`
	TenantID      string   `json:"tenantId"`
	GatewayID     string   `json:"gatewayId"`
	CreatedAt     string   `json:"createdAt"` // RFC 3339, UTC
	CreatedBy     string   `json:"createdBy"`
	ApprovedBy    string   `json:"approvedBy,omitempty"` // set when the release is approved; part of the digest
	Targets       []Target `json:"targets"`
	Grants        []Grant  `json:"grants"`
	Auth          Auth     `json:"auth"`
	// DriftAction: what the gateway does when an upstream's live catalog differs from the pinned
	// one: "block" (refuse calls to that target, default) or "report".
	DriftAction string `json:"driftAction"`
	// ToolNaming: "prefixed" exposes <target>__<name> for tools and prompts; "native" exposes the
	// upstream names unchanged and requires them to be unique across all targets.
	ToolNaming string `json:"toolNaming"`
}

// Tool naming modes.
const (
	NamingPrefixed = "prefixed"
	NamingNative   = "native"
)

// Capabilities a target can contribute to the federation (besides tools, which are pinned).
const (
	CapTools       = "tools"
	CapPrompts     = "prompts"
	CapResources   = "resources"
	CapCompletions = "completions"
)

// Expose returns the client-facing name of a target's tool or prompt.
func (d *Document) Expose(target, name string) string {
	if d.ToolNaming == NamingNative {
		return name
	}
	return ExposedName(target, name)
}

// HasCapability reports whether the target advertised capability c at approval.
func (t *Target) HasCapability(c string) bool {
	for _, x := range t.Capabilities {
		if x == c {
			return true
		}
	}
	return false
}

// Target is one upstream MCP server with its pinned, approved tool catalog.
type Target struct {
	Name     string `json:"name"`
	ServerID string `json:"serverId"`
	Endpoint string `json:"endpoint"`
	// Network is the address class the registry approved for the endpoint: "public", "private"
	// (an exact host on the private allowlist) or "loopback" (development only). The gateway allows
	// dials to that class only (ADR-0001 D8).
	Network        string          `json:"network"`
	SnapshotDigest string          `json:"snapshotDigest"` // CatalogDigest(Tools, Prompts): the full approved catalog
	Tools          []server.Tool   `json:"tools"`          // native names
	Prompts        []server.Prompt `json:"prompts"`        // native names; pinned like tools (M3)
	// Capabilities the server advertised in server/discover at approval, limited to the federated
	// ones (tools, prompts, resources, completions). Prompts and resources are passed through live,
	// not pinned; grants decide who may use them.
	Capabilities []string `json:"capabilities"`
}

// Network classes of a target.
const (
	NetworkPublic   = "public"
	NetworkPrivate  = "private"
	NetworkLoopback = "loopback"
)

// Grant allows principals holding any of Roles to use, on Target: the listed Tools, the listed
// Prompts ("*" = all prompts of the target) and, if Resources, its resources and resource templates.
// The tenant is the release's tenant (ADR-0001 D6).
type Grant struct {
	Target    string   `json:"target"`
	Tools     []string `json:"tools"`
	Prompts   []string `json:"prompts,omitempty"`
	Resources bool     `json:"resources,omitempty"`
	Roles     []string `json:"roles"`
}

// Auth is the data-plane authentication profile.
type Auth struct {
	Mode    string   `json:"mode"` // "api-key" or "jwt"
	APIKeys []APIKey `json:"apiKeys,omitempty"`
	JWT     *JWT     `json:"jwt,omitempty"`
}

// APIKey maps a key (stored as SHA-256 hex only) to a principal.
type APIKey struct {
	ID      string   `json:"id"`
	Subject string   `json:"subject"`
	Roles   []string `json:"roles"`
	SHA256  string   `json:"sha256"`
}

// JWT configures bearer token validation and RFC 9728 protected resource metadata.
type JWT struct {
	Issuer string `json:"issuer"`
	// Resource is the canonical MCP resource URI (the gateway's public /mcp URL); tokens must name it
	// in aud (RFC 8707 audience binding).
	Resource             string   `json:"resource"`
	JWKSURL              string   `json:"jwksUrl"`
	AuthorizationServers []string `json:"authorizationServers"`
	TenantClaim          string   `json:"tenantClaim"`
	RolesClaim           string   `json:"rolesClaim"`
}

// Envelope is what is stored and distributed: the document plus its digest.
type Envelope struct {
	Digest   string          `json:"digest"`
	Document json.RawMessage `json:"document"`
}

// Seal computes the digest of a validated document and wraps it.
func Seal(d *Document) (*Envelope, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	raw, err := Canonical(d)
	if err != nil {
		return nil, err
	}
	digest, err := Digest(json.RawMessage(raw))
	if err != nil {
		return nil, err
	}
	return &Envelope{Digest: digest, Document: raw}, nil
}

// Open verifies an envelope's digest and validates its document. A gateway runs nothing else.
func Open(e *Envelope) (*Document, error) {
	digest, err := Digest(e.Document)
	if err != nil {
		return nil, fmt.Errorf("release document is not JSON: %w", err)
	}
	if digest != e.Digest {
		return nil, errors.New("release digest does not match its document")
	}
	var d Document
	dec := json.NewDecoder(strings.NewReader(string(e.Document)))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("release document: %w", err)
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// ExposedName is the tool name clients see.
func ExposedName(target, tool string) string { return target + Separator + tool }

// CatalogDigest is the snapshot digest of a server's approved catalog: its tools and its prompts.
func CatalogDigest(tools []server.Tool, prompts []server.Prompt) (string, error) {
	if tools == nil {
		tools = []server.Tool{}
	}
	if prompts == nil {
		prompts = []server.Prompt{}
	}
	return Digest(map[string]any{"tools": tools, "prompts": prompts})
}

// SplitExposedName reverses ExposedName. Target names never contain '_', so the first separator is
// the boundary.
func SplitExposedName(name string) (target, tool string, ok bool) {
	i := strings.Index(name, Separator)
	if i <= 0 || i+len(Separator) >= len(name) {
		return "", "", false
	}
	return name[:i], name[i+len(Separator):], true
}

// Validate checks the internal consistency of a document. It fails closed on anything a gateway
// could misinterpret.
func (d *Document) Validate() error {
	var errs []string
	bad := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	if d.SchemaVersion != SchemaVersion {
		bad("schemaVersion must be %s", SchemaVersion)
	}
	if d.ReleaseID == "" || d.TenantID == "" || d.GatewayID == "" || d.CreatedBy == "" || d.CreatedAt == "" {
		bad("releaseId, tenantId, gatewayId, createdAt and createdBy are required")
	}
	if d.DriftAction != "block" && d.DriftAction != "report" {
		bad("driftAction must be block or report")
	}
	if d.ToolNaming != NamingPrefixed && d.ToolNaming != NamingNative {
		bad("toolNaming must be prefixed or native")
	}
	exposed := map[string]string{}        // exposed tool name -> target
	exposedPrompts := map[string]string{} // exposed prompt name -> target
	prompts := map[string]map[string]bool{}
	caps := map[string]map[string]bool{}
	tools := map[string]map[string]bool{}
	for _, t := range d.Targets {
		if !ValidTargetName(t.Name) {
			bad("target name %q is invalid", t.Name)
			continue
		}
		if tools[t.Name] != nil {
			bad("duplicate target %q", t.Name)
			continue
		}
		u, err := url.Parse(t.Endpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			bad("target %s: endpoint must be an http(s) URL without credentials, query or fragment", t.Name)
		}
		if t.ServerID == "" {
			bad("target %s: serverId is required", t.Name)
		}
		if t.Network != NetworkPublic && t.Network != NetworkPrivate && t.Network != NetworkLoopback {
			bad("target %s: network must be public, private or loopback", t.Name)
		}
		if dg, err := CatalogDigest(t.Tools, t.Prompts); err != nil || dg != t.SnapshotDigest {
			bad("target %s: tools and prompts do not match snapshotDigest", t.Name)
		}
		caps[t.Name] = map[string]bool{}
		for _, c := range t.Capabilities {
			if c != CapTools && c != CapPrompts && c != CapResources && c != CapCompletions {
				bad("target %s: unknown capability %q", t.Name, c)
			}
			caps[t.Name][c] = true
		}
		tools[t.Name] = map[string]bool{}
		for _, tool := range t.Tools {
			if !ValidToolName(tool.Name) || !ValidToolName(ExposedName(t.Name, tool.Name)) {
				bad("target %s: tool name %q is invalid", t.Name, tool.Name)
			}
			if tools[t.Name][tool.Name] {
				bad("target %s: duplicate tool %q", t.Name, tool.Name)
			}
			if other, dup := exposed[d.Expose(t.Name, tool.Name)]; dup && other != t.Name {
				bad("tool name %q is exposed by targets %s and %s; use prefixed naming", tool.Name, other, t.Name)
			}
			exposed[d.Expose(t.Name, tool.Name)] = t.Name
			if tool.InputSchema == nil {
				bad("target %s: tool %s has no inputSchema", t.Name, tool.Name)
			}
			tools[t.Name][tool.Name] = true
		}
		if len(t.Tools) == 0 {
			bad("target %s has no tools", t.Name)
		}
		prompts[t.Name] = map[string]bool{}
		if len(t.Prompts) > 0 && !caps[t.Name][CapPrompts] {
			bad("target %s pins prompts without the prompts capability", t.Name)
		}
		for _, p := range t.Prompts {
			if !ValidToolName(p.Name) || !ValidToolName(d.Expose(t.Name, p.Name)) || prompts[t.Name][p.Name] {
				bad("target %s: prompt name %q is invalid or duplicated", t.Name, p.Name)
			}
			prompts[t.Name][p.Name] = true
			if other, dup := exposedPrompts[d.Expose(t.Name, p.Name)]; dup && other != t.Name {
				bad("prompt name %q is exposed by targets %s and %s; use prefixed naming", p.Name, other, t.Name)
			}
			exposedPrompts[d.Expose(t.Name, p.Name)] = t.Name
		}
	}
	for i, g := range d.Grants {
		if tools[g.Target] == nil {
			bad("grant %d: unknown target %q", i, g.Target)
			continue
		}
		if len(g.Roles) == 0 || (len(g.Tools) == 0 && len(g.Prompts) == 0 && !g.Resources) {
			bad("grant %d: roles and at least one of tools, prompts or resources are required", i)
		}
		if len(g.Prompts) > 0 && !caps[g.Target][CapPrompts] {
			bad("grant %d: target %s does not offer prompts", i, g.Target)
		}
		if g.Resources && !caps[g.Target][CapResources] {
			bad("grant %d: target %s does not offer resources", i, g.Target)
		}
		for _, p := range g.Prompts {
			if p != "*" && !prompts[g.Target][p] {
				bad("grant %d: target %s has no pinned prompt %q", i, g.Target, p)
			}
		}
		for _, tool := range g.Tools {
			if !tools[g.Target][tool] {
				bad("grant %d: target %s has no tool %q", i, g.Target, tool)
			}
		}
		for _, r := range g.Roles {
			if !roleRE.MatchString(r) {
				bad("grant %d: invalid role %q", i, r)
			}
		}
	}
	switch d.Auth.Mode {
	case "api-key":
		if len(d.Auth.APIKeys) == 0 || d.Auth.JWT != nil {
			bad("api-key auth needs at least one key and no jwt profile")
		}
		seen := map[string]bool{}
		for _, k := range d.Auth.APIKeys {
			if k.ID == "" || k.Subject == "" || !sha256HexRE.MatchString(k.SHA256) || seen[k.SHA256] {
				bad("api key %q: id, subject and a unique sha256 are required", k.ID)
			}
			seen[k.SHA256] = true
		}
	case "jwt":
		j := d.Auth.JWT
		if j == nil || len(d.Auth.APIKeys) > 0 {
			bad("jwt auth needs a jwt profile and no api keys")
			break
		}
		for name, v := range map[string]string{"issuer": j.Issuer, "resource": j.Resource, "jwksUrl": j.JWKSURL} {
			if u, err := url.Parse(v); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Fragment != "" {
				bad("jwt %s must be an absolute http(s) URL", name)
			}
		}
		if j.TenantClaim == "" || j.RolesClaim == "" || len(j.AuthorizationServers) == 0 {
			bad("jwt tenantClaim, rolesClaim and authorizationServers are required")
		}
	default:
		bad("auth mode must be api-key or jwt")
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("invalid release: %s", strings.Join(errs, "; "))
	}
	return nil
}
