// Package federation turns upstream MCP tool catalogs into the normalized form that is pinned in a
// release, and compares live catalogs with pinned ones (drift, ADR-0001 D3). The registry service
// (when it snapshots a server) and the gateway (when it checks drift) use the same normalization, so
// their digests agree by construction.
package federation

import (
	"encoding/json"
	"fmt"
	"sort"
	"unicode/utf8"

	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
)

// Limits on an upstream catalog.
const (
	MaxTools        = 500
	MaxDescription  = 4096
	MaxTitle        = 256
	MaxSchemaBytes  = 64 << 10
	MaxCatalogPages = 20
)

// NormalizeTools validates an upstream catalog and returns it in pinned form, sorted by name. Every
// field of a tool is kept (see server.Tool). Invalid catalogs are refused rather than repaired: a
// truncated description would pin something the upstream never said.
func NormalizeTools(raws []json.RawMessage) ([]server.Tool, error) {
	if len(raws) == 0 {
		return nil, fmt.Errorf("catalog is empty")
	}
	if len(raws) > MaxTools {
		return nil, fmt.Errorf("catalog has %d tools, more than %d", len(raws), MaxTools)
	}
	seen := map[string]bool{}
	out := make([]server.Tool, 0, len(raws))
	for _, raw := range raws {
		if len(raw) > MaxSchemaBytes*4 {
			return nil, fmt.Errorf("a tool definition exceeds %d bytes", MaxSchemaBytes*4)
		}
		var t server.Tool
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("tool entry: %w", err)
		}
		if !release.ValidToolName(t.Name) {
			return nil, fmt.Errorf("tool name %q is invalid", t.Name)
		}
		if seen[t.Name] {
			return nil, fmt.Errorf("duplicate tool %q", t.Name)
		}
		seen[t.Name] = true
		if !utf8.ValidString(t.Description) || len(t.Description) > MaxDescription || len(t.Title) > MaxTitle {
			return nil, fmt.Errorf("tool %s: title or description too long or not UTF-8", t.Name)
		}
		if t.InputSchema == nil {
			return nil, fmt.Errorf("tool %s: inputSchema is required", t.Name)
		}
		for what, v := range map[string]any{"inputSchema": t.InputSchema, "outputSchema": t.OutputSchema, "annotations": t.Annotations} {
			if b, _ := json.Marshal(v); len(b) > MaxSchemaBytes {
				return nil, fmt.Errorf("tool %s: %s exceeds %d bytes", t.Name, what, MaxSchemaBytes)
			}
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// MaxPrompts bounds a pinned prompt catalog.
const MaxPrompts = 500

// NormalizePrompts validates an upstream prompt catalog and returns it in pinned form, sorted by
// name. An empty catalog is valid (a server may offer the capability without prompts).
func NormalizePrompts(raws []json.RawMessage) ([]server.Prompt, error) {
	if len(raws) > MaxPrompts {
		return nil, fmt.Errorf("catalog has %d prompts, more than %d", len(raws), MaxPrompts)
	}
	seen := map[string]bool{}
	out := make([]server.Prompt, 0, len(raws))
	for _, raw := range raws {
		if len(raw) > MaxSchemaBytes {
			return nil, fmt.Errorf("a prompt definition exceeds %d bytes", MaxSchemaBytes)
		}
		var p server.Prompt
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("prompt entry: %w", err)
		}
		if !release.ValidToolName(p.Name) || seen[p.Name] {
			return nil, fmt.Errorf("prompt name %q is invalid or duplicated", p.Name)
		}
		seen[p.Name] = true
		if !utf8.ValidString(p.Description) || len(p.Description) > MaxDescription || len(p.Title) > MaxTitle || len(p.Arguments) > 64 {
			return nil, fmt.Errorf("prompt %s: title, description or arguments too long", p.Name)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ToolsDigest is the snapshot digest of a server that pins tools only.
func ToolsDigest(tools []server.Tool) (string, error) { return release.CatalogDigest(tools, nil) }

// CatalogDigest is the snapshot digest of a normalized catalog (tools and prompts).
func CatalogDigest(tools []server.Tool, prompts []server.Prompt) (string, error) {
	return release.CatalogDigest(tools, prompts)
}

// Capabilities maps a server/discover capability object to the federated capability names a release
// records for the target (release.Cap*), sorted.
func Capabilities(caps map[string]any) []string {
	var out []string
	for _, c := range []string{release.CapTools, release.CapPrompts, release.CapResources, release.CapCompletions} {
		if _, ok := caps[c]; ok {
			out = append(out, c)
		}
	}
	if res, ok := caps["resources"].(map[string]any); ok {
		if v, _ := res["subscribe"].(bool); v {
			out = append(out, release.CapResourcesSubscribe)
		}
		if v, _ := res["listChanged"].(bool); v {
			out = append(out, release.CapResourcesListChanged)
		}
	}
	if ext, ok := caps["extensions"].(map[string]any); ok {
		if _, ok := ext[release.TasksExtensionID]; ok {
			out = append(out, release.CapTasks)
		}
	}
	sort.Strings(out)
	return out
}
