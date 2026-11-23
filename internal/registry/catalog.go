package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"

	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
)

// The reviewer's view of a server's catalog (ADR-0001 D53). What a reviewer approves is the catalog: the names,
// descriptions, input schemas and annotations of what the gateway will let callers use, which is also what the
// model of every caller will read. A description is an instruction to a model, so a reviewer who is shown only the
// names has not reviewed it. The view therefore returns every tool, prompt and resource as it is pinned, and, for a
// catalog that differs from the approved one, what changed.

// CatalogSnapshot is one snapshot of a server's catalog, complete.
type CatalogSnapshot struct {
	SnapshotID        string                    `json:"snapshotId"`
	Digest            string                    `json:"digest"`
	CreatedAt         time.Time                 `json:"createdAt"`
	Tools             []server.Tool             `json:"tools"`
	Prompts           []server.Prompt           `json:"prompts"`
	Resources         []server.Resource         `json:"resources"`
	ResourceTemplates []server.ResourceTemplate `json:"resourceTemplates"`
	// DescriptionLimit is the limit, in bytes, that the catalog was checked against (external servers only; null for an
	// internal server and for a snapshot taken before ADR-0001 15.3). Approving the snapshot pins it.
	DescriptionLimit *int `json:"descriptionLimit"`
}

// DescriptionLimit is what the reviewer of an external server's catalog is told about the limit on its descriptions.
type DescriptionLimit struct {
	Bytes             int  `json:"bytes"`             // what applies to this server now
	DeploymentDefault int  `json:"deploymentDefault"` // IDP_EXTERNAL_MAX_DESCRIPTION
	Cap               int  `json:"cap"`               // IDP_EXTERNAL_MAX_DESCRIPTION_CAP
	ServerSetting     *int `json:"serverSetting"`     // the operator's value for this server; null = the default
}

// Change is one entry of a catalog that was added, removed or changed since the approved snapshot. Fields names
// what changed in a changed entry, by its JSON key (description, inputSchema, annotations, title, outputSchema, _meta,
// ...), so that a reviewer can look first at what matters.
type Change struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"` // added, removed, changed
	Fields []string `json:"fields,omitempty"`
}

// CatalogChanges is the difference between the latest snapshot and the approved one. With nothing approved yet,
// every entry is added.
type CatalogChanges struct {
	Tools             []Change `json:"tools"`
	Prompts           []Change `json:"prompts"`
	Resources         []Change `json:"resources"`
	ResourceTemplates []Change `json:"resourceTemplates"`
	Identical         bool     `json:"identical"`
}

// CatalogView is what a reviewer reads before approving a server or a new catalog of it.
type CatalogView struct {
	ServerID   string `json:"serverId"`
	TargetName string `json:"targetName"`
	Class      string `json:"class"`
	// DescriptionLimit is set for a server of class external: "descriptions allowed up to Bytes bytes (deployment
	// default DeploymentDefault)". Null for an internal server.
	DescriptionLimit *DescriptionLimit `json:"descriptionLimit"`
	Latest           *CatalogSnapshot  `json:"latest"`   // what approval would approve; null before the first discovery
	Approved         *CatalogSnapshot  `json:"approved"` // what the gateways run now; null before the first approval
	Changes          CatalogChanges    `json:"changes"`
}

func loadSnapshot(ctx context.Context, tx pgx.Tx, id *string) (*CatalogSnapshot, error) {
	if id == nil {
		return nil, nil
	}
	var snap CatalogSnapshot
	var tools, prompts, resources, templates string
	if err := tx.QueryRow(ctx, `SELECT id::text, digest, created_at, tools, prompts, resources, resource_templates, description_limit FROM snapshots WHERE id = $1`, *id).
		Scan(&snap.SnapshotID, &snap.Digest, &snap.CreatedAt, &tools, &prompts, &resources, &templates, &snap.DescriptionLimit); err != nil {
		return nil, err
	}
	var err error
	if snap.Tools, err = toolsOf([]byte(tools)); err != nil {
		return nil, err
	}
	for _, pair := range []struct {
		raw  string
		into any
	}{{prompts, &snap.Prompts}, {resources, &snap.Resources}, {templates, &snap.ResourceTemplates}} {
		if err := json.Unmarshal([]byte(pair.raw), pair.into); err != nil {
			return nil, err
		}
	}
	return &snap, nil
}

// GetCatalog returns the reviewer's view of a server (any administrator may read it).
func (s *Service) GetCatalog(ctx context.Context, p Principal, id string) (*CatalogView, error) {
	var out *CatalogView
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		sv, err := getServer(ctx, tx, id, false)
		if err != nil {
			return err
		}
		v := &CatalogView{ServerID: sv.ID, TargetName: sv.TargetName, Class: sv.Class}
		if sv.Class == release.ClassExternal {
			v.DescriptionLimit = &DescriptionLimit{Bytes: s.descriptionLimitOf(sv), DeploymentDefault: s.maxDescription(), Cap: s.descriptionCap(), ServerSetting: sv.MaxDescriptionBytes}
		}
		if v.Latest, err = loadSnapshot(ctx, tx, sv.SnapshotID); err != nil {
			return err
		}
		if v.Approved, err = loadSnapshot(ctx, tx, sv.ApprovedSnapshotID); err != nil {
			return err
		}
		v.Changes, err = diffCatalogs(v.Approved, v.Latest)
		out = v
		return err
	})
	return out, err
}

func orEmptySnap(s *CatalogSnapshot) CatalogSnapshot {
	if s == nil {
		return CatalogSnapshot{}
	}
	return *s
}

func diffCatalogs(approved, latest *CatalogSnapshot) (CatalogChanges, error) {
	a, l := orEmptySnap(approved), orEmptySnap(latest)
	var c CatalogChanges
	var err error
	if c.Tools, err = diffEntries(a.Tools, l.Tools, "name"); err != nil {
		return c, err
	}
	if c.Prompts, err = diffEntries(a.Prompts, l.Prompts, "name"); err != nil {
		return c, err
	}
	if c.Resources, err = diffEntries(a.Resources, l.Resources, "uri"); err != nil {
		return c, err
	}
	if c.ResourceTemplates, err = diffEntries(a.ResourceTemplates, l.ResourceTemplates, "uriTemplate"); err != nil {
		return c, err
	}
	c.Identical = approved != nil && latest != nil && approved.Digest == latest.Digest
	return c, nil
}

// diffEntries compares two lists of catalog entries keyed by the JSON field key, field by field on canonical JSON.
func diffEntries[T any](approved, latest []T, key string) ([]Change, error) {
	index := func(xs []T) (map[string]map[string]string, error) {
		out := map[string]map[string]string{}
		for _, x := range xs {
			raw, err := json.Marshal(x)
			if err != nil {
				return nil, err
			}
			var m map[string]json.RawMessage
			if err := json.Unmarshal(raw, &m); err != nil {
				return nil, err
			}
			var name string
			_ = json.Unmarshal(m[key], &name)
			fields := map[string]string{}
			for k, v := range m {
				c, err := release.Canonical(json.RawMessage(v))
				if err != nil {
					return nil, err
				}
				fields[k] = string(c)
			}
			out[name] = fields
		}
		return out, nil
	}
	a, err := index(approved)
	if err != nil {
		return nil, err
	}
	l, err := index(latest)
	if err != nil {
		return nil, err
	}
	out := []Change{}
	for name, lf := range l {
		af, had := a[name]
		if !had {
			out = append(out, Change{Name: name, Kind: "added"})
			continue
		}
		var changed []string
		for k, v := range lf {
			if af[k] != v {
				changed = append(changed, k)
			}
		}
		for k := range af {
			if _, ok := lf[k]; !ok {
				changed = append(changed, k)
			}
		}
		if len(changed) > 0 {
			sort.Strings(changed)
			out = append(out, Change{Name: name, Kind: "changed", Fields: changed})
		}
	}
	for name := range a {
		if _, ok := l[name]; !ok {
			out = append(out, Change{Name: name, Kind: "removed"})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Kind < out[j].Kind
	})
	return out, nil
}

// CheckExternalDescriptions refuses a catalog of an external server whose text could carry what the reviewer
// cannot be expected to see (ADR-0001 D53): a description or title longer than limit bytes, in a tool, a prompt, or
// anywhere in a tool's input or output schema, or text with a control character or an invisible one (zero-width,
// the tag characters, bidirectional overrides), which is how an instruction is hidden from a person and not from a
// model. The error names the tool and where.
func CheckExternalDescriptions(tools []server.Tool, prompts []server.Prompt, limit int) error {
	check := func(owner, where, text string) error {
		if len(text) > limit {
			return fmt.Errorf("%s: %s is %d bytes, more than the %d allowed for a server of class external", owner, where, len(text), limit)
		}
		for _, r := range text {
			if (unicode.IsControl(r) && r != '\n' && r != '\t' && r != '\r') || unicode.Is(unicode.Cf, r) {
				return fmt.Errorf("%s: %s has the invisible or control character U+%04X, which a class external server's text may not have", owner, where, r)
			}
		}
		return nil
	}
	var walk func(owner, where string, v any) error
	walk = func(owner, where string, v any) error {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if text, ok := x[k].(string); ok && (k == "description" || k == "title") {
					if err := check(owner, where+"/"+k, text); err != nil {
						return err
					}
				}
				if err := walk(owner, where+"/"+k, x[k]); err != nil {
					return err
				}
			}
		case []any:
			for i, e := range x {
				if err := walk(owner, fmt.Sprintf("%s/%d", where, i), e); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, t := range tools {
		owner := "tool " + t.Name
		for where, text := range map[string]string{"description": t.Description, "title": t.Title} {
			if err := check(owner, where, text); err != nil {
				return err
			}
		}
		if err := walk(owner, "inputSchema", map[string]any(t.InputSchema)); err != nil {
			return err
		}
		if t.OutputSchema != nil {
			if err := walk(owner, "outputSchema", map[string]any(t.OutputSchema)); err != nil {
				return err
			}
		}
		if t.Annotations != nil {
			if err := walk(owner, "annotations", map[string]any(t.Annotations)); err != nil {
				return err
			}
		}
	}
	for _, p := range prompts {
		for where, text := range map[string]string{"description": p.Description, "title": p.Title} {
			if err := check("prompt "+p.Name, where, text); err != nil {
				return err
			}
		}
	}
	return nil
}

// externalCapabilities removes from the capabilities of an external server's release target those that would
// have the gateway relay what the server pushes: tasks and resource subscriptions (ADR-0001 D51).
func externalCapabilities(caps []string) []string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		if c != release.CapTasks && c != release.CapResourcesSubscribe && c != release.CapResourcesListChanged {
			out = append(out, c)
		}
	}
	return out
}
