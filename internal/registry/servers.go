package registry

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"idp-mcp/adapters/store/postgres"
	"idp-mcp/internal/audit"
	"idp-mcp/internal/client"
	"idp-mcp/internal/federation"
	"idp-mcp/internal/policy"
	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
)

// Service is the registry.
type Service struct {
	Store         *postgres.Store
	Policy        *policy.Upstream // registration policy; also the discovery client's dial policy
	Upstream      *client.Client
	DeployTimeout time.Duration
	PollEvery     time.Duration
	// StaleAfter: an instance whose last heartbeat is older than this no longer counts for
	// attestation (default 30s); instances silent for a day are forgotten.
	StaleAfter time.Duration
	Log        *slog.Logger
}

func (s *Service) staleAfter() time.Duration {
	if s.StaleAfter > 0 {
		return s.StaleAfter
	}
	return 30 * time.Second
}

var roleRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

const serverColumns = `s.id::text, s.target_name, s.display_name, s.endpoint, s.network, s.identity, s.lifecycle,
  s.snapshot_id::text, s.approved_snapshot_id::text, ls.digest, aps.digest,
  coalesce((SELECT array_agg(t->>'name' ORDER BY t->>'name') FROM jsonb_array_elements(ls.tools::jsonb) t), '{}'),
  coalesce((SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(coalesce(ls.discovery->'capabilities', '{}'::jsonb)) k
            WHERE k IN ('tools', 'prompts', 'resources', 'completions')), '{}'),
  s.created_by, s.approved_by, s.created_at
FROM servers s LEFT JOIN snapshots ls ON ls.id = s.snapshot_id LEFT JOIN snapshots aps ON aps.id = s.approved_snapshot_id`

func scanServer(row pgx.Row) (*Server, error) {
	var s Server
	err := row.Scan(&s.ID, &s.TargetName, &s.DisplayName, &s.Endpoint, &s.Network, &s.Identity, &s.Lifecycle, &s.SnapshotID,
		&s.ApprovedSnapshotID, &s.SnapshotDigest, &s.ApprovedDigest, &s.ToolNames, &s.Capabilities, &s.CreatedBy, &s.ApprovedBy, &s.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	return &s, err
}

func getServer(ctx context.Context, tx pgx.Tx, id string, lock bool) (*Server, error) {
	if !isUUID(id) {
		return nil, errNotFound
	}
	q := `SELECT ` + serverColumns + ` WHERE s.id = $1`
	if lock {
		q += ` FOR UPDATE OF s`
	}
	return scanServer(tx.QueryRow(ctx, q, id))
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func isUUID(s string) bool { return uuidRE.MatchString(s) }

// RegisterInput registers a server.
type RegisterInput struct {
	DisplayName string `json:"displayName"`
	TargetName  string `json:"targetName"`
	Endpoint    string `json:"endpoint"`
	// Identity "forward" has the gateway pass the verified caller to this server with every call (the server
	// then knows who is asking); the default "none" passes nothing. It is fixed at registration and reviewed
	// with the release.
	Identity string `json:"identity,omitempty"`
}

// RegisterServer adds a DRAFT server after the endpoint passed the upstream policy.
func (s *Service) RegisterServer(ctx context.Context, p Principal, in RegisterInput) (*Server, error) {
	if err := require(p, RoleOperator); err != nil {
		return nil, err
	}
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if !release.ValidTargetName(in.TargetName) {
		return nil, fail(http.StatusBadRequest, "targetName must match [a-z0-9-], 1-40 chars, no leading/trailing '-'")
	}
	if in.DisplayName == "" || len(in.DisplayName) > 120 {
		return nil, fail(http.StatusBadRequest, "displayName must be 1-120 characters")
	}
	if in.Identity == "" {
		in.Identity = release.IdentityNone
	}
	if in.Identity != release.IdentityNone && in.Identity != release.IdentityForward {
		return nil, fail(http.StatusBadRequest, "identity must be none or forward")
	}
	u, err := s.Policy.CheckEndpoint(ctx, in.Endpoint)
	if err != nil {
		return nil, fail(http.StatusBadRequest, "%s", err.Error())
	}
	id := NewID()
	var out *Server
	err = s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO servers (id, tenant_id, target_name, display_name, endpoint, network, identity, lifecycle, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'DRAFT', $8)`, id, p.Tenant, in.TargetName, in.DisplayName, u.String(), s.Policy.NetworkOf(u), in.Identity, p.Subject); err != nil {
			if strings.Contains(err.Error(), "duplicate key") {
				return fail(http.StatusConflict, "a server with this targetName or endpoint is already registered")
			}
			return err
		}
		if err := audit.Write(ctx, tx, p.Tenant, p.Subject, "server.register", id, map[string]string{"endpoint": client.Redact(u.String()), "targetName": in.TargetName, "identity": in.Identity}); err != nil {
			return err
		}
		var err error
		out, err = getServer(ctx, tx, id, false)
		return err
	})
	return out, err
}

// ListServers lists the tenant's servers.
func (s *Service) ListServers(ctx context.Context, p Principal) ([]Server, error) {
	var out []Server
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+serverColumns+` ORDER BY s.created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			sv, err := scanServer(rows)
			if err != nil {
				return err
			}
			out = append(out, *sv)
		}
		return rows.Err()
	})
	return orEmpty(out), err
}

// GetServer returns one server.
func (s *Service) GetServer(ctx context.Context, p Principal, id string) (*Server, error) {
	var out *Server
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) (err error) {
		out, err = getServer(ctx, tx, id, false)
		return err
	})
	return out, err
}

// DiscoverServer snapshots the server's live catalog. A catalog that differs from the approved one
// sends the server back to REVIEWED; existing releases keep the snapshot they pinned.
func (s *Service) DiscoverServer(ctx context.Context, p Principal, id string) (*Server, error) {
	if err := require(p, RoleOperator); err != nil {
		return nil, err
	}
	sv, err := s.GetServer(ctx, p, id)
	if err != nil {
		return nil, err
	}
	if sv.Lifecycle == "RETIRED" {
		return nil, fail(http.StatusConflict, "server is retired")
	}
	if _, err := s.Policy.CheckEndpoint(ctx, sv.Endpoint); err != nil { // the policy may have tightened
		return nil, fail(http.StatusConflict, "%s", err.Error())
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	disc, err := s.Upstream.Discover(dctx, sv.Endpoint)
	if err != nil {
		return nil, fail(http.StatusBadGateway, "discovery failed: %s", err.Error())
	}
	raws, err := s.Upstream.ListTools(dctx, sv.Endpoint)
	if err != nil {
		return nil, fail(http.StatusBadGateway, "tools/list failed: %s", err.Error())
	}
	tools, err := federation.NormalizeTools(raws)
	if err != nil {
		return nil, fail(http.StatusUnprocessableEntity, "catalog refused: %s", err.Error())
	}
	var prompts []server.Prompt
	if _, ok := disc.Capabilities[release.CapPrompts]; ok {
		praws, err := s.Upstream.ListPrompts(dctx, sv.Endpoint)
		if err != nil {
			return nil, fail(http.StatusBadGateway, "prompts/list failed: %s", err.Error())
		}
		if prompts, err = federation.NormalizePrompts(praws); err != nil {
			return nil, fail(http.StatusUnprocessableEntity, "prompt catalog refused: %s", err.Error())
		}
	}
	var resources []server.Resource
	var templates []server.ResourceTemplate
	if _, ok := disc.Capabilities[release.CapResources]; ok {
		rraws, err := s.Upstream.List(dctx, sv.Endpoint, "resources/list", "resources")
		if err != nil {
			return nil, fail(http.StatusBadGateway, "resources/list failed: %s", err.Error())
		}
		if resources, err = federation.NormalizeResources(rraws); err != nil {
			return nil, fail(http.StatusUnprocessableEntity, "resource catalog refused: %s", err.Error())
		}
		traws, err := s.Upstream.List(dctx, sv.Endpoint, "resources/templates/list", "resourceTemplates")
		if err != nil {
			return nil, fail(http.StatusBadGateway, "resources/templates/list failed: %s", err.Error())
		}
		if templates, err = federation.NormalizeResourceTemplates(traws); err != nil {
			return nil, fail(http.StatusUnprocessableEntity, "resource template catalog refused: %s", err.Error())
		}
	}
	if err := s.checkSchemas(tools); err != nil {
		return nil, fail(http.StatusUnprocessableEntity, "catalog refused: %s", err.Error())
	}
	digest, _ := release.Catalog{Tools: tools, Prompts: prompts, Resources: resources, ResourceTemplates: templates}.Digest()
	if resources == nil {
		resources = []server.Resource{}
	}
	if templates == nil {
		templates = []server.ResourceTemplate{}
	}
	resourcesJSON, _ := release.Canonical(resources)
	templatesJSON, _ := release.Canonical(templates)
	discovery, _ := json.Marshal(map[string]any{"supportedVersions": disc.SupportedVersions, "capabilities": disc.Capabilities, "serverInfo": disc.ServerInfo()})
	toolsJSON, _ := release.Canonical(tools)
	if prompts == nil {
		prompts = []server.Prompt{}
	}
	promptsJSON, _ := release.Canonical(prompts)
	var out *Server
	err = s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		cur, err := getServer(ctx, tx, id, true)
		if err != nil {
			return err
		}
		snap := NewID()
		if _, err := tx.Exec(ctx, `INSERT INTO snapshots (id, tenant_id, server_id, digest, discovery, tools, prompts, resources, resource_templates)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			snap, p.Tenant, id, digest, discovery, string(toolsJSON), string(promptsJSON), string(resourcesJSON), string(templatesJSON)); err != nil {
			return err
		}
		lifecycle := "REVIEWED"
		if cur.Lifecycle == "APPROVED" && cur.ApprovedDigest != nil && *cur.ApprovedDigest == digest {
			lifecycle = "APPROVED" // unchanged catalog: no re-approval needed
		}
		if _, err := tx.Exec(ctx, `UPDATE servers SET snapshot_id = $2, lifecycle = $3, updated_at = now() WHERE id = $1`, id, snap, lifecycle); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, p.Tenant, p.Subject, "server.discover", id, map[string]any{"digest": digest, "tools": len(tools), "prompts": len(prompts),
			"resources": len(resources), "resourceTemplates": len(templates), "lifecycle": lifecycle}); err != nil {
			return err
		}
		out, err = getServer(ctx, tx, id, false)
		return err
	})
	return out, err
}

// ApproveServer approves the latest snapshot (four-eyes).
func (s *Service) ApproveServer(ctx context.Context, p Principal, id string) (*Server, error) {
	if err := require(p, RoleReviewer); err != nil {
		return nil, err
	}
	var out *Server
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		sv, err := getServer(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if sv.Lifecycle != "REVIEWED" || sv.SnapshotID == nil {
			return fail(http.StatusConflict, "only a REVIEWED server with a snapshot can be approved (is %s)", sv.Lifecycle)
		}
		if err := fourEyes(p, sv.CreatedBy); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE servers SET lifecycle = 'APPROVED', approved_snapshot_id = snapshot_id, approved_by = $2, updated_at = now() WHERE id = $1`, id, p.Subject); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, p.Tenant, p.Subject, "server.approve", id, map[string]any{"digest": *sv.SnapshotDigest}); err != nil {
			return err
		}
		out, err = getServer(ctx, tx, id, false)
		return err
	})
	return out, err
}

// checkSchemas refuses a catalog whose input schemas the gateway could not enforce (M3).
func (s *Service) checkSchemas(tools []server.Tool) error {
	_, err := policy.CompileToolSchemas(tools, func(n string) string { return n })
	return err
}

// ---- grants ----------------------------------------------------------------------------------

// GrantInput proposes a grant: tools by name, prompts by name or "*", and/or the server's resources.
type GrantInput struct {
	ServerID  string   `json:"serverId"`
	Tools     []string `json:"tools"`
	Prompts   []string `json:"prompts"`
	Resources bool     `json:"resources"`
	Roles     []string `json:"roles"`
}

const grantColumns = `id::text, server_id::text, tools, prompts, resources, roles, status, created_by, decided_by, created_at, decided_at FROM grants`

func scanGrant(row pgx.Row) (*Grant, error) {
	var g Grant
	err := row.Scan(&g.ID, &g.ServerID, &g.Tools, &g.Prompts, &g.Resources, &g.Roles, &g.Status, &g.CreatedBy, &g.DecidedBy, &g.CreatedAt, &g.DecidedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	return &g, err
}

// approvedCatalog returns the tool names, prompt names and federated capabilities of a server's
// approved snapshot.
func approvedCatalog(ctx context.Context, tx pgx.Tx, serverID string) (tools, prompts, caps map[string]bool, err error) {
	var names, promptNames, capList []string
	err = tx.QueryRow(ctx, `SELECT coalesce((SELECT array_agg(t->>'name') FROM jsonb_array_elements(sn.tools::jsonb) t), '{}'),
		coalesce((SELECT array_agg(t->>'name') FROM jsonb_array_elements(sn.prompts::jsonb) t), '{}'),
		coalesce((SELECT array_agg(k) FROM jsonb_object_keys(coalesce(sn.discovery->'capabilities', '{}'::jsonb)) k), '{}')
		FROM servers s JOIN snapshots sn ON sn.id = s.approved_snapshot_id WHERE s.id = $1 AND s.lifecycle = 'APPROVED'`, serverID).Scan(&names, &promptNames, &capList)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil, fail(http.StatusConflict, "server is not approved")
	}
	set := func(xs []string) map[string]bool {
		m := map[string]bool{}
		for _, x := range xs {
			m[x] = true
		}
		return m
	}
	return set(names), set(promptNames), set(capList), err
}

func cleanList(in []string, valid func(string) bool, what string) ([]string, error) {
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if !valid(v) {
			return nil, fail(http.StatusBadRequest, "invalid %s %q", what, v)
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, fail(http.StatusBadRequest, "%s must not be empty", what)
	}
	slices.Sort(out)
	return out, nil
}

// ProposeGrant proposes access for roles to tools of an approved server.
func (s *Service) ProposeGrant(ctx context.Context, p Principal, in GrantInput) (*Grant, error) {
	if err := require(p, RoleOperator); err != nil {
		return nil, err
	}
	tools, err := optionalList(in.Tools, release.ValidToolName, "tools")
	if err != nil {
		return nil, err
	}
	prompts, err := optionalList(in.Prompts, func(p string) bool { return p == "*" || release.ValidToolName(p) }, "prompts")
	if err != nil {
		return nil, err
	}
	if len(tools) == 0 && len(prompts) == 0 && !in.Resources {
		return nil, fail(http.StatusBadRequest, "a grant needs tools, prompts or resources")
	}
	roles, err := cleanList(in.Roles, roleRE.MatchString, "roles")
	if err != nil {
		return nil, err
	}
	if !isUUID(in.ServerID) {
		return nil, errNotFound
	}
	var out *Grant
	err = s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		have, havePrompts, caps, err := approvedCatalog(ctx, tx, in.ServerID)
		if err != nil {
			return err
		}
		for _, pn := range prompts {
			if pn != "*" && !havePrompts[pn] {
				return fail(http.StatusBadRequest, "the approved snapshot has no prompt %q", pn)
			}
		}
		for _, t := range tools {
			if !have[t] {
				return fail(http.StatusBadRequest, "the approved snapshot has no tool %q", t)
			}
		}
		if len(prompts) > 0 && !caps[release.CapPrompts] {
			return fail(http.StatusBadRequest, "the server does not offer prompts")
		}
		if in.Resources && !caps[release.CapResources] {
			return fail(http.StatusBadRequest, "the server does not offer resources")
		}
		id := NewID()
		if _, err := tx.Exec(ctx, `INSERT INTO grants (id, tenant_id, server_id, tools, prompts, resources, roles, status, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'PROPOSED', $8)`,
			id, p.Tenant, in.ServerID, tools, prompts, in.Resources, roles, p.Subject); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, p.Tenant, p.Subject, "grant.propose", id, map[string]any{"serverId": in.ServerID, "tools": tools,
			"prompts": prompts, "resources": in.Resources, "roles": roles}); err != nil {
			return err
		}
		out, err = scanGrant(tx.QueryRow(ctx, `SELECT `+grantColumns+` WHERE id = $1`, id))
		return err
	})
	return out, err
}

func (s *Service) decideGrant(ctx context.Context, p Principal, id, from, to, action string) (*Grant, error) {
	if !isUUID(id) {
		return nil, errNotFound
	}
	var out *Grant
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		g, err := scanGrant(tx.QueryRow(ctx, `SELECT `+grantColumns+` WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if !strings.Contains(from, g.Status) {
			return fail(http.StatusConflict, "grant is %s", g.Status)
		}
		if to == "APPROVED" {
			if err := fourEyes(p, g.CreatedBy); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE grants SET status = $2, decided_by = $3, decided_at = now() WHERE id = $1`, id, to, p.Subject); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, p.Tenant, p.Subject, action, id, nil); err != nil {
			return err
		}
		out, err = scanGrant(tx.QueryRow(ctx, `SELECT `+grantColumns+` WHERE id = $1`, id))
		return err
	})
	return out, err
}

// ApproveGrant approves a proposed grant (four-eyes).
func (s *Service) ApproveGrant(ctx context.Context, p Principal, id string) (*Grant, error) {
	if err := require(p, RoleReviewer); err != nil {
		return nil, err
	}
	return s.decideGrant(ctx, p, id, "PROPOSED", "APPROVED", "grant.approve")
}

// RevokeGrant revokes a grant; it disappears from the next release.
func (s *Service) RevokeGrant(ctx context.Context, p Principal, id string) (*Grant, error) {
	if err := require(p, RoleReviewer, RoleAdmin); err != nil {
		return nil, err
	}
	return s.decideGrant(ctx, p, id, "PROPOSED APPROVED", "REVOKED", "grant.revoke")
}

// ListGrants lists the tenant's grants.
func (s *Service) ListGrants(ctx context.Context, p Principal) ([]Grant, error) {
	var out []Grant
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+grantColumns+` ORDER BY created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g, err := scanGrant(rows)
			if err != nil {
				return err
			}
			out = append(out, *g)
		}
		return rows.Err()
	})
	return orEmpty(out), err
}

func optionalList(in []string, valid func(string) bool, what string) ([]string, error) {
	if len(in) == 0 {
		return []string{}, nil
	}
	return cleanList(in, valid, what)
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// toolsOf decodes a stored, normalized catalog.
func toolsOf(raw []byte) ([]server.Tool, error) {
	var tools []server.Tool
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	return tools, dec.Decode(&tools)
}
