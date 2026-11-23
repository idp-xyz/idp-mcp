package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	// Bridges are the addresses of the bridge endpoints: a server registered at one must be of class external
	// (ADR-0001 D50). MaxExternalDescription bounds, in bytes, every description of an external server's catalog
	// (D51); zero means DefaultMaxExternalDescription.
	Bridges                policy.Endpoints
	MaxExternalDescription int
	// MaxExternalDescriptionCap is the most an operator may set for one server (maxDescriptionBytes); zero means
	// DefaultMaxExternalDescriptionCap (ADR-0001 15.3).
	MaxExternalDescriptionCap int
}

// DefaultMaxExternalDescriptionCap is the deployment's ceiling for a server's own limit.
const DefaultMaxExternalDescriptionCap = 8192

func (s *Service) descriptionCap() int {
	if s.MaxExternalDescriptionCap > 0 {
		return s.MaxExternalDescriptionCap
	}
	return DefaultMaxExternalDescriptionCap
}

// ValidateDescriptionLimits refuses a deployment whose default limit is above its cap.
func (s *Service) ValidateDescriptionLimits() error {
	if s.maxDescription() > s.descriptionCap() {
		return fmt.Errorf("the default description limit (%d bytes) is above the cap (%d bytes)", s.maxDescription(), s.descriptionCap())
	}
	return nil
}

// descriptionLimitOf is the limit that applies to a server: its own, else the deployment default.
func (s *Service) descriptionLimitOf(sv *Server) int {
	if sv.MaxDescriptionBytes != nil {
		return *sv.MaxDescriptionBytes
	}
	return s.maxDescription()
}

// checkDescriptionSetting refuses a per-server limit that is not allowed: for an internal server, not positive, or
// above the cap.
func (s *Service) checkDescriptionSetting(class string, n int) error {
	switch {
	case class != release.ClassExternal:
		return fail(http.StatusBadRequest, "maxDescriptionBytes is for a server of class external only")
	case n < 1:
		return fail(http.StatusBadRequest, "maxDescriptionBytes must be a positive number of bytes")
	case n > s.descriptionCap():
		return fail(http.StatusBadRequest, "maxDescriptionBytes %d is above the cap of %d bytes this deployment allows (IDP_EXTERNAL_MAX_DESCRIPTION_CAP)", n, s.descriptionCap())
	}
	return nil
}

// DefaultMaxExternalDescription is the longest description, in bytes, an external server's tool may have, and the
// longest description or title inside its input schema. The descriptions of well-written tools are a sentence or
// two; the room a description leaves for instructions to the model is the room an attacker has, and the reviewer
// has to read all of it. 1 KiB is about 150 words, a quarter of what NormalizeTools accepts for a server of ours.
const DefaultMaxExternalDescription = 1024

func (s *Service) maxDescription() int {
	if s.MaxExternalDescription > 0 {
		return s.MaxExternalDescription
	}
	return DefaultMaxExternalDescription
}

func (s *Service) staleAfter() time.Duration {
	if s.StaleAfter > 0 {
		return s.StaleAfter
	}
	return 30 * time.Second
}

var roleRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

const serverColumns = `s.id::text, s.target_name, s.display_name, s.endpoint, s.network, s.identity, s.class, s.max_description_bytes, s.lifecycle,
  s.snapshot_id::text, s.approved_snapshot_id::text, ls.digest, aps.digest,
  coalesce((SELECT array_agg(t->>'name' ORDER BY t->>'name') FROM jsonb_array_elements(ls.tools::jsonb) t), '{}'),
  coalesce((SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(coalesce(ls.discovery->'capabilities', '{}'::jsonb)) k
            WHERE k IN ('tools', 'prompts', 'resources', 'completions')), '{}'),
  s.created_by, s.approved_by, s.created_at
FROM servers s LEFT JOIN snapshots ls ON ls.id = s.snapshot_id LEFT JOIN snapshots aps ON aps.id = s.approved_snapshot_id`

func scanServer(row pgx.Row) (*Server, error) {
	var s Server
	err := row.Scan(&s.ID, &s.TargetName, &s.DisplayName, &s.Endpoint, &s.Network, &s.Identity, &s.Class, &s.MaxDescriptionBytes, &s.Lifecycle, &s.SnapshotID,
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
	// Class "external" marks a third party's server (ADR-0001 D50): the gateway forwards it no identity, a short
	// allow-list of _meta, takes no request from it, bounds its results, and marks its tools; "internal" (the
	// default) is today's behaviour. Fixed at registration, reviewed and pinned in the release: to change it,
	// register the server again. A server at a bridge address must be external.
	Class string `json:"class,omitempty"`
	// MaxDescriptionBytes (class external only) is the longest description, in bytes, this server's catalog may have
	// (ADR-0001 D53, 15.3); absent = the deployment default. At most the deployment's cap.
	MaxDescriptionBytes *int `json:"maxDescriptionBytes,omitempty"`
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
	if in.Class == "" {
		in.Class = release.ClassInternal
	}
	if in.Class != release.ClassInternal && in.Class != release.ClassExternal {
		return nil, fail(http.StatusBadRequest, "class must be internal or external")
	}
	if in.Class == release.ClassExternal && in.Identity != release.IdentityNone {
		return nil, fail(http.StatusBadRequest, "a server of class external cannot be sent the caller's identity: identity must be none")
	}
	if in.MaxDescriptionBytes != nil {
		if err := s.checkDescriptionSetting(in.Class, *in.MaxDescriptionBytes); err != nil {
			return nil, err
		}
	}
	u, err := s.Policy.CheckEndpoint(ctx, in.Endpoint)
	if err != nil {
		return nil, fail(http.StatusBadRequest, "%s", err.Error())
	}
	if err := s.checkBridge(u.String(), in.Class); err != nil {
		return nil, err
	}
	id := NewID()
	var out *Server
	err = s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO servers (id, tenant_id, target_name, display_name, endpoint, network, identity, class, max_description_bytes, lifecycle, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'DRAFT', $10)`, id, p.Tenant, in.TargetName, in.DisplayName, u.String(), s.Policy.NetworkOf(u), in.Identity, in.Class, in.MaxDescriptionBytes, p.Subject); err != nil {
			if strings.Contains(err.Error(), "duplicate key") {
				return fail(http.StatusConflict, "a server with this targetName or endpoint is already registered")
			}
			return err
		}
		if err := audit.Write(ctx, tx, p.Tenant, p.Subject, "server.register", id, map[string]any{"endpoint": client.Redact(u.String()), "targetName": in.TargetName, "identity": in.Identity, "class": in.Class, "maxDescriptionBytes": in.MaxDescriptionBytes}); err != nil {
			return err
		}
		var err error
		out, err = getServer(ctx, tx, id, false)
		return err
	})
	return out, err
}

// checkBridge refuses a server of class internal at a bridge address, so that the class cannot be forgotten for the
// one kind of upstream that is known to be external (ADR-0001 D50).
func (s *Service) checkBridge(endpoint, class string) error {
	if class != release.ClassExternal && s.Bridges.Matches(endpoint) {
		return fail(http.StatusBadRequest, "this endpoint is at a bridge address, which serves third parties' servers: register it with class external")
	}
	return nil
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
	if err := s.checkBridge(sv.Endpoint, sv.Class); err != nil { // the setting may have been added since the registration
		return nil, fail(http.StatusConflict, "%s", err.Error())
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	up := s.Upstream
	if sv.Class == release.ClassExternal {
		up = up.Anonymized() // a third party is told neither which program asks nor which trace the request belongs to
	}
	disc, err := up.Discover(dctx, sv.Endpoint)
	if err != nil {
		return nil, fail(http.StatusBadGateway, "discovery failed: %s", err.Error())
	}
	raws, err := up.ListTools(dctx, sv.Endpoint)
	if err != nil {
		return nil, fail(http.StatusBadGateway, "tools/list failed: %s", err.Error())
	}
	tools, err := federation.NormalizeTools(raws)
	if err != nil {
		return nil, fail(http.StatusUnprocessableEntity, "catalog refused: %s", err.Error())
	}
	var prompts []server.Prompt
	if _, ok := disc.Capabilities[release.CapPrompts]; ok {
		praws, err := up.ListPrompts(dctx, sv.Endpoint)
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
		rraws, err := up.List(dctx, sv.Endpoint, "resources/list", "resources")
		if err != nil {
			return nil, fail(http.StatusBadGateway, "resources/list failed: %s", err.Error())
		}
		if resources, err = federation.NormalizeResources(rraws); err != nil {
			return nil, fail(http.StatusUnprocessableEntity, "resource catalog refused: %s", err.Error())
		}
		traws, err := up.List(dctx, sv.Endpoint, "resources/templates/list", "resourceTemplates")
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
	var descLimit *int // the limit this catalog was checked against, recorded with the snapshot
	if sv.Class == release.ClassExternal {
		l := s.descriptionLimitOf(sv)
		descLimit = &l
		if err := CheckExternalDescriptions(tools, prompts, l); err != nil {
			return nil, fail(http.StatusUnprocessableEntity, "catalog refused: %s", err.Error())
		}
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
		if _, err := tx.Exec(ctx, `INSERT INTO snapshots (id, tenant_id, server_id, digest, discovery, tools, prompts, resources, resource_templates, description_limit)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			snap, p.Tenant, id, digest, discovery, string(toolsJSON), string(promptsJSON), string(resourcesJSON), string(templatesJSON), descLimit); err != nil {
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
			"resources": len(resources), "resourceTemplates": len(templates), "lifecycle": lifecycle, "descriptionLimit": descLimit}); err != nil {
			return err
		}
		out, err = getServer(ctx, tx, id, false)
		return err
	})
	return out, err
}

// UpdateServerInput changes the description limit of a server of class external. MaxDescriptionBytes is a JSON
// number to set the limit and null to go back to the deployment default.
type UpdateServerInput struct {
	MaxDescriptionBytes json.RawMessage `json:"maxDescriptionBytes"`
}

// UpdateServer changes the per-server description limit of a server of class external (ADR-0001 15.3). It is
// audited, and it invalidates the approval: the server goes back to DRAFT, so that its catalog has to be discovered
// again under the new limit and approved again by someone else; releases already made keep what they pinned. A change
// to the value it already has changes nothing.
func (s *Service) UpdateServer(ctx context.Context, p Principal, id string, in UpdateServerInput) (*Server, error) {
	if err := require(p, RoleOperator); err != nil {
		return nil, err
	}
	var want *int
	switch raw := strings.TrimSpace(string(in.MaxDescriptionBytes)); raw {
	case "":
		return nil, fail(http.StatusBadRequest, "maxDescriptionBytes is required: a number of bytes, or null for the deployment default")
	case "null":
	default:
		var n int
		if err := json.Unmarshal(in.MaxDescriptionBytes, &n); err != nil {
			return nil, fail(http.StatusBadRequest, "maxDescriptionBytes must be a whole number of bytes or null")
		}
		want = &n
	}
	var out *Server
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		sv, err := getServer(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if sv.Class != release.ClassExternal {
			return fail(http.StatusBadRequest, "maxDescriptionBytes is for a server of class external only")
		}
		if sv.Lifecycle == "RETIRED" {
			return fail(http.StatusConflict, "server is retired")
		}
		if want != nil {
			if err := s.checkDescriptionSetting(sv.Class, *want); err != nil {
				return err
			}
		}
		if (want == nil && sv.MaxDescriptionBytes == nil) || (want != nil && sv.MaxDescriptionBytes != nil && *want == *sv.MaxDescriptionBytes) {
			out = sv
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE servers SET max_description_bytes = $2, lifecycle = 'DRAFT', updated_at = now() WHERE id = $1`, id, want); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, p.Tenant, p.Subject, "server.update", id, map[string]any{"maxDescriptionBytes": want, "was": sv.MaxDescriptionBytes,
			"lifecycleWas": sv.Lifecycle, "lifecycle": "DRAFT"}); err != nil {
			return err
		}
		out, err = getServer(ctx, tx, id, false)
		return err
	})
	return out, err
}

// ApproveServer approves the latest snapshot (four-eyes). digest is the catalog digest the reviewer read (see
// GetCatalog): if given, it must be the latest snapshot's, so that a catalog discovered after the reviewer looked is
// not approved unseen; for a server of class external it is required, because the descriptions of a third party's
// tools are the one thing a reviewer must have read (ADR-0001 D53).
func (s *Service) ApproveServer(ctx context.Context, p Principal, id, digest string) (*Server, error) {
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
		if sv.Class == release.ClassExternal && digest == "" {
			return fail(http.StatusBadRequest, "approving a server of class external needs the digest of the catalog you reviewed: read it at GET /api/v1/servers/%s/catalog and send {\"digest\": ...}", id)
		}
		if digest != "" && digest != *sv.SnapshotDigest {
			return fail(http.StatusConflict, "the latest catalog is not the one you reviewed (its digest is %s): read it again", *sv.SnapshotDigest)
		}
		if _, err := tx.Exec(ctx, `UPDATE servers SET lifecycle = 'APPROVED', approved_snapshot_id = snapshot_id, approved_by = $2, updated_at = now() WHERE id = $1`, id, p.Subject); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, p.Tenant, p.Subject, "server.approve", id, map[string]any{"digest": *sv.SnapshotDigest, "class": sv.Class}); err != nil {
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
