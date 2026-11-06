package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"idp-mcp/adapters/identity"
	"idp-mcp/internal/audit"
	"idp-mcp/internal/federation"
	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
)

// ---- gateways and credentials ----------------------------------------------------------------

// GatewayInput creates a gateway.
type GatewayInput struct {
	Name        string      `json:"name"`
	AuthMode    string      `json:"authMode"`
	ToolNaming  string      `json:"toolNaming"` // prefixed (default) or native
	JWT         *JWTProfile `json:"jwt"`
	DriftAction string      `json:"driftAction"`
}

const gatewayColumns = `id::text, name, auth_mode, tool_naming, jwt_profile, drift_action, desired_release_id::text, last_status, last_heartbeat_at, created_by, created_at FROM gateways`

func scanGateway(row pgx.Row) (*Gateway, error) {
	var g Gateway
	var jwtRaw, statusRaw []byte
	err := row.Scan(&g.ID, &g.Name, &g.AuthMode, &g.ToolNaming, &jwtRaw, &g.DriftAction, &g.DesiredReleaseID, &statusRaw, &g.LastHeartbeatAt, &g.CreatedBy, &g.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(jwtRaw) > 0 {
		g.JWT = &JWTProfile{}
		_ = json.Unmarshal(jwtRaw, g.JWT)
	}
	if len(statusRaw) > 0 {
		g.LastStatus = &GatewayStatus{}
		_ = json.Unmarshal(statusRaw, g.LastStatus)
	}
	return &g, nil
}

func getGateway(ctx context.Context, tx pgx.Tx, id string, lock bool) (*Gateway, error) {
	if !isUUID(id) {
		return nil, errNotFound
	}
	q := `SELECT ` + gatewayColumns + ` WHERE id = $1`
	if lock {
		q += ` FOR UPDATE`
	}
	g, err := scanGateway(tx.QueryRow(ctx, q, id))
	if err != nil {
		return nil, err
	}
	g.Instances, err = loadInstances(ctx, tx, id, 0)
	return g, err
}

// loadInstances lists a gateway's instances; staleAfter > 0 marks liveness.
func loadInstances(ctx context.Context, tx pgx.Tx, gatewayID string, staleAfter time.Duration) ([]Instance, error) {
	rows, err := tx.Query(ctx, `SELECT instance_id, status, last_heartbeat_at FROM gateway_instances WHERE gateway_id = $1 ORDER BY instance_id`, gatewayID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Instance{}
	for rows.Next() {
		var in Instance
		var raw []byte
		if err := rows.Scan(&in.InstanceID, &raw, &in.LastHeartbeatAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(raw, &in.Status)
		in.Live = staleAfter > 0 && time.Since(in.LastHeartbeatAt) < staleAfter
		out = append(out, in)
	}
	return out, rows.Err()
}

func absURL(v string) bool {
	u, err := url.Parse(v)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.Fragment == "" && u.User == nil
}

// CreateGateway registers a data-plane instance and returns its credential once.
func (s *Service) CreateGateway(ctx context.Context, p Principal, in GatewayInput) (*Gateway, string, error) {
	if err := require(p, RoleAdmin); err != nil {
		return nil, "", err
	}
	in.Name = strings.TrimSpace(in.Name)
	if !release.ValidTargetName(in.Name) {
		return nil, "", fail(http.StatusBadRequest, "name must match [a-z0-9-]")
	}
	if in.DriftAction == "" {
		in.DriftAction = "block"
	}
	if in.ToolNaming == "" {
		in.ToolNaming = release.NamingPrefixed
	}
	if in.ToolNaming != release.NamingPrefixed && in.ToolNaming != release.NamingNative {
		return nil, "", fail(http.StatusBadRequest, "toolNaming must be prefixed or native")
	}
	if in.DriftAction != "block" && in.DriftAction != "report" {
		return nil, "", fail(http.StatusBadRequest, "driftAction must be block or report")
	}
	var jwtRaw []byte
	switch in.AuthMode {
	case "api-key":
		if in.JWT != nil {
			return nil, "", fail(http.StatusBadRequest, "api-key gateways take no jwt profile")
		}
	case "jwt":
		j := in.JWT
		if j == nil || !absURL(j.Issuer) || !absURL(j.Resource) || !absURL(j.JWKSURL) || j.TenantClaim == "" || j.RolesClaim == "" {
			return nil, "", fail(http.StatusBadRequest, "jwt needs issuer, resource, jwksUrl (absolute URLs), tenantClaim and rolesClaim")
		}
		if len(j.AuthorizationServers) == 0 {
			j.AuthorizationServers = []string{j.Issuer}
		}
		jwtRaw, _ = json.Marshal(j)
	default:
		return nil, "", fail(http.StatusBadRequest, "authMode must be api-key or jwt")
	}
	id, token := NewID(), NewSecret("idpgw_")
	var out *Gateway
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO gateways (id, tenant_id, name, auth_mode, tool_naming, jwt_profile, drift_action, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			id, p.Tenant, in.Name, in.AuthMode, in.ToolNaming, jwtRaw, in.DriftAction, p.Subject); err != nil {
			if strings.Contains(err.Error(), "duplicate key") {
				return fail(http.StatusConflict, "a gateway with this name exists")
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO gateway_credentials (token_sha256, gateway_id, tenant_id) VALUES ($1, $2, $3)`, identity.HashKey(token), id, p.Tenant); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, p.Tenant, p.Subject, "gateway.create", id, map[string]string{"name": in.Name, "authMode": in.AuthMode}); err != nil {
			return err
		}
		var err error
		out, err = getGateway(ctx, tx, id, false)
		return err
	})
	return out, token, err
}

// GetGateway returns a gateway with its last attested status.
func (s *Service) GetGateway(ctx context.Context, p Principal, id string) (*Gateway, error) {
	var out *Gateway
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) (err error) {
		if out, err = getGateway(ctx, tx, id, false); err != nil {
			return err
		}
		out.Instances, err = loadInstances(ctx, tx, id, s.staleAfter())
		return err
	})
	return out, err
}

// ListGateways lists the tenant's gateways.
func (s *Service) ListGateways(ctx context.Context, p Principal) ([]Gateway, error) {
	var out []Gateway
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+gatewayColumns+` ORDER BY created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g, err := scanGateway(rows)
			if err != nil {
				return err
			}
			out = append(out, *g)
		}
		return rows.Err()
	})
	return orEmpty(out), err
}

// APIKeyInput creates a data-plane API key.
type APIKeyInput struct {
	Subject string   `json:"subject"`
	Roles   []string `json:"roles"`
}

// CreateAPIKey issues a data-plane key for an api-key gateway; it takes effect with the next
// release (keys are part of the approved release) and is returned only once.
func (s *Service) CreateAPIKey(ctx context.Context, p Principal, gatewayID string, in APIKeyInput) (map[string]any, error) {
	if err := require(p, RoleAdmin); err != nil {
		return nil, err
	}
	roles, err := cleanList(in.Roles, roleRE.MatchString, "roles")
	if err != nil {
		return nil, err
	}
	if in.Subject = strings.TrimSpace(in.Subject); in.Subject == "" || len(in.Subject) > 120 {
		return nil, fail(http.StatusBadRequest, "subject must be 1-120 characters")
	}
	id, secret := NewID(), NewSecret("idpk_")
	err = s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		g, err := getGateway(ctx, tx, gatewayID, false)
		if err != nil {
			return err
		}
		if g.AuthMode != "api-key" {
			return fail(http.StatusConflict, "gateway uses %s authentication", g.AuthMode)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO api_keys (id, tenant_id, gateway_id, subject, roles, sha256, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			id, p.Tenant, gatewayID, in.Subject, roles, identity.HashKey(secret), p.Subject); err != nil {
			return err
		}
		return audit.Write(ctx, tx, p.Tenant, p.Subject, "apikey.create", id, map[string]any{"gatewayId": gatewayID, "subject": in.Subject, "roles": roles})
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"keyId": id, "subject": in.Subject, "roles": roles, "key": secret,
		"note": "shown once; effective after the next release is deployed"}, nil
}

// ---- releases --------------------------------------------------------------------------------

const releaseColumns = `id::text, gateway_id::text, status, digest, document, created_by, approved_by, failure_reason, created_at, approved_at, deployed_at FROM releases`

func scanRelease(row pgx.Row) (*Release, error) {
	var r Release
	var doc string
	err := row.Scan(&r.ID, &r.GatewayID, &r.Status, &r.Digest, &doc, &r.CreatedBy, &r.ApprovedBy, &r.FailureReason, &r.CreatedAt, &r.ApprovedAt, &r.DeployedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	r.Document = json.RawMessage(doc)
	return &r, err
}

func getRelease(ctx context.Context, tx pgx.Tx, id string, lock bool) (*Release, error) {
	if !isUUID(id) {
		return nil, errNotFound
	}
	q := `SELECT ` + releaseColumns + ` WHERE id = $1`
	if lock {
		q += ` FOR UPDATE`
	}
	return scanRelease(tx.QueryRow(ctx, q, id))
}

// CompileRelease builds a CANDIDATE release for a gateway from every APPROVED grant on an APPROVED
// server, each server pinned at its approved snapshot. Servers without grants are left out.
func (s *Service) CompileRelease(ctx context.Context, p Principal, gatewayID string) (*Release, error) {
	if err := require(p, RoleOperator); err != nil {
		return nil, err
	}
	var out *Release
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		g, err := getGateway(ctx, tx, gatewayID, false)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT gr.id::text, gr.tools, gr.prompts, gr.resources, gr.roles, s.id::text, s.target_name, s.endpoint, s.network, s.identity, sn.digest, sn.tools, sn.prompts, sn.resources, sn.resource_templates,
			coalesce(sn.discovery->'capabilities', '{}'::jsonb)
			FROM grants gr JOIN servers s ON s.id = gr.server_id JOIN snapshots sn ON sn.id = s.approved_snapshot_id
			WHERE gr.status = 'APPROVED' AND s.lifecycle = 'APPROVED' ORDER BY s.target_name, gr.id`)
		if err != nil {
			return err
		}
		targets := map[string]*release.Target{}
		var grants []release.Grant
		for rows.Next() {
			var gid, sid, name, endpoint, network, identity, digest, toolsRaw, promptsRaw, resourcesRaw, templatesRaw string
			var tools, prompts, roles []string
			var resources bool
			var capObj map[string]any
			if err := rows.Scan(&gid, &tools, &prompts, &resources, &roles, &sid, &name, &endpoint, &network, &identity, &digest, &toolsRaw, &promptsRaw, &resourcesRaw, &templatesRaw, &capObj); err != nil {
				rows.Close()
				return err
			}
			if targets[name] == nil {
				pinned, err := toolsOf([]byte(toolsRaw))
				if err != nil {
					rows.Close()
					return err
				}
				var pinnedPrompts []server.Prompt
				if err := json.Unmarshal([]byte(promptsRaw), &pinnedPrompts); err != nil {
					rows.Close()
					return err
				}
				if len(pinnedPrompts) == 0 {
					pinnedPrompts = nil
				}
				var pinnedResources []server.Resource
				var pinnedTemplates []server.ResourceTemplate
				if err := json.Unmarshal([]byte(resourcesRaw), &pinnedResources); err != nil {
					rows.Close()
					return err
				}
				if err := json.Unmarshal([]byte(templatesRaw), &pinnedTemplates); err != nil {
					rows.Close()
					return err
				}
				if len(pinnedResources) == 0 {
					pinnedResources = nil
				}
				if len(pinnedTemplates) == 0 {
					pinnedTemplates = nil
				}
				targets[name] = &release.Target{Name: name, ServerID: sid, Endpoint: endpoint, Network: network, Identity: release.IdentityOf(identity), SnapshotDigest: digest,
					Tools: pinned, Prompts: pinnedPrompts, Resources: pinnedResources, ResourceTemplates: pinnedTemplates, Capabilities: federation.Capabilities(capObj)}
			}
			have := map[string]bool{}
			for _, t := range targets[name].Tools {
				have[t.Name] = true
			}
			for _, t := range tools {
				if !have[t] {
					rows.Close()
					return fail(http.StatusConflict, "grant %s names tool %q, which the approved snapshot of %s no longer has; revoke or re-propose it", gid, t, name)
				}
			}
			if len(prompts) == 0 {
				prompts = nil
			}
			grants = append(grants, release.Grant{Target: name, Tools: tools, Prompts: prompts, Resources: resources, Roles: roles})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(grants) == 0 {
			return fail(http.StatusConflict, "no approved grants on approved servers: nothing to release")
		}
		doc := &release.Document{SchemaVersion: release.SchemaVersion, ReleaseID: NewID(), TenantID: p.Tenant, GatewayID: g.ID,
			CreatedAt: time.Now().UTC().Format(time.RFC3339), CreatedBy: p.Subject, DriftAction: g.DriftAction, ToolNaming: g.ToolNaming, Grants: grants}
		names := make([]string, 0, len(targets))
		for n := range targets {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			doc.Targets = append(doc.Targets, *targets[n])
		}
		doc.Auth.Mode = g.AuthMode
		if g.AuthMode == "jwt" {
			j := release.JWT(*g.JWT)
			doc.Auth.JWT = &j
		} else {
			krows, err := tx.Query(ctx, `SELECT id::text, subject, roles, sha256 FROM api_keys WHERE gateway_id = $1 AND revoked_at IS NULL ORDER BY created_at`, g.ID)
			if err != nil {
				return err
			}
			for krows.Next() {
				var k release.APIKey
				if err := krows.Scan(&k.ID, &k.Subject, &k.Roles, &k.SHA256); err != nil {
					krows.Close()
					return err
				}
				doc.Auth.APIKeys = append(doc.Auth.APIKeys, k)
			}
			krows.Close()
			if len(doc.Auth.APIKeys) == 0 {
				return fail(http.StatusConflict, "api-key gateway has no active keys")
			}
		}
		if err := doc.Validate(); err != nil {
			return fail(http.StatusConflict, "%s", err.Error())
		}
		raw, err := release.Canonical(doc)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO releases (id, tenant_id, gateway_id, status, document, created_by) VALUES ($1, $2, $3, 'CANDIDATE', $4, $5)`,
			doc.ReleaseID, p.Tenant, g.ID, string(raw), p.Subject); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, p.Tenant, p.Subject, "release.compile", doc.ReleaseID, map[string]any{"gatewayId": g.ID, "targets": names, "grants": len(grants)}); err != nil {
			return err
		}
		out, err = getRelease(ctx, tx, doc.ReleaseID, false)
		return err
	})
	return out, err
}

// ApproveRelease records the approver in the document and seals it (four-eyes).
func (s *Service) ApproveRelease(ctx context.Context, p Principal, id string) (*Release, error) {
	if err := require(p, RoleReviewer); err != nil {
		return nil, err
	}
	var out *Release
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		r, err := getRelease(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if r.Status != "CANDIDATE" {
			return fail(http.StatusConflict, "release is %s", r.Status)
		}
		if err := fourEyes(p, r.CreatedBy); err != nil {
			return err
		}
		var doc release.Document
		dec := json.NewDecoder(strings.NewReader(string(r.Document.(json.RawMessage))))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			return err
		}
		doc.ApprovedBy = p.Subject
		env, err := release.Seal(&doc)
		if err != nil {
			return fail(http.StatusConflict, "%s", err.Error())
		}
		envRaw, _ := json.Marshal(env)
		if _, err := tx.Exec(ctx, `UPDATE releases SET status = 'APPROVED', approved_by = $2, approved_at = now(), digest = $3, envelope = $4, document = $5 WHERE id = $1`,
			id, p.Subject, env.Digest, string(envRaw), string(env.Document)); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, p.Tenant, p.Subject, "release.approve", id, map[string]string{"digest": env.Digest}); err != nil {
			return err
		}
		out, err = getRelease(ctx, tx, id, false)
		return err
	})
	return out, err
}

// ListReleases lists releases, optionally of one gateway.
func (s *Service) ListReleases(ctx context.Context, p Principal, gatewayID string) ([]Release, error) {
	var out []Release
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		q, args := `SELECT `+releaseColumns+` ORDER BY created_at DESC LIMIT 100`, []any{}
		if gatewayID != "" {
			if !isUUID(gatewayID) {
				return nil
			}
			q, args = `SELECT `+releaseColumns+` WHERE gateway_id = $1 ORDER BY created_at DESC LIMIT 100`, []any{gatewayID}
		}
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRelease(rows)
			if err != nil {
				return err
			}
			out = append(out, *r)
		}
		return rows.Err()
	})
	return orEmpty(out), err
}

// GetRelease returns one release.
func (s *Service) GetRelease(ctx context.Context, p Principal, id string) (*Release, error) {
	var out *Release
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) (err error) {
		out, err = getRelease(ctx, tx, id, false)
		return err
	})
	return out, err
}

// DeployResult is the outcome of a deployment.
type DeployResult struct {
	Release     *Release       `json:"release"`
	Attestation *GatewayStatus `json:"attestation"`
	RolledBack  bool           `json:"rolledBackToPrevious"`
}

// Deploy makes the release the gateway's desired state and waits for the gateway to attest that it
// runs it with every target's live catalog matching the pinned snapshot (ADR-0001 D4). On failure
// or timeout the desired state returns to the previous release. APPROVED, SUPERSEDED (rollback) and
// FAILED (retry) releases can be deployed.
func (s *Service) Deploy(ctx context.Context, p Principal, id string) (*DeployResult, error) {
	if err := require(p, RoleAdmin); err != nil {
		return nil, err
	}
	var r *Release
	var previous *string
	started := time.Now()
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		var err error
		if r, err = getRelease(ctx, tx, id, true); err != nil {
			return err
		}
		if r.Status != "APPROVED" && r.Status != "SUPERSEDED" && r.Status != "FAILED" {
			return fail(http.StatusConflict, "release is %s", r.Status)
		}
		g, err := getGateway(ctx, tx, r.GatewayID, true) // serializes deployments per gateway
		if err != nil {
			return err
		}
		var busy int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM releases WHERE gateway_id = $1 AND status = 'DEPLOYING'`, g.ID).Scan(&busy); err != nil {
			return err
		}
		if busy > 0 {
			return fail(http.StatusConflict, "another deployment to this gateway is in progress")
		}
		previous = g.DesiredReleaseID
		if _, err := tx.Exec(ctx, `UPDATE gateways SET desired_release_id = $2 WHERE id = $1`, g.ID, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE releases SET status = 'DEPLOYING', failure_reason = NULL WHERE id = $1`, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, p.Tenant, p.Subject, "release.deploy", id, map[string]any{"gatewayId": g.ID, "previous": previous})
	})
	if err != nil {
		return nil, err
	}
	att, reason := s.awaitAttestation(ctx, p.Tenant, r.GatewayID, *r.Digest, started)
	res := &DeployResult{Attestation: att}
	err = s.Store.InTenant(context.WithoutCancel(ctx), p.Tenant, func(tx pgx.Tx) error {
		if reason == "" {
			if _, err := tx.Exec(ctx, `UPDATE releases SET status = 'SUPERSEDED' WHERE gateway_id = $1 AND status = 'GOOD' AND id <> $2`, r.GatewayID, id); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE releases SET status = 'GOOD', deployed_at = now() WHERE id = $1`, id); err != nil {
				return err
			}
			if err := audit.Write(ctx, tx, p.Tenant, p.Subject, "release.good", id, map[string]string{"digest": *r.Digest}); err != nil {
				return err
			}
		} else {
			if _, err := tx.Exec(ctx, `UPDATE releases SET status = 'FAILED', failure_reason = $2 WHERE id = $1`, id, reason); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE gateways SET desired_release_id = $2 WHERE id = $1 AND desired_release_id = $3`, r.GatewayID, previous, id); err != nil {
				return err
			}
			res.RolledBack = previous != nil
			if err := audit.Write(ctx, tx, p.Tenant, p.Subject, "release.fail", id, map[string]any{"reason": reason, "restoredDesired": previous}); err != nil {
				return err
			}
		}
		var err error
		res.Release, err = getRelease(ctx, tx, id, false)
		return err
	})
	if err != nil {
		return nil, err
	}
	if reason != "" {
		return res, fail(http.StatusBadGateway, "deployment not attested: %s%s", reason, map[bool]string{true: "; desired state returned to the previous release", false: ""}[res.RolledBack])
	}
	return res, nil
}

// awaitAttestation waits until every live instance of the gateway (heartbeat within StaleAfter and
// after the deployment started) runs digest with all targets OK. One refusing instance fails the
// deployment at once; a lagging one fails it at the deadline, naming the instance. The returned
// status is that of the newest heartbeat.
func (s *Service) awaitAttestation(ctx context.Context, tenant, gatewayID, digest string, since time.Time) (*GatewayStatus, string) {
	deadline := time.Now().Add(s.DeployTimeout)
	var last *GatewayStatus
	var lastAt time.Time
	var pending string
	for {
		var instances []Instance
		err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) (err error) {
			instances, err = loadInstances(ctx, tx, gatewayID, s.staleAfter())
			return err
		})
		if err == nil {
			var fresh []Instance // live and heard since the deployment started
			for _, in := range instances {
				if in.Live && in.LastHeartbeatAt.After(since) {
					fresh = append(fresh, in)
					if in.LastHeartbeatAt.After(lastAt) {
						st := in.Status
						last, lastAt = &st, in.LastHeartbeatAt
					}
				}
			}
			var notYet, bad []string
			for _, in := range fresh {
				st := in.Status
				if st.Digest != digest && st.RefusedDigest == digest {
					return &st, fmt.Sprintf("instance %s refused the release: %s", in.InstanceID, st.RefusedReason)
				}
				if st.Digest != digest || !st.Checked {
					notYet = append(notYet, in.InstanceID)
					continue
				}
				for _, t := range st.Targets {
					if t.Status != "OK" {
						bad = append(bad, in.InstanceID+":"+t.Name+"="+t.Status)
					}
				}
			}
			if len(fresh) > 0 && len(notYet) == 0 {
				if len(bad) == 0 {
					return last, ""
				}
				return last, "targets not healthy: " + strings.Join(bad, ", ")
			}
			if len(fresh) == 0 {
				pending = "no live instance has reported since the deployment started"
			} else {
				pending = fmt.Sprintf("%d of %d live instances not yet on the release: %s", len(notYet), len(fresh), strings.Join(notYet, ", "))
			}
		}
		if time.Now().After(deadline) {
			return last, fmt.Sprintf("no attestation within %s (%s)", s.DeployTimeout, pending)
		}
		select {
		case <-ctx.Done():
			return last, "deployment request cancelled"
		case <-time.After(s.PollEvery):
		}
	}
}

// ---- gateway-facing (internal API) -----------------------------------------------------------

// Desired returns the gateway's desired release envelope, or nil.
func (s *Service) Desired(ctx context.Context, gatewayID, tenant string) (json.RawMessage, string, error) {
	var env, digest *string
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT r.envelope, r.digest FROM gateways g LEFT JOIN releases r ON r.id = g.desired_release_id WHERE g.id = $1`, gatewayID).Scan(&env, &digest)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		return err
	})
	if err != nil || env == nil {
		return nil, "", err
	}
	return json.RawMessage(*env), *digest, nil
}

// Heartbeat stores the gateway's attested status.
func (s *Service) Heartbeat(ctx context.Context, gatewayID, tenant string, st GatewayStatus) error {
	if st.GatewayID != gatewayID {
		return fail(http.StatusBadRequest, "heartbeat for another gateway")
	}
	if st.InstanceID == "" {
		st.InstanceID = "default"
	}
	if len(st.InstanceID) > 253 {
		return fail(http.StatusBadRequest, "instanceId too long")
	}
	raw, _ := json.Marshal(st)
	return s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO gateway_instances (gateway_id, instance_id, tenant_id, status, last_heartbeat_at) VALUES ($1, $2, $3, $4, now())
			ON CONFLICT (gateway_id, instance_id) DO UPDATE SET status = EXCLUDED.status, last_heartbeat_at = now()`, gatewayID, st.InstanceID, tenant, raw); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM gateway_instances WHERE gateway_id = $1 AND last_heartbeat_at < now() - interval '1 day'`, gatewayID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE gateways SET last_status = $2, last_heartbeat_at = now() WHERE id = $1`, gatewayID, raw)
		return err
	})
}

// InvocationInput is one record as the gateway ships it.
type InvocationInput struct {
	At            time.Time `json:"at"`
	ReleaseDigest string    `json:"releaseDigest"`
	Subject       string    `json:"subject"`
	Client        string    `json:"client"`
	Actor         string    `json:"actor"`
	AuthMethod    string    `json:"authMethod"`
	Method        string    `json:"method"`
	Tool          string    `json:"tool"`
	Target        string    `json:"target"`
	Decision      string    `json:"decision"`
	Outcome       string    `json:"outcome"`
	LatencyMS     int64     `json:"latencyMs"`
	TraceID       string    `json:"traceId"`
	ArgsDigest    string    `json:"argsDigest"`
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// RecordInvocations stores a batch from a gateway.
func (s *Service) RecordInvocations(ctx context.Context, gatewayID, tenant string, recs []InvocationInput) error {
	if len(recs) > 1000 {
		return fail(http.StatusRequestEntityTooLarge, "at most 1000 records per batch")
	}
	return s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		for _, r := range recs {
			if r.Method == "" {
				r.Method = "tools/call"
			}
			if r.At.IsZero() || r.Subject == "" || r.Tool == "" || len(r.Tool) > 2048 || len(r.Method) > 64 || (r.Decision != "ALLOW" && r.Decision != "DENY") {
				return fail(http.StatusBadRequest, "malformed invocation record")
			}
			b.Queue(`INSERT INTO invocations (tenant_id, gateway_id, at, release_digest, subject, auth_method, method, tool, target, decision, outcome, latency_ms, trace_id, args_digest, client, actor)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
				tenant, gatewayID, r.At, r.ReleaseDigest, r.Subject, r.AuthMethod, r.Method, r.Tool, nullable(r.Target), r.Decision, r.Outcome, r.LatencyMS, nullable(r.TraceID), nullable(r.ArgsDigest),
				nullable(r.Client), nullable(r.Actor))
		}
		return tx.SendBatch(ctx, b).Close()
	})
}

// ---- reading the record ----------------------------------------------------------------------

// ListAudit returns the latest audit events.
func (s *Service) ListAudit(ctx context.Context, p Principal) ([]AuditEvent, error) {
	var out []AuditEvent
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, at, subject, action, resource_id, detail FROM audit_events ORDER BY id DESC LIMIT 500`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e AuditEvent
			var detail []byte
			if err := rows.Scan(&e.ID, &e.At, &e.Subject, &e.Action, &e.ResourceID, &detail); err != nil {
				return err
			}
			if len(detail) > 0 {
				e.Detail = json.RawMessage(detail)
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return orEmpty(out), err
}

// ListInvocations returns the latest invocation records.
func (s *Service) ListInvocations(ctx context.Context, p Principal) ([]Invocation, error) {
	var out []Invocation
	err := s.Store.InTenant(ctx, p.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, gateway_id::text, at, release_digest, subject, client, actor, auth_method, method, tool, target, decision, outcome, latency_ms, trace_id, args_digest
			FROM invocations ORDER BY id DESC LIMIT 500`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v Invocation
			if err := rows.Scan(&v.ID, &v.GatewayID, &v.At, &v.ReleaseDigest, &v.Subject, &v.Client, &v.Actor, &v.AuthMethod, &v.Method, &v.Tool, &v.Target, &v.Decision,
				&v.Outcome, &v.LatencyMS, &v.TraceID, &v.ArgsDigest); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return orEmpty(out), err
}
