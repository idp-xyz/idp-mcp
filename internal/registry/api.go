package registry

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"idp-mcp/adapters/identity"
	"idp-mcp/internal/gateway"
	"idp-mcp/internal/observability"
	"idp-mcp/internal/transport"
)

// AdminAuth verifies admin API tokens.
type AdminAuth interface {
	Verify(ctx context.Context, token string) (identity.AdminClaims, error)
}

// API is the registry's HTTP interface: the admin API (/api/v1, admin JWT) and the gateway-facing
// internal API (/internal/v1, gateway credential).
type API struct {
	Svc   *Service
	Admin AdminAuth
	Log   *slog.Logger
	// RequireGatewayCert binds gateway credentials to mutual TLS: the internal API then also needs a
	// verified client certificate whose spiffe://idp-mcp/gateway/<id> URI names the token's gateway.
	RequireGatewayCert bool
	Metrics            *observability.Metrics // optional; default: a fresh registry
}

func (a *API) metrics() *observability.Metrics {
	if a.Metrics == nil {
		a.Metrics = observability.NewMetrics()
	}
	return a.Metrics
}

type adminHandler func(r *http.Request, p Principal) (int, any, error)

func writeErr(w http.ResponseWriter, log *slog.Logger, err error) {
	status := StatusOf(err)
	msg := err.Error()
	if status == http.StatusInternalServerError {
		log.Error("request failed", "err", err)
		msg = "internal error"
	}
	transport.WriteJSON(w, status, map[string]string{"error": msg})
}

func (a *API) admin(h adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, err := identity.Bearer(r)
		var c identity.AdminClaims
		if err == nil {
			c, err = a.Admin.Verify(r.Context(), tok)
		}
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			transport.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		status, body, err := h(r, Principal{Subject: c.Subject, Tenant: c.Tenant, Roles: c.Roles})
		if err != nil {
			writeErr(w, a.Log, err)
			return
		}
		transport.WriteJSON(w, status, body)
	}
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fail(http.StatusBadRequest, "invalid JSON body: %s", err.Error())
	}
	return nil
}

func items[T any](v []T, err error) (int, any, error) {
	return http.StatusOK, map[string]any{"items": v}, err
}

func one[T any](v T, err error) (int, any, error) { return http.StatusOK, v, err }

func created[T any](v T, err error) (int, any, error) { return http.StatusCreated, v, err }

// Routes lists the method+path patterns the handler serves (documented in api/openapi.yaml;
// tests/api keeps the two in step).
func (a *API) Routes() []string {
	var out []string
	a.routes(func(pattern string, _ http.HandlerFunc) { out = append(out, pattern) })
	return out
}

// Handler returns the registry HTTP handler.
func (a *API) Handler() http.Handler {
	m := http.NewServeMux()
	a.routes(func(pattern string, h http.HandlerFunc) { m.HandleFunc(pattern, h) })
	m.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		transport.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	})
	return observability.HTTPMetrics(a.metrics(), "idp_mcp_registry", m)
}

func (a *API) routes(handle func(pattern string, h http.HandlerFunc)) {
	m := struct {
		HandleFunc func(string, http.HandlerFunc)
	}{handle}
	// liveness: the process answers. Not the database: a liveness probe on /api/v1/health had the kubelet restart the registry
	// after a minute of database failover, and again and again in a longer outage, which a restart does not cure
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		transport.WriteJSON(w, http.StatusOK, map[string]string{"status": "live"})
	})
	m.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if err := a.Svc.Store.Pool.Ping(r.Context()); err != nil {
			transport.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "database unavailable"})
			return
		}
		transport.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "component": "registry-service"})
	})
	m.HandleFunc("POST /api/v1/servers", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		var in RegisterInput
		if err := decode(r, &in); err != nil {
			return 0, nil, err
		}
		return created(a.Svc.RegisterServer(r.Context(), p, in))
	}))
	m.HandleFunc("GET /api/v1/servers", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		return items(a.Svc.ListServers(r.Context(), p))
	}))
	m.HandleFunc("GET /api/v1/servers/{id}", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		return one(a.Svc.GetServer(r.Context(), p, r.PathValue("id")))
	}))
	m.HandleFunc("POST /api/v1/servers/{id}/discover", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		return one(a.Svc.DiscoverServer(r.Context(), p, r.PathValue("id")))
	}))
	m.HandleFunc("POST /api/v1/servers/{id}/approve", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		return one(a.Svc.ApproveServer(r.Context(), p, r.PathValue("id")))
	}))
	m.HandleFunc("POST /api/v1/grants", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		var in GrantInput
		if err := decode(r, &in); err != nil {
			return 0, nil, err
		}
		return created(a.Svc.ProposeGrant(r.Context(), p, in))
	}))
	m.HandleFunc("GET /api/v1/grants", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		return items(a.Svc.ListGrants(r.Context(), p))
	}))
	m.HandleFunc("POST /api/v1/grants/{id}/approve", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		return one(a.Svc.ApproveGrant(r.Context(), p, r.PathValue("id")))
	}))
	m.HandleFunc("POST /api/v1/grants/{id}/revoke", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		return one(a.Svc.RevokeGrant(r.Context(), p, r.PathValue("id")))
	}))
	m.HandleFunc("POST /api/v1/gateways", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		var in GatewayInput
		if err := decode(r, &in); err != nil {
			return 0, nil, err
		}
		g, token, err := a.Svc.CreateGateway(r.Context(), p, in)
		return http.StatusCreated, map[string]any{"gateway": g, "token": token, "note": "the gateway token is shown once"}, err
	}))
	m.HandleFunc("GET /api/v1/gateways", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		return items(a.Svc.ListGateways(r.Context(), p))
	}))
	m.HandleFunc("GET /api/v1/gateways/{id}", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		return one(a.Svc.GetGateway(r.Context(), p, r.PathValue("id")))
	}))
	m.HandleFunc("POST /api/v1/gateways/{id}/api-keys", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		var in APIKeyInput
		if err := decode(r, &in); err != nil {
			return 0, nil, err
		}
		return created(a.Svc.CreateAPIKey(r.Context(), p, r.PathValue("id"), in))
	}))
	m.HandleFunc("POST /api/v1/releases", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		var in struct {
			GatewayID string `json:"gatewayId"`
		}
		if err := decode(r, &in); err != nil {
			return 0, nil, err
		}
		return created(a.Svc.CompileRelease(r.Context(), p, in.GatewayID))
	}))
	m.HandleFunc("GET /api/v1/releases", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		return items(a.Svc.ListReleases(r.Context(), p, r.URL.Query().Get("gatewayId")))
	}))
	m.HandleFunc("GET /api/v1/releases/{id}", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		return one(a.Svc.GetRelease(r.Context(), p, r.PathValue("id")))
	}))
	m.HandleFunc("POST /api/v1/releases/{id}/approve", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		return one(a.Svc.ApproveRelease(r.Context(), p, r.PathValue("id")))
	}))
	m.HandleFunc("POST /api/v1/releases/{id}/deploy", func(w http.ResponseWriter, r *http.Request) {
		// a failed deployment still returns the attestation it was judged on
		deployments := a.metrics().Counter("idp_mcp_registry_deployments_total", "Deployments by result.", "result")
		a.admin(func(r *http.Request, p Principal) (int, any, error) {
			res, err := a.Svc.Deploy(r.Context(), p, r.PathValue("id"))
			if res != nil && res.Release != nil {
				deployments.Inc(res.Release.Status)
			}
			if err != nil && res != nil {
				return StatusOf(err), map[string]any{"error": err.Error(), "result": res}, nil
			}
			return one(res, err)
		})(w, r)
	})
	m.HandleFunc("GET /api/v1/audit-events", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		return items(a.Svc.ListAudit(r.Context(), p))
	}))
	m.HandleFunc("GET /api/v1/invocations", a.admin(func(r *http.Request, p Principal) (int, any, error) {
		return items(a.Svc.ListInvocations(r.Context(), p))
	}))

	m.HandleFunc("GET "+gateway.PathDesired, a.gatewayAuth(func(w http.ResponseWriter, r *http.Request, gw, tenant string) {
		env, digest, err := a.Svc.Desired(r.Context(), gw, tenant)
		switch {
		case err != nil:
			writeErr(w, a.Log, err)
		case env == nil:
			w.WriteHeader(http.StatusNoContent)
		case r.Header.Get("If-None-Match") == `"`+digest+`"`:
			w.WriteHeader(http.StatusNotModified)
		default:
			w.Header().Set("ETag", `"`+digest+`"`)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write(env)
		}
	}))
	m.HandleFunc("POST "+gateway.PathHeartbeat, a.gatewayAuth(func(w http.ResponseWriter, r *http.Request, gw, tenant string) {
		var st GatewayStatus
		if err := decode(r, &st); err != nil {
			writeErr(w, a.Log, err)
			return
		}
		if err := a.Svc.Heartbeat(r.Context(), gw, tenant, st); err != nil {
			writeErr(w, a.Log, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	m.HandleFunc("POST "+gateway.PathInvocations, a.gatewayAuth(func(w http.ResponseWriter, r *http.Request, gw, tenant string) {
		var in struct {
			Records []InvocationInput `json:"records"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, a.Log, err)
			return
		}
		if err := a.Svc.RecordInvocations(r.Context(), gw, tenant, in.Records); err != nil {
			writeErr(w, a.Log, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

func (a *API) gatewayAuth(h func(w http.ResponseWriter, r *http.Request, gatewayID, tenant string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, err := identity.Bearer(r)
		var gw, tenant string
		if err == nil && strings.HasPrefix(tok, "idpgw_") {
			gw, tenant, err = a.Svc.Store.GatewayByToken(r.Context(), identity.HashKey(tok))
		} else if err == nil {
			err = pgx.ErrNoRows
		}
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) && !errors.Is(err, identity.ErrNoCredentials) && !errors.Is(err, identity.ErrInvalid) {
				a.Log.Error("gateway credential lookup", "err", err)
			}
			w.Header().Set("WWW-Authenticate", "Bearer")
			transport.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if a.RequireGatewayCert {
			if id := transport.GatewayIdentity(r.TLS); id != gw {
				a.Log.Warn("gateway credential without a matching client certificate", "gateway", gw, "certificate", id)
				transport.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		h(w, r, gw, tenant)
	}
}
