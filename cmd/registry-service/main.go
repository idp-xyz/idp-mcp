// Command registry-service is the idp-mcp control plane.
//
//	registry-service [serve]                          run the API (default)
//	registry-service migrate                          apply schema migrations (owner connection)
//	registry-service ensure-login USER                create/update a login role in idp_mcp_app;
//	                                                  password from IDP_APP_DB_PASSWORD[_FILE]
//	registry-service seed-tenant SLUG [ID]            create a tenant (random or given UUID), print TENANT_ID=<id>
//	registry-service dev-token TENANT SUBJECT ROLE..  print a development admin token (dev mode only)
//
// Environment:
//
//	IDP_DATABASE_URL             service connection (a member of idp_mcp_app, never a superuser)
//	IDP_MIGRATION_DATABASE_URL   schema owner connection (migrate, ensure-login, seed-tenant)
//	IDP_REGISTRY_LISTEN          default 127.0.0.1:8250
//	IDP_DEV_MODE                 "true": loopback/plaintext private upstreams, HS256 admin tokens
//	IDP_ADMIN_ISSUER             admin token issuer (default idp-mcp-dev)
//	IDP_ADMIN_AUDIENCE           admin token audience (default idp-mcp-registry)
//	IDP_ADMIN_JWKS_URL           admin token keys (production)
//	IDP_DEV_ADMIN_SECRET[_FILE]  HS256 admin token secret (dev mode only, >= 32 bytes)
//	IDP_ALLOWED_UPSTREAM_HOSTS   hosts MCP servers may be registered on, comma separated
//	IDP_PRIVATE_UPSTREAM_HOSTS   of those, the ones that may resolve to private addresses
//	IDP_DEPLOY_TIMEOUT           how long a deployment waits for the gateway's attestation (30s)
//	IDP_INSTANCE_STALE_AFTER     a gateway instance silent for longer no longer counts (30s)
//	IDP_METRICS_LISTEN           serve Prometheus metrics (/metrics) on this address; off when unset
//	IDP_TLS_CERT_FILE / IDP_TLS_KEY_FILE   serve HTTPS
//	IDP_GATEWAY_CLIENT_CA_FILE   require mutual TLS on /internal/v1: a client certificate from this CA
//	                             whose spiffe://idp-mcp/gateway/<id> URI matches the gateway credential
//	IDP_UPSTREAM_CA_FILE         extra trusted CAs for https MCP servers (discovery)
//	IDP_IDENTITY_CA_FILE         extra trusted CAs for the admin JWKS endpoint
//	OTEL_EXPORTER_OTLP_ENDPOINT / OTEL_EXPORTER_OTLP_TRACES_ENDPOINT / OTEL_EXPORTER_OTLP_HEADERS /
//	OTEL_EXPORTER_OTLP_CERTIFICATE / OTEL_SERVICE_NAME   OTLP/HTTP trace export (off without an endpoint)
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"idp-mcp/adapters/identity"
	"idp-mcp/adapters/store/postgres"
	"idp-mcp/internal/client"
	"idp-mcp/internal/observability"
	"idp-mcp/internal/policy"
	"idp-mcp/internal/registry"
	"idp-mcp/internal/server"
	"idp-mcp/internal/transport"
)

var version = "0.1.0-dev"

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func secret(key string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if path := os.Getenv(key + "_FILE"); path != "" {
		if b, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

func hostSet(key string) map[string]bool {
	out := map[string]bool{}
	for _, h := range strings.Split(env(key, ""), ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			out[h] = true
		}
	}
	return out
}

func main() {
	log := observability.NewLogger(os.Stdout, env("IDP_LOG_LEVEL", "info"))
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	ctx := context.Background()
	var err error
	switch cmd {
	case "serve":
		err = serve(log)
	case "migrate":
		var applied []string
		applied, err = postgres.Migrate(ctx, env("IDP_MIGRATION_DATABASE_URL", ""))
		if err == nil {
			fmt.Printf("OK: %d migration(s) applied %v\n", len(applied), applied)
		}
	case "ensure-login":
		if len(args) != 1 || secret("IDP_APP_DB_PASSWORD") == "" {
			err = errors.New("usage: ensure-login USER (password in IDP_APP_DB_PASSWORD[_FILE])")
			break
		}
		err = postgres.EnsureLogin(ctx, env("IDP_MIGRATION_DATABASE_URL", ""), args[0], secret("IDP_APP_DB_PASSWORD"))
		if err == nil {
			fmt.Printf("OK: login role %s is a member of idp_mcp_app\n", args[0])
		}
	case "seed-tenant":
		if len(args) < 1 || len(args) > 2 {
			err = errors.New("usage: seed-tenant SLUG [UUID]")
			break
		}
		id := registry.NewID()
		if len(args) == 2 {
			id = args[1]
		}
		id, err = postgres.SeedTenant(ctx, env("IDP_MIGRATION_DATABASE_URL", ""), id, args[0])
		if err == nil {
			fmt.Printf("TENANT_ID=%s\n", id)
		}
	case "dev-token":
		if env("IDP_DEV_MODE", "false") != "true" || len(args) < 3 {
			err = errors.New("usage (dev mode only): dev-token TENANT SUBJECT ROLE [ROLE...]")
			break
		}
		var tok string
		tok, err = identity.DevAdminToken([]byte(secret("IDP_DEV_ADMIN_SECRET")), env("IDP_ADMIN_ISSUER", "idp-mcp-dev"),
			env("IDP_ADMIN_AUDIENCE", "idp-mcp-registry"), args[1], args[0], args[2:], 15*time.Minute)
		if err == nil {
			fmt.Println(tok)
		}
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		log.Error("registry-service", "command", cmd, "err", err)
		os.Exit(1)
	}
}

func serve(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	tp, stopTracing, err := observability.Setup("idp-mcp-registry", version, log)
	if err != nil {
		return err
	}
	defer func() {
		fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = stopTracing(fctx)
	}()
	dev := env("IDP_DEV_MODE", "false") == "true"
	issuer, audience := env("IDP_ADMIN_ISSUER", "idp-mcp-dev"), env("IDP_ADMIN_AUDIENCE", "idp-mcp-registry")
	var admin registry.AdminAuth
	identityTLS, err := transport.ClientTLS(env("IDP_IDENTITY_CA_FILE", ""), "", "")
	if err != nil {
		return fmt.Errorf("IDP_IDENTITY_CA_FILE: %w", err)
	}
	upstreamTLS, err := transport.ClientTLS(env("IDP_UPSTREAM_CA_FILE", ""), "", "")
	if err != nil {
		return fmt.Errorf("IDP_UPSTREAM_CA_FILE: %w", err)
	}
	switch {
	case env("IDP_ADMIN_JWKS_URL", "") != "":
		admin = identity.NewJWKSAdminVerifier(issuer, audience, &identity.JWKS{URL: env("IDP_ADMIN_JWKS_URL", ""),
			HTTP: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: identityTLS}}, TTL: 10 * time.Minute, MinRefresh: 30 * time.Second})
	case dev && secret("IDP_DEV_ADMIN_SECRET") != "":
		v, err := identity.NewDevAdminVerifier(issuer, audience, []byte(secret("IDP_DEV_ADMIN_SECRET")))
		if err != nil {
			return err
		}
		admin = v
	default:
		return errors.New("configure IDP_ADMIN_JWKS_URL (or, in dev mode, IDP_DEV_ADMIN_SECRET)")
	}
	store, err := postgres.Open(ctx, env("IDP_DATABASE_URL", ""))
	if err != nil {
		return err
	}
	defer store.Close()
	deployTimeout, err := time.ParseDuration(env("IDP_DEPLOY_TIMEOUT", "30s"))
	if err != nil {
		return fmt.Errorf("IDP_DEPLOY_TIMEOUT: %w", err)
	}
	pol := &policy.Upstream{AllowedHosts: hostSet("IDP_ALLOWED_UPSTREAM_HOSTS"), PrivateHosts: hostSet("IDP_PRIVATE_UPSTREAM_HOSTS"), DevMode: dev}
	staleAfter, err := time.ParseDuration(env("IDP_INSTANCE_STALE_AFTER", "30s"))
	if err != nil {
		return fmt.Errorf("IDP_INSTANCE_STALE_AFTER: %w", err)
	}
	svc := &registry.Service{Store: store, Policy: pol, DeployTimeout: deployTimeout, PollEvery: 250 * time.Millisecond, StaleAfter: staleAfter, Log: log,
		Upstream: &client.Client{HTTP: client.NewHTTPClient(pol, 15*time.Second, upstreamTLS), Info: server.ServerInfo{Name: "idp-mcp-registry", Version: version}}}
	certFile, keyFile, clientCA := env("IDP_TLS_CERT_FILE", ""), env("IDP_TLS_KEY_FILE", ""), env("IDP_GATEWAY_CLIENT_CA_FILE", "")
	if clientCA != "" && certFile == "" {
		return errors.New("IDP_GATEWAY_CLIENT_CA_FILE needs IDP_TLS_CERT_FILE and IDP_TLS_KEY_FILE")
	}
	api := &registry.API{Svc: svc, Admin: admin, Log: log, RequireGatewayCert: clientCA != "", Metrics: observability.NewMetrics()}
	if ms := observability.ServeMetrics(env("IDP_METRICS_LISTEN", ""), api.Metrics, log); ms != nil {
		defer ms.Close()
	}
	srv := &http.Server{Addr: env("IDP_REGISTRY_LISTEN", "127.0.0.1:8250"), Handler: observability.HTTPMiddleware(tp, "idp-mcp/registry", api.Handler()),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 120 * time.Second}
	if certFile != "" {
		if srv.TLSConfig, err = transport.ServerTLS(certFile, keyFile, clientCA); err != nil {
			return fmt.Errorf("TLS: %w", err)
		}
	}
	errc := make(chan error, 1)
	go func() {
		if srv.TLSConfig != nil {
			errc <- srv.ListenAndServeTLS("", "")
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	log.Info("registry-service listening", "addr", srv.Addr, "devMode", dev, "tls", srv.TLSConfig != nil, "gatewayMTLS", clientCA != "")
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}
