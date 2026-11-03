// Command mcp-gateway is the idp-mcp data plane (ADR-0001 D1).
//
// Configuration (environment):
//
//	IDP_GATEWAY_ID             gateway id (required; releases for other gateways are refused)
//	IDP_GATEWAY_LISTEN         listen address (default 127.0.0.1:3220)
//	IDP_GATEWAY_ALLOWED_HOSTS  extra Host names accepted besides loopback, comma separated
//	IDP_DEV_MODE               "true" allows loopback upstreams
//	IDP_REGISTRY_URL           registry service base URL; with IDP_GATEWAY_TOKEN[_FILE] the gateway
//	                           follows its desired release and reports heartbeats and invocations
//	IDP_RELEASE_FILE           static mode instead: run this release envelope (offline / on-prem)
//	IDP_RELEASE_CACHE          last activated envelope, so the gateway starts while the registry is down
//	IDP_CALL_TIMEOUT           per tools/call (default 60s)
//	IDP_DRIFT_INTERVAL         catalog drift checks (default 60s)
//	IDP_LOG_LEVEL              debug | info | warn | error
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"idp-mcp/internal/gateway"
	"idp-mcp/internal/invocation"
	"idp-mcp/internal/observability"
	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
)

var version = "0.1.0-dev"

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func duration(key string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(env(key, def.String()))
	if err != nil || d <= 0 {
		fmt.Fprintf(os.Stderr, "invalid %s; using %s\n", key, def)
		return def
	}
	return d
}

func secret(key string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if path := os.Getenv(key + "_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

func main() {
	log := observability.NewLogger(os.Stdout, env("IDP_LOG_LEVEL", "info"))
	if err := run(log); err != nil {
		log.Error("mcp-gateway stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	id := env("IDP_GATEWAY_ID", "")
	if id == "" {
		return errors.New("IDP_GATEWAY_ID is required")
	}
	registry, token, file := env("IDP_REGISTRY_URL", ""), secret("IDP_GATEWAY_TOKEN"), env("IDP_RELEASE_FILE", "")
	if (registry == "") == (file == "") {
		return errors.New("set exactly one of IDP_REGISTRY_URL (with IDP_GATEWAY_TOKEN) or IDP_RELEASE_FILE")
	}
	if registry != "" && token == "" {
		return errors.New("IDP_REGISTRY_URL needs IDP_GATEWAY_TOKEN or IDP_GATEWAY_TOKEN_FILE")
	}
	var hosts []string
	for _, h := range strings.Split(env("IDP_GATEWAY_ALLOWED_HOSTS", ""), ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			hosts = append(hosts, h)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := gateway.Config{GatewayID: id, Info: server.ServerInfo{Name: "idp-mcp-gateway", Version: version},
		DevMode: env("IDP_DEV_MODE", "false") == "true", AllowedHosts: hosts,
		CallTimeout: duration("IDP_CALL_TIMEOUT", 60*time.Second), DriftInterval: duration("IDP_DRIFT_INTERVAL", time.Minute), Log: log}
	var sync *gateway.RegistrySync
	var batcher *invocation.Batcher
	if registry != "" {
		sync = &gateway.RegistrySync{BaseURL: registry, Token: token, CacheFile: env("IDP_RELEASE_CACHE", ""), Log: log,
			HTTP:         &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil}},
			PollInterval: duration("IDP_POLL_INTERVAL", 2*time.Second), HeartbeatInterval: duration("IDP_HEARTBEAT_INTERVAL", 2*time.Second)}
		batcher = invocation.NewBatcher(sync.Sink(), log)
	} else {
		batcher = invocation.NewBatcher(func(_ context.Context, b []invocation.Record) error {
			for _, r := range b {
				log.Info("invocation", "subject", r.Subject, "tool", r.Tool, "decision", r.Decision, "outcome", r.Outcome,
					"latencyMs", r.LatencyMS, "traceId", r.TraceID, "release", r.ReleaseDigest)
			}
			return nil
		}, log)
	}
	cfg.Recorder, cfg.Dropped = batcher, batcher.Dropped
	g := gateway.New(cfg)
	if sync != nil {
		sync.Gateway = g
	}
	go batcher.Run(ctx)
	go g.RunDriftChecks(ctx)

	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		var envl release.Envelope
		if err := json.Unmarshal(b, &envl); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		if err := g.Activate(&envl); err != nil {
			return err
		}
	} else {
		sync.LoadCache()
		go sync.Run(ctx)
	}

	srv := &http.Server{Addr: env("IDP_GATEWAY_LISTEN", "127.0.0.1:3220"), Handler: g.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("mcp-gateway listening", "addr", srv.Addr, "gateway", id, "mode", map[bool]string{true: "static", false: "registry"}[file != ""])
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}
