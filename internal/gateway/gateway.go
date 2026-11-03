// Package gateway is the MCP data plane: one process that admits modern MCP requests,
// authenticates and authorizes callers, serves the pinned tool catalog of the running release,
// routes tools/call to upstream servers and records every decision (ADR-0001 D1).
package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"idp-mcp/adapters/identity"
	"idp-mcp/internal/authorization"
	"idp-mcp/internal/client"
	"idp-mcp/internal/invocation"
	"idp-mcp/internal/policy"
	"idp-mcp/internal/release"
	"idp-mcp/internal/routing"
	"idp-mcp/internal/server"
)

// Config of a gateway instance.
type Config struct {
	GatewayID     string
	Info          server.ServerInfo
	DevMode       bool          // allows loopback upstreams
	AllowedHosts  []string      // Host header names accepted besides loopback and the JWT resource host
	CallTimeout   time.Duration // per tools/call
	DriftInterval time.Duration
	Recorder      invocation.Recorder
	Dropped       func() int64 // invocation records lost, reported in Status
	IdentityHTTP  *http.Client // JWKS fetches
	UpstreamTLS   *tls.Config  // extra trusted CAs for https upstreams (optional)
	Log           *slog.Logger
}

// Target health as last checked against the pinned catalog.
const (
	TargetPending     = "PENDING"
	TargetOK          = "OK"
	TargetDrifted     = "DRIFTED"
	TargetUnreachable = "UNREACHABLE"
	TargetInvalid     = "INVALID"
)

// TargetStatus is one target's last drift check.
type TargetStatus struct {
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	LiveDigest string    `json:"liveDigest,omitempty"`
	CheckedAt  time.Time `json:"checkedAt,omitzero"`
	Detail     string    `json:"detail,omitempty"`
}

// Status is what the gateway attests about itself (ADR-0001 D4).
type Status struct {
	GatewayID          string         `json:"gatewayId"`
	Version            string         `json:"version"`
	ReleaseID          string         `json:"releaseId,omitempty"`
	Digest             string         `json:"digest,omitempty"`
	LoadedAt           time.Time      `json:"loadedAt,omitzero"`
	Checked            bool           `json:"checked"` // every target has been checked at least once
	Targets            []TargetStatus `json:"targets"`
	InvocationsDropped int64          `json:"invocationsDropped"`
	LastError          string         `json:"lastError,omitempty"`
	// RefusedDigest / RefusedReason name the last release the gateway refused to activate, so the
	// registry can fail that deployment at once instead of waiting for a timeout.
	RefusedDigest string `json:"refusedDigest,omitempty"`
	RefusedReason string `json:"refusedReason,omitempty"`
}

// state is everything derived from one release; replaced atomically on activation.
type state struct {
	env      *release.Envelope
	doc      *release.Document
	auth     identity.Authenticator
	policy   *authorization.Policy
	router   *routing.Router
	args     *policy.ArgumentSchemas // pinned input schemas by exposed tool name
	upstream *client.Client
	loadedAt time.Time

	listings listings // prompt/resource ownership, cached from upstream listings

	mu      sync.Mutex
	targets map[string]TargetStatus
}

func (s *state) target(name string) TargetStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.targets[name]
}

func (s *state) setTarget(ts TargetStatus) {
	s.mu.Lock()
	s.targets[ts.Name] = ts
	s.mu.Unlock()
}

// Gateway is a running data plane.
type Gateway struct {
	cfg       Config
	cur       atomic.Pointer[state]
	checkNow  chan struct{}
	lastError atomic.Value // string
	refused   atomic.Value // [2]string{digest, reason}
	hosts     map[string]bool
	listeners hub // open subscriptions/listen streams
}

// New returns a gateway without a release; it answers 503 until one is activated.
func New(cfg Config) *Gateway {
	if cfg.CallTimeout == 0 {
		cfg.CallTimeout = 60 * time.Second
	}
	if cfg.DriftInterval == 0 {
		cfg.DriftInterval = time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Recorder == nil {
		cfg.Recorder = discard{}
	}
	if cfg.IdentityHTTP == nil {
		cfg.IdentityHTTP = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	}
	g := &Gateway{cfg: cfg, checkNow: make(chan struct{}, 1), hosts: map[string]bool{"127.0.0.1": true, "localhost": true, "::1": true}}
	for _, h := range cfg.AllowedHosts {
		g.hosts[h] = true
	}
	g.lastError.Store("")
	g.refused.Store([2]string{})
	return g
}

type discard struct{}

func (discard) Record(invocation.Record) {}

// Activate opens, verifies and switches to a release. In-flight requests finish on the release they
// started with. A release for another gateway is refused.
func (g *Gateway) Activate(env *release.Envelope) error {
	err := g.activate(env)
	if err != nil {
		g.lastError.Store(err.Error())
		g.refused.Store([2]string{env.Digest, err.Error()})
	}
	return err
}

func (g *Gateway) activate(env *release.Envelope) error {
	doc, err := release.Open(env)
	if err != nil {
		return err
	}
	if doc.GatewayID != g.cfg.GatewayID {
		return fmt.Errorf("release %s is for gateway %s, not %s", doc.ReleaseID, doc.GatewayID, g.cfg.GatewayID)
	}
	var auth identity.Authenticator
	switch doc.Auth.Mode {
	case "api-key":
		auth = identity.NewAPIKeys(doc)
	case "jwt":
		auth = identity.NewJWTAuth(doc, &identity.JWKS{URL: doc.Auth.JWT.JWKSURL, HTTP: g.cfg.IdentityHTTP,
			TTL: 10 * time.Minute, MinRefresh: 30 * time.Second})
	}
	hosts := map[string]string{}
	for _, t := range doc.Targets {
		u, _ := url.Parse(t.Endpoint)
		hosts[u.Hostname()] = t.Network
		if t.Network == release.NetworkLoopback && !g.cfg.DevMode {
			return fmt.Errorf("release %s has loopback target %s; loopback upstreams need development mode", doc.ReleaseID, t.Name)
		}
	}
	args := &policy.ArgumentSchemas{}
	for _, t := range doc.Targets {
		name := t.Name
		if err := args.Add(t.Tools, func(tool string) string { return doc.Expose(name, tool) }); err != nil {
			return fmt.Errorf("release %s: %w", doc.ReleaseID, err)
		}
	}
	st := &state{env: env, doc: doc, auth: auth, policy: authorization.Compile(doc), router: routing.New(doc), args: args,
		upstream: &client.Client{HTTP: client.NewHTTPClient(policy.ForTargets(hosts, g.cfg.DevMode), g.cfg.CallTimeout, g.cfg.UpstreamTLS), Info: g.cfg.Info},
		loadedAt: time.Now().UTC(), targets: map[string]TargetStatus{}}
	for _, t := range doc.Targets {
		st.targets[t.Name] = TargetStatus{Name: t.Name, Status: TargetPending}
	}
	old := g.cur.Swap(st)
	if old != nil {
		old.upstream.HTTP.CloseIdleConnections()
	}
	g.lastError.Store("")
	g.cfg.Log.Info("release activated", "release", doc.ReleaseID, "digest", env.Digest, "targets", len(doc.Targets))
	if old != nil && old.env.Digest != env.Digest {
		g.listeners.broadcast() // pinned lists may have changed; listen streams re-check their caller
	}
	select {
	case g.checkNow <- struct{}{}:
	default:
	}
	return nil
}

// RecordError makes a release-source failure visible in Status.
func (g *Gateway) RecordError(err error) { g.lastError.Store(err.Error()) }

// Status reports the running release and target health.
func (g *Gateway) Status() Status {
	refused := g.refused.Load().([2]string)
	s := Status{GatewayID: g.cfg.GatewayID, Version: g.cfg.Info.Version, Targets: []TargetStatus{}, LastError: g.lastError.Load().(string),
		RefusedDigest: refused[0], RefusedReason: refused[1]}
	if g.cfg.Dropped != nil {
		s.InvocationsDropped = g.cfg.Dropped()
	}
	st := g.cur.Load()
	if st == nil {
		return s
	}
	s.ReleaseID, s.Digest, s.LoadedAt = st.doc.ReleaseID, st.env.Digest, st.loadedAt
	s.Checked = true
	st.mu.Lock()
	for _, ts := range st.targets {
		s.Targets = append(s.Targets, ts)
		if ts.Status == TargetPending {
			s.Checked = false
		}
	}
	st.mu.Unlock()
	sort.Slice(s.Targets, func(i, j int) bool { return s.Targets[i].Name < s.Targets[j].Name })
	return s
}

// RunDriftChecks checks the running release on activation and every DriftInterval.
func (g *Gateway) RunDriftChecks(ctx context.Context) {
	t := time.NewTicker(g.cfg.DriftInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-g.checkNow:
		}
		if st := g.cur.Load(); st != nil {
			g.CheckDrift(ctx, st)
		}
	}
}

// CheckDrift compares every target's live catalog with the pinned snapshot (ADR-0001 D3).
func (g *Gateway) CheckDrift(ctx context.Context, st *state) {
	for _, t := range st.doc.Targets {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		ts := checkTarget(cctx, st.upstream, t)
		cancel()
		prev := st.target(t.Name)
		st.setTarget(ts)
		if ts.Status != prev.Status {
			level := slog.LevelInfo
			if ts.Status != TargetOK {
				level = slog.LevelWarn
			}
			g.cfg.Log.Log(ctx, level, "target status", "target", t.Name, "status", ts.Status, "detail", ts.Detail)
		}
	}
}

func checkTarget(ctx context.Context, c *client.Client, t release.Target) TargetStatus {
	ts := TargetStatus{Name: t.Name, CheckedAt: time.Now().UTC()}
	fail := func(err error) TargetStatus {
		var rpc *client.RPCError
		if errors.As(err, &rpc) {
			ts.Status, ts.Detail = TargetInvalid, "list request answered an error"
		} else {
			ts.Status, ts.Detail = TargetUnreachable, err.Error()
		}
		return ts
	}
	raws, err := c.ListTools(ctx, t.Endpoint)
	if err != nil {
		return fail(err)
	}
	var promptRaws []json.RawMessage
	if t.HasCapability(release.CapPrompts) {
		if promptRaws, err = c.ListPrompts(ctx, t.Endpoint); err != nil {
			return fail(err)
		}
	}
	digest, err := liveDigest(raws, promptRaws)
	if err != nil {
		ts.Status, ts.Detail = TargetInvalid, err.Error()
		return ts
	}
	ts.LiveDigest = digest
	if digest == t.SnapshotDigest {
		ts.Status = TargetOK
	} else {
		ts.Status, ts.Detail = TargetDrifted, "live catalog differs from the approved snapshot"
	}
	return ts
}

// blocked reports whether calls to target are refused because of drift.
func (st *state) blocked(target string) bool {
	return st.doc.DriftAction == "block" && st.target(target).Status == TargetDrifted
}
