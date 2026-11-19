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
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"idp-mcp/adapters/identity"
	"idp-mcp/internal/admission"
	"idp-mcp/internal/authorization"
	"idp-mcp/internal/client"
	"idp-mcp/internal/invocation"
	"idp-mcp/internal/observability"
	"idp-mcp/internal/policy"
	"idp-mcp/internal/release"
	"idp-mcp/internal/routing"
	"idp-mcp/internal/server"

	"go.opentelemetry.io/otel/trace"
)

// Config of a gateway instance.
type Config struct {
	GatewayID     string
	InstanceID    string // this replica (pod name, hostname); several replicas may share a gateway record
	Info          server.ServerInfo
	DevMode       bool          // allows loopback upstreams
	AllowedHosts  []string      // Host header names accepted besides loopback and the JWT resource host
	CallTimeout   time.Duration // per tools/call
	DriftInterval time.Duration
	Recorder      invocation.Recorder
	Dropped       func() int64           // invocation records lost, reported in Status
	IdentityHTTP  *http.Client           // JWKS fetches
	UpstreamTLS   *tls.Config            // extra trusted CAs for https upstreams (optional)
	Tracer        trace.TracerProvider   // optional; default: SDK provider without exporter
	Metrics       *observability.Metrics // optional; default: a fresh registry (see Metrics())
	Log           *slog.Logger
	// CallerSigner signs the caller forwarded to targets approved for identity (ADR-0001 D44); nil sends the
	// caller unsigned, and the upstream then has only the network to trust.
	CallerSigner *CallerSigner
	// Clients lists the OAuth clients the gateway serves and what each may reach (ADR-0001 D46 to D49), and
	// holds the rate limits. Nil lists nobody, so every client sees nothing: the program refuses to start
	// without the file, and a library user who forgets it gets the closed answer, not an open one.
	Clients *admission.Clients
	// Bridges lists the addresses of the bridge endpoints (ADR-0001 D50): a release that has a target at one of them
	// and does not call it external is refused at activation, as the registry refuses the registration. Empty by
	// default.
	Bridges policy.Endpoints
	// ExternalMaxResult bounds, in bytes, one answer from a target of class external, and one event of its event
	// stream; ExternalMaxStream bounds all that such a stream carries (ADR-0001 D51 d). ExternalProbeFailures is how
	// many consecutive failed catalog probes of an external target block calls to it (D51 f).
	ExternalMaxResult     int64
	ExternalMaxStream     int64
	ExternalProbeFailures int
}

// Defaults of the settings for external targets. The HOST reads at most 8 MiB of an answer (idp-host
// internal/mcpclient MaxResponse) and hands the model 16 KiB of a tool result (internal/harness ToolResultLimit), so a
// plain answer of 1 MiB is already 64 times what the model reads and an eighth of what the HOST accepts; a stream
// of 4 MiB is half of it, since the HOST reads a whole stream as one response. The memory a call holds is bounded
// by the first number, so a hundred concurrent calls are a hundred MiB at the worst. Three failed probes at the
// default interval of a minute block calls after about three minutes: a restart or a deploy of the upstream does
// not block anything, an upstream that stays away or keeps answering nonsense does (ADR-0001 D51).
const (
	DefaultExternalMaxResult     = 1 << 20
	DefaultExternalMaxStream     = 4 << 20
	DefaultExternalProbeFailures = 3
)

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
	// Failures counts the consecutive probes that failed (unreachable, or an answer that is not a catalog); it is
	// reset by a probe that found the approved catalog. Blocked says calls to the target are refused now, and
	// External that the target is of class external, whose calls are also blocked while it has not been verified
	// or after ExternalProbeFailures failures (ADR-0001 D51 f). verified: some probe of this release found the
	// approved catalog.
	Failures int  `json:"failures,omitempty"`
	Blocked  bool `json:"blocked,omitempty"`
	External bool `json:"external,omitempty"`
	verified bool
}

// Status is what the gateway attests about itself (ADR-0001 D4).
type Status struct {
	GatewayID          string         `json:"gatewayId"`
	InstanceID         string         `json:"instanceId,omitempty"`
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
	// anonymous is the same connections without clientInfo and trace context: what the gateway uses toward targets of
	// class external (ADR-0001 D51 b).
	anonymous *client.Client
	loadedAt  time.Time

	resources map[string]*resourceIndex // pinned resource URIs and templates per target

	mu      sync.Mutex
	targets map[string]TargetStatus
}

// resourceIndex answers "does this target pin uri" (exactly, or by template).
type resourceIndex struct {
	uris      map[string]bool
	templates []*regexp.Regexp
}

func (x *resourceIndex) owns(uri string) (exact, byTemplate bool) {
	if x == nil {
		return false, false
	}
	if x.uris[uri] {
		return true, false
	}
	for _, re := range x.templates {
		if re.MatchString(uri) {
			return false, true
		}
	}
	return false, false
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
	cfg          Config
	cur          atomic.Pointer[state]
	checkNow     chan struct{}
	lastError    atomic.Value // string
	refused      atomic.Value // [2]string{digest, reason}
	hosts        map[string]bool
	listeners    hub // open subscriptions/listen streams
	tasks        taskStore
	tracer       trace.Tracer
	metrics      *observability.Metrics
	limiter      *admission.Limiter // request windows per client and per subject (D49)
	authFailures *observability.CounterVec
}

// meteredRecorder counts every decision and observes its latency before passing it on.
type meteredRecorder struct {
	inner     invocation.Recorder
	decisions *observability.CounterVec
	latency   *observability.HistogramVec
}

func (m *meteredRecorder) Record(r invocation.Record) {
	m.decisions.Inc(r.Method, r.Decision, r.Outcome)
	m.latency.Observe(float64(r.LatencyMS)/1000, r.Method)
	m.inner.Record(r)
}

// Metrics returns the gateway's metrics registry (served by IDP_METRICS_LISTEN).
func (g *Gateway) Metrics() *observability.Metrics { return g.metrics }

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
	if cfg.ExternalMaxResult <= 0 {
		cfg.ExternalMaxResult = DefaultExternalMaxResult
	}
	if cfg.ExternalMaxStream <= 0 {
		cfg.ExternalMaxStream = DefaultExternalMaxStream
	}
	if cfg.ExternalProbeFailures <= 0 {
		cfg.ExternalProbeFailures = DefaultExternalProbeFailures
	}
	if cfg.Recorder == nil {
		cfg.Recorder = discard{}
	}
	if cfg.IdentityHTTP == nil {
		cfg.IdentityHTTP = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	}
	if cfg.Tracer == nil {
		cfg.Tracer = observability.NewTracerProvider(cfg.Info.Name, cfg.Info.Version, nil)
	}
	if cfg.Metrics == nil {
		cfg.Metrics = observability.NewMetrics()
	}
	cfg.Recorder = &meteredRecorder{inner: cfg.Recorder,
		decisions: cfg.Metrics.Counter("idp_mcp_gateway_decisions_total", "Gateway decisions by MCP method, decision and outcome.", "method", "decision", "outcome"),
		latency:   cfg.Metrics.Histogram("idp_mcp_gateway_decision_duration_seconds", "Latency of decided requests by MCP method.", observability.DurationBuckets, "method")}
	g := &Gateway{cfg: cfg, checkNow: make(chan struct{}, 1), hosts: map[string]bool{"127.0.0.1": true, "localhost": true, "::1": true},
		tracer: cfg.Tracer.Tracer("idp-mcp/gateway"), metrics: cfg.Metrics, limiter: admission.NewLimiter(nil),
		authFailures: cfg.Metrics.Counter("idp_mcp_gateway_auth_failures_total", "Requests whose bearer credential was missing or refused, audited or not.")}
	g.metrics.GaugeFunc("idp_mcp_gateway_listen_streams", "Open subscriptions/listen streams.", nil,
		func() []observability.LabeledValue {
			return []observability.LabeledValue{{Value: float64(g.ListenStreams())}}
		})
	g.metrics.GaugeFunc("idp_mcp_gateway_task_bindings", "Task ids the gateway can route.", nil,
		func() []observability.LabeledValue {
			return []observability.LabeledValue{{Value: float64(g.tasks.Count())}}
		})
	g.metrics.GaugeFunc("idp_mcp_gateway_invocations_dropped_total", "Invocation records lost to a full buffer.", nil,
		func() []observability.LabeledValue {
			if cfg.Dropped == nil {
				return nil
			}
			return []observability.LabeledValue{{Value: float64(cfg.Dropped())}}
		})
	g.metrics.GaugeFunc("idp_mcp_gateway_target_up", "1 when the target's live catalog matches the approved snapshot.", []string{"target", "status"},
		func() []observability.LabeledValue {
			var out []observability.LabeledValue
			for _, t := range g.Status().Targets {
				v := 0.0
				if t.Status == TargetOK {
					v = 1
				}
				out = append(out, observability.LabeledValue{Labels: []string{t.Name, t.Status}, Value: v})
			}
			return out
		})
	g.metrics.GaugeFunc("idp_mcp_gateway_target_blocked", "1 while calls to the target are refused: drift, or for an external target also an unverified or unreachable catalog.", []string{"target", "class"},
		func() []observability.LabeledValue {
			var out []observability.LabeledValue
			for _, t := range g.Status().Targets {
				v, class := 0.0, "internal"
				if t.Blocked {
					v = 1
				}
				if t.External {
					class = "external"
				}
				out = append(out, observability.LabeledValue{Labels: []string{t.Name, class}, Value: v})
			}
			return out
		})
	g.metrics.GaugeFunc("idp_mcp_gateway_release_info", "The running release (always 1).", []string{"release", "digest"},
		func() []observability.LabeledValue {
			s := g.Status()
			if s.Digest == "" {
				return nil
			}
			return []observability.LabeledValue{{Labels: []string{s.ReleaseID, s.Digest}, Value: 1}}
		})
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
		if g.cfg.Bridges.Matches(t.Endpoint) && !t.External() {
			return fmt.Errorf("release %s: target %s is at a bridge address and is not of class external", doc.ReleaseID, t.Name)
		}
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
	resources := map[string]*resourceIndex{}
	for _, t := range doc.Targets {
		idx := &resourceIndex{uris: map[string]bool{}}
		for _, r := range t.Resources {
			idx.uris[r.URI] = true
		}
		for _, r := range t.ResourceTemplates {
			idx.templates = append(idx.templates, templateRE(r.URITemplate))
		}
		resources[t.Name] = idx
	}
	st := &state{env: env, doc: doc, auth: auth, policy: authorization.Compile(doc, g.cfg.Clients), router: routing.New(doc), args: args, resources: resources,
		upstream: &client.Client{HTTP: client.NewHTTPClient(policy.ForTargets(hosts, g.cfg.DevMode), g.cfg.CallTimeout, g.cfg.UpstreamTLS), Info: g.cfg.Info},
		loadedAt: time.Now().UTC(), targets: map[string]TargetStatus{}}
	st.anonymous = st.upstream.Anonymized()
	for _, t := range doc.Targets {
		st.targets[t.Name] = TargetStatus{Name: t.Name, Status: TargetPending, External: t.External()}
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
	s := Status{GatewayID: g.cfg.GatewayID, InstanceID: g.cfg.InstanceID, Version: g.cfg.Info.Version, Targets: []TargetStatus{}, LastError: g.lastError.Load().(string),
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
		ts.Blocked = g.blockReason(st, ts) != ""
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

// CheckDrift compares every target's live catalog with the pinned snapshot (ADR-0001 D3). The probe of a target of
// class external is anonymous, and its failures are counted (D51 f).
func (g *Gateway) CheckDrift(ctx context.Context, st *state) {
	for _, t := range st.doc.Targets {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		c := st.upstream
		if t.External() {
			c = st.anonymous
		}
		ts := checkTarget(cctx, c, t)
		cancel()
		prev := st.target(t.Name)
		ts.External = t.External()
		switch ts.Status {
		case TargetOK:
			ts.verified = true
		case TargetDrifted:
			// a catalog that differs is blocked at once; once it is back the next probe verifies it again
			ts.Failures = 0
		default:
			ts.Failures, ts.verified = prev.Failures+1, prev.verified
		}
		st.setTarget(ts)
		blocked := g.blockReason(st, ts) != ""
		if ts.Status != prev.Status || blocked != (g.blockReason(st, prev) != "") {
			level := slog.LevelInfo
			if ts.Status != TargetOK {
				level = slog.LevelWarn
			}
			g.cfg.Log.Log(ctx, level, "target status", "target", t.Name, "status", ts.Status, "detail", ts.Detail, "failures", ts.Failures, "blocked", blocked)
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
	var promptRaws, resRaws, tplRaws []json.RawMessage
	if t.HasCapability(release.CapPrompts) {
		if promptRaws, err = c.ListPrompts(ctx, t.Endpoint); err != nil {
			return fail(err)
		}
	}
	if t.HasCapability(release.CapResources) {
		if resRaws, err = c.List(ctx, t.Endpoint, "resources/list", "resources"); err != nil {
			return fail(err)
		}
		if tplRaws, err = c.List(ctx, t.Endpoint, "resources/templates/list", "resourceTemplates"); err != nil {
			return fail(err)
		}
	}
	digest, err := liveDigest(raws, promptRaws, resRaws, tplRaws)
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

// blockReason says why calls to the target are refused, "" when they are not.
//
// Every target: a catalog that differs from the approved one blocks when the release's driftAction is block.
// A target of class external is also blocked whatever the driftAction says, and by more (ADR-0001 D51 f): until a
// probe of this release found its approved catalog, and when ExternalProbeFailures consecutive probes failed,
// until one succeeds. Fewer failures than that, after the catalog was verified, do not block: a restart of the
// upstream is not an incident.
func (g *Gateway) blockReason(st *state, ts TargetStatus) string {
	drifted := "the upstream catalog changed since approval"
	if !ts.External {
		if st.doc.DriftAction == "block" && ts.Status == TargetDrifted {
			return drifted
		}
		return ""
	}
	switch {
	case ts.Status == TargetDrifted:
		return drifted
	case ts.Status == TargetOK:
		return ""
	case ts.Status == TargetPending || !ts.verified:
		return "the upstream catalog has not been checked against the approved one yet"
	case ts.Failures >= g.cfg.ExternalProbeFailures:
		return fmt.Sprintf("the upstream catalog could not be checked against the approved one in the last %d probes", ts.Failures)
	}
	return ""
}

// blocked reports why calls to target are refused, "" if they are not.
func (g *Gateway) blocked(st *state, target string) string {
	return g.blockReason(st, st.target(target))
}

// isExternal reports whether target is of class external.
func (st *state) isExternal(target string) bool {
	for _, t := range st.doc.Targets {
		if t.Name == target {
			return t.External()
		}
	}
	return false
}
